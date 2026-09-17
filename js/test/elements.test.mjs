// Elements in the TypeScript SDK: the Elements key derived from key sync, element keys wrapped and records and files
// sealed and padded, a vector sealed by Python (kuno_protocol and the cryptography package) opening here, the Python SDK
// (kunoworld.elements) sealing the same bytes as this one and each SDK's Elements opening in the other
// (data/elements_sdk_vectors.json, shared with sdk/python/tests), and the client against a fake gateway: only ciphertext
// and ids sent, files kept or replaced, rotation re-wraps, and Elements attached to a request as ordinary inputs plus
// prompt lines.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  ELEMENT_RULES,
  KunoClient,
  KunoError,
  addElementLines,
  b64d,
  b64e,
  blobVersion,
  deriveElementsKey,
  elementDraftProblems,
  elementPromptLine,
  elementRoles,
  formatElementsKey,
  openElement,
  openElementFile,
  openElementRecord,
  parseElementsKey,
  rewrapElementKey,
  sealElement,
  unpadPayload,
  unwrapElementKey,
  decryptBlob,
  wrapElementKey,
} from "../dist/index.js";

const vector = JSON.parse(readFileSync(new URL("./data/elements_vector.json", import.meta.url), "utf8"));
const SDK_VECTORS = JSON.parse(readFileSync(new URL("./data/elements_sdk_vectors.json", import.meta.url), "utf8"));
const ACCOUNT = "0123456789abcdef0123456789abcdef";
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...new TextEncoder().encode("a green raincoat".repeat(30))]);
const WAV = new Uint8Array([...new TextEncoder().encode("RIFF\0\0\0\0WAVEfmt "), ...new Uint8Array(400)]);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const text = (bytes) => new TextDecoder().decode(bytes);
const hex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, "0")).join("");

function freshKey(keyId = hex(16)) {
  return deriveElementsKey(crypto.getRandomValues(new Uint8Array(32)), ACCOUNT, keyId);
}

const mara = (extra = {}) => ({
  kind: "character",
  name: "Mara",
  description: "a woman in her 60s with short silver hair and a green raincoat",
  consent: { subject: "Mara Jones", relationship: "permission", grantedOn: "2026-09-01", use: "Videos made on KunoWorld", affirmedAt: 1789600000 },
  files: [{ data: PNG, mime: "image/png", name: "mara.png", width: 512, height: 512 }],
  ...extra,
});

test("a Python-sealed Element opens here with the key sync master key", () => {
  const key = deriveElementsKey(b64d(vector.master_key), vector.account_id, vector.master_key_id);
  assert.equal(b64e(key.key), vector.elements_key);
  const element = openElement(key, vector.row);
  assert.equal(b64e(element.elementKey), vector.element_key);
  assert.deepEqual(
    { v: element.v, elementId: element.elementId, kind: element.kind, name: element.name, description: element.description, consent: element.consent, files: element.files },
    vector.record,
  );
  assert.deepEqual(openElementFile(element.elementKey, element.elementId, 0, b64d(vector.sealed_file_0), element.files[0]), b64d(vector.file_0));
  assert.equal(b64d(vector.row.meta).length, vector.meta_sealed_bytes, "the record is padded to 4 KiB");
});

/** Runs `fn` with the randomness replaced by the vectors' byte stream: 0, 1, 2, …, 255, 0, … in the order it is drawn. */
function withCounterRandomness(fn) {
  const real = crypto.getRandomValues;
  let n = 0;
  crypto.getRandomValues = (array) => {
    for (let i = 0; i < array.length; i++) array[i] = (n + i) % 256;
    n += array.length;
    return array;
  };
  try {
    return fn();
  } finally {
    crypto.getRandomValues = real;
  }
}

test("the Python SDK seals exactly these bytes, and each SDK's Elements open in the other", () => {
  const v = SDK_VECTORS;
  const key = deriveElementsKey(b64d(v.master_key), v.account_id, v.master_key_id);
  assert.equal(b64e(key.key), v.elements_key);
  assert.equal(formatElementsKey(key), v.elements_key_text);
  const files = Object.fromEntries(Object.entries(v.files).map(([name, data]) => [name, b64d(data)]));
  const draftOf = (draft) => ({ ...draft, files: (draft.files ?? []).map(({ file, ...rest }) => ({ data: files[file], ...rest })) });

  const sealed = [];
  for (const c of v.deterministic) {
    const kept = sealed[c.keep_files_of];
    const s = withCounterRandomness(() =>
      kept
        ? sealElement(key, c.element_id, { ...draftOf(c.draft), files: [] }, { elementKey: kept.elementKey, keepFiles: kept.record.files })
        : sealElement(key, c.element_id, draftOf(c.draft)),
    );
    sealed.push(s);
    assert.equal(b64e(s.elementKey), c.element_key, c.name);
    assert.equal(s.wrappedKey, c.wrapped_key, c.name);
    assert.equal(s.meta, c.meta, c.name);
    assert.deepEqual(s.files.map(b64e), c.sealed_files, c.name);
    const json = text(unpadPayload(decryptBlob(s.elementKey, `element/${c.element_id}/meta`, b64d(s.meta))));
    assert.equal(json, c.record_json, c.name);
  }
  // The text cases: trimmed as JavaScript trims, a file name cut at 200 UTF-16 units, withdrawal written in the record.
  assert.equal(sealed[0].record.name, "Mára Jó 🎬");
  assert.match(v.deterministic[0].record_json, /smiling\\u001c"/);
  assert.match(v.deterministic[0].record_json, /\\ud83c"/);
  assert.equal(sealed[2].record.consent.withdrawnAt, 1790000000.5);

  for (const [who, made] of [["Python", v.sealed_by_python], ["JavaScript", v.sealed_by_javascript]]) {
    const element = openElement(key, made.row);
    assert.equal(JSON.stringify(openElementRecord(element.elementKey, element.elementId, made.row.meta)), made.record_json, who);
    assert.equal(element.name, "Mára Jó 🎬", who);
    assert.equal(element.consent.subject, "Mára Jó", who);
    made.files.forEach((name, position) => {
      assert.deepEqual(openElementFile(element.elementKey, element.elementId, position, b64d(made.sealed_files[position]), element.files[position]), files[name], who);
    });
  }
});

test("the Elements key is bound to its account and travels as text", () => {
  const master = crypto.getRandomValues(new Uint8Array(32));
  const key = deriveElementsKey(master, ACCOUNT, "f".repeat(32));
  assert.notDeepEqual(deriveElementsKey(master, "another-account", "f".repeat(32)).key, key.key);
  assert.equal(key.key.length, 32);
  const written = formatElementsKey(key);
  assert.match(written, /^kwek1\.0123456789abcdef0123456789abcdef\.f{32}\.[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(parseElementsKey(` ${written}\n`), key);
  for (const bad of ["", "kwek1..", written.replace("kwek1", "kwek2"), written.slice(0, -1)]) {
    assert.throws(() => parseElementsKey(bad), (err) => err instanceof KunoError && err.code === "invalid_element");
  }
  assert.throws(() => deriveElementsKey(new Uint8Array(16), ACCOUNT, "f".repeat(32)), /32 bytes/);
});

test("an element key opens only for its account and Element, and a rotation re-wraps the same key", () => {
  const key = freshKey();
  const elementId = hex(16);
  const elementKey = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = wrapElementKey(key, elementId, elementKey);
  assert.equal(b64d(wrapped).length, 64);
  assert.equal(text(b64d(wrapped).subarray(0, 4)), "KVE1");
  assert.deepEqual(unwrapElementKey(key, elementId, wrapped), elementKey);
  const failed = (err) => err instanceof KunoError && err.code === "decrypt_failed";
  assert.throws(() => unwrapElementKey(key, hex(16), wrapped), failed);
  assert.throws(() => unwrapElementKey({ ...key, accountId: "someone-else" }, elementId, wrapped), failed);
  const rotated = freshKey();
  const rewrapped = rewrapElementKey(key, rotated, elementId, wrapped);
  assert.deepEqual(unwrapElementKey(rotated, elementId, rewrapped), elementKey);
  assert.throws(() => unwrapElementKey(key, elementId, rewrapped), failed);
});

test("sealing pads the record and every file, and nothing readable is left in what is sent", () => {
  const key = freshKey();
  const elementId = hex(16);
  const sealed = sealElement(key, elementId, mara());
  const meta = b64d(sealed.meta);
  assert.equal(blobVersion(meta), 2);
  assert.equal(meta.length, vector.meta_sealed_bytes);
  assert.equal(unpadPayload(decryptBlob(sealed.elementKey, `element/${elementId}/meta`, meta)).length < 4096, true);
  assert.equal(sealed.files.length, 1);
  assert.equal(blobVersion(sealed.files[0]), 2);
  assert.equal(sealed.record.files[0].sha256, sha256(PNG));
  const everything = sealed.meta + sealed.wrappedKey + b64e(sealed.files[0]) + text(sealed.files[0]) + text(meta);
  for (const plain of ["Mara", "raincoat", "character", "a green raincoat"]) assert.equal(everything.includes(plain), false, plain);
  // A record past 4 KiB of JSON takes the next bucket, 8 KiB: 18 + padme(8 + 8192) + 16 bytes sealed.
  const named = { ...mara().files[0], name: "é".repeat(200) };
  const longer = sealElement(key, elementId, mara({ description: "é".repeat(1000), consent: { ...mara().consent, use: "é".repeat(200) }, files: Array(4).fill(named) }));
  assert.equal(b64d(longer.meta).length, 8738);
  // A file that isn't the one the record lists is refused.
  assert.throws(
    () => openElementFile(sealed.elementKey, elementId, 0, sealElement(key, elementId, mara({ files: [{ data: WAV, mime: "image/png" }] })).files[0], sealed.record.files[0]),
    (err) => err instanceof KunoError && (err.code === "integrity" || err.code === "decrypt_failed"),
  );
});

test("drafts follow the Elements rules", () => {
  const check = (draft) => elementDraftProblems({ ...draft, files: draft.files.map((f) => ({ mime: f.mime, size: f.data.length, durationS: f.durationS })) });
  assert.deepEqual(check(mara()), []);
  assert.deepEqual(check(mara({ consent: null })), [], "a character need not be a real person");
  assert.deepEqual(check({ kind: "voice", name: "Narrator", files: [{ data: WAV, mime: "audio/wav", durationS: 12 }] }), []);
  const cases = [
    [mara({ name: " " }), /Give it a name/],
    [mara({ name: "x".repeat(81) }), /at most 80 characters/],
    [mara({ name: "two\nlines" }), /on one line/],
    [mara({ description: "x".repeat(1001) }), /at most 1,000 characters/],
    [mara({ files: [] }), /Add 1 to 4 images/],
    [mara({ files: Array(5).fill(mara().files[0]) }), /Add 1 to 4 images/],
    [mara({ files: [{ data: WAV, mime: "audio/wav" }] }), /PNG, JPEG or WebP/],
    [{ kind: "voice", name: "Narrator", files: [{ data: PNG, mime: "image/png" }] }, /WAV, MP3, Ogg or FLAC/],
    [{ kind: "voice", name: "Narrator", files: [{ data: WAV, mime: "audio/wav", durationS: 31 }] }, /at most 30 seconds/],
    [{ kind: "product", name: "Mug", files: mara().files, consent: mara().consent }, /Only characters and voices/],
    [mara({ consent: { ...mara().consent, subject: "" } }), /who gave consent/],
    [mara({ consent: { ...mara().consent, grantedOn: "last week" } }), /when consent was given/],
    [mara({ kind: "celebrity" }), /one of: character, product/],
  ];
  for (const [draft, message] of cases) assert.match(check(draft).join(" "), message, message.source);
  assert.throws(() => sealElement(freshKey(), hex(16), mara({ files: [] })), (err) => err.code === "invalid_element");
});

test("which models can use an Element's files", () => {
  const fast = { modes: ["text_to_video", "image_to_video", "last_frame", "first_last_frame", "keyframes", "retake", "storyboard"], limits: { max_inputs: { first_frame: 1, last_frame: 1, keyframe: 8, source_video: 1 } } };
  const reference = { modes: ["reference_to_video", "video_edit", "extend_video", "audio_to_video"], limits: { max_inputs: { reference_image: 9, reference_video: 3, reference_audio: 3, first_frame: 1 } } };
  const fourK = { modes: ["text_to_video", "image_to_video", "keyframes"], limits: { max_inputs: { first_frame: 1, keyframe: 8 } } };
  assert.deepEqual(elementRoles({ kind: "character" }, fast), ["first_frame", "last_frame", "keyframe"]);
  assert.deepEqual(elementRoles({ kind: "location" }, fourK), ["first_frame", "keyframe"]);
  assert.deepEqual(elementRoles({ kind: "product" }, reference), ["reference_image"]);
  assert.deepEqual(elementRoles({ kind: "voice" }, reference), ["reference_audio"]);
  assert.deepEqual(elementRoles({ kind: "voice" }, fast), [], "LTX-2.5 takes no reference audio: the voice is kept for later");
  assert.equal(elementPromptLine({ name: " Mara ", description: "a woman\n in her 60s " }), "Mara: a woman in her 60s");
  assert.equal(elementPromptLine({ name: "Harbour", description: "" }), "Harbour");
  const once = addElementLines("A walk at dusk.", [{ name: "Mara", description: "silver hair" }]);
  assert.equal(once, "A walk at dusk.\nMara: silver hair");
  assert.equal(addElementLines(once, [{ name: "Mara", description: "silver hair" }]), once, "a line already there isn't added twice");
  assert.equal(addElementLines("", [{ name: "Harbour", description: "" }]), "Harbour");
});

// ---------------------------------------------------------------- the client against a fake gateway

/** Stores what the SDK sends, like the gateway: uploads by id, Elements by id with revisions. Refuses readable fields. */
function fakeGateway() {
  const blobs = new Map();
  const elements = new Map();
  const calls = [];
  let masterKeyId = null;
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const fail = (status, code, extra = {}) => json({ detail: { code, message: code, ...extra } }, status);
  const fetch = async (url, init = {}) => {
    const u = new URL(url);
    const method = init.method ?? "GET";
    const body = init.body instanceof Blob ? new Uint8Array(await init.body.arrayBuffer()) : init.body;
    calls.push({ method, path: u.pathname, body, headers: init.headers ?? {} });
    if (method === "POST" && u.pathname === "/v1/blobs") {
      if (text(body.subarray(0, 6)) !== "KUNOB1") return fail(400, "not_encrypted");
      const id = hex(16);
      blobs.set(id, body);
      return json({ blob_id: id, sha256: sha256(body), size: body.length }, 201);
    }
    if (method === "GET" && u.pathname === "/v1/elements") {
      return json({ master_key_id: masterKeyId, elements: [...elements.values()].map((e) => e.row), next_cursor: null });
    }
    const match = /^\/v1\/elements\/([0-9a-f]{32})(?:\/files\/(\d+))?$/.exec(u.pathname);
    if (!match) return fail(404, "not_found");
    const [, id, position] = match;
    const current = elements.get(id);
    if (position !== undefined) return current ? new Response(blobs.get(current.files[Number(position)])) : fail(404, "not_found");
    if (method === "GET") return current ? json(current.row) : fail(404, "not_found");
    if (method === "DELETE") {
      elements.delete(id);
      return new Response(null, { status: 204 });
    }
    const put = JSON.parse(body);
    const allowed = new Set(["master_key_id", "expected_revision", "wrapped_key", "meta", "file_blob_ids", "affirm_rules"]);
    if (Object.keys(put).some((k) => !allowed.has(k)) || put.affirm_rules !== true) return fail(422, "invalid");
    if (put.master_key_id !== masterKeyId) return fail(409, "vault_changed");
    if (put.expected_revision === null ? current : current?.row.revision !== put.expected_revision) return fail(409, "element_changed");
    const files = put.file_blob_ids ?? current.files;
    const row = {
      element_id: id,
      revision: (current?.row.revision ?? 0) + 1,
      master_key_id: masterKeyId,
      wrapped_key: put.wrapped_key ?? current.row.wrapped_key,
      meta: put.meta,
      files: files.map((b, i) => ({ position: i, size: blobs.get(b).length, sha256: sha256(blobs.get(b)) })),
      files_bytes: files.reduce((n, b) => n + blobs.get(b).length, 0),
      created_at: 1,
      updated_at: 2,
    };
    elements.set(id, { row, files });
    return json(row, current ? 200 : 201);
  };
  return { blobs, elements, calls, fetch, setKeyId: (id) => (masterKeyId = id) };
}

test("create, list, replace and delete send only ciphertext and ids, and keep or replace files as asked", async () => {
  const gw = fakeGateway();
  const key = freshKey();
  gw.setKeyId(key.keyId);
  const kuno = new KunoClient({ apiKey: "kw_live_test", baseUrl: "https://gw.test", fetch: gw.fetch });

  await assert.rejects(kuno.elements.create(key, mara(), {}), (err) => err.code === "rules_not_affirmed");
  assert.equal(gw.calls.length, 0, "nothing is sent before the rules are affirmed");

  const made = await kuno.elements.create(key, mara(), { affirmRules: true });
  assert.equal(made.revision, 1);
  assert.equal(made.name, "Mara");
  const [upload, put] = gw.calls;
  assert.equal(upload.path, "/v1/blobs");
  assert.equal(upload.headers.authorization, "Bearer kw_live_test");
  const sent = JSON.parse(put.body);
  assert.deepEqual(Object.keys(sent).sort(), ["affirm_rules", "expected_revision", "file_blob_ids", "master_key_id", "meta", "wrapped_key"]);
  assert.equal(sent.expected_revision, null);
  for (const call of gw.calls) {
    const seen = typeof call.body === "string" ? call.body : text(call.body);
    for (const plain of ["Mara", "raincoat", "character", "Mara Jones", "permission"]) assert.equal(seen.includes(plain), false, `${plain} in ${call.path}`);
  }
  assert.deepEqual(await kuno.elements.file(made), PNG);

  // A rename keeps the files and the key: no uploads, no wrapped key.
  gw.calls.length = 0;
  const renamed = await kuno.elements.update(key, made, { ...mara(), files: undefined, name: "Mara (older)" }, { affirmRules: true });
  assert.deepEqual(gw.calls.map((c) => `${c.method} ${c.path}`), [`PUT /v1/elements/${made.elementId}`]);
  assert.deepEqual(Object.keys(JSON.parse(gw.calls[0].body)).sort(), ["affirm_rules", "expected_revision", "master_key_id", "meta"]);
  assert.equal(renamed.revision, 2);
  assert.equal(renamed.name, "Mara (older)");
  assert.deepEqual(renamed.elementKey, made.elementKey);
  assert.deepEqual(await kuno.elements.file(renamed), PNG);

  // A stale copy is refused; new files come with a new key.
  await assert.rejects(kuno.elements.update(key, made, { ...mara(), files: undefined }, { affirmRules: true }), (err) => err.code === "element_changed");
  const side = new Uint8Array([...PNG, 1, 2, 3]);
  const replaced = await kuno.elements.update(key, renamed, mara({ files: [{ data: PNG, mime: "image/png" }, { data: side, mime: "image/png" }] }), { affirmRules: true });
  assert.equal(replaced.files.length, 2);
  assert.notDeepEqual(replaced.elementKey, made.elementKey);
  assert.deepEqual(await kuno.elements.file(replaced, 1), side);

  // Tampered storage doesn't open quietly.
  const stored = gw.elements.get(made.elementId);
  gw.blobs.set(stored.files[1], sealElement(key, made.elementId, mara({ files: [{ data: PNG, mime: "image/png" }] })).files[0]);
  await assert.rejects(kuno.elements.file(replaced, 1), (err) => err.code === "decrypt_failed" || err.code === "integrity");

  // Another device lists and opens it; an Element made under an older key sync generation is listed as unreadable.
  const second = await kuno.elements.create(key, { kind: "voice", name: "Narrator", files: [{ data: WAV, mime: "audio/wav", durationS: 8 }] }, { affirmRules: true });
  const listed = await kuno.elements.list(key);
  assert.deepEqual(listed.elements.map((e) => e.name).sort(), ["Mara", "Narrator"]);
  assert.equal(listed.keyId, key.keyId);
  gw.elements.get(second.elementId).row.master_key_id = hex(16);
  assert.deepEqual((await kuno.elements.list(key)).unreadable.map((u) => u.reason), ["key_rotated"]);
  const stranger = await kuno.elements.list(freshKey(key.keyId));
  assert.deepEqual(stranger.unreadable.map((u) => u.reason).sort(), ["decrypt_failed", "key_rotated"]);

  await kuno.elements.delete(made.elementId);
  assert.equal(gw.elements.has(made.elementId), false);
});

test("a rotation re-wraps what rows() returns, and the old key stops writing", async () => {
  const gw = fakeGateway();
  const key = freshKey();
  gw.setKeyId(key.keyId);
  const kuno = new KunoClient({ apiKey: "kw_live_test", baseUrl: "https://gw.test", fetch: gw.fetch });
  const made = await kuno.elements.create(key, mara(), { affirmRules: true });
  const next = freshKey();
  const { rows, keyId } = await kuno.elements.rows();
  assert.equal(keyId, key.keyId);
  const rewrapped = rows.map((row) => ({ element_id: row.element_id, wrapped_key: rewrapElementKey(key, next, row.element_id, row.wrapped_key) }));
  // What the gateway's rotation does with them:
  gw.setKeyId(next.keyId);
  for (const { element_id, wrapped_key } of rewrapped) Object.assign(gw.elements.get(element_id).row, { wrapped_key, master_key_id: next.keyId });
  const opened = await kuno.elements.get(next, made.elementId);
  assert.deepEqual(opened.elementKey, made.elementKey);
  assert.deepEqual(await kuno.elements.file(opened), PNG);
  await assert.rejects(kuno.elements.create(key, mara(), { affirmRules: true }), (err) => err.code === "vault_changed");
});

test("attach adds each Element's line to the prompt and its files as ordinary inputs", async () => {
  const gw = fakeGateway();
  const key = freshKey();
  gw.setKeyId(key.keyId);
  const kuno = new KunoClient({ apiKey: "kw_live_test", baseUrl: "https://gw.test", fetch: gw.fetch });
  const side = new Uint8Array([...PNG, 9]);
  const character = await kuno.elements.create(key, mara({ files: [{ data: PNG, mime: "image/png" }, { data: side, mime: "image/png" }] }), { affirmRules: true });
  const voice = await kuno.elements.create(key, { kind: "voice", name: "Narrator", description: "a low, calm voice", files: [{ data: WAV, mime: "audio/wav" }] }, { affirmRules: true });

  const request = await kuno.elements.attach({ prompt: "She walks along the pier.", model: "ltx-2.5-fast" }, [{ element: character, role: "first_frame", file: 1 }]);
  assert.equal(request.prompt, `She walks along the pier.\n${elementPromptLine(character)}`);
  assert.deepEqual(request.inputs.map((i) => i.role), ["first_frame"]);
  assert.deepEqual(request.inputs[0].file, side);

  const references = await kuno.elements.attach({ prompt: "", model: "h3-reference", inputs: [{ role: "reference_image", file: PNG }] }, [
    { element: character, role: "reference_image", file: "all" },
    { element: voice, role: "reference_audio" },
  ]);
  assert.deepEqual(references.inputs.map((i) => i.role), ["reference_image", "reference_image", "reference_image", "reference_audio"]);
  assert.equal(references.prompt, `${elementPromptLine(character)}\n${elementPromptLine(voice)}`);

  // A storyboard takes descriptions only, into its scene.
  const board = { prompt: "A harbour town.", shots: [{ prompt: "Morning.", durationS: 5 }, { prompt: "Noon.", durationS: 5 }] };
  const scene = await kuno.elements.attach(board, [{ element: character }]);
  assert.equal(scene.prompt, `A harbour town.\n${elementPromptLine(character)}`);
  assert.equal(scene.inputs, undefined);
  gw.calls.length = 0;
  await assert.rejects(kuno.elements.attach(board, [{ element: character, role: "first_frame" }]), (err) => err.code === "invalid_element" && /description only/.test(err.message));
  await assert.rejects(kuno.elements.attach({ prompt: "" }, [{ element: voice, role: "first_frame" }]), (err) => err.code === "invalid_element");
  await assert.rejects(kuno.elements.attach({ prompt: "" }, [{ element: character, role: "first_frame", file: 4 }]), (err) => err.code === "invalid_element");
  const withdrawn = { ...character, consent: { ...character.consent, withdrawnAt: 1789700000 } };
  await assert.rejects(kuno.elements.attach({ prompt: "" }, [{ element: withdrawn }]), (err) => err.code === "consent_withdrawn");
  assert.equal(gw.calls.length, 0, "refused uses download nothing");
  assert.match(ELEMENT_RULES, /public figures/);
});
