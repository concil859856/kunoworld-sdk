// The sealed request (the HPKE plaintext) padded to a power-of-two bucket, in TypeScript: the shared vectors reproduce
// byte for byte and open, buckets and limits match, malformed framing is refused, and bare JSON still opens.
// subnet/protocol/tests/test_sealed_payload_padding.py runs the same checks in Python.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";

import {
  DecryptionError,
  KunoClient,
  KunoError,
  PAYLOAD_MAX_PADDED,
  PAYLOAD_MIN_PADDED,
  PAYLOAD_V1,
  PAYLOAD_V2,
  b64d,
  b64e,
  canonicalJson,
  enclaveIdFor,
  fromHex,
  jobAad,
  openSenderSession,
  padPayload,
  paddedPayloadLength,
  payloadVersion,
  reportDataFor,
  sha256Hex,
  toHex,
  unpadPayload,
} from "../dist/index.js";

const V = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8")).sealed_payload;
const utf8 = (s) => new TextEncoder().encode(s);
const text = (bytes) => new TextDecoder().decode(bytes);
const buffer = (bytes) => bytes.slice().buffer;
const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });
const INFO = utf8("kuno/v1/job");
/** The JSON the SDK seals for a text-only request, in the same key order as Python's SealedPayload. */
const requestJson = (prompt) => utf8(JSON.stringify({ v: 1, prompt, negative_prompt: null, seed: null, inputs: [], options: {} }));

function sparse({ head_hex, tail_hex, length }) {
  const out = new Uint8Array(length);
  const tail = fromHex(tail_hex);
  out.set(fromHex(head_hex), 0);
  out.set(tail, length - tail.length);
  return out;
}

test("the limits are the published ones", () => {
  assert.deepEqual([V.min_padded, V.max_padded, V.info], [PAYLOAD_MIN_PADDED, PAYLOAD_MAX_PADDED, "kuno/v1/job"]);
  assert.deepEqual([PAYLOAD_V1, PAYLOAD_V2, PAYLOAD_MIN_PADDED, PAYLOAD_MAX_PADDED], [1, 2, 4096, 262144]);
});

test("the sealed vectors reproduce byte for byte and open", async () => {
  const recipient = await suite.kem.deriveKeyPair(buffer(fromHex(V.recipient_ikm_hex)));
  assert.equal(toHex(new Uint8Array(await suite.kem.serializePublicKey(recipient.publicKey))), toHex(b64d(V.recipient_public_key_b64)));
  assert.equal(toHex(new Uint8Array(await suite.kem.serializePrivateKey(recipient.privateKey))), toHex(b64d(V.recipient_private_key_b64)));
  const aad = utf8(V.aad);
  assert.deepEqual(V.sealed.map((c) => c.form), [PAYLOAD_V2, PAYLOAD_V2, PAYLOAD_V1]);
  for (const c of V.sealed) {
    const json = utf8(c.payload_json);
    const plaintext = c.form === PAYLOAD_V2 ? padPayload(json) : json;
    assert.equal(plaintext.length, c.plaintext_length, c.name);
    assert.equal(await sha256Hex(plaintext), c.plaintext_sha256, c.name);

    const sender = await suite.createSenderContext({ recipientPublicKey: recipient.publicKey, info: INFO, ekm: buffer(fromHex(c.ephemeral_ikm_hex)) });
    const ciphertext = b64d(c.ciphertext_b64);
    assert.equal(toHex(new Uint8Array(sender.enc)), toHex(b64d(c.enc_b64)), c.name);
    assert.equal(toHex(new Uint8Array(await sender.export(utf8("kuno/v1/input-key"), 32))), c.input_key_hex);
    assert.equal(toHex(new Uint8Array(await sender.export(utf8("kuno/v1/output-key"), 32))), c.output_key_hex);
    assert.deepEqual(new Uint8Array(await sender.seal(plaintext, aad)), ciphertext, c.name);

    const opener = await suite.createRecipientContext({ recipientKey: recipient, enc: buffer(b64d(c.enc_b64)), info: INFO });
    const opened = new Uint8Array(await opener.open(ciphertext, aad));
    assert.equal(payloadVersion(opened), c.form, c.name);
    assert.equal(text(unpadPayload(opened)), c.payload_json, c.name);
  }
});

test("the bucket table and padded plaintexts match Python", async () => {
  for (const [jsonLength, padded] of V.buckets) {
    if (padded === null) assert.throws(() => paddedPayloadLength(jsonLength), RangeError, String(jsonLength));
    else assert.equal(paddedPayloadLength(jsonLength), padded, String(jsonLength));
  }
  for (const c of V.padded) {
    const json = requestJson("a".repeat(c.prompt_chars));
    assert.equal(json.length, c.json_length, c.name);
    const padded = padPayload(json);
    assert.equal(padded.length, c.padded_length, c.name);
    assert.equal(await sha256Hex(padded), c.padded_sha256, c.name);
    assert.deepEqual(unpadPayload(padded), json);
  }
});

test("authentic plaintexts with bad framing or padding are refused", () => {
  assert.equal(V.invalid.length, 10);
  for (const c of V.invalid) {
    assert.throws(() => unpadPayload(sparse(c)), DecryptionError, c.name);
  }
});

test("a request sealed with the SDK's session is padded, and short prompts all seal to one size", async () => {
  const recipient = await suite.kem.generateKeyPair();
  const publicKey = new Uint8Array(await suite.kem.serializePublicKey(recipient.publicKey));
  const aad = utf8("aad");
  const sizes = new Set();
  for (const prompt of ["", "a paper boat", "é".repeat(2006), "a".repeat(4012)]) {
    const session = await openSenderSession(publicKey);
    const ciphertext = await session.seal(padPayload(requestJson(prompt)), aad);
    sizes.add(ciphertext.length);
    const opener = await suite.createRecipientContext({ recipientKey: recipient, enc: buffer(session.enc), info: INFO });
    assert.equal(JSON.parse(text(unpadPayload(new Uint8Array(await opener.open(ciphertext, aad))))).prompt, prompt);
  }
  assert.deepEqual([...sizes], [PAYLOAD_MIN_PADDED + 16]);
  assert.equal(padPayload(requestJson("a".repeat(4013))).length, 2 * PAYLOAD_MIN_PADDED);
  assert.equal(padPayload(requestJson("a".repeat(7000))).length, 2 * PAYLOAD_MIN_PADDED);
});

test("bucket boundaries, the size limit, non-zero padding and bare JSON", () => {
  for (let bucket = PAYLOAD_MIN_PADDED; bucket <= PAYLOAD_MAX_PADDED; bucket *= 2) {
    const exact = new Uint8Array(bucket - 5).fill(0x20);
    exact[0] = 0x7b;
    assert.equal(padPayload(exact).length, bucket);
    assert.deepEqual(unpadPayload(padPayload(exact)), exact);
    if (bucket < PAYLOAD_MAX_PADDED) assert.equal(paddedPayloadLength(exact.length + 1), 2 * bucket);
  }
  assert.throws(() => padPayload(new Uint8Array(PAYLOAD_MAX_PADDED - 4)), RangeError);

  const json = requestJson("a fox in the snow");
  const padded = padPayload(json);
  for (const index of [5 + json.length, padded.length >> 1, padded.length - 1]) {
    const bad = padded.slice();
    bad[index] = 0x20;
    assert.throws(() => unpadPayload(bad), DecryptionError, String(index));
  }
  const bare = utf8(` ${text(requestJson("sealed before padding"))}`);
  assert.equal(payloadVersion(bare), PAYLOAD_V1);
  assert.deepEqual(unpadPayload(bare), bare);
});

const PROFILE = {
  id: "ltx-2.5-fast",
  modes: ["text_to_video"],
  limits: { sizes: { "1080p": { "16:9": [1920, 1080] } }, fps: [24], default_fps: 24, min_duration_s: 2, max_duration_s: 10, audio: true },
  pricing: { usd_per_second: { "1080p": 0.04 } },
};

/** A fake gateway routing to one mock-attested enclave whose HPKE private key this test holds. */
async function privateWorld() {
  const recipient = await suite.kem.generateKeyPair();
  const hpke = new Uint8Array(await suite.kem.serializePublicKey(recipient.publicKey));
  const signing = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const quoteKey = generateKeyPairSync("ed25519");
  const measurements = { mrtd: "aa", rtmr0: "bb", rtmr1: "cc", rtmr2: "dd", rtmr3: "ee" };
  const gpu = canonicalJson({ format: "kuno/v1/nvidia-gpu", nonce: toHex(nonce), gpus: [{ arch: "HOPPER" }], cc: { mode: "spt", devtools: false } });
  const body = { measurements, report_data: toHex(reportDataFor(nonce, hpke, signing, gpu)) };
  const signature = new Uint8Array(sign(null, new Uint8Array([...utf8("kuno/v1/mock-quote\n"), ...canonicalJson(body)]), quoteKey.privateKey));
  const evidence = {
    tee: "mock",
    quote: b64e(utf8(JSON.stringify({ body, signature: b64e(signature) }))),
    gpu_evidence: b64e(gpu),
    nonce: toHex(nonce),
    hpke_public_key: b64e(hpke),
    signing_public_key: b64e(signing),
    image_digest: "sha256:img",
    profiles: [PROFILE.id],
    hardware: {},
    created_at: Date.now() / 1000,
  };
  const enclave = { enclave_id: enclaveIdFor(hpke, signing), hpke_public_key: evidence.hpke_public_key, signing_public_key: evidence.signing_public_key, evidence };
  const answers = {
    "GET /v1/route": { profile_id: PROFILE.id, requested_profile_id: PROFILE.id, fallback_reason: null, enclaves: [enclave] },
    "GET /v1/models": { country: null, workers_online: 1, switch: {}, models: [PROFILE] },
    "GET /v1/manifest": {
      version: 1,
      issued_at: 0,
      allowed: [{ platform: "mock", image_digest: "sha256:img", profiles: [PROFILE.id], ...measurements }],
      mock_quote_keys: [quoteKey.publicKey.export({ format: "jwk" }).x],
      max_evidence_age_s: 600,
    },
  };
  const submitted = [];
  const reply = (status, value) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
  const fetch = async (url, init = {}) => {
    const key = `${init.method ?? "GET"} ${new URL(String(url)).pathname}`;
    if (key === "POST /v1/videos") {
      const sent = JSON.parse(typeof init.body === "string" ? init.body : await new Response(init.body).text());
      submitted.push(sent);
      return reply(201, { job_id: sent.job_id });
    }
    return key in answers ? reply(200, answers[key]) : reply(404, { detail: { code: "not_found", message: key } });
  };
  const open = async (request) => {
    const opener = await suite.createRecipientContext({ recipientKey: recipient, enc: buffer(b64d(request.enc)), info: INFO });
    const aad = jobAad(request.job_id, request.enclave_id, request.params, request.input_blob_ids);
    return new Uint8Array(await opener.open(b64d(request.ciphertext), aad));
  };
  return { kuno: new KunoClient({ apiKey: "kw_test", baseUrl: "https://gw.test", fetch }), submitted, open };
}

test("the SDK's private submit seals a padded request whose size doesn't follow the prompt", async () => {
  const world = await privateWorld();
  for (const prompt of ["a lantern in the rain", "a".repeat(3000)]) {
    await world.kuno.submit({ prompt, model: PROFILE.id, seed: 9, options: { camera_motion: "static" } });
  }
  assert.equal(world.submitted.length, 2);
  for (const [index, request] of world.submitted.entries()) {
    assert.equal(b64d(request.ciphertext).length, PAYLOAD_MIN_PADDED + 16);
    const plaintext = await world.open(request);
    assert.equal(payloadVersion(plaintext), PAYLOAD_V2);
    const payload = JSON.parse(text(unpadPayload(plaintext)));
    assert.equal(payload.prompt, index === 0 ? "a lantern in the rain" : "a".repeat(3000));
    assert.deepEqual([payload.seed, payload.options], [9, { camera_motion: "static" }]);
  }

  const tooLarge = world.kuno.submit({ prompt: "a boat", model: PROFILE.id, options: { notes: "x".repeat(PAYLOAD_MAX_PADDED) } });
  await assert.rejects(tooLarge, (err) => err instanceof KunoError && err.code === "request_too_large");
  assert.equal(world.submitted.length, 2, "nothing is submitted");
});
