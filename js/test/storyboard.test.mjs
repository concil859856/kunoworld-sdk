// Storyboards in the TypeScript SDK: the frame counts and rules kuno_protocol/profiles.py sets, a shot list that changes no
// other job's bytes, the price and envelope fit on the longest shot, and storyboard requests built in both privacy modes.
// subnet/protocol/tests/test_storyboard.py runs the same rules in Python; the lengths themselves are shared vectors.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";

import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";

import {
  KunoClient,
  KunoError,
  b64d,
  b64e,
  canonicalJson,
  enclaveIdFor,
  envelopeFits,
  fitParams,
  jobAad,
  numFrames,
  priceQuote,
  priceUsd,
  renderDurationS,
  reportDataFor,
  shotPrompt,
  storyboardDurationS,
  storyboardFrames,
  storyboardStage,
  storyboardTrimFrames,
  toHex,
  unpadPayload,
  validateStoryboard,
} from "../dist/index.js";

const utf8 = (s) => new TextEncoder().encode(s);
const text = (bytes) => new TextDecoder().decode(bytes);

/** ltx-2.5-fast as kuno_protocol/profiles.json has it, trimmed to what these rules read. */
const FAST = {
  id: "ltx-2.5-fast",
  name: "LTX-2.5 Fast",
  family: "ltx-2.5",
  modes: ["text_to_video", "image_to_video", "storyboard"],
  limits: {
    sizes: { "720p": { "16:9": [1280, 704] }, "1080p": { "16:9": [1920, 1088] } },
    fps: [24, 25, 48, 50],
    default_fps: 24,
    min_duration_s: 2,
    max_duration_s: 20,
    duration_step_s: 1,
    max_duration_s_by_fps: { 48: 10, 50: 10 },
    audio: true,
    max_prompt_chars: 4000,
    storyboard: { max_shots: 12, max_total_s: 120, overlap_latent_frames: 3 },
  },
  pricing: {
    usd_per_second: { "720p": 0.05, "1080p": 0.08 },
    standard_usd_per_second: { "720p": 0.04, "1080p": 0.06 },
    min_job_usd: 0.1,
    fps_multipliers: { 48: 1.5, 50: 1.5 },
  },
};

const shots = (...spec) => spec.map(([duration_s, join]) => ({ duration_s, join }));

function board(shotList, fps = 24, change = {}) {
  return {
    profile_id: FAST.id,
    mode: "storyboard",
    duration_s: storyboardDurationS(FAST, shotList, fps),
    resolution: "720p",
    aspect_ratio: "16:9",
    fps,
    audio: true,
    input_roles: [],
    shots: shotList,
    ...change,
  };
}

test("frame counts follow each family's grid, rounding halves to even like Python", () => {
  assert.equal(numFrames(FAST, 5, 24), 121);
  assert.equal(numFrames(FAST, 20, 25), 497, "62.5 latent steps round down to 62");
  assert.equal(numFrames(FAST, 10, 50), 497);
  assert.equal(numFrames(FAST, 2, 25), 49);
  assert.equal(numFrames({ family: "minimax-h3" }, 5, 24), 124);
  assert.equal(numFrames({ family: "minimax-h3" }, 14, 24), 345, "H3 caps at 345 frames");
});

test("the stitched length drops each joined shot's overlap and matches the GPU run", () => {
  assert.equal(storyboardTrimFrames(FAST), 17);
  const longTake = shots([5, "fresh"], ...Array(7).fill([5, "continue"]));
  assert.deepEqual([storyboardFrames(FAST, longTake, 24), storyboardDurationS(FAST, longTake, 24)], [849, 35.375]);
  const mixed = shots([3, "fresh"], [3, "continue"], [3, "cut"], [3, "fresh"]);
  assert.deepEqual([storyboardFrames(FAST, mixed, 24), storyboardDurationS(FAST, mixed, 24)], [258, 10.75]);
  assert.equal(storyboardTrimFrames({ ...FAST, limits: { ...FAST.limits, storyboard: { max_shots: 12, max_total_s: 120 } } }), 17, "overlap defaults to 3");
  assert.throws(() => storyboardTrimFrames({ ...FAST, name: "LTX-2.5 Pro", limits: { ...FAST.limits, storyboard: null } }), (err) => err.code === "invalid_params" && /does not support storyboard/.test(err.message));
});

test("a shot's model prompt is the scene, a blank line, then the shot", () => {
  assert.equal(shotPrompt("A small blue fishing boat. ", " It leaves the harbor."), "A small blue fishing boat.\n\nIt leaves the harbor.");
  assert.equal(shotPrompt("", "Night falls."), "Night falls.");
  assert.equal(shotPrompt("  ", "Night falls. "), "Night falls.");
});

test("a job's stage names the shot being rendered", () => {
  assert.deepEqual(storyboardStage("shot 3/8"), { shot: 3, shots: 8 });
  for (const stage of [null, undefined, "rendering", "sealing", "shot 9/8", "shot 0/8", "shots 1/2"]) assert.equal(storyboardStage(stage), null, String(stage));
});

test("a valid storyboard passes", () => {
  validateStoryboard(FAST, board(shots([5, "fresh"], [5, "continue"], [5, "cut"])));
  validateStoryboard(FAST, board(shots([10, "fresh"], [4, "continue"], [9, "fresh"]), 50));
  // Not a storyboard, no shots: nothing to check.
  validateStoryboard(FAST, { mode: "text_to_video", fps: 24, duration_s: 5 });
});

for (const [name, list, fps, message] of [
  ["one shot", shots([5, "fresh"]), 24, /between 2 and 12 shots/],
  ["thirteen shots", shots(...Array(13).fill([2, "fresh"])), 24, /between 2 and 12 shots/],
  ["a joined first shot", shots([5, "continue"], [5, "continue"]), 24, /first shot must be fresh/],
  ["a shot too long", shots([5, "fresh"], [21, "continue"]), 24, /shot 2's duration must be between 2 and 20 seconds/],
  ["a shot off the step", shots([5, "fresh"], [2.5, "cut"]), 24, /shot 2's duration must be in 1-second steps/],
  ["a shot over the fps cap", shots([5, "fresh"], [11, "cut"]), 48, /at 48 fps, shot 2's duration must be at most 10 seconds/],
  ["a stitched video over 120 s", shots(...Array(7).fill([20, "fresh"])), 24, /at most 120 seconds, these shots make 140.292/],
]) {
  test(`a storyboard is refused: ${name}`, () => {
    assert.throws(() => validateStoryboard(FAST, board(list, fps)), (err) => err instanceof KunoError && err.code === "invalid_params" && message.test(err.message));
  });
}

test("duration_s must be the stitched length exactly, and shots belong to storyboards only", () => {
  const params = board(shots([5, "fresh"], [5, "continue"]));
  assert.throws(() => validateStoryboard(FAST, { ...params, duration_s: 10 }), /must be its stitched length, 9.375 seconds/);
  assert.throws(() => validateStoryboard(FAST, { ...params, mode: "text_to_video" }), /shots are only for storyboard mode/);
  const wide = { ...FAST, limits: { ...FAST.limits, storyboard: { ...FAST.limits.storyboard, overlap_latent_frames: 7 } } };
  const short = shots([2, "fresh"], [2, "continue"]);
  assert.throws(
    () => validateStoryboard(wide, { ...board(short), duration_s: storyboardDurationS(wide, short, 24) }),
    /shot 2 is too short to join: it would keep no frames after its 49-frame overlap/,
  );
});

test("every other job's associated data is unchanged: no shots key, and a null one is left out as Python does", () => {
  const params = fitParams(FAST, "text_to_video", [], { durationS: 5, resolution: "720p", fps: 24 }, null);
  assert.equal("shots" in params, false);
  const expected =
    '{"enclave_id":"e","inputs":[],"job_id":"j","params":{"aspect_ratio":"16:9","audio":true,"duration_s":5,"fps":24,' +
    '"input_roles":[],"mode":"text_to_video","profile_id":"ltx-2.5-fast","resolution":"720p"},"v":1}';
  assert.equal(text(jobAad("j", "e", params, [])), expected);
  assert.equal(text(jobAad("j", "e", { ...params, shots: null }, [])), expected);
  assert.equal(text(jobAad("j", "e", { ...params, shots: undefined }, [])), expected);
});

test("fitParams gives a storyboard its shots and stitched length, and fits each shot after a fallback", () => {
  const req = { resolution: "720p", fps: 24, durationS: 3, shots: [{ prompt: "a", durationS: 5 }, { prompt: "b", durationS: 4 }, { prompt: "c", durationS: 6, join: "cut" }] };
  const params = fitParams(FAST, "storyboard", [], req, null);
  assert.deepEqual(params.shots, shots([5, "fresh"], [4, "continue"], [6, "cut"]));
  assert.equal(params.duration_s, 13.708333333333334, "the request's own durationS is ignored");
  assert.equal(renderDurationS(params), 6);

  const fallen = fitParams(FAST, "storyboard", [], { fps: 48, shots: [{ prompt: "a", durationS: 14 }, { prompt: "b", durationS: 1 }] }, "capacity");
  assert.deepEqual(fallen.shots, shots([10, "fresh"], [2, "continue"]));
  assert.equal(fallen.duration_s, storyboardDurationS(FAST, fallen.shots, 48));
});

test("a storyboard pays for its stitched seconds; the long-clip rule and envelopes look at the longest shot", () => {
  const params = board(shots([8, "fresh"], [8, "continue"], [8, "continue"]));
  assert.ok(params.duration_s > 20);
  assert.equal(renderDurationS(params), 8);
  assert.equal(priceUsd(FAST, params), Math.round(0.05 * params.duration_s * 10000) / 10000);
  assert.equal(priceUsd(FAST, params, "standard"), Math.round(0.04 * params.duration_s * 10000) / 10000);

  const longClip = { ...FAST, pricing: { ...FAST.pricing, long_clip: { over_s: 10, multiplier: 1.4 } } };
  assert.equal(priceQuote(longClip, params).multiplier, 1, "no shot is over 10 s, however long the stitched video");
  const longShot = board(shots([12, "fresh"], [5, "continue"]));
  assert.equal(priceQuote(longClip, longShot).multiplier, 1.4);
  assert.equal(priceQuote(longClip, longShot, "standard").multiplier, 1, "Standard stays flat");

  assert.equal(envelopeFits({ [FAST.id]: { "720p": { "16:9": { 24: 10 } } } }, params), true);
  assert.equal(envelopeFits({ [FAST.id]: { "720p": { "16:9": { 24: 7 } } } }, params), false);
});

// ------------------------------------------------------------ building requests

const route = { profile_id: FAST.id, requested_profile_id: FAST.id, fallback_reason: null };
const reply = (status, value) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });

/** A fake gateway: one mock-attested enclave whose HPKE private key this test holds, and a Standard create route. */
async function world() {
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
    profiles: [FAST.id],
    hardware: {},
    created_at: Date.now() / 1000,
  };
  const enclave = { enclave_id: enclaveIdFor(hpke, signing), hpke_public_key: evidence.hpke_public_key, signing_public_key: evidence.signing_public_key, evidence };
  const answers = {
    "GET /v1/route": { ...route, enclaves: [enclave] },
    "GET /v1/models": { country: null, workers_online: 1, switch: {}, models: [FAST] },
    "GET /v1/manifest": {
      version: 1,
      issued_at: 0,
      allowed: [{ platform: "mock", image_digest: "sha256:img", profiles: [FAST.id], ...measurements }],
      mock_quote_keys: [quoteKey.publicKey.export({ format: "jwk" }).x],
      max_evidence_age_s: 600,
    },
  };
  const calls = [];
  const fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    const key = `${init.method ?? "GET"} ${u.pathname}`;
    const body = typeof init.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ key, query: Object.fromEntries(u.searchParams), body });
    if (key === "POST /v1/videos") return reply(201, { job_id: body.job_id });
    if (key === "POST /v1/standard/videos") return reply(201, { job_id: body.job_id, status: "queued", params: body.params, enclave_id: "e-open", created_at: 1, privacy: "standard" });
    return key in answers ? reply(200, answers[key]) : reply(404, { detail: { code: "not_found", message: key } });
  };
  const open = async (request) => {
    const opener = await suite.createRecipientContext({ recipientKey: recipient, enc: b64d(request.enc).slice().buffer, info: utf8("kuno/v1/job") });
    const aad = jobAad(request.job_id, request.enclave_id, request.params, request.input_blob_ids);
    return JSON.parse(text(unpadPayload(new Uint8Array(await opener.open(b64d(request.ciphertext), aad)))));
  };
  return { kuno: new KunoClient({ apiKey: "kw_test", baseUrl: "https://gw.test", fetch }), calls, open };
}

const STORY = {
  prompt: "A small blue fishing boat, early morning, soft light.",
  model: FAST.id,
  resolution: "720p",
  aspectRatio: "16:9",
  fps: 24,
  shots: [
    { prompt: "It leaves the harbor.", durationS: 5 },
    { prompt: "Gulls follow it out to sea.", durationS: 4, join: "continue" },
    { prompt: "The fisherman hauls in the net.", durationS: 6, join: "cut" },
  ],
};

test("a private storyboard seals the scene and every shot prompt, and binds the shot list into the associated data", async () => {
  const w = await world();
  const handle = await w.kuno.submit(STORY);
  assert.equal(handle.profileId, FAST.id);

  const routed = w.calls.find((c) => c.key === "GET /v1/route");
  assert.equal(routed.query.mode, "storyboard");
  assert.equal(routed.query.duration_s, "6", "routed by its longest shot, the longest render a worker must fit");

  const sent = w.calls.find((c) => c.key === "POST /v1/videos").body;
  assert.equal(sent.params.mode, "storyboard");
  assert.deepEqual(sent.params.shots, shots([5, "fresh"], [4, "continue"], [6, "cut"]));
  assert.equal(sent.params.duration_s, 13.708333333333334);
  assert.equal(JSON.stringify(sent).includes("harbor"), false, "no prompt leaves the page readable");

  const payload = await w.open(sent);
  assert.equal(payload.prompt, STORY.prompt);
  assert.deepEqual(payload.shots, [{ prompt: "It leaves the harbor." }, { prompt: "Gulls follow it out to sea." }, { prompt: "The fisherman hauls in the net." }]);

  // The shot list is associated data: a relay that edits it makes the enclave's open fail.
  const tampered = { ...sent, params: { ...sent.params, shots: shots([5, "fresh"], [4, "cut"], [6, "cut"]) } };
  await assert.rejects(w.open(tampered));
});

test("a private text job's sealed request carries no shots", async () => {
  const w = await world();
  await w.kuno.submit({ prompt: "a lantern in the rain", model: FAST.id, resolution: "720p" });
  const sent = w.calls.find((c) => c.key === "POST /v1/videos").body;
  assert.equal("shots" in sent.params, false);
  assert.equal("shots" in (await w.open(sent)), false);
});

test("a standard storyboard sends the scene as prompt and each shot's prompt beside params.shots", async () => {
  const w = await world();
  const handle = await w.kuno.submit({ ...STORY, privacy: "standard", seed: 7 });
  assert.equal(handle.privacy, "standard");
  assert.equal(w.calls.find((c) => c.key === "GET /v1/route").query.privacy, "standard");
  const sent = w.calls.find((c) => c.key === "POST /v1/standard/videos").body;
  assert.equal(sent.prompt, STORY.prompt);
  assert.deepEqual(sent.shots, STORY.shots.map(({ prompt }) => ({ prompt })));
  assert.deepEqual(sent.params.shots, shots([5, "fresh"], [4, "continue"], [6, "cut"]));
  assert.equal(sent.params.duration_s, 13.708333333333334);
  assert.equal(sent.seed, 7);

  await w.kuno.submit({ prompt: "a paper boat", model: FAST.id, privacy: "standard" });
  const plain = w.calls.filter((c) => c.key === "POST /v1/standard/videos")[1].body;
  assert.equal("shots" in plain, false);
  assert.equal("shots" in plain.params, false);
});

test("bad storyboard requests are refused before anything is sealed or sent", async () => {
  const w = await world();
  const refused = async (req, message) => {
    await assert.rejects(w.kuno.submit(req), (err) => err instanceof KunoError && err.code === "invalid_params" && message.test(err.message));
  };
  await refused({ ...STORY, shots: STORY.shots.slice(0, 1) }, /at least 2 shots/);
  await refused({ prompt: "x", model: FAST.id, mode: "storyboard" }, /at least 2 shots/);
  await refused({ ...STORY, mode: "text_to_video" }, /only for storyboard mode/);
  await refused({ ...STORY, shots: [STORY.shots[0], { prompt: "  ", durationS: 5 }] }, /shot 2 needs a prompt/);
  await refused({ ...STORY, inputs: [{ role: "first_frame", file: new Uint8Array([0x89, 0x50, 0x4e, 0x47]) }] }, /takes no inputs/);
  await refused({ ...STORY, shots: [{ ...STORY.shots[0], join: "continue" }, STORY.shots[1]] }, /first shot must be fresh/);
  await refused({ ...STORY, shots: [STORY.shots[0], { prompt: "x".repeat(3960), durationS: 5 }] }, /shot 2's prompt, with the scene, must be at most 4000 characters/);
  await refused({ ...STORY, privacy: "standard", shots: Array(13).fill(STORY.shots[0]) }, /between 2 and 12 shots/);
  assert.equal(w.calls.some((c) => c.key === "POST /v1/videos" || c.key === "POST /v1/standard/videos" || c.key === "POST /v1/blobs"), false);
});
