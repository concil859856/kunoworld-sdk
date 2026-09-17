// The TypeScript implementation must reproduce the shared protocol vectors exactly.
// subnet/protocol/tests/test_vectors.py runs the same checks in Python.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  b64d,
  briefQuotes,
  canonicalJson,
  decryptBlob,
  DecryptionError,
  enclaveIdFor,
  encodePlan,
  encryptBlob,
  fitPlan,
  gpuNonceFor,
  jobAad,
  KunoError,
  missingQuotes,
  openPlan,
  padPayload,
  parsePlan,
  planContext,
  planOutputLabel,
  planShotSpecs,
  priceQuote,
  reportDataFor,
  sha256Hex,
  storyboardDurationS,
  storyboardFrames,
  toHex,
  validatePlan,
} from "../dist/index.js";

const VECTORS = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const text = (bytes) => new TextDecoder().decode(bytes);
const utf8 = (s) => new TextEncoder().encode(s);

test("canonical JSON", () => {
  for (const { value, encoded } of VECTORS.canonical_json) {
    assert.equal(text(canonicalJson(value)), encoded);
  }
});

test("blob format", () => {
  const { base_key_b64, label, plaintext_b64, ciphertext_b64, chunk_size } = VECTORS.blob;
  const key = b64d(base_key_b64);
  const plaintext = b64d(plaintext_b64);
  assert.deepEqual(decryptBlob(key, label, b64d(ciphertext_b64)), plaintext);
  assert.throws(() => decryptBlob(key, "other/label", b64d(ciphertext_b64)), DecryptionError);
  assert.deepEqual(decryptBlob(key, label, encryptBlob(key, label, plaintext, chunk_size)), plaintext);
});

test("attestation binding", () => {
  const a = VECTORS.attestation;
  const nonce = Uint8Array.from(a.nonce_hex.match(/../g).map((h) => parseInt(h, 16)));
  const hpke = b64d(a.hpke_public_key_b64);
  const signing = b64d(a.signing_public_key_b64);
  const gpu = b64d(a.gpu_evidence_b64);
  assert.equal(enclaveIdFor(hpke, signing), a.enclave_id);
  assert.equal(toHex(gpuNonceFor(nonce, hpke, signing)), a.gpu_nonce_hex);
  assert.equal(toHex(reportDataFor(nonce, hpke, signing, gpu)), a.report_data_hex);
  assert.equal(toHex(reportDataFor(nonce, hpke, signing, null)), a.report_data_without_gpu_hex);
});

test("job AAD", () => {
  const { job_id, enclave_id, params, input_blob_ids, encoded } = VECTORS.job_aad;
  assert.equal(text(jobAad(job_id, enclave_id, params, input_blob_ids)), encoded);
});

// The vectors name profiles by id; only the fields the lengths depend on are needed, as in kuno_protocol/profiles.json.
const STORYBOARD_PROFILES = {
  "ltx-2.5-fast": { id: "ltx-2.5-fast", name: "LTX-2.5 Fast", family: "ltx-2.5", limits: { storyboard: { max_shots: 12, max_total_s: 120, overlap_latent_frames: 3 } } },
};

test("storyboard lengths", () => {
  for (const { profile_id, fps, shots, frames, duration_s } of VECTORS.storyboard.lengths) {
    const profile = STORYBOARD_PROFILES[profile_id];
    assert.ok(profile, `a fixture for ${profile_id}`);
    assert.equal(storyboardFrames(profile, shots, fps), frames);
    // Exactly, not approximately: duration_s is part of the encryption's associated data.
    assert.equal(storyboardDurationS(profile, shots, fps), duration_s);
  }
});

test("storyboard job AAD", () => {
  const { job_id, enclave_id, params, input_blob_ids, encoded } = VECTORS.storyboard.job_aad;
  assert.equal(text(jobAad(job_id, enclave_id, params, input_blob_ids)), encoded);
  const profile = STORYBOARD_PROFILES[params.profile_id];
  assert.equal(storyboardDurationS(profile, params.shots, params.fps), params.duration_s);
});

test("receipt message", () => {
  const { body, message_b64 } = VECTORS.receipt;
  const prefix = utf8("kuno/v1/receipt\n");
  const encoded = canonicalJson(body);
  const message = new Uint8Array(prefix.length + encoded.length);
  message.set(prefix, 0);
  message.set(encoded, prefix.length);
  assert.deepEqual(message, b64d(message_b64));
});

// ---------------------------------------------------------------- plans (kuno_protocol.plans)

// LTX-2.5 Fast's limits and prices as kuno_protocol/profiles.json has them: everything planContext and validatePlan read.
const FAST = {
  id: "ltx-2.5-fast",
  name: "LTX-2.5 Fast",
  family: "ltx-2.5",
  modes: ["text_to_video", "storyboard", "plan"],
  limits: {
    min_duration_s: 2,
    max_duration_s: 20,
    duration_step_s: 1,
    max_duration_s_by_fps: { 48: 10, 50: 10 },
    sizes: {
      "720p": { "16:9": [1280, 704], "9:16": [704, 1280], "4:3": [960, 704], "3:4": [704, 960], "1:1": [960, 960], "21:9": [1664, 704] },
      "1080p": { "16:9": [1920, 1088], "9:16": [1088, 1920], "4:3": [1472, 1088], "3:4": [1088, 1472], "1:1": [1088, 1088], "21:9": [2560, 1088] },
    },
    fps: [24, 25, 48, 50],
    default_fps: 24,
    audio: true,
    max_prompt_chars: 4000,
    storyboard: { max_shots: 12, max_total_s: 120, overlap_latent_frames: 3 },
    plan: { min_target_s: 4, max_brief_chars: 4000, max_style_chars: 500, max_new_tokens: 2048, planner: "prompt_enhancer", prompt_version: "plan/1" },
  },
  pricing: {
    usd_per_second: { "720p": 0.12, "1080p": 0.17 },
    standard_usd_per_second: { "720p": 0.09, "1080p": 0.13 },
    min_job_usd: 0.1,
    fps_multipliers: { 48: 1.5, 50: 1.5 },
    plan_usd: 0.1,
    standard_plan_usd: 0.08,
  },
};

test("plans: contexts, and every delivered plan passes validatePlan and encodes byte for byte", () => {
  for (const c of VECTORS.plans.repair) {
    const context = planContext(FAST, c.params, c.options);
    assert.deepEqual(
      { min_shot_s: context.minShotS, max_shot_s: context.maxShotS, min_shots: context.minShots, max_shots: context.maxShots },
      c.context,
      c.name,
    );
    if (!c.plan) {
      assert.equal(c.delivered_json, null, c.name);
      continue;
    }
    const delivered = parsePlan(c.delivered_json);
    validatePlan(delivered, FAST, context);
    assert.equal(new TextDecoder().decode(encodePlan(delivered)), c.delivered_json, c.name);
    assert.equal(storyboardDurationS(FAST, planShotSpecs(delivered), delivered.fps), delivered.duration_s, c.name);
    // The plan before its notices is the same storyboard.
    validatePlan(parsePlan(JSON.stringify(c.plan)), FAST, context);
  }
});

test("plans: validatePlan refuses what breaks a rule", () => {
  const c = VECTORS.plans.repair[0];
  const context = planContext(FAST, c.params, c.options);
  const plan = parsePlan(c.delivered_json);
  const broken = [
    (p) => (p.shots[0].join = "cut"),
    (p) => (p.shots = p.shots.slice(0, 1)),
    (p) => (p.duration_s += 1),
    (p) => (p.shots[1].duration_s = 12.5),
    (p) => (p.shots[1].duration_s = 12),
    (p) => (p.title = "t".repeat(81)),
    (p) => (p.shots[2].beat = "b".repeat(61)),
    (p) => (p.scene = "s".repeat(1001)),
    (p) => (p.shots[3].prompt = " "),
    (p) => (p.fps = 48),
  ];
  for (const breakIt of broken) {
    const copy = structuredClone(plan);
    breakIt(copy);
    assert.throws(() => validatePlan(copy, FAST, context), (err) => err instanceof KunoError && err.code === "invalid_plan", breakIt.toString());
  }
  // Another target, another frame, or a longest shot below the plan's.
  assert.throws(() => validatePlan(plan, FAST, planContext(FAST, { ...c.params, duration_s: 45 }, c.options)), KunoError);
  assert.throws(() => validatePlan(plan, FAST, planContext(FAST, { ...c.params, aspect_ratio: "9:16" }, c.options)), KunoError);
  assert.throws(() => validatePlan(plan, FAST, planContext(FAST, c.params, { max_shot_s: 5 })), /longer than 5 s/);
  assert.throws(() => planContext(FAST, c.params, { max_shot_s: 1.5 }), /can't be shorter than LTX-2.5 Fast's shortest, 2 s/);
  assert.throws(() => parsePlan(JSON.stringify({ ...JSON.parse(c.delivered_json), extra: 1 })), /not a Plan v1/);
});

test("plans: fit", () => {
  for (const c of VECTORS.plans.fit) {
    const params = { profile_id: c.profile_id, mode: "plan", duration_s: c.target_s, resolution: "720p", aspect_ratio: "16:9", fps: c.fps, audio: true };
    const context = planContext(FAST, params, { max_shot_s: c.max_shot_s });
    const shots = c.shots.map((shot) => ({ beat: "b", prompt: "p", ...shot }));
    const fitted = fitPlan(shots, context, c.movable);
    assert.deepEqual(fitted.shots.map((shot) => shot.duration_s), c.durations, c.name);
    assert.deepEqual(fitted.repairs, c.repairs, c.name);
    assert.equal(storyboardDurationS(FAST, planShotSpecs(fitted), c.fps), c.duration_s, c.name);
  }
});

test("plans: brief quotes", () => {
  for (const c of VECTORS.plans.quotes) {
    assert.deepEqual(briefQuotes(c.brief), c.quotes, c.brief);
    assert.deepEqual(missingQuotes(c.brief, c.prompts), c.missing, c.brief);
  }
});

test("plans: output framing, sealing and opening", async () => {
  const { label, plan_json, sha256, padded_length, sealed_size } = VECTORS.plans.output;
  const json = utf8(plan_json);
  assert.equal(await sha256Hex(json), sha256);
  assert.equal(new TextDecoder().decode(encodePlan(parsePlan(plan_json))), plan_json);
  assert.equal(padPayload(json).length, padded_length);
  const jobId = VECTORS.plans.job_aad.job_id;
  assert.equal(planOutputLabel(jobId), label);

  const key = crypto.getRandomValues(new Uint8Array(32));
  const sealed = encryptBlob(key, label, padPayload(json));
  assert.equal(sealed.length, sealed_size);
  const opened = openPlan(key, jobId, sealed);
  assert.deepEqual(opened.json, json);
  assert.equal(opened.plan.duration_s, 30.375);
  // Another job's label, another key, and bare JSON (form 1 framing) are all refused.
  assert.throws(() => openPlan(key, "00000000-0000-4000-8000-000000000000", sealed), DecryptionError);
  assert.throws(() => openPlan(crypto.getRandomValues(new Uint8Array(32)), jobId, sealed), DecryptionError);
  assert.throws(() => openPlan(key, jobId, encryptBlob(key, label, json)), (err) => err instanceof KunoError && /not padded plan JSON/.test(err.message));
});

test("plans: receipt message and job AAD", () => {
  const { body, message_b64 } = VECTORS.plans.receipt;
  assert.ok(body.plan && !("video" in body));
  const prefix = utf8("kuno/v1/receipt\n");
  const encoded = canonicalJson(body);
  const message = new Uint8Array(prefix.length + encoded.length);
  message.set(prefix, 0);
  message.set(encoded, prefix.length);
  assert.deepEqual(message, b64d(message_b64));

  const { job_id, enclave_id, params, input_blob_ids, encoded: aad } = VECTORS.plans.job_aad;
  assert.equal(text(jobAad(job_id, enclave_id, params, input_blob_ids)), aad);
});

test("plans: a plan's price is flat", () => {
  for (const duration_s of [4, 30, 120]) {
    assert.deepEqual(priceQuote(FAST, { mode: "plan", duration_s, resolution: "1080p", fps: 50 }), { usd: 0.1, usdPerSecond: 0, multiplier: 1, minimumApplied: false });
    assert.equal(priceQuote(FAST, { mode: "plan", duration_s, resolution: "720p", fps: 24 }, "standard").usd, 0.08);
  }
  assert.equal(priceQuote({ ...FAST, pricing: { ...FAST.pricing, plan_usd: null } }, { mode: "plan", duration_s: 30, resolution: "720p", fps: 24 }), null);
});
