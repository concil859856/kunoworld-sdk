// Plans (Director) in the TypeScript SDK: `plan` routes only to attested workers that list plan/1, asks for shots no longer
// than their envelopes serve, seals the brief and style, and opens the sealed plan here against the signed receipt and
// the plan rules; `revisePlan` sends a clean, restitched Plan v1; Standard plans use /v1/standard/plans; `planToShots`
// renders a plan as its storyboard exactly. The plans themselves come from the shared vectors.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
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
  encryptBlob,
  fitParams,
  jobAad,
  padPayload,
  parsePlan,
  planStoryboardParams,
  planToShots,
  reportDataFor,
  sha256Hex,
  storyboardDurationS,
  toHex,
  unpadPayload,
} from "../dist/index.js";

const VECTORS = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8")).plans;
const utf8 = (s) => new TextEncoder().encode(s);
const text = (bytes) => new TextDecoder().decode(bytes);
const ROASTERY = VECTORS.repair.find((c) => c.name === "gpu spike e2b roastery");
const REVISION = VECTORS.repair.find((c) => c.name === "revision of shot 2 only");

const FAST = {
  id: "ltx-2.5-fast",
  name: "LTX-2.5 Fast",
  family: "ltx-2.5",
  modes: ["text_to_video", "storyboard", "plan"],
  limits: {
    sizes: { "720p": { "16:9": [1280, 704], "9:16": [704, 1280] }, "1080p": { "16:9": [1920, 1088] } },
    fps: [24, 25, 48, 50],
    default_fps: 24,
    min_duration_s: 2,
    max_duration_s: 20,
    duration_step_s: 1,
    max_duration_s_by_fps: { 48: 10, 50: 10 },
    audio: true,
    max_prompt_chars: 4000,
    storyboard: { max_shots: 12, max_total_s: 120, overlap_latent_frames: 3 },
    plan: { min_target_s: 4, max_brief_chars: 4000, max_style_chars: 500 },
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

const reply = (status, value) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });

/** A mock-attested enclave whose HPKE and signing keys this test holds. */
async function makeEnclave(quoteKey, measurements, extra = {}) {
  const recipient = await suite.kem.generateKeyPair();
  const hpke = new Uint8Array(await suite.kem.serializePublicKey(recipient.publicKey));
  const signingKey = generateKeyPairSync("ed25519");
  const signing = b64d(signingKey.publicKey.export({ format: "jwk" }).x);
  const nonce = crypto.getRandomValues(new Uint8Array(32));
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
  return {
    info: { enclave_id: enclaveIdFor(hpke, signing), hpke_public_key: evidence.hpke_public_key, signing_public_key: evidence.signing_public_key, evidence, ...extra },
    recipient,
    signingKey,
  };
}

/** A fake gateway with two workers: an older one without features and a plan worker whose 720p shots stop at 11 s. */
async function world({ features = true } = {}) {
  const quoteKey = generateKeyPairSync("ed25519");
  const measurements = { mrtd: "aa", rtmr0: "bb", rtmr1: "cc", rtmr2: "dd", rtmr3: "ee" };
  const older = await makeEnclave(quoteKey, measurements);
  const planner = await makeEnclave(quoteKey, measurements, {
    envelope: { [FAST.id]: { "720p": { "16:9": { 24: 11 } } } },
    ...(features ? { features: ["plan/1"] } : {}),
  });
  const jobs = new Map();
  const blobs = new Map();
  const calls = [];
  const answers = {
    "GET /v1/models": { country: null, workers_online: 2, switch: {}, models: [FAST] },
    "GET /v1/manifest": {
      version: 1,
      issued_at: 0,
      allowed: [{ platform: "mock", image_digest: "sha256:img", profiles: [FAST.id], ...measurements }],
      mock_quote_keys: [quoteKey.publicKey.export({ format: "jwk" }).x],
      max_evidence_age_s: 600,
    },
  };
  const deliver = async (job) => {
    const json = utf8(job.revise ? REVISION.delivered_json : ROASTERY.delivered_json);
    let stored = json;
    if (job.privacy === "private") {
      stored = encryptBlob(job.outputKey, `${job.jobId}/output/plan`, padPayload(job.tamperFraming ? new Uint8Array(4096) : json));
      job.blobId = `blob-${job.jobId}`;
      blobs.set(job.blobId, stored);
    }
    job.plan = JSON.parse(text(json));
    const body = {
      v: 1, job_id: job.jobId, enclave_id: planner.info.enclave_id, profile_id: FAST.id, image_digest: "sha256:img", params_digest: "0",
      input_digest: "0", output_digest: await sha256Hex(stored), output_bytes: stored.length, content_digest: await sha256Hex(json),
      attestation_digest: "0", started_at: 1, finished_at: 2, gpu_seconds: 1, miner_hotkey: null,
      plan: { shots: job.plan.shots.length, duration_s: job.plan.duration_s, planner: job.plan.planner.model, prompt_version: "plan/1", output_tokens: 400 },
    };
    const signature = sign(null, new Uint8Array([...utf8("kuno/v1/receipt\n"), ...canonicalJson(body)]), planner.signingKey.privateKey);
    job.receipt = { body, signature: b64e(new Uint8Array(signature)) };
  };
  const status = (job) => ({
    job_id: job.jobId, status: job.polls > 1 ? "succeeded" : "running", stage: job.polls > 1 ? "done" : "planning", progress: job.polls > 1 ? 1 : 0.05,
    params: job.params, enclave_id: planner.info.enclave_id, price_usd: job.privacy === "private" ? 0.1 : 0.08, created_at: 1, updated_at: 2,
    output_blob_id: job.polls > 1 ? job.blobId ?? null : null, receipt: job.polls > 1 ? job.receipt : null, error_code: null, error: null, privacy: job.privacy,
  });
  const fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    const key = `${init.method ?? "GET"} ${u.pathname}`;
    const body = typeof init.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ key, query: Object.fromEntries(u.searchParams), body });
    if (key === "GET /v1/route") return reply(200, { profile_id: FAST.id, requested_profile_id: FAST.id, fallback_reason: null, enclaves: [older.info, planner.info] });
    if (key === "POST /v1/videos") {
      const opener = await suite.createRecipientContext({ recipientKey: planner.recipient, enc: b64d(body.enc).slice().buffer, info: utf8("kuno/v1/job") });
      const aad = jobAad(body.job_id, body.enclave_id, body.params, body.input_blob_ids);
      const payload = JSON.parse(text(unpadPayload(new Uint8Array(await opener.open(b64d(body.ciphertext), aad)))));
      const outputKey = new Uint8Array(await opener.export(utf8("kuno/v1/output-key"), 32));
      jobs.set(body.job_id, { jobId: body.job_id, params: body.params, privacy: "private", payload, outputKey, revise: Boolean(payload.options.plan.revise), polls: 0 });
      return reply(201, { job_id: body.job_id });
    }
    if (key === "POST /v1/standard/plans") {
      jobs.set(body.job_id, { jobId: body.job_id, params: body.params, privacy: "standard", request: body, revise: Boolean(body.options.revise), polls: 0 });
      return reply(201, { job_id: body.job_id, status: "queued", params: body.params, enclave_id: "e", price_usd: 0.08, created_at: 1, updated_at: 1, privacy: "standard" });
    }
    const [, v1, kind, id, extra] = u.pathname.split("/");
    if (v1 === "v1" && kind === "videos" && jobs.has(id) && !extra) {
      const job = jobs.get(id);
      job.polls += 1;
      if (job.polls === 2) await deliver(job);
      return reply(200, status(job));
    }
    if (key === `GET /v1/blobs/${id}` && blobs.has(id)) return new Response(blobs.get(id));
    const planId = u.pathname.startsWith("/v1/standard/plans/") ? u.pathname.slice("/v1/standard/plans/".length) : null;
    if (key.startsWith("GET ") && planId && jobs.get(planId)?.plan) {
      // The stored plan's bytes, as the gateway serves them; a wrapped document is read too.
      const job = jobs.get(planId);
      if (job.wrapped) return reply(200, { job_id: planId, plan: job.stored ?? job.plan });
      return new Response(job.stored ? JSON.stringify(job.stored) : job.revise ? REVISION.delivered_json : ROASTERY.delivered_json, { headers: { "content-type": "application/json" } });
    }
    return key in answers ? reply(200, answers[key]) : reply(404, { detail: { code: "not_found", message: key } });
  };
  return { kuno: new KunoClient({ apiKey: "kw_test", baseUrl: "https://gw.test", fetch }), calls, jobs, blobs, planner };
}

const REQUEST = { brief: ROASTERY.brief, targetS: 30, resolution: "720p", style: "35mm film, warm", seed: 11 };
const fast = { pollMs: 1 };

test("a private plan goes to a plan worker, with the longest shot its envelope serves, and opens here", async () => {
  const w = await world();
  const stages = [];
  const result = await w.kuno.plan(REQUEST, { ...fast, onStage: (s) => stages.push(s) });
  assert.deepEqual(stages, ["routing", "verifying", "encrypting", "submitting"]);

  const routed = w.calls.find((c) => c.key === "GET /v1/route");
  assert.equal(routed.query.mode, "plan");
  assert.equal("duration_s" in routed.query, false, "a plan renders nothing, so it isn't routed by a length");

  const sent = w.calls.find((c) => c.key === "POST /v1/videos").body;
  assert.equal(sent.enclave_id, w.planner.info.enclave_id, "only the worker that lists plan/1");
  assert.deepEqual(sent.params, ROASTERY.params);
  assert.deepEqual(sent.input_blob_ids, []);
  assert.equal(JSON.stringify(sent).includes("roastery"), false, "the brief never leaves the page readable");
  const { payload } = w.jobs.get(sent.job_id);
  assert.equal(payload.prompt, ROASTERY.brief);
  assert.equal(payload.seed, 11);
  assert.deepEqual(payload.options.plan, { v: 1, min_shots: 2, style: "35mm film, warm", max_shot_s: 11 });

  assert.equal(text(result.json), ROASTERY.delivered_json);
  assert.deepEqual(result.plan, parsePlan(ROASTERY.delivered_json));
  assert.equal(result.receipt.body.plan.shots, 5);
  assert.equal(result.privacy, "private");

  // It renders as its storyboard exactly: the same shot specs, the same stitched length.
  const params = fitParams(FAST, "storyboard", [], { resolution: "720p", aspectRatio: "16:9", fps: 24, shots: planToShots(result.plan) }, null);
  assert.deepEqual(params, planStoryboardParams(result.plan));
  assert.equal(storyboardDurationS(FAST, params.shots, 24), result.plan.duration_s);
});

test("a plan that doesn't match its receipt, or isn't framed as a plan, is refused", async () => {
  const w = await world();
  const handle = await w.kuno.submitPlan(REQUEST);
  await w.kuno.status(handle.jobId);
  const status = await w.kuno.status(handle.jobId);
  const blob = w.blobs.get(status.output_blob_id);
  w.blobs.set(status.output_blob_id, blob.map((b, i) => (i === blob.length - 1 ? b ^ 1 : b)));
  await assert.rejects(w.kuno.planResult(handle, status), (err) => err.code === "integrity");
  w.blobs.set(status.output_blob_id, blob);
  await assert.rejects(w.kuno.planResult({ ...handle, outputKey: b64e(new Uint8Array(32)) }, status), (err) => err.code === "decrypt_failed");
  await assert.rejects(w.kuno.planResult({ ...handle, maxShotS: 5 }, status), (err) => err.code === "integrity" && /longer than 5 s/.test(err.message));
  const forged = { ...status, receipt: { ...status.receipt, signature: b64e(new Uint8Array(64)) } };
  await assert.rejects(w.kuno.planResult(handle, forged), (err) => err.code === "integrity" && /not signed/.test(err.message));
  assert.equal((await w.kuno.planResult(handle, status)).plan.title, "Handmade Coffee Roastery Ad");

  const bad = await w.kuno.submitPlan(REQUEST);
  w.jobs.get(bad.jobId).tamperFraming = true;
  await assert.rejects(w.kuno.waitPlan(bad, fast), (err) => err.code === "integrity");
});

test("without a worker that lists plan/1 nothing is sealed, and the reason is plain", async () => {
  const w = await world({ features: false });
  await assert.rejects(w.kuno.plan(REQUEST, fast), (err) => err instanceof KunoError && err.code === "plans_unavailable" && /doesn't say which workers write plans/.test(err.message));
  // A size no plan worker serves.
  const v = await world();
  await assert.rejects(v.kuno.plan({ ...REQUEST, resolution: "1080p" }, fast), (err) => err.code === "plans_unavailable" && /No confidential worker/.test(err.message));
  assert.equal([...w.calls, ...v.calls].some((c) => c.key === "POST /v1/videos"), false);
});

test("plans that can't be made are refused before anything is sent", async () => {
  const w = await world();
  const refused = async (req, code) => {
    await assert.rejects(w.kuno.submitPlan({ ...REQUEST, ...req }), (err) => err instanceof KunoError && err.code === code, JSON.stringify(req).slice(0, 80));
  };
  await refused({ brief: "  " }, "brief_required");
  await refused({ brief: "x".repeat(4001) }, "prompt_too_long");
  await refused({ style: "y".repeat(501) }, "prompt_too_long");
  await refused({ targetS: 3 }, "invalid_params");
  await refused({ targetS: 121 }, "invalid_params");
  await refused({ targetS: Number.NaN }, "invalid_params");
  await refused({ privacy: "public" }, "invalid_privacy");
  assert.equal(w.calls.some((c) => c.key === "POST /v1/videos"), false);
  // Code points, not UTF-16 units: 4,000 emoji are a brief of 4,000 characters.
  const long = await w.kuno.submitPlan({ ...REQUEST, brief: "🎬".repeat(4000) });
  assert.equal(long.kind, "plan");
});

test("a revision sends a clean, restitched Plan v1 and listed shots", async () => {
  const w = await world();
  const earlier = parsePlan(JSON.stringify(REVISION.options.revise.plan));
  // What an app keeps on its cards stays behind, and an edited length is measured again.
  const edited = structuredClone(earlier);
  edited.shots = edited.shots.map((shot, i) => ({ ...shot, id: `card-${i}` }));
  edited.extra = "not a plan field";
  const result = await w.kuno.revisePlan(REVISION.options.revise.plan, "darker", { shots: [2, 2], ...fast });
  const sent = w.calls.find((c) => c.key === "POST /v1/videos").body;
  assert.equal(sent.params.duration_s, 30);
  const { payload } = w.jobs.get(sent.job_id);
  assert.equal(payload.prompt, "");
  assert.deepEqual(payload.options.plan.revise, { plan: canonicalPlan(earlier), instruction: "darker", shots: [2] });
  assert.equal(text(result.json), REVISION.delivered_json);

  edited.shots[0].duration_s = 5;
  await w.kuno.submitRevision(edited, "", { shots: [3] });
  const second = w.calls.filter((c) => c.key === "POST /v1/videos")[1].body;
  const revise = w.jobs.get(second.job_id).payload.options.plan.revise;
  assert.equal("extra" in revise.plan, false);
  assert.equal(revise.plan.shots.some((shot) => "id" in shot), false);
  assert.equal(revise.plan.duration_s, storyboardDurationS(FAST, revise.plan.shots, 24));
  assert.notEqual(revise.plan.duration_s, earlier.duration_s);

  for (const [plan, opts, pattern] of [
    [earlier, { shots: [9] }, /has 5 shots/],
    [earlier, { shots: [0] }, /numbered from 1/],
    [{ ...earlier, shots: [{ ...earlier.shots[0], join: "cut" }, ...earlier.shots.slice(1)] }, {}, /first shot must be fresh/],
    [{ ...earlier, title: "t".repeat(81) }, {}, /title is longer than 80/],
  ]) {
    await assert.rejects(w.kuno.submitRevision(plan, "x", opts), (err) => err.code === "invalid_plan" && pattern.test(err.message), pattern.toString());
  }
});

function canonicalPlan(plan) {
  return JSON.parse(text(canonicalJson(plan)));
}

test("a Standard plan goes through /v1/standard/plans and is checked against its receipt", async () => {
  const w = await world();
  const result = await w.kuno.plan({ ...REQUEST, privacy: "standard" }, fast);
  const sent = w.calls.find((c) => c.key === "POST /v1/standard/plans").body;
  assert.equal(sent.brief, ROASTERY.brief);
  assert.equal(sent.style, "35mm film, warm");
  assert.equal(sent.seed, 11);
  assert.deepEqual(sent.params, ROASTERY.params);
  assert.deepEqual(sent.options, { v: 1, min_shots: 2, max_shot_s: 11 });
  assert.equal(w.calls.some((c) => c.key === "POST /v1/videos"), false);
  assert.equal(result.privacy, "standard");
  assert.equal(text(result.json), ROASTERY.delivered_json);

  // A Standard plan still needs no plan worker listed by the gateway: it routes the job itself.
  const v = await world({ features: false });
  const handle = await v.kuno.submitPlan({ ...REQUEST, privacy: "standard" });
  assert.equal(handle.maxShotS, null);

  const wrapped = await w.kuno.submitPlan({ ...REQUEST, privacy: "standard" });
  w.jobs.get(wrapped.jobId).wrapped = true;
  assert.equal(text((await w.kuno.waitPlan(wrapped, fast)).json), ROASTERY.delivered_json);

  const other = await w.kuno.submitPlan({ ...REQUEST, privacy: "standard" });
  await w.kuno.status(other.jobId);
  const status = await w.kuno.status(other.jobId);
  w.jobs.get(other.jobId).stored = { ...w.jobs.get(other.jobId).plan, title: "Changed by someone" };
  await assert.rejects(w.kuno.planResult(other, status), (err) => err.code === "integrity" && /content digest/.test(err.message));
});
