// Quotes and the budget guard in the TypeScript SDK, as the Python SDK has them (sdk/python/tests/test_sdk_quotes.py):
// `quote` sends a job's shape and never a prompt, and `maxPriceUsd` on `submit`/`generate` (videos and storyboards, Private
// and Standard), `submitPlan`/`plan` and `submitRevision`/`revisePlan` has the gateway quote the exact params about to be
// sent, refusing `over_budget` before any input is read or uploaded, a worker is picked or anything is sealed. Against a
// fake gateway that prices with `fitParams` and `priceQuote`, and a mock-attested enclave whose keys this test holds.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";

import {
  ERROR_CODES,
  KunoError,
  KunoClient,
  b64d,
  b64e,
  canonicalJson,
  enclaveIdFor,
  fitParams,
  inferMode,
  jobAad,
  parsePlan,
  planStoryboardParams,
  priceUsd,
  reportDataFor,
  storyboardDurationS,
  toHex,
  unpadPayload,
} from "../dist/index.js";

const PLANS = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8")).plans;
const ROASTERY = PLANS.repair.find((c) => c.name === "gpu spike e2b roastery");
const REVISION = PLANS.repair.find((c) => c.name === "revision of shot 2 only");
const utf8 = (s) => new TextEncoder().encode(s);
const text = (bytes) => new TextDecoder().decode(bytes);

const FAST = {
  id: "ltx-2.5-fast",
  name: "LTX-2.5 Fast",
  family: "ltx-2.5",
  modes: ["text_to_video", "image_to_video", "first_last_frame", "storyboard", "plan"],
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
    max_inputs: { first_frame: 1, last_frame: 1 },
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

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...new Array(32).fill(0x30)]);
const SCENE = "A lighthouse keeper's cottage on a cliff, storm light, 35 mm film.";
const SECRET = "the keeper whispers the combination 4-8-15";
const SHOTS = [
  { prompt: `${SECRET}, shot one`, durationS: 5 },
  { prompt: "Waves hit the rocks below.", durationS: 5 },
  { prompt: "Inside, the lamp is lit.", durationS: 4, join: "cut" },
];
// What the gateway assumes a mode's inputs are when a quote names none (kuno_protocol.profiles.example_roles).
const EXAMPLE_ROLES = { image_to_video: ["first_frame"], first_last_frame: ["first_frame", "last_frame"] };

const reply = (status, value) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });

/** A fake gateway with one mock-attested worker that renders and writes plans. */
async function world() {
  const quoteKey = generateKeyPairSync("ed25519");
  const measurements = { mrtd: "aa", rtmr0: "bb", rtmr1: "cc", rtmr2: "dd", rtmr3: "ee" };
  const recipient = await suite.kem.generateKeyPair();
  const hpke = new Uint8Array(await suite.kem.serializePublicKey(recipient.publicKey));
  const signing = b64d(generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x);
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const gpu = canonicalJson({ format: "kuno/v1/nvidia-gpu", nonce: toHex(nonce), gpus: [{ arch: "HOPPER" }], cc: { mode: "spt", devtools: false } });
  const quoteBody = { measurements, report_data: toHex(reportDataFor(nonce, hpke, signing, gpu)) };
  const signature = new Uint8Array(sign(null, new Uint8Array([...utf8("kuno/v1/mock-quote\n"), ...canonicalJson(quoteBody)]), quoteKey.privateKey));
  const evidence = {
    tee: "mock",
    quote: b64e(utf8(JSON.stringify({ body: quoteBody, signature: b64e(signature) }))),
    gpu_evidence: b64e(gpu),
    nonce: toHex(nonce),
    hpke_public_key: b64e(hpke),
    signing_public_key: b64e(signing),
    image_digest: "sha256:img",
    profiles: [FAST.id],
    hardware: {},
    created_at: Date.now() / 1000,
  };
  const enclave = { enclave_id: enclaveIdFor(hpke, signing), hpke_public_key: evidence.hpke_public_key, signing_public_key: evidence.signing_public_key, evidence, features: ["plan/1"] };
  const answers = {
    "GET /v1/route": { profile_id: FAST.id, requested_profile_id: FAST.id, fallback_reason: null, enclaves: [enclave] },
    "GET /v1/models": { country: null, workers_online: 1, switch: {}, models: [FAST] },
    "GET /v1/manifest": {
      version: 1,
      issued_at: 0,
      allowed: [{ platform: "mock", image_digest: "sha256:img", profiles: [FAST.id], ...measurements }],
      mock_quote_keys: [quoteKey.publicKey.export({ format: "jwk" }).x],
      max_evidence_age_s: 600,
    },
  };
  const w = {
    calls: [],
    quotes: [],
    refuse: {},
    // A test sets these to make the gateway answer differently.
    priceUsd: null,
    balanceUsd: 25,
    changeQuote: (body) => body,
  };

  /** Prices a quote body the way api_quote.py does: the SDKs' defaults, then the profile's price. */
  const quote = (body) => {
    w.quotes.push(body);
    const asked = w.changeQuote(body);
    const frame = { resolution: asked.resolution, aspectRatio: asked.aspect_ratio, fps: asked.fps, audio: asked.audio };
    let params;
    if (asked.mode === "plan") {
      params = fitParams(FAST, "plan", [], { ...frame, durationS: asked.duration_s }, null);
    } else if (asked.shots) {
      params = fitParams(FAST, "storyboard", [], { ...frame, shots: asked.shots.map((s) => ({ prompt: "-", durationS: s.duration_s ?? 5, join: s.join ?? undefined })) }, null);
    } else {
      const mode = asked.mode ?? inferMode(asked.input_roles ?? []);
      params = fitParams(FAST, mode, asked.input_roles ?? EXAMPLE_ROLES[mode] ?? [], { ...frame, durationS: asked.duration_s }, null);
    }
    const privacy = asked.privacy ?? "private";
    const price = w.priceUsd ?? priceUsd(FAST, params, privacy);
    const flat = params.mode === "plan";
    return reply(200, {
      price_usd: price,
      currency: "USD",
      privacy,
      profile_id: FAST.id,
      profile_name: FAST.name,
      requested_profile_id: asked.profile_id ?? null,
      fallback_reason: null,
      params,
      breakdown: {
        usd_per_second: flat ? null : FAST.pricing[privacy === "private" ? "usd_per_second" : "standard_usd_per_second"][params.resolution],
        billable_seconds: flat ? 0 : params.duration_s,
        fps_multiplier: 1,
        long_clip_over_s: null,
        long_clip_multiplier: 1,
        subtotal_usd: price,
        min_job_usd: 0.1,
        minimum_applied: false,
        ...(flat ? { plan_usd: price } : {}),
      },
      placeholder: true,
      balance_usd: w.balanceUsd,
      balance_covers: w.balanceUsd >= price,
    });
  };

  const fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    const key = `${init.method ?? "GET"} ${u.pathname}`;
    const body = typeof init.body === "string" ? JSON.parse(init.body) : undefined;
    w.calls.push({ key, query: Object.fromEntries(u.searchParams), body, raw: typeof init.body === "string" ? init.body : "" });
    if (w.refuse[key]) return w.refuse[key];
    if (key === "POST /v1/quote") return quote(body);
    if (key === "POST /v1/blobs") return reply(201, { blob_id: `blob-${w.calls.length}` });
    if (key === "POST /v1/videos") return reply(201, { job_id: body.job_id });
    if (key === "POST /v1/standard/uploads") return reply(201, { upload_id: `up-${w.calls.length}` });
    if (key === "POST /v1/standard/videos" || key === "POST /v1/standard/plans") {
      return reply(201, { job_id: body.job_id, status: "queued", params: body.params, enclave_id: "e-open", created_at: 1, privacy: "standard" });
    }
    return key in answers ? reply(200, answers[key]) : reply(404, { detail: { code: "not_found", message: key } });
  };
  w.kuno = new KunoClient({ apiKey: "kw_test", baseUrl: "https://gw.test", fetch });
  w.keys = () => w.calls.map((c) => c.key);
  w.sent = () => w.calls.map((c) => c.raw).join("\n");
  w.open = async (request) => {
    const opener = await suite.createRecipientContext({ recipientKey: recipient, enc: b64d(request.enc).slice().buffer, info: utf8("kuno/v1/job") });
    const aad = jobAad(request.job_id, request.enclave_id, request.params, request.input_blob_ids);
    return JSON.parse(text(unpadPayload(new Uint8Array(await opener.open(b64d(request.ciphertext), aad)))));
  };
  return w;
}

const code = (expected) => (err) => err instanceof KunoError && err.code === expected;

test("a quote sends the job's shape, never a prompt or a file, and reads back a typed quote", async () => {
  const w = await world();
  const quote = await w.kuno.quote({ model: FAST.id, shots: SHOTS, resolution: "720p" });
  assert.deepEqual(w.quotes[0], {
    privacy: "private",
    audio: true,
    profile_id: FAST.id,
    mode: "storyboard",
    resolution: "720p",
    shots: [{ duration_s: 5, join: null }, { duration_s: 5, join: null }, { duration_s: 4, join: "cut" }],
  });
  assert.equal(w.sent().includes("keeper"), false);

  const specs = [{ duration_s: 5, join: "fresh" }, { duration_s: 5, join: "continue" }, { duration_s: 4, join: "cut" }];
  assert.deepEqual(quote.params.shots, specs);
  assert.equal(quote.params.duration_s, storyboardDurationS(FAST, specs, 24));
  assert.equal(quote.priceUsd, priceUsd(FAST, quote.params));
  assert.equal(quote.breakdown.billableSeconds, quote.params.duration_s);
  assert.equal(quote.breakdown.usdPerSecond, 0.12);
  assert.equal(quote.breakdown.planUsd, null);
  assert.deepEqual(
    [quote.profileId, quote.profileName, quote.privacy, quote.placeholder, quote.currency, quote.balanceUsd, quote.balanceCovers, quote.fallbackReason],
    [FAST.id, "LTX-2.5 Fast", "private", true, "USD", 25, true, null],
  );

  // ShotSpecs work too, and the mode follows the roles of the inputs a job will send, as submit infers it.
  await w.kuno.quote({ shots: specs, privacy: "standard" });
  assert.deepEqual(w.quotes[1].shots[2], { duration_s: 4, join: "cut" });
  assert.equal("profile_id" in w.quotes[1], false);
  await w.kuno.quote({ model: FAST.id, inputRoles: ["first_frame", "last_frame"], durationS: 8 });
  assert.deepEqual([w.quotes[2].mode, w.quotes[2].input_roles, w.quotes[2].duration_s], ["first_last_frame", ["first_frame", "last_frame"], 8]);

  // A request as submit takes it: only its shape is read. The file is never opened, the prompt never sent.
  let opened = false;
  const file = { arrayBuffer: async () => ((opened = true), PNG.buffer) };
  const request = { prompt: SECRET, model: FAST.id, inputs: [{ role: "first_frame", file }], seed: 7, maxPriceUsd: 1 };
  const fromRequest = await w.kuno.quote(request);
  assert.deepEqual(w.quotes[3], { privacy: "private", audio: true, profile_id: FAST.id, mode: "image_to_video", input_roles: ["first_frame"] });
  assert.equal(opened, false);
  assert.equal(w.sent().includes("keeper"), false);
  assert.equal(fromRequest.params.duration_s, 5);

  // No roles at all: the gateway assumes what the mode needs.
  await w.kuno.quote({ model: FAST.id, mode: "image_to_video" });
  assert.equal("input_roles" in w.quotes[4], false);
  w.balanceUsd = 0.2;
  assert.equal((await w.kuno.quote({ model: FAST.id, durationS: 10 })).balanceCovers, false);
  assert.deepEqual(w.keys(), Array(6).fill("POST /v1/quote"));
});

test("a plan's quote is flat, and a plan quotes as the storyboard it renders as", async () => {
  const w = await world();
  for (const target of [10, 90]) {
    const quote = await w.kuno.quote({ model: FAST.id, mode: "plan", durationS: target });
    assert.deepEqual(
      [quote.priceUsd, quote.params.mode, quote.breakdown.planUsd, quote.breakdown.usdPerSecond, quote.breakdown.billableSeconds],
      [0.1, "plan", 0.1, null, 0],
    );
  }
  assert.equal((await w.kuno.quote({ model: FAST.id, mode: "plan", durationS: 30, privacy: "standard" })).priceUsd, 0.08);

  // A gateway that leaves a plan's per-second terms out reads the same.
  w.refuse["POST /v1/quote"] = reply(200, { price_usd: 0.1, privacy: "private", profile_id: FAST.id, params: ROASTERY.params, breakdown: { plan_usd: 0.1 } });
  const bare = await w.kuno.quote({ model: FAST.id, mode: "plan", durationS: 30 });
  assert.deepEqual(bare.breakdown, {
    usdPerSecond: null, billableSeconds: 0, fpsMultiplier: 1, longClipMultiplier: 1, subtotalUsd: 0.1, minJobUsd: 0, minimumApplied: false,
    longClipOverS: null, planUsd: 0.1,
  });
  assert.deepEqual([bare.placeholder, bare.balanceUsd, bare.balanceCovers, bare.profileName], [true, null, null, ""]);
  delete w.refuse["POST /v1/quote"];

  const plan = parsePlan(ROASTERY.delivered_json);
  const rendering = await w.kuno.quote({ plan });
  assert.deepEqual(rendering.params, planStoryboardParams(plan));
  assert.equal(w.sent().includes(plan.shots[0].prompt), false, "a plan's shot prompts stay here");
  assert.equal(w.sent().includes(plan.scene), false);
  await assert.rejects(w.kuno.quote({ plan, shots: SHOTS }), code("invalid_params"));
  await assert.rejects(w.kuno.quote({ plan, resolution: "1080p" }), (err) => err.code === "invalid_params" && /written for resolution 720p/.test(err.message));
  await assert.rejects(w.kuno.quote({ plan, mode: "text_to_video" }), code("invalid_params"));
  await assert.rejects(w.kuno.quote({ plan: { title: "not a plan" } }), code("invalid_plan"));
});

test("a quote that can't be a job is refused before sending", async () => {
  const w = await world();
  for (const [request, expected] of [
    [{ shots: SHOTS, durationS: 10 }, "invalid_params"],
    [{ shots: SHOTS, mode: "text_to_video" }, "invalid_shots"],
    [{ mode: "storyboard" }, "invalid_shots"],
    [{ shots: SHOTS, inputRoles: ["first_frame"] }, "invalid_inputs"],
    [{ shots: [{ durationS: 5 }, { durationS: 5, join: "dissolve" }] }, "invalid_shots"],
    [{ shots: [null, { durationS: 5 }] }, "invalid_shots"],
    [{ privacy: "public" }, "invalid_privacy"],
  ]) {
    await assert.rejects(w.kuno.quote({ model: FAST.id, ...request }), code(expected), JSON.stringify(request));
  }
  assert.deepEqual(w.calls, []);
});

test("gateway refusals come back with their codes", async () => {
  const w = await world();
  w.refuse["POST /v1/quote"] = reply(451, { detail: { code: "region_restricted", message: "MiniMax H3 is not licensed in your region" } });
  await assert.rejects(w.kuno.quote({ model: "h3" }), (err) => err.status === 451 && err.code === "region_restricted");
});

// ---------------------------------------------------------------- the budget guard

test("over budget, a private job is refused before an input is read, a worker is picked or anything is sealed", async () => {
  const w = await world();
  w.priceUsd = 2.5;
  let opened = false;
  const file = { arrayBuffer: async () => ((opened = true), PNG.buffer) };
  const stages = [];
  await assert.rejects(
    w.kuno.submit({ prompt: "A glass flower turns.", model: FAST.id, inputs: [{ role: "first_frame", file }], maxPriceUsd: 2.49 }, (s) => stages.push(s)),
    (err) => {
      assert.equal(err.code, "over_budget");
      assert.deepEqual(err.details, { price_usd: 2.5, max_price_usd: 2.49, profile_id: FAST.id });
      assert.match(err.message, /\$2\.5 \(LTX-2\.5 Fast, private\), over the \$2\.49 limit/);
      assert.equal(err.explanation, ERROR_CODES.over_budget);
      return true;
    },
  );
  assert.equal(opened, false);
  assert.deepEqual(stages, ["routing"]);
  for (const key of ["GET /v1/manifest", "POST /v1/blobs", "POST /v1/videos"]) assert.equal(w.keys().includes(key), false, key);

  // The quote was for exactly the params submit would have sealed: every field sent, on the routed profile.
  assert.deepEqual(w.quotes, [
    { profile_id: FAST.id, mode: "image_to_video", privacy: "private", resolution: "720p", aspect_ratio: "16:9", fps: 24, audio: true, input_roles: ["first_frame"], duration_s: 5 },
  ]);
  await assert.rejects(w.kuno.generate({ prompt: "A fox.", model: FAST.id, maxPriceUsd: 1 }), code("over_budget"));
});

test("within budget, a private storyboard goes ahead and its handle keeps the quote", async () => {
  const w = await world();
  const request = { prompt: SCENE, model: FAST.id, shots: SHOTS, resolution: "1080p", maxPriceUsd: 5 };
  const handle = await w.kuno.submit(request);
  const sent = w.calls.find((c) => c.key === "POST /v1/videos").body;
  assert.ok(handle.quote);
  assert.deepEqual(handle.quote.params, sent.params);
  assert.equal(handle.quote.priceUsd, priceUsd(FAST, sent.params));
  assert.ok(handle.quote.priceUsd <= 5);
  assert.deepEqual(w.quotes[0].shots, sent.params.shots);
  assert.equal(w.sent().includes("keeper"), false, "the shot prompts went sealed, and never into the quote");
  assert.equal((await w.open(sent)).shots[0].prompt, SHOTS[0].prompt);
  assert.deepEqual(w.keys().indexOf("POST /v1/quote") < w.keys().indexOf("GET /v1/manifest"), true);

  // A price exactly at the limit is within it.
  w.priceUsd = handle.quote.priceUsd;
  assert.ok((await w.kuno.submit({ ...request, maxPriceUsd: handle.quote.priceUsd })).quote);
});

test("over budget, a Standard job uploads nothing; within it, the job goes ahead; without one, nothing is quoted", async () => {
  const w = await world();
  w.priceUsd = 1;
  await assert.rejects(
    w.kuno.submit({ prompt: "A quiet beach.", privacy: "standard", model: FAST.id, inputs: [{ role: "first_frame", file: PNG }], maxPriceUsd: 0.5 }),
    code("over_budget"),
  );
  assert.equal(w.quotes.at(-1).privacy, "standard");
  assert.equal(w.keys().includes("POST /v1/standard/uploads") || w.keys().includes("POST /v1/standard/videos"), false);

  w.priceUsd = null;
  const standard = await w.kuno.submit({ prompt: "A quiet beach.", privacy: "standard", model: FAST.id, maxPriceUsd: 0.5 });
  assert.equal(standard.quote.privacy, "standard");
  assert.equal(standard.quote.priceUsd, 0.45);
  assert.equal(w.calls.find((c) => c.key === "POST /v1/standard/videos").body.prompt, "A quiet beach.");
  assert.equal(standard.privacy, "standard");

  const storyboard = await w.kuno.submit({ prompt: SCENE, privacy: "standard", model: FAST.id, shots: SHOTS, resolution: "720p", maxPriceUsd: 5 });
  assert.deepEqual(storyboard.quote.params.shots, w.calls.filter((c) => c.key === "POST /v1/standard/videos")[1].body.params.shots);

  const before = w.quotes.length;
  const plain = await w.kuno.submit({ prompt: "A fox.", model: FAST.id });
  const unbudgeted = await w.kuno.submit({ prompt: "A fox.", model: FAST.id, privacy: "standard", maxPriceUsd: null });
  assert.equal(w.quotes.length, before);
  assert.equal("quote" in plain, false);
  assert.equal("quote" in unbudgeted, false);
});

test("a quote for other params than the job is refused", async () => {
  const w = await world();
  w.changeQuote = (body) => ({ ...body, duration_s: 9 });
  await assert.rejects(w.kuno.submit({ prompt: "A fox.", model: FAST.id, durationS: 5, maxPriceUsd: 10 }), (err) => {
    assert.equal(err.code, "quote_mismatch");
    assert.equal(err.details.quote.duration_s, 9);
    return true;
  });
  assert.equal(w.keys().includes("POST /v1/videos"), false);
});

test("a budget must be a real amount, on every entry point", async () => {
  const w = await world();
  const plan = REVISION.options.revise.plan;
  for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY, "5", true, {}]) {
    await assert.rejects(w.kuno.submit({ prompt: "A fox.", model: FAST.id, maxPriceUsd: bad }), code("invalid_budget"), String(bad));
    await assert.rejects(w.kuno.submit({ prompt: "A fox.", privacy: "standard", maxPriceUsd: bad }), code("invalid_budget"));
    await assert.rejects(w.kuno.generate({ prompt: "A fox.", maxPriceUsd: bad }), code("invalid_budget"));
    await assert.rejects(w.kuno.submitPlan({ brief: ROASTERY.brief, targetS: 30, maxPriceUsd: bad }), code("invalid_budget"));
    await assert.rejects(w.kuno.plan({ brief: ROASTERY.brief, targetS: 30, privacy: "standard", maxPriceUsd: bad }), code("invalid_budget"));
    await assert.rejects(w.kuno.submitRevision(plan, "darker", { maxPriceUsd: bad }), code("invalid_budget"));
    await assert.rejects(w.kuno.revisePlan(plan, "darker", { maxPriceUsd: bad }), code("invalid_budget"));
  }
  assert.deepEqual(w.calls, []);
  assert.equal(ERROR_CODES.invalid_budget, "maxPriceUsd must be a finite number, zero or more.");
  // Zero is an amount: a free job would go ahead, and anything priced is over it.
  await assert.rejects(w.kuno.submit({ prompt: "A fox.", model: FAST.id, maxPriceUsd: 0 }), code("over_budget"));
});

test("plans keep to the budget in either mode, revisions included, and a plan within it carries its flat quote", async () => {
  const w = await world();
  const brief = { brief: ROASTERY.brief, targetS: 30, resolution: "720p" };
  await assert.rejects(w.kuno.submitPlan({ ...brief, maxPriceUsd: 0.05 }), (err) => err.code === "over_budget" && err.details.price_usd === 0.1);
  await assert.rejects(w.kuno.plan({ ...brief, privacy: "standard", maxPriceUsd: 0.05 }), (err) => err.code === "over_budget" && err.details.price_usd === 0.08);
  assert.deepEqual(w.quotes[0], { ...ROASTERY.params, privacy: "private" });
  assert.equal(w.quotes[1].privacy, "standard");
  for (const key of ["POST /v1/videos", "POST /v1/standard/plans", "GET /v1/manifest"]) assert.equal(w.keys().includes(key), false, key);
  assert.equal(w.sent().includes("roastery"), false, "a brief is never quoted");

  const priv = await w.kuno.submitPlan({ ...brief, maxPriceUsd: 0.1 });
  assert.deepEqual([priv.quote.priceUsd, priv.quote.breakdown.planUsd, priv.quote.params.mode], [0.1, 0.1, "plan"]);
  assert.deepEqual(priv.quote.params, w.calls.find((c) => c.key === "POST /v1/videos").body.params);
  const standard = await w.kuno.submitPlan({ ...brief, privacy: "standard", maxPriceUsd: 0.08 });
  assert.equal(standard.quote.priceUsd, 0.08);

  const revise = REVISION.options.revise.plan;
  const posted = () => w.keys().filter((k) => k === "POST /v1/videos").length;
  await assert.rejects(w.kuno.submitRevision(revise, "darker", { shots: [2], maxPriceUsd: 0.09 }), code("over_budget"));
  assert.equal(posted(), 1);
  const revision = await w.kuno.submitRevision(revise, "darker", { shots: [2], maxPriceUsd: 0.1 });
  assert.equal(revision.quote.priceUsd, 0.1);
  assert.equal(posted(), 2);
  assert.equal("quote" in (await w.kuno.submitPlan(brief)), false);
});
