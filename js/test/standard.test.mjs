// Standard mode and the account-safety errors, against a fake gateway: no network, no enclave.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { isStandardHandle, KunoClient, KunoError } from "../dist/index.js";

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...new Array(24).fill(0x30)]);
const VIDEO = new TextEncoder().encode("\0\0\0\x18ftypisom a standard film");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const PROFILE = {
  id: "ltx-2.5-fast",
  modes: ["text_to_video", "image_to_video"],
  limits: { sizes: { "1080p": { "16:9": [1920, 1080] } }, fps: [24], default_fps: 24, min_duration_s: 2, max_duration_s: 10, audio: true },
  pricing: { usd_per_second: { "1080p": 0.04 } },
};

function status(jobId, state, extra = {}) {
  return {
    job_id: jobId,
    status: state,
    stage: null,
    progress: state === "succeeded" ? 1 : 0,
    params: { profile_id: PROFILE.id, mode: "image_to_video", duration_s: 5, resolution: "1080p", aspect_ratio: "16:9", fps: 24, audio: true, input_roles: ["first_frame"] },
    enclave_id: "enc-open-1",
    price_usd: 0.2,
    created_at: 1_700_000_000,
    updated_at: 1_700_000_001,
    output_blob_id: null,
    receipt: state === "succeeded" ? { body: { job_id: jobId, content_digest: sha256(VIDEO) }, signature: "sig" } : null,
    error_code: null,
    error: null,
    privacy: "standard",
    ...extra,
  };
}

/** A gateway that answers from `routes` ("METHOD /path" → handler) and records every call. */
function fakeGateway(routes) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    const u = new URL(url);
    const key = `${init.method ?? "GET"} ${u.pathname}`;
    const call = { key, query: u.searchParams, headers: init.headers ?? {}, body: init.body };
    calls.push(call);
    const handler = routes[key];
    if (!handler) return new Response(JSON.stringify({ detail: { code: "not_found", message: key } }), { status: 404 });
    const out = await handler(call);
    if (out instanceof Response) return out;
    if (out instanceof Uint8Array) return new Response(out, { status: 200 });
    // { status: <number>, body } sets the HTTP status; anything else (a JobStatus has its own `status`) is a 200 body.
    const wrapped = out && typeof out.status === "number" && "body" in out;
    return new Response(JSON.stringify(wrapped ? out.body : out), {
      status: wrapped ? out.status : 200,
      headers: { "content-type": "application/json" },
    });
  };
  return { calls, fetch };
}

const error = (status, detail) => () => new Response(JSON.stringify({ detail }), { status });

test("a standard take uploads plaintext, lets the gateway seal it, and downloads the video", async () => {
  let created;
  const gw = fakeGateway({
    "GET /v1/route": () => ({ profile_id: PROFILE.id, requested_profile_id: PROFILE.id, fallback_reason: null, enclaves: [] }),
    "GET /v1/models": () => ({ country: null, workers_online: 1, switch: {}, models: [PROFILE] }),
    "POST /v1/standard/uploads": () => ({ status: 201, body: { upload_id: "up-1", sha256: sha256(PNG), size: PNG.length, mime: "image/png" } }),
    "POST /v1/standard/videos": async (call) => {
      created = JSON.parse(call.body);
      return { status: 201, body: status(created.job_id, "queued") };
    },
    "GET /v1/videos/job-std": () => status("job-std", "succeeded"),
    "GET /v1/standard/videos/job-std/video": () => VIDEO,
  });
  // The fake echoes the client's job id, so pin it to one the status route knows.
  const realUuid = crypto.randomUUID;
  crypto.randomUUID = () => "job-std";
  try {
    const kuno = new KunoClient({ apiKey: "kw_test", baseUrl: "https://gw.test", fetch: gw.fetch });
    const stages = [];
    const handle = await kuno.submit(
      { prompt: "A lantern in the rain", model: PROFILE.id, privacy: "standard", inputs: [{ role: "first_frame", file: PNG }] },
      (s) => stages.push(s),
    );
    assert.equal(isStandardHandle(handle), true);
    assert.equal(handle.jobId, "job-std");
    assert.equal("outputKey" in handle, false, "a standard handle holds no key");
    assert.deepEqual(stages, ["routing", "uploading", "submitting"]);

    const result = await kuno.wait(handle, { pollMs: 1 });
    assert.equal(result.privacy, "standard");
    assert.deepEqual(result.video, VIDEO);
  } finally {
    crypto.randomUUID = realUuid;
  }

  const route = gw.calls.find((c) => c.key === "GET /v1/route");
  assert.equal(route.query.get("privacy"), "standard");
  const upload = gw.calls.find((c) => c.key === "POST /v1/standard/uploads");
  assert.equal(upload.query.get("role"), "first_frame");
  assert.equal(upload.headers["content-type"], "image/png");
  assert.deepEqual(new Uint8Array(await upload.body.arrayBuffer()), PNG, "inputs go up as they are");

  assert.equal(created.prompt, "A lantern in the rain");
  assert.deepEqual(created.inputs.map((i) => [i.upload_id, i.index, i.role]), [["up-1", 0, "first_frame"]]);
  assert.equal(created.params.profile_id, PROFILE.id);
  assert.equal("ciphertext" in created || "enc" in created, false);
  // No attestation, sealing or ciphertext relay on the standard path.
  for (const path of ["GET /v1/manifest", "POST /v1/blobs", "POST /v1/videos"]) {
    assert.equal(gw.calls.some((c) => c.key === path), false, `${path} should not be called`);
  }
});

test("a standard video that doesn't match its receipt is refused", async () => {
  const gw = fakeGateway({
    "GET /v1/videos/job-x": () => status("job-x", "succeeded"),
    "GET /v1/standard/videos/job-x/video": () => new TextEncoder().encode("something else"),
  });
  const kuno = new KunoClient({ apiKey: "kw_test", baseUrl: "https://gw.test", fetch: gw.fetch });
  const handle = kuno.standardHandle({ job_id: "job-x", profile_id: PROFILE.id, created_at: 1 });
  await assert.rejects(kuno.result(handle), (err) => err instanceof KunoError && err.code === "integrity");
});

test("private-mode and restriction errors keep their details", async () => {
  const gw = fakeGateway({
    "GET /v1/route": error(403, { code: "private_mode_not_eligible", message: "Private mode needs a verified payment.", reasons: ["no_verified_payment", "too_many_strikes"] }),
    "POST /v1/standard/uploads": error(422, { code: "upload_blocked", message: "This file can't be used." }),
    "GET /v1/account/eligibility": error(403, { code: "account_restricted", message: "Restricted.", restricted_until: 1_900_000_000 }),
  });
  const kuno = new KunoClient({ apiKey: "kw_test", baseUrl: "https://gw.test", fetch: gw.fetch });

  const denied = await kuno.submit({ prompt: "x" }).catch((e) => e);
  assert.ok(denied instanceof KunoError);
  assert.equal(denied.status, 403);
  assert.equal(denied.code, "private_mode_not_eligible");
  assert.deepEqual(denied.reasons, ["no_verified_payment", "too_many_strikes"]);
  assert.equal(denied.restrictedUntil, null);
  assert.equal(gw.calls[0].headers.authorization, "Bearer kw_test", "routing carries the credential");

  const blocked = await kuno.uploadStandard("first_frame", PNG).catch((e) => e);
  assert.equal(blocked.code, "upload_blocked");

  const restricted = await kuno.eligibility().catch((e) => e);
  assert.equal(restricted.code, "account_restricted");
  assert.equal(restricted.restrictedUntil, 1_900_000_000);
});

test("reports go out without a credential; library calls use the account's", async () => {
  const gw = fakeGateway({
    "POST /v1/reports": () => ({ status: 202, body: { report_id: "rep-1" } }),
    "GET /v1/standard/videos": () => [{ job_id: "a", status: "succeeded", profile_id: PROFILE.id, params: status("a", "succeeded").params, prompt: "p", created_at: 2, finished_at: 3, has_video: true, error_code: null }],
    "GET /v1/standard/videos/a/thumbnail": () => new Uint8Array([0xff, 0xd8, 0xff]),
    "DELETE /v1/standard/videos/a": () => new Response(null, { status: 204 }),
    "GET /v1/account/eligibility": () => ({ private_mode: { eligible: true, reasons: [] }, restricted_until: null, strikes_24h: 0, strikes_7d: 1 }),
  });
  const kuno = new KunoClient({ apiKey: "kw_test", baseUrl: "https://gw.test", fetch: gw.fetch });

  assert.deepEqual(await kuno.report({ job_id: "a", reason: "copyright", details: "my film" }), { report_id: "rep-1" });
  const report = gw.calls.find((c) => c.key === "POST /v1/reports");
  assert.equal(report.headers.authorization, undefined);
  assert.deepEqual(JSON.parse(report.body), { job_id: "a", reason: "copyright", details: "my film" });

  const [row] = await kuno.listStandard(10);
  assert.equal(row.job_id, "a");
  assert.equal(gw.calls.find((c) => c.key === "GET /v1/standard/videos").query.get("limit"), "10");
  assert.deepEqual(await kuno.standardThumbnail("a"), new Uint8Array([0xff, 0xd8, 0xff]));
  await kuno.deleteStandard("a");
  assert.equal((await kuno.eligibility()).strikes_7d, 1);
  for (const c of gw.calls.filter((c) => c.key !== "POST /v1/reports")) assert.equal(c.headers.authorization, "Bearer kw_test");
});

test("private submissions still take the encrypted path", async () => {
  const gw = fakeGateway({
    "GET /v1/route": () => ({ profile_id: PROFILE.id, requested_profile_id: PROFILE.id, fallback_reason: null, enclaves: [] }),
    "GET /v1/models": () => ({ country: null, workers_online: 0, switch: {}, models: [PROFILE] }),
    "GET /v1/manifest": () => ({ version: 1, issued_at: 0, allowed: [], mock_quote_keys: [], max_evidence_age_s: 600 }),
  });
  const kuno = new KunoClient({ apiKey: "kw_test", baseUrl: "https://gw.test", fetch: gw.fetch });
  // No enclave passes verification, so nothing is uploaded: the private path refuses rather than falling back.
  await assert.rejects(kuno.submit({ prompt: "x", model: PROFILE.id }), (err) => err.code === "no_attested_worker");
  assert.equal(gw.calls.find((c) => c.key === "GET /v1/route").query.has("privacy"), false);
  assert.equal(gw.calls.some((c) => c.key.includes("/standard/")), false);
});
