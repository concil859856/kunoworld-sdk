// Route filtering by a worker's serving envelope, against a fake gateway: the SDK sends the request's size, frame
// rate and duration to /v1/route and skips a listed worker whose envelope can't fit the job.
import assert from "node:assert/strict";
import { test } from "node:test";

import { KunoClient, KunoError, envelopeFits } from "../dist/index.js";

const PROFILE = {
  id: "ltx-2.5-fast",
  modes: ["text_to_video"],
  limits: { sizes: { "1080p": { "16:9": [1920, 1088] } }, fps: [24], default_fps: 24, min_duration_s: 2, max_duration_s: 20, audio: true },
  pricing: { usd_per_second: { "1080p": 0.08 }, standard_usd_per_second: { "1080p": 0.06 } },
};
const SMALL = { [PROFILE.id]: { "1080p": { "16:9": { "24": 8 } } } };

function fakeGateway(routes) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    const u = new URL(url);
    const key = `${init.method ?? "GET"} ${u.pathname}`;
    calls.push({ key, query: u.searchParams, body: init.body });
    const handler = routes[key];
    const [status, body] = handler ? handler({ body: init.body }) : [404, { detail: { code: "not_found", message: key } }];
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  };
  return { calls, client: new KunoClient({ apiKey: "kw_live_test", baseUrl: "https://gw.test", fetch }) };
}

const route = (enclaves = []) => () => [200, { profile_id: PROFILE.id, requested_profile_id: PROFILE.id, fallback_reason: null, enclaves }];
const models = () => [200, { country: null, workers_online: 1, switch: {}, models: [PROFILE], pricing_placeholder: true }];

test("route sends only the fit fields it is given", async () => {
  const { calls, client } = fakeGateway({ "GET /v1/route": route() });
  await client.route("text_to_video", PROFILE.id);
  await client.route("text_to_video", PROFILE.id, undefined, undefined, { resolution: "1080p", aspectRatio: "16:9", fps: 24, durationS: 10 });
  await client.route("text_to_video", PROFILE.id, undefined, "standard", { durationS: 8 });
  const [bare, full, partial] = calls.map((c) => Object.fromEntries(c.query));
  assert.deepEqual(bare, { mode: "text_to_video", profile_id: PROFILE.id });
  assert.deepEqual(full, { mode: "text_to_video", profile_id: PROFILE.id, resolution: "1080p", aspect_ratio: "16:9", fps: "24", duration_s: "10" });
  assert.deepEqual(partial, { mode: "text_to_video", profile_id: PROFILE.id, privacy: "standard", duration_s: "8" });
});

test("envelopeFits looks the job up by resolution, aspect ratio and fps", () => {
  const job = { profile_id: PROFILE.id, resolution: "1080p", aspect_ratio: "16:9", fps: 24, duration_s: 8 };
  assert.equal(envelopeFits(null, { ...job, duration_s: 20 }), true, "no envelope: the profile's limits");
  assert.equal(envelopeFits({ other: {} }, { ...job, duration_s: 20 }), true, "a profile left out: its limits");
  assert.equal(envelopeFits(SMALL, job), true);
  assert.equal(envelopeFits(SMALL, { ...job, duration_s: 9 }), false);
  assert.equal(envelopeFits(SMALL, { ...job, aspect_ratio: "21:9", duration_s: 2 }), false, "a size left out is not served");
});

test("a standard job routes with its size, frame rate and duration", async () => {
  const { calls, client } = fakeGateway({
    "GET /v1/route": route(),
    "GET /v1/models": models,
    "POST /v1/standard/videos": ({ body }) => {
      const sent = JSON.parse(body);
      return [201, { job_id: sent.job_id, status: "queued", params: sent.params, enclave_id: "e1", created_at: 1, privacy: "standard" }];
    },
  });
  await client.submit({ prompt: "a lighthouse at dusk", model: PROFILE.id, privacy: "standard", resolution: "1080p", aspectRatio: "16:9", fps: 24, durationS: 8 });
  const query = Object.fromEntries(calls.find((c) => c.key === "GET /v1/route").query);
  assert.deepEqual(
    { resolution: query.resolution, aspect_ratio: query.aspect_ratio, fps: query.fps, duration_s: query.duration_s },
    { resolution: "1080p", aspect_ratio: "16:9", fps: "24", duration_s: "8" },
  );
});

test("a private job skips a listed worker whose envelope can't fit it", async () => {
  const small = { enclave_id: "e-small", envelope: SMALL, evidence: {}, hpke_public_key: "", signing_public_key: "" };
  const { calls, client } = fakeGateway({ "GET /v1/route": route([small]), "GET /v1/models": models, "GET /v1/manifest": () => [200, {}] });
  await assert.rejects(
    client.submit({ prompt: "a lighthouse at dusk", model: PROFILE.id, resolution: "1080p", aspectRatio: "16:9", fps: 24, durationS: 10 }),
    (err) => err instanceof KunoError && err.code === "no_capacity" && err.status === 503,
  );
  const query = calls.find((c) => c.key === "GET /v1/route").query;
  assert.equal(query.get("duration_s"), "10");
  assert.equal(query.has("privacy"), false);
  assert.equal(calls.some((c) => c.key === "POST /v1/videos"), false, "nothing was sealed or submitted");
});
