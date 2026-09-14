// Keyless same-origin proxy mode, deleting jobs, and the documented error codes, against a fake gateway.
import assert from "node:assert/strict";
import { test } from "node:test";

import { ERROR_CODES, KunoClient, KunoError } from "../dist/index.js";

/** Records every call and answers from `routes` ("METHOD /path" → Response factory). */
function fakeFetch(routes) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    calls.push({ url: String(url), method: init.method ?? "GET", headers: init.headers ?? {}, credentials: init.credentials });
    const path = String(url).replace(/^https?:\/\/[^/]+/, "").split("?")[0];
    const handler = routes[`${init.method ?? "GET"} ${path}`];
    return handler ? handler() : new Response(JSON.stringify({ detail: { code: "not_found", message: path } }), { status: 404 });
  };
  return { calls, fetch };
}

const json = (status, body) => () => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const keyed = (gw) => new KunoClient({ apiKey: "kw_live_test", baseUrl: "https://gw.test", fetch: gw.fetch });

const PROFILE = {
  id: "ltx-2.5-fast",
  modes: ["text_to_video"],
  limits: { sizes: { "1080p": { "16:9": [1920, 1080] } }, fps: [24], default_fps: 24, min_duration_s: 2, max_duration_s: 10, audio: true },
  pricing: { usd_per_second: { "1080p": 0.04 } },
};

test("a proxy client sends no credential of its own, keeps the same-origin path, and sends cookies", async () => {
  const gw = fakeFetch({ "GET /api/kuno/v1/videos": json(200, []) });
  const kuno = KunoClient.forProxy("/api/kuno/", { fetch: gw.fetch });
  assert.deepEqual(await kuno.list(5), []);
  const [call] = gw.calls;
  assert.equal(call.url, "/api/kuno/v1/videos?limit=5", "the trailing slash is trimmed and the path stays relative");
  assert.equal(call.credentials, "same-origin");
  assert.equal("authorization" in call.headers, false, "no bearer token leaves the page");
});

test("a keyed client sends its API key, and no credentials mode unless asked", async () => {
  const gw = fakeFetch({ "GET /v1/videos": json(200, []) });
  await keyed(gw).list();
  assert.equal(gw.calls[0].headers.authorization, "Bearer kw_live_test");
  assert.equal(gw.calls[0].credentials, undefined);
});

test("studio tokens are refused before any request", () => {
  assert.throws(
    () => new KunoClient({ apiKey: "kwt_abc", baseUrl: "https://gw.test" }),
    (err) => err instanceof KunoError && err.code === "gone" && err.status === 410,
  );
});

test("delete sends DELETE /v1/videos/{id}, escapes the id, and accepts 204", async () => {
  const gw = fakeFetch({ "DELETE /v1/videos/job%2F1": () => new Response(null, { status: 204 }) });
  await keyed(gw).delete("job/1");
  assert.equal(gw.calls[0].method, "DELETE");
  assert.equal(gw.calls[0].url, "https://gw.test/v1/videos/job%2F1");
});

test("a failed delete surfaces the gateway's code", async () => {
  const gw = fakeFetch({ "DELETE /v1/videos/gone-1": json(404, { detail: { code: "not_found", message: "No such job." } }) });
  await assert.rejects(keyed(gw).delete("gone-1"), (err) => err instanceof KunoError && err.code === "not_found" && err.status === 404);
});

test("the new error codes are documented, and content-policy refusals are recognisable", () => {
  for (const code of ["content_policy", "content_not_reviewable", "key_not_accepted", "gone"]) {
    assert.equal(typeof ERROR_CODES[code], "string", `${code} is documented`);
  }
  const refused = new KunoError(422, "content_policy", "This request breaks the content policy.");
  assert.equal(refused.isContentPolicy, true);
  assert.match(refused.explanation, /NSFW/);
  assert.equal(new KunoError(0, "safety_blocked", "").isContentPolicy, true);
  assert.equal(new KunoError(403, "content_not_reviewable", "").isContentPolicy, false);
  assert.equal(new KunoError(500, "something_new", "").explanation, null);
});

test("a standard job refused by the content policy throws content_policy, and placeholder pricing is flagged", async () => {
  const gw = fakeFetch({
    "GET /v1/route": json(200, { profile_id: PROFILE.id, requested_profile_id: PROFILE.id, fallback_reason: null, enclaves: [] }),
    "GET /v1/models": json(200, { country: null, workers_online: 1, switch: {}, models: [PROFILE], pricing_placeholder: true }),
    "POST /v1/standard/videos": json(422, { detail: { code: "content_policy", message: "This request breaks the content policy." } }),
  });
  const kuno = keyed(gw);
  await assert.rejects(
    kuno.submit({ prompt: "not allowed", model: PROFILE.id, privacy: "standard" }),
    (err) => err instanceof KunoError && err.code === "content_policy" && err.status === 422 && err.isContentPolicy,
  );
  assert.equal((await kuno.models(0)).pricing_placeholder, true);
});
