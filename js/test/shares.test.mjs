// Share links, against a fake gateway: owner calls carry the API key, public calls never do, and
// open() checks and decrypts a really sealed video with the key from the link's fragment.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { ed25519 } from "@noble/curves/ed25519.js";

import { b64e, canonicalJson, encryptBlob, ERROR_CODES, KunoClient, KunoError, parseShareLink, shareUrlWithKey } from "../dist/index.js";

const SITE = "https://kunoworld.test";
const VIDEO = new TextEncoder().encode("\0\0\0\x18ftypisom a film worth sharing");
const TOKEN = b64e(new Uint8Array(32).fill(7));
const OTHER_TOKEN = b64e(new Uint8Array(32).fill(9));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** A gateway that answers from `routes` ("METHOD /path" → handler) and records every call. */
function fakeGateway(routes) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    const u = new URL(url, "https://proxy.test");
    const key = `${init.method ?? "GET"} ${u.pathname}`;
    const call = { key, url: String(url), query: u.searchParams, headers: init.headers ?? {}, body: init.body };
    calls.push(call);
    const handler = routes[key];
    if (!handler) return new Response(JSON.stringify({ detail: { code: "not_found", message: key } }), { status: 404 });
    const out = await handler(call);
    if (out instanceof Response) return out;
    if (out instanceof Uint8Array) return new Response(out, { status: 200, headers: { "content-type": "application/octet-stream" } });
    // { status: <number>, body } sets the HTTP status; anything else is a 200 body.
    const wrapped = out && typeof out.status === "number" && "body" in out;
    return new Response(JSON.stringify(wrapped ? out.body : out), {
      status: wrapped ? out.status : 200,
      headers: { "content-type": "application/json" },
    });
  };
  return { calls, fetch };
}

const error = (status, detail) => () => new Response(JSON.stringify({ detail }), { status });
const keyed = (gw) => new KunoClient({ apiKey: "kw_live_test", baseUrl: "https://gw.test", fetch: gw.fetch });
const keyless = (gw) => new KunoClient({ baseUrl: "https://gw.test", fetch: gw.fetch });
const integrity = (err) => err instanceof KunoError && err.code === "integrity";

function row(jobId, privacy, extra = {}) {
  return {
    share_id: "sh-1",
    job_id: jobId,
    privacy,
    profile_id: "ltx-2.5-fast",
    created_at: 1_800_000_000,
    expires_at: null,
    revoked_at: null,
    status: "active",
    view_count: 0,
    ...extra,
  };
}

const made = (jobId, privacy) => ({ ...row(jobId, privacy), token: TOKEN, url_path: `/s/${TOKEN}`, url: `${SITE}/s/${TOKEN}` });

function privateHandle(jobId, outputKey) {
  return { jobId, outputKey, signingPublicKey: "", enclaveId: "enc-1", profileId: "ltx-2.5-fast", fallbackReason: null, createdAt: 1 };
}

/**
 * A private video as the gateway shares it: the sealed output blob, and details whose receipt a real
 * Ed25519 key signed. `sealedFor` seals the blob under another job's label.
 */
function privateVideo({ jobId = "job-priv", sealedFor = jobId } = {}) {
  const outputKey = crypto.getRandomValues(new Uint8Array(32));
  const sealed = encryptBlob(outputKey, `${sealedFor}/output/video`, VIDEO);
  const secretKey = ed25519.utils.randomSecretKey();
  const body = {
    v: 1,
    job_id: jobId,
    enclave_id: "enc-1",
    profile_id: "ltx-2.5-fast",
    image_digest: "a".repeat(64),
    params_digest: "b".repeat(64),
    input_digest: "c".repeat(64),
    output_digest: sha256(sealed),
    output_bytes: sealed.length,
    content_digest: sha256(VIDEO),
    attestation_digest: "d".repeat(64),
    started_at: 1_800_000_000,
    finished_at: 1_800_000_042.5,
    gpu_seconds: 40.25,
    video: { duration_s: 5, width: 1920, height: 1080, fps: 24, frames: 120, audio: true },
    miner_hotkey: null,
  };
  const message = new Uint8Array([...new TextEncoder().encode("kuno/v1/receipt\n"), ...canonicalJson(body)]);
  const receipt = { body, signature: b64e(ed25519.sign(message, secretKey)) };
  const details = {
    privacy: "private",
    profile_id: "ltx-2.5-fast",
    created_at: 1_800_000_000,
    shared_at: 1_800_000_100,
    expires_at: null,
    content_digest: sha256(VIDEO),
    receipt,
    signing_public_key: b64e(ed25519.getPublicKey(secretKey)),
  };
  return { key: b64e(outputKey), sealed, details };
}

const publicRoutes = (details, video) => ({
  [`GET /v1/shares/${TOKEN}`]: () => details,
  [`GET /v1/shares/${TOKEN}/video`]: () => video,
});

test("create adds the key to a private handle's link, and never to a job id or a standard link", async () => {
  const bodies = [];
  const gw = fakeGateway({
    "POST /v1/videos/job-priv/shares": (call) => {
      bodies.push(JSON.parse(call.body));
      return { status: 201, body: made("job-priv", "private") };
    },
    "POST /v1/videos/job-std/shares": (call) => {
      bodies.push(JSON.parse(call.body));
      return { status: 201, body: made("job-std", "standard") };
    },
  });
  const kuno = keyed(gw);
  const { key } = privateVideo();

  const link = await kuno.shares.create(privateHandle("job-priv", key), { expiresAt: new Date(1_900_000_000_000) });
  assert.equal(link.url, `${SITE}/s/${TOKEN}#k=${key}`);
  assert.equal(link.keyIncluded, true);
  assert.equal(link.urlPath, `/s/${TOKEN}`, "the path never carries the key");
  assert.deepEqual(
    [link.shareId, link.jobId, link.privacy, link.profileId, link.status, link.viewCount, link.revokedAt, link.token],
    ["sh-1", "job-priv", "private", "ltx-2.5-fast", "active", 0, null, TOKEN],
  );
  assert.deepEqual(bodies.shift(), { expires_at: 1_900_000_000 }, "a Date goes up as Unix seconds");

  const byId = await kuno.shares.create("job-priv", { expiresAt: 1_900_000_000 });
  assert.equal(byId.url, `${SITE}/s/${TOKEN}`, "a job id alone has no key to add");
  assert.equal(byId.keyIncluded, false);
  assert.equal(shareUrlWithKey(byId.url, key), link.url);
  assert.deepEqual(bodies.shift(), { expires_at: 1_900_000_000 });

  const standard = await kuno.shares.create({ privacy: "standard", jobId: "job-std", enclaveId: "", profileId: "ltx-2.5-fast", fallbackReason: null, createdAt: 1 });
  assert.equal(standard.url, `${SITE}/s/${TOKEN}`);
  assert.equal(standard.keyIncluded, false);
  assert.deepEqual(bodies.shift(), { expires_at: null });

  // A handle that holds a key still gets no fragment when the gateway says the video is Standard.
  const mismatched = await kuno.shares.create(privateHandle("job-std", key));
  assert.equal(mismatched.url.includes("#"), false);
  assert.equal(mismatched.keyIncluded, false);

  for (const call of gw.calls) {
    assert.equal(call.headers.authorization, "Bearer kw_live_test", `${call.key} carries the API key`);
    assert.equal(call.url.includes(key) || String(call.body).includes(key), false, "the key never leaves this process");
  }
});

test("a bad expiry or a malformed output key is refused before a link is made", async () => {
  const gw = fakeGateway({});
  const kuno = keyed(gw);
  await assert.rejects(kuno.shares.create("job-priv", { expiresAt: Number.NaN }), (err) => err instanceof KunoError && err.code === "invalid_expiry");
  await assert.rejects(kuno.shares.create("job-priv", { expiresAt: new Date("not a date") }), (err) => err.code === "invalid_expiry");
  await assert.rejects(kuno.shares.create(privateHandle("job-priv", "short")), (err) => err.code === "invalid_key");
  assert.equal(gw.calls.length, 0);

  assert.throws(() => shareUrlWithKey(`${SITE}/s/${TOKEN}`, new Uint8Array(16)), (err) => err.code === "invalid_key");
  assert.equal(shareUrlWithKey(`${SITE}/s/${TOKEN}#k=old`, new Uint8Array(32)), `${SITE}/s/${TOKEN}#k=${"A".repeat(43)}`, "raw bytes work, and an old fragment is replaced");
});

test("list and revoke use the account routes with the API key; a proxy client sends none", async () => {
  const gw = fakeGateway({
    "GET /v1/account/shares": () => [
      row("job-priv", "private", { view_count: 3 }),
      row("job-std", "standard", { share_id: "sh-0", status: "expired", expires_at: 1_800_000_060 }),
    ],
    "DELETE /v1/account/shares/sh-1": () => row("job-priv", "private", { status: "revoked", revoked_at: 1_800_000_500 }),
    "POST /api/kuno/v1/videos/job-std/shares": () => ({ status: 201, body: made("job-std", "standard") }),
    "GET /api/kuno/v1/account/shares": () => [],
    "DELETE /api/kuno/v1/account/shares/sh-1": () => row("job-std", "standard", { status: "revoked", revoked_at: 1 }),
  });
  const kuno = keyed(gw);

  const rows = await kuno.shares.list({ jobId: "job-priv", limit: 10 });
  assert.deepEqual(rows[0], {
    shareId: "sh-1",
    jobId: "job-priv",
    privacy: "private",
    profileId: "ltx-2.5-fast",
    createdAt: 1_800_000_000,
    expiresAt: null,
    revokedAt: null,
    status: "active",
    viewCount: 3,
  });
  assert.equal("token" in rows[0] || "url" in rows[0], false, "a listed link never has its token");
  assert.deepEqual([rows[1].shareId, rows[1].status, rows[1].expiresAt], ["sh-0", "expired", 1_800_000_060]);
  assert.equal(gw.calls[0].query.get("job_id"), "job-priv");
  assert.equal(gw.calls[0].query.get("limit"), "10");

  await kuno.shares.list();
  assert.equal(gw.calls[1].query.get("limit"), "100");
  assert.equal(gw.calls[1].query.has("job_id"), false);

  const revoked = await kuno.shares.revoke("sh-1");
  assert.deepEqual([revoked.shareId, revoked.status, revoked.revokedAt], ["sh-1", "revoked", 1_800_000_500]);
  for (const call of gw.calls) assert.equal(call.headers.authorization, "Bearer kw_live_test");

  const proxy = KunoClient.forProxy("/api/kuno", { fetch: gw.fetch });
  await proxy.shares.create("job-std");
  await proxy.shares.list();
  await proxy.shares.revoke("sh-1");
  const proxied = gw.calls.slice(3);
  assert.deepEqual(proxied.map((c) => c.url), ["/api/kuno/v1/videos/job-std/shares", "/api/kuno/v1/account/shares?limit=100", "/api/kuno/v1/account/shares/sh-1"]);
  for (const call of proxied) assert.equal("authorization" in call.headers, false, "the proxy adds the session");
});

test("public calls send no API key, and get() reads the key from the fragment without sending it", async () => {
  const { key, sealed, details } = privateVideo();
  const gw = fakeGateway(publicRoutes(details, sealed));
  const kuno = keyed(gw);

  const got = await kuno.shares.get(`${SITE}/s/${TOKEN}#k=${key}`);
  assert.deepEqual(
    [got.token, got.key, got.privacy, got.profileId, got.createdAt, got.sharedAt, got.expiresAt, got.contentDigest, got.signingPublicKey],
    [TOKEN, key, "private", "ltx-2.5-fast", 1_800_000_000, 1_800_000_100, null, sha256(VIDEO), details.signing_public_key],
  );
  assert.equal(got.receipt.body.job_id, "job-priv");
  assert.equal((await kuno.shares.get(TOKEN)).key, null, "a bare token has no key");
  assert.equal((await kuno.shares.get(`/s/${TOKEN}`)).token, TOKEN);
  for (const call of gw.calls) {
    assert.equal(call.headers.authorization, undefined, "public routes never get the API key");
    assert.equal(call.url, `https://gw.test/v1/shares/${TOKEN}`, "only the token is sent");
  }

  assert.deepEqual(parseShareLink(`${SITE}/s/${TOKEN}/?utm_source=x#k=${key}`), { token: TOKEN, key });
  assert.deepEqual(parseShareLink(`${TOKEN}#k=${key}`), { token: TOKEN, key });
  await assert.rejects(kuno.shares.get(`${SITE}/s/not-a-token`), (err) => err instanceof KunoError && err.code === "not_found" && err.status === 0);
  await assert.rejects(kuno.shares.get(`${SITE}/s/${TOKEN}/../../v1/account/shares`), (err) => err.code === "not_found");
  assert.equal(gw.calls.length, 3, "a malformed link is refused before anything is sent");
});

test("open() checks the receipt and decrypts a private video with the key from the link", async () => {
  const { key, sealed, details } = privateVideo();
  const gw = fakeGateway(publicRoutes(details, sealed));
  const kuno = keyed(gw);

  const opened = await kuno.shares.open(`${SITE}/s/${TOKEN}#k=${key}`);
  assert.deepEqual(opened.video, VIDEO);
  assert.deepEqual([opened.privacy, opened.contentDigest, opened.profileId, opened.receipt.body.job_id], ["private", sha256(VIDEO), "ltx-2.5-fast", "job-priv"]);

  const passed = await kuno.shares.open(`${SITE}/s/${TOKEN}`, key);
  assert.deepEqual(passed.video, VIDEO, "the key can be passed separately");

  assert.deepEqual(gw.calls.map((c) => c.key), [`GET /v1/shares/${TOKEN}`, `GET /v1/shares/${TOKEN}/video`, `GET /v1/shares/${TOKEN}`, `GET /v1/shares/${TOKEN}/video`]);
  for (const call of gw.calls) {
    assert.equal(call.headers.authorization, undefined);
    assert.equal(call.url.includes(key), false, "the key is never sent");
  }
});

test("a private link without its key, or with the wrong one, doesn't open", async () => {
  const { sealed, details } = privateVideo();
  const gw = fakeGateway(publicRoutes(details, sealed));
  const kuno = keyless(gw);

  const missing = await kuno.shares.open(`${SITE}/s/${TOKEN}`).catch((e) => e);
  assert.ok(missing instanceof KunoError);
  assert.equal(missing.code, "missing_key");
  assert.equal(missing.explanation, ERROR_CODES.missing_key);
  assert.equal(gw.calls.some((c) => c.key.endsWith("/video")), false, "nothing is downloaded without a key");

  const wrong = b64e(crypto.getRandomValues(new Uint8Array(32)));
  await assert.rejects(kuno.shares.open(`${SITE}/s/${TOKEN}#k=${wrong}`), (err) => err instanceof KunoError && err.code === "decrypt_failed");
  await assert.rejects(kuno.shares.open(`${SITE}/s/${TOKEN}`, "not-a-key"), (err) => err.code === "decrypt_failed");
});

test("a tampered video, a receipt from another key, or a mismatched digest is refused", async () => {
  const { key, sealed, details } = privateVideo();
  const link = `${SITE}/s/${TOKEN}#k=${key}`;

  const tampered = sealed.slice();
  tampered[tampered.length - 5] ^= 1;
  await assert.rejects(keyless(fakeGateway(publicRoutes(details, tampered))).shares.open(link), integrity);

  const otherSigner = { ...details, signing_public_key: b64e(ed25519.getPublicKey(ed25519.utils.randomSecretKey())) };
  await assert.rejects(keyless(fakeGateway(publicRoutes(otherSigner, sealed))).shares.open(link), integrity);

  const relabelled = { ...details, content_digest: "0".repeat(64) };
  await assert.rejects(keyless(fakeGateway(publicRoutes(relabelled, sealed))).shares.open(link), integrity);

  const forgedBody = { ...details, receipt: { ...details.receipt, body: { ...details.receipt.body, profile_id: "h3-turbo" } } };
  await assert.rejects(keyless(fakeGateway(publicRoutes(forgedBody, sealed))).shares.open(link), integrity);

  // A blob sealed for another job doesn't open under this receipt's job id, even with the right key.
  const swapped = privateVideo({ sealedFor: "job-other" });
  await assert.rejects(
    keyless(fakeGateway(publicRoutes(swapped.details, swapped.sealed))).shares.open(`${SITE}/s/${TOKEN}#k=${swapped.key}`),
    (err) => err.code === "decrypt_failed",
  );
});

test("a standard link plays as it is, checked against its digest", async () => {
  const { details } = privateVideo();
  const standard = { ...details, privacy: "standard" };
  const opened = await keyless(fakeGateway(publicRoutes(standard, VIDEO))).shares.open(`${SITE}/s/${TOKEN}`);
  assert.deepEqual(opened.video, VIDEO);
  assert.equal(opened.privacy, "standard");

  const other = new TextEncoder().encode("\0\0\0\x18ftypisom another film");
  await assert.rejects(keyless(fakeGateway(publicRoutes(standard, other))).shares.open(TOKEN), integrity);
});

test("a link that stopped working, and refused links, surface the gateway's codes", async () => {
  const gw = fakeGateway({
    [`GET /v1/shares/${TOKEN}`]: error(410, { code: "share_unavailable", message: "This link no longer works." }),
    [`GET /v1/shares/${OTHER_TOKEN}`]: error(429, { code: "rate_limited", message: "Too many requests from this network." }),
    "POST /v1/videos/full/shares": error(409, { code: "too_many_shares", message: "A video can have 20 working links. Revoke one first." }),
    "POST /v1/videos/soon/shares": error(422, { code: "invalid_expiry", message: "expires_at must be between a minute and ten years from now." }),
    "POST /v1/videos/held/shares": error(403, { code: "account_restricted", message: "This account can't share videos right now.", restricted_until: 1_900_000_000 }),
    "DELETE /v1/account/shares/nope": error(404, { code: "not_found", message: "No such share link." }),
  });
  const kuno = keyed(gw);

  const gone = await kuno.shares.open(`${SITE}/s/${TOKEN}#k=${"A".repeat(43)}`).catch((e) => e);
  assert.ok(gone instanceof KunoError);
  assert.deepEqual([gone.status, gone.code, gone.message], [410, "share_unavailable", "This link no longer works."]);
  assert.match(gone.explanation, /revoked/);
  assert.equal(gw.calls.length, 1, "no video is fetched for a dead link");

  await assert.rejects(kuno.shares.get(OTHER_TOKEN), (err) => err.status === 429 && err.code === "rate_limited");
  await assert.rejects(kuno.shares.create("full"), (err) => err.status === 409 && err.code === "too_many_shares");
  await assert.rejects(kuno.shares.create("soon", { expiresAt: 1 }), (err) => err.status === 422 && err.code === "invalid_expiry");
  const restricted = await kuno.shares.create("held").catch((e) => e);
  assert.deepEqual([restricted.code, restricted.restrictedUntil], ["account_restricted", 1_900_000_000]);
  await assert.rejects(kuno.shares.revoke("nope"), (err) => err.status === 404 && err.code === "not_found");

  for (const code of ["share_unavailable", "missing_key", "too_many_shares", "invalid_expiry"]) {
    assert.equal(typeof ERROR_CODES[code], "string", `${code} is documented`);
  }
});
