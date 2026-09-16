// Price estimates mirror kuno_protocol's ModelProfile.price_usd: rate per privacy mode, multipliers, minimum charge.
import assert from "node:assert/strict";
import { test } from "node:test";

import { fitParams, priceQuote, priceUsd, privacyModes } from "../dist/index.js";

const FAST = {
  id: "ltx-2.5-fast",
  modes: ["text_to_video"],
  limits: {
    sizes: { "720p": { "16:9": [1280, 704] }, "1080p": { "16:9": [1920, 1088] } },
    fps: [24, 25, 48, 50],
    default_fps: 24,
    min_duration_s: 2,
    max_duration_s: 20,
    max_duration_s_by_fps: { 48: 10, 50: 10 },
    audio: true,
  },
  pricing: {
    usd_per_second: { "720p": 0.05, "1080p": 0.08 },
    standard_usd_per_second: { "720p": 0.04, "1080p": 0.06 },
    min_job_usd: 0.1,
    long_clip: null,
    fps_multipliers: { 48: 1.5, 50: 1.5 },
  },
};

const H3 = {
  id: "h3",
  modes: ["text_to_video"],
  limits: { sizes: { "768p": { "16:9": [1344, 768] } }, fps: [24], default_fps: 24, min_duration_s: 5, max_duration_s: 14, audio: true },
  pricing: { usd_per_second: { "768p": 0.2 }, standard_usd_per_second: null, min_job_usd: 0.1, long_clip: { over_s: 10, multiplier: 1.2 } },
};

const job = (resolution, duration_s, fps = 24) => ({ resolution, duration_s, fps });

test("Private is the default price and Standard has its own table", () => {
  assert.equal(priceUsd(FAST, job("1080p", 5)), 0.4);
  assert.equal(priceUsd(FAST, job("1080p", 5), "private"), 0.4);
  assert.equal(priceUsd(FAST, job("1080p", 5), "standard"), 0.3);
  assert.equal(priceUsd(FAST, job("4K", 5)), null);
});

test("48 and 50 fps multiply the whole job, and long H3 clips cost more", () => {
  assert.deepEqual(priceQuote(FAST, job("720p", 5, 48)), { usd: 0.375, usdPerSecond: 0.05, multiplier: 1.5, minimumApplied: false });
  assert.equal(priceUsd(FAST, job("720p", 5, 25)), 0.25);
  assert.equal(priceUsd(H3, job("768p", 10)), 2);
  assert.equal(priceUsd(H3, job("768p", 12)), 2.88);
});

test("the long-clip multiplier is Private-only: Standard stays flat per second, like the market's list prices", () => {
  const turbo = { ...H3, id: "h3-turbo", pricing: { ...H3.pricing, standard_usd_per_second: { "768p": 0.04 } } };
  assert.equal(priceUsd(turbo, job("768p", 12)), 2.88);
  assert.deepEqual(priceQuote(turbo, job("768p", 12), "standard"), { usd: 0.48, usdPerSecond: 0.04, multiplier: 1, minimumApplied: false });
});

test("the minimum charge sets the price of a very short job, and says so", () => {
  assert.deepEqual(priceQuote(FAST, job("720p", 2), "standard"), { usd: 0.1, usdPerSecond: 0.04, multiplier: 1, minimumApplied: true });
  assert.equal(priceQuote(FAST, job("720p", 2)).minimumApplied, false); // 0.05 x 2 is exactly the minimum
});

test("a Private-only profile has no Standard price", () => {
  assert.deepEqual(privacyModes(H3), ["private"]);
  assert.deepEqual(privacyModes(FAST), ["private", "standard"]);
  assert.equal(priceQuote(H3, job("768p", 5), "standard"), null);
  // /v1/models lists the modes; that list wins over reading the pricing.
  assert.deepEqual(privacyModes({ ...FAST, privacy_modes: ["private"] }), ["private"]);
  assert.equal(priceUsd({ ...FAST, privacy_modes: ["private"] }, job("720p", 5), "standard"), null);
});

test("a profile without the newer pricing fields is priced at its list rate", () => {
  const old = { ...FAST, pricing: { usd_per_second: { "720p": 0.024 } } };
  assert.deepEqual(privacyModes(old), ["private"]);
  assert.equal(priceUsd(old, job("720p", 2, 48)), 0.048);
});

test("after a fallback, the duration is fitted to the frame rate's cap", () => {
  assert.equal(fitParams(FAST, "text_to_video", [], { durationS: 14, fps: 48 }, "region").duration_s, 10);
  assert.equal(fitParams(FAST, "text_to_video", [], { durationS: 14, fps: 24 }, "region").duration_s, 14);
});
