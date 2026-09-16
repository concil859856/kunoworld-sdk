// TDX workers checked in full in the SDK, with what Intel and NVIDIA signed, relayed by a gateway it doesn't trust.
// endorsement_vectors.json comes from subnet/protocol/tests/make_endorsement_vectors.py: the JS verdicts must match
// Python's. The dcap fixtures are Phala's real TDX quote and Intel collateral; the NRAS entry is NVIDIA's live JWKS.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  NRAS_INTERMEDIATE_SPKI_SHA256,
  b64d,
  pinnedNrasKey,
  verifyEndorsedToken,
  verifyEvidence,
  verifySignedManifest,
  verifyTdxQuoteSignature,
} from "../dist/index.js";

const read = (path) => readFileSync(new URL(path, import.meta.url));
const VECTORS = JSON.parse(read("./endorsement_vectors.json"));
const QUOTE = new Uint8Array(read("./data/dcap/tdx_quote"));
const COLLATERAL = JSON.parse(read("./data/dcap/tdx_quote_collateral.json"));
const VALID_AT = 1751000000; // inside the sample collateral's validity window

// The vectors' quote is synthetic (no Intel signature), so, as in Python, a verifier accepts exactly their collateral.
const vectorQuoteVerifier = (_quote, collateral) =>
  JSON.stringify(collateral) === JSON.stringify(VECTORS.collateral)
    ? { ok: true, detail: "TCB status UpToDate", status: "UpToDate" }
    : { ok: false, detail: collateral === null ? "no Intel collateral was relayed for this quote" : "collateral does not verify" };

// Python prints strings with repr quotes where JS uses JSON's.
const normal = (reason) => reason.replaceAll("'", '"');

for (const vector of VECTORS.cases) {
  test(`vector ${vector.name}: the JS verdict matches Python's`, () => {
    const verdict = verifyEvidence(VECTORS.evidence, VECTORS.manifest, {
      endorsements: vector.endorsements,
      expectedNonce: b64d(Buffer.from(VECTORS.expected_nonce, "hex").toString("base64")),
      now: vector.now ?? VECTORS.now,
      nvidiaTrustedSpki: VECTORS.trusted_spki,
      tdxQuoteVerifier: vectorQuoteVerifier,
    });
    assert.equal(verdict.ok, vector.ok, JSON.stringify(verdict.reasons));
    assert.deepEqual(verdict.reasons.map(normal), vector.reasons.map(normal));
    if (vector.ok) {
      assert.equal(verdict.gpuCount, vector.gpu_count);
      assert.equal(verdict.signatureVerified, true);
    }
  });
}

test("the production NVIDIA pin refuses the vectors' local intermediate", () => {
  const good = VECTORS.cases.find((c) => c.name === "good");
  const verdict = verifyEvidence(VECTORS.evidence, VECTORS.manifest, {
    endorsements: good.endorsements, now: VECTORS.now, tdxQuoteVerifier: vectorQuoteVerifier,
  });
  assert.equal(verdict.ok, false);
  assert.ok(verdict.reasons.some((r) => r.includes("pinned attestation intermediate")), verdict.reasons.join("; "));
});

test("Intel DCAP: a real quote verifies against relayed collateral, and forgeries don't", () => {
  const good = verifyTdxQuoteSignature(QUOTE, COLLATERAL, { now: VALID_AT });
  assert.deepEqual([good.ok, good.status], [true, "UpToDate"], good.detail);
  const forged = QUOTE.slice();
  forged[48 + 520 + 1] ^= 1; // REPORTDATA: a relay can't retarget a real quote at other keys
  assert.equal(verifyTdxQuoteSignature(forged, COLLATERAL, { now: VALID_AT }).ok, false);
  const other = JSON.parse(read("./data/dcap/tdx_quote_outdated_collateral.json"));
  assert.equal(verifyTdxQuoteSignature(QUOTE, other, { now: VALID_AT }).ok, false);
  const tampered = { ...COLLATERAL, tcb_info: COLLATERAL.tcb_info.replace("UpToDate", "UpToDate ") };
  assert.equal(verifyTdxQuoteSignature(QUOTE, tampered, { now: VALID_AT }).ok, false);
  assert.equal(verifyTdxQuoteSignature(QUOTE, null, { now: VALID_AT }).detail, "no Intel collateral was relayed for this quote");
  const strict = verifyTdxQuoteSignature(QUOTE, COLLATERAL, { now: VALID_AT, tdxAllowedTcbStatuses: ["SWHardeningNeeded"] });
  assert.equal(strict.ok, false);
  assert.match(strict.detail, /TCB status UpToDate is not accepted/);
});

test("NVIDIA's real signing certificate chains to the production pin, only while it is valid", () => {
  const jwk = JSON.parse(read("./data/nras/jwks_entry_2026-09-16.json")).key;
  const issued = Date.parse("2026-09-16T12:00:00Z") / 1000;
  const point = pinnedNrasKey(jwk, issued);
  assert.equal(point.length, 97);
  assert.equal(NRAS_INTERMEDIATE_SPKI_SHA256[0], "fd32837f954e2c45db073105166dfe6985ae0480bb113fba63b091a75affe896");
  assert.throws(() => pinnedNrasKey(jwk, Date.parse("2026-09-20T00:00:00Z") / 1000), /not valid when the token was issued/);
  const leaf = Buffer.from(jwk.x5c[0], "base64");
  leaf[leaf.length - 10] ^= 1;
  assert.throws(() => pinnedNrasKey({ ...jwk, x5c: [leaf.toString("base64"), jwk.x5c[1]] }, issued), /not signed by the pinned intermediate/);
  assert.throws(() => pinnedNrasKey({ ...jwk, x5c: [jwk.x5c[0]] }, issued), /x5c of two/);
  assert.throws(() => pinnedNrasKey({ ...jwk, x: jwk.y }, issued), /not the key its certificate holds/);
  assert.throws(() => pinnedNrasKey(jwk, issued, ["00".repeat(32)]), /pinned attestation intermediate/);
});

test("an owner-signed manifest is accepted as signed, and a widened or re-signed one is refused", () => {
  const owner = b64d(VECTORS.signed_manifests.owner_public_key);
  for (const document of VECTORS.signed_manifests.valid) {
    assert.deepEqual(verifySignedManifest(document, owner), document.manifest);
  }
  for (const document of VECTORS.signed_manifests.invalid) {
    assert.throws(() => verifySignedManifest(document, owner), /not signed by the subnet owner/);
  }
  assert.throws(() => verifySignedManifest({ manifest: VECTORS.manifest }, owner), /not an owner-signed manifest/);
});

test("an NRAS token older than a client accepts is refused even with fresh evidence", () => {
  const good = VECTORS.cases.find((c) => c.name === "good").endorsements.nvidia[0];
  const token = good.answer[0][1];
  const opts = { nvidiaTrustedSpki: VECTORS.trusted_spki, maxTokenAgeS: 3600 };
  assert.equal(verifyEndorsedToken(token, good.keys, { ...opts, now: VECTORS.now }).eat_nonce.length, 64);
  assert.throws(() => verifyEndorsedToken(token, good.keys, { ...opts, now: VECTORS.now + 7200 }), /older than a client accepts/);
  assert.throws(() => verifyEndorsedToken(token, good.keys, { ...opts, now: VECTORS.now - 3600 }), /issued in the future/);
});
