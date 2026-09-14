// The GPU mode and counts a golden manifest entry requires, checked against the GPU evidence the worker declares.
// subnet/protocol/tests/test_gpu_cc_modes.py covers the Python verifier, which checks NVIDIA-attested counts.
import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { test } from "node:test";

import { b64e, canonicalJson, reportDataFor, toHex, verifyEvidence } from "../dist/index.js";

const utf8 = (s) => new TextEncoder().encode(s);
const MEASUREMENTS = { mrtd: "aa", rtmr0: "bb", rtmr1: "cc", rtmr2: "dd", rtmr3: "ee" };

function world({ entry = {}, cc = { mode: "spt", devtools: false }, gpus = 1, switches = 0 } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const hpke = new Uint8Array(randomBytes(32));
  const signing = new Uint8Array(randomBytes(32));
  const nonce = new Uint8Array(randomBytes(32));
  const document = { format: "kuno/v1/nvidia-gpu", nonce: toHex(nonce), gpus: Array.from({ length: gpus }, () => ({ arch: "HOPPER" })) };
  if (cc) document.cc = cc;
  if (switches) document.switches = Array.from({ length: switches }, () => ({ arch: "LS10" }));
  const gpu = canonicalJson(document);
  const body = { measurements: MEASUREMENTS, report_data: toHex(reportDataFor(nonce, hpke, signing, gpu)) };
  const message = new Uint8Array([...utf8("kuno/v1/mock-quote\n"), ...canonicalJson(body)]);
  const signature = new Uint8Array(sign(null, message, privateKey));
  const evidence = {
    tee: "mock",
    quote: b64e(utf8(JSON.stringify({ body, signature: b64e(signature) }))),
    gpu_evidence: b64e(gpu),
    nonce: toHex(nonce),
    hpke_public_key: b64e(hpke),
    signing_public_key: b64e(signing),
    image_digest: "sha256:img",
    profiles: ["h3"],
    hardware: {},
    created_at: Date.now() / 1000,
  };
  const manifest = {
    version: 1,
    issued_at: 0,
    allowed: [{ platform: "mock", image_digest: "sha256:img", profiles: ["h3"], ...MEASUREMENTS, ...entry }],
    mock_quote_keys: [publicKey.export({ format: "jwk" }).x],
    max_evidence_age_s: 600,
  };
  return { evidence, manifest };
}

test("an entry signed before GPU modes accepts any mode and count", () => {
  const { evidence, manifest } = world({ cc: { mode: "ppcie", devtools: false }, gpus: 4, switches: 4 });
  const verdict = verifyEvidence(evidence, manifest);
  assert.deepEqual(verdict.reasons, []);
  assert.equal(verdict.ok, true);
});

test("the declared mode and counts must match the entry", () => {
  const entry = { gpu_mode: "ppcie", gpus_per_enclave: 4, nvswitches_per_enclave: 4 };
  assert.equal(verifyEvidence(...Object.values(world({ entry, cc: { mode: "ppcie", devtools: false }, gpus: 4, switches: 4 }))).ok, true);

  const wrongMode = verifyEvidence(...Object.values(world({ entry, cc: { mode: "spt", devtools: false }, gpus: 4, switches: 4 })));
  assert.match(wrongMode.reasons.join("; "), /declares spt, but the manifest entry requires ppcie/);

  const noMode = verifyEvidence(...Object.values(world({ entry, cc: null, gpus: 4, switches: 4 })));
  assert.match(noMode.reasons.join("; "), /declares no GPU mode/);

  const counts = verifyEvidence(...Object.values(world({ entry, cc: { mode: "ppcie", devtools: false }, gpus: 8, switches: 0 })));
  assert.match(counts.reasons.join("; "), /carries 8 GPU\(s\), but the manifest entry requires 4/);
  assert.match(counts.reasons.join("; "), /carries 0 NVSwitch\(es\), but the manifest entry requires 4/);
});

test("devtools mode is refused wherever the entry names a mode", () => {
  const { evidence, manifest } = world({ entry: { gpu_mode: "spt" }, cc: { mode: "spt", devtools: true } });
  assert.match(verifyEvidence(evidence, manifest).reasons.join("; "), /devtools/);
});
