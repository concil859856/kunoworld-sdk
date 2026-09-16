// The TypeScript implementation must reproduce the shared protocol vectors exactly.
// subnet/protocol/tests/test_vectors.py runs the same checks in Python.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  b64d,
  canonicalJson,
  decryptBlob,
  DecryptionError,
  enclaveIdFor,
  encryptBlob,
  gpuNonceFor,
  jobAad,
  reportDataFor,
  storyboardDurationS,
  storyboardFrames,
  toHex,
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
