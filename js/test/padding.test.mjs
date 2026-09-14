// Blob format version 2 (padded) in TypeScript: the shared vectors, PADMÉ buckets, tampering and version 1 compatibility.
// subnet/protocol/tests/test_blob_padding.py runs the same checks in Python.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  BLOB_V1,
  BLOB_V2,
  DEFAULT_BLOB_VERSION,
  DecryptionError,
  b64d,
  blobVersion,
  decryptBlob,
  encryptBlob,
  fromHex,
  paddedStreamLength,
  padme,
  sealedBlobSize,
} from "../dist/index.js";
import { sealStreamWithPrefix } from "../dist/crypto.js";

const VECTORS = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const KEY = Uint8Array.from({ length: 32 }, (_, i) => i);
const LABEL = "job/output/video";
const random = (n) => {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
  return out;
};

/** The version 2 stream: length:u64be | plaintext | zeros up to padme(8 + length). */
function padStream(plaintext) {
  const stream = new Uint8Array(paddedStreamLength(plaintext.length));
  new DataView(stream.buffer).setUint32(4, plaintext.length, false);
  stream.set(plaintext, 8);
  return stream;
}

test("the version 2 vectors decrypt and reproduce byte for byte", () => {
  const { base_key_b64, label, chunk_size, cases } = VECTORS.blob_v2;
  const key = b64d(base_key_b64);
  assert.deepEqual(cases.map((c) => c.padded_stream_length), [8, 10, 1344, 1344]);
  for (const c of cases) {
    const plaintext = b64d(c.plaintext_b64);
    const ciphertext = b64d(c.ciphertext_b64);
    assert.deepEqual(decryptBlob(key, label, ciphertext), plaintext, c.name);
    assert.equal(paddedStreamLength(plaintext.length), c.padded_stream_length);
    assert.equal(sealedBlobSize(plaintext.length, chunk_size), c.sealed_size);
    assert.equal(ciphertext.length, c.sealed_size);
    assert.deepEqual(sealStreamWithPrefix(key, label, padStream(plaintext), chunk_size, BLOB_V2, fromHex(c.nonce_prefix_hex)), ciphertext);
    assert.equal(encryptBlob(key, label, plaintext, chunk_size).length, c.sealed_size);
    assert.throws(() => decryptBlob(key, "other/label", ciphertext), DecryptionError);
  }
});

test("authentic version 2 streams with a bad length or padding are refused", () => {
  const { base_key_b64, label, invalid } = VECTORS.blob_v2;
  const key = b64d(base_key_b64);
  assert.equal(invalid.length, 6);
  for (const c of invalid) {
    assert.throws(() => decryptBlob(key, label, b64d(c.ciphertext_b64)), DecryptionError, c.name);
  }
});

test("PADMÉ buckets and sealed sizes match the Python implementation", () => {
  for (const [length, padded] of VECTORS.blob_v2.padme) assert.equal(padme(length), padded, String(length));
  for (const row of VECTORS.blob_v2.sealed_sizes) {
    assert.equal(sealedBlobSize(row.plaintext_length, row.chunk_size, BLOB_V1), row.v1);
    assert.equal(sealedBlobSize(row.plaintext_length, row.chunk_size, BLOB_V2), row.v2);
    if (row.plaintext_length <= 1_000_000) {
      assert.equal(encryptBlob(KEY, LABEL, random(row.plaintext_length), row.chunk_size).length, row.v2);
    }
  }
  let worst = 0;
  for (let n = 2; n < 200_000; n++) worst = Math.max(worst, (padme(n) - n) / n);
  assert.ok(Math.abs(worst - 15 / 129) < 1e-12, "maximum overhead is +11.63%, at 129 bytes");
  assert.throws(() => padme(-1), RangeError);
});

test("the published version 1 vector still decrypts and reproduces", () => {
  const { base_key_b64, label, plaintext_b64, ciphertext_b64, chunk_size } = VECTORS.blob;
  const key = b64d(base_key_b64);
  const ciphertext = b64d(ciphertext_b64);
  assert.equal(blobVersion(ciphertext), BLOB_V1);
  assert.deepEqual(decryptBlob(key, label, ciphertext), b64d(plaintext_b64));
  assert.deepEqual(sealStreamWithPrefix(key, label, b64d(plaintext_b64), chunk_size, BLOB_V1, ciphertext.subarray(11, 18)), ciphertext);
});

test("new blobs are padded by default; version 1 can still be written and read", () => {
  assert.equal(DEFAULT_BLOB_VERSION, BLOB_V2);
  const data = random(5000);
  assert.equal(blobVersion(encryptBlob(KEY, LABEL, data)), BLOB_V2);
  const old = encryptBlob(KEY, LABEL, data, undefined, BLOB_V1);
  assert.equal(blobVersion(old), BLOB_V1);
  assert.equal(old.length, 18 + data.length + 16);
  assert.deepEqual(decryptBlob(KEY, LABEL, old), data);
  assert.equal(blobVersion(new TextEncoder().encode("plainly not a blob at all")), null);
});

test("padded round trips across chunk boundaries, and one bucket seals to one size", () => {
  for (const chunk of [8, 100, 1024]) {
    for (const n of [0, 1, 7, 8, 9, 255, 256, 1023, 1024, 1025, 3 * 1024 + 17, 70_000]) {
      const data = random(n);
      assert.deepEqual(decryptBlob(KEY, LABEL, encryptBlob(KEY, LABEL, data, chunk)), data, `${n}@${chunk}`);
    }
  }
  const sizes = new Set();
  for (let n = 1273; n <= 1336; n++) sizes.add(encryptBlob(KEY, LABEL, random(n), 100).length);
  assert.deepEqual([...sizes], [sealedBlobSize(1336, 100)]);
  assert.ok(encryptBlob(KEY, LABEL, random(1337), 100).length > sealedBlobSize(1336, 100));
});

test("tampering with the length, padding or version fails", () => {
  const sealed = encryptBlob(KEY, LABEL, random(1280), 100);
  const flip = (index) => {
    const out = sealed.slice();
    out[index] ^= 1;
    return out;
  };
  const downgraded = sealed.slice();
  downgraded[6] = BLOB_V1;
  for (const blob of [flip(18), flip(sealed.length - 17), downgraded, sealed.subarray(0, 18 + 13 * 116), sealed.subarray(0, sealed.length - 1)]) {
    assert.throws(() => decryptBlob(KEY, LABEL, blob), DecryptionError);
  }
  const future = sealed.slice();
  future[6] = 3;
  assert.throws(() => decryptBlob(KEY, LABEL, future), /not a KunoWorld blob/);
});
