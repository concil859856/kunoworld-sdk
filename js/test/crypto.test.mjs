import assert from "node:assert/strict";
import { test } from "node:test";

import { canonicalJson, decryptBlob, DecryptionError, encryptBlob, inferMode } from "../dist/index.js";

const text = (bytes) => new TextDecoder().decode(bytes);

test("canonical JSON matches Python's encoding", () => {
  assert.equal(text(canonicalJson({ b: 5.0, a: [1.5, "é", null, true], c: { z: 1, y: 2 } })), '{"a":[1.5,"é",null,true],"b":5,"c":{"y":2,"z":1}}');
});

test("blob round trip across chunk boundaries, with tamper and relabel detection", () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const data = crypto.getRandomValues(new Uint8Array(3 * 1024 + 17));
  const sealed = encryptBlob(key, "job/input/0", data, 1024);
  assert.deepEqual(decryptBlob(key, "job/input/0", sealed), data);
  assert.throws(() => decryptBlob(key, "job/input/1", sealed), DecryptionError);
  assert.throws(() => decryptBlob(key, "job/input/0", sealed.subarray(0, 18 + 2 * (1024 + 16))), DecryptionError);
  const flipped = sealed.slice();
  flipped[40] ^= 1;
  assert.throws(() => decryptBlob(key, "job/input/0", flipped), DecryptionError);
});

test("mode inference", () => {
  assert.equal(inferMode([]), "text_to_video");
  assert.equal(inferMode(["first_frame", "last_frame"]), "first_last_frame");
  assert.equal(inferMode(["reference_image", "reference_audio"]), "reference_to_video");
});
