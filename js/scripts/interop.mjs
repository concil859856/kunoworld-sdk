// Cross-language check used by tests/test_js_interop.py: the JS SDK encrypts inputs and
// seals the job, a Python enclave decrypts and generates, and the JS SDK verifies the
// receipt and decrypts the output.
import { readFileSync } from "node:fs";

import { KunoClient, sha256Hex } from "../dist/index.js";

const [baseUrl, apiKey, manifestPath, imagePath] = process.argv.slice(2);
const client = new KunoClient({ apiKey, baseUrl, manifest: JSON.parse(readFileSync(manifestPath, "utf8")), country: "JP" });

const handle = await client.submit({
  prompt: "Interop: fishing boats at dawn, gulls overhead — ünïcødé ✓",
  model: "h3-turbo",
  durationS: 5,
  aspectRatio: "9:16",
  inputs: [{ role: "first_frame", file: new Uint8Array(readFileSync(imagePath)) }],
});
const result = await client.wait(handle, { pollMs: 250, timeoutMs: 60000 });
const proof = await client.provenance(result.video);
console.log(
  JSON.stringify({
    profile: result.profileId,
    mp4: new TextDecoder().decode(result.video.subarray(4, 8)) === "ftyp",
    width: result.receipt.body.video.width,
    digestMatches: (await sha256Hex(result.video)) === result.receipt.body.content_digest,
    provenanceValid: proof.signature_valid,
  }),
);
