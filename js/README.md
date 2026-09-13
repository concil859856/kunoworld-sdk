# @kunoworld/sdk

The JavaScript client for KunoWorld. It encrypts prompts and reference media in the browser or
in Node.js, to a GPU enclave whose attestation evidence it checks first; verifies the
enclave-signed receipt; and decrypts the finished video locally. Cryptography uses WebCrypto,
so it runs in modern browsers and Node.js 20+. The package is ES modules only.

> **Development preview.** Workers on development gateways use simulated attestation and may
> return placeholder video. Real TDX and NVIDIA evidence verification is not built yet.

## Install

The package is not on npm yet. Build it from this repository and install the folder:

```bash
cd js
npm install
npm run build
npm install /path/to/kunoworld-sdk/js     # from your own project
```

## Generate a video

```js
import { KunoClient } from "@kunoworld/sdk";
import { readFile, writeFile } from "node:fs/promises";

// The golden manifest lists the enclave measurements you trust. Get it from your operator
// through a trusted channel and pin it, rather than trusting whatever the gateway serves.
const manifest = JSON.parse(await readFile("./trusted-manifest.json", "utf8"));

const kuno = new KunoClient({
  baseUrl: process.env.KUNO_GATEWAY_URL,
  apiKey: process.env.KUNO_API_KEY,
  manifest,
});

const job = await kuno.submit({
  prompt: "Paper lanterns drift inside a vast spiral library. A slow camera push.",
  model: "ltx-2.5-fast",
  durationS: 5,
  resolution: "1080p",
  aspectRatio: "16:9",
});

const { video, receipt, profileId, fallbackReason } = await kuno.wait(job, {
  onProgress: (status) => console.log(status.status),
});

await writeFile("my-world.mp4", video);
await writeFile("my-world.receipt.json", JSON.stringify(receipt, null, 2));
```

Never put a server API key in a frontend build variable.

## Inputs and modes

Reference media go in `inputs`, each with a role. The mode is inferred from the roles when you
don't set one.

```js
const job = await kuno.submit({
  prompt: "A blown-glass flower turns slowly under soft studio light.",
  model: "ltx-2.5-fast",
  mode: "image_to_video",
  inputs: [{ role: "first_frame", file: imageBytes }],   // Blob or Uint8Array
  durationS: 5,
});
```

Roles are `first_frame`, `last_frame`, `keyframe` (with `timeS`), `reference_image`,
`reference_video`, `reference_audio`, `source_video` (with `startS`/`endS` for a retake) and
`source_audio`. Which modes and roles a model accepts, and its limits, come from
`await kuno.models()` — read `modes` and `limits` for the profile instead of assuming.

## Routing and fallbacks

Before submitting, the client asks the gateway which model will serve the request. The owner's
model switch, licence regions (MiniMax H3 is not licensed everywhere) and capacity can route a
job to a compatible fallback, and the client adapts duration, resolution, aspect ratio and frame
rate to it. The handle and the result carry `profileId` and `fallbackReason`
(`region`, `switched_off` or `capacity`); show them, so people know which model made the film.

## The job handle is a secret

`submit` returns a `JobHandle` containing `outputKey`, the only key that decrypts the result.
Store it like a password. With it you can fetch and decrypt the film later:

```js
const result = await kuno.result(handle);
```

## Client reference

`new KunoClient({ apiKey, baseUrl, manifest, country, fetch })` — `baseUrl` defaults to
`https://api.kunoworld.com`; `country` is for development gateways only.

| Method | What it does |
|---|---|
| `models(maxAgeMs = 15000)` | model profiles, availability and the switch; cached for 15 s |
| `manifest()` | the golden manifest the gateway serves |
| `route(mode, model?, family?)` | which profile and enclaves would serve a request |
| `submit(request, onStage?)` | route, verify evidence, encrypt, upload; returns a `JobHandle`. `onStage` reports `routing`, `verifying`, `encrypting`, `uploading`, `submitting` |
| `wait(handle, { onProgress, signal, pollMs, timeoutMs })` | poll to completion, then verify and decrypt |
| `result(handle, status?)` | download, verify and decrypt a finished job |
| `status(jobId)` / `list(limit = 50)` | job status, or your recent jobs |
| `cancel(jobId)` | request cancellation. Stopping polling does not cancel a job |
| `provenance(file)` / `provenanceByDigest(sha256)` | look up a film's public certificate by its hash |

Failures throw `KunoError` with the HTTP `status` and a machine-readable `code`. The package
also exports `verifyReceipt`, `verifyEvidence` and the encryption primitives for independent
checks.

The gateway holds a job's price when it is submitted and refunds it automatically if the job
fails, is canceled or times out.

## Develop

```bash
npm run build
npm test
```
