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

## Private or Standard

Every job has a privacy mode, set with `privacy`:

- `"private"` (the default) is everything above: encrypted in this process to an attested
  confidential enclave, and opened only with the handle's `outputKey`. Nobody at KunoWorld can
  read it. Private jobs only ever run on confidential-tier miners.
- `"standard"` sends the prompt and inputs to KunoWorld readable. **KunoWorld and the GPU provider
  can see the video and your prompt.** There is no client-side encryption and no key to keep; the
  job can run on any miner, and KunoWorld keeps the video, prompt and inputs (30 days by default)
  so the account's credentials can fetch them again.

```js
const job = await kuno.submit({ prompt: "A paper boat crosses a rain puddle", model: "ltx-2.5-fast", privacy: "standard" });
const { video, receipt } = await kuno.wait(job);   // downloads the stored video and checks it against the receipt's digest

const [latest] = await kuno.listStandard();         // this account's standard jobs, newest first
const poster = await kuno.standardThumbnail(latest.job_id);
await kuno.deleteStandard(latest.job_id);           // deletes the stored video, prompt and inputs
```

`kuno.generate(request, options)` submits and waits in one call, in either mode. Every
`JobStatus` carries `privacy`.

### Account requirements and errors

Private mode needs an account in good standing: by default at least one credited top-up or
operator credit, no active restriction and fewer than 2 blocked jobs in 30 days.
`await kuno.eligibility()` returns `{ private_mode: { eligible, reasons }, restricted_until,
strikes_24h, strikes_7d }`.

| `KunoError.code` | What happened |
|---|---|
| `private_mode_not_eligible` (403) | this account can't make private jobs yet; `err.reasons` lists why |
| `account_restricted` (403) | too many blocked jobs; nothing can be made in either mode until `err.restrictedUntil` (Unix seconds) |
| `upload_blocked` (422) | a standard upload matched the content scan |
| `scan_unavailable` (503) | the upload scanner couldn't be reached; nothing was charged, try again |
| `unsupported_media` (422) | the gateway didn't recognize an upload's type (it reads the bytes, not the content-type) |
| `safety_blocked` | the in-enclave content check stopped the job; it counts as a strike |
| `bad_output` | the video didn't match its receipt, so the job failed and was refunded |
| `expired` / `deleted` / `removed` (410) | a standard video or thumbnail is past retention, was deleted, or was removed after review |

The rest of an error body is on `err.details`. An indefinite restriction (until an operator
reviews the account) has `restrictedUntil` 253402300799, in year 9999; it is never null while an
account is restricted.

### Reporting a video

```js
await kuno.report({ content_digest: sha256, reason: "copyright", details: "This is my film." });
```

Reports are sent without your API key. `reason` is one of `csam`, `sexual_minor`,
`nonconsensual_intimate`, `violent_extremism`, `harassment`, `copyright` or `other`; identify
the video with `content_digest`, `job_id` or `url`. Include `output_key` only for a private video
you were given with its key and want reviewed: it opens that one video.

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
| `route(mode, model?, family?, privacy?)` | which profile and enclaves would serve a request |
| `submit(request, onStage?)` | private: route, verify evidence, encrypt, upload; returns a `JobHandle`. Standard (`privacy: "standard"`): upload inputs, create; returns a `StandardJobHandle`. `onStage` reports `routing`, `verifying`, `encrypting`, `uploading`, `submitting` |
| `generate(request, { onStage, ...waitOptions })` | `submit` then `wait` |
| `wait(handle, { onProgress, signal, pollMs, timeoutMs })` | poll to completion, then fetch the video (verified and decrypted for private jobs) |
| `result(handle, status?)` | fetch a finished job's video |
| `status(jobId)` / `list(limit = 50)` | job status (including `privacy`), or your recent jobs |
| `cancel(jobId)` | request cancellation. Stopping polling does not cancel a job |
| `listStandard(limit = 50)` / `standardHandle(row)` | your standard jobs, and a handle to wait on one |
| `standardVideo(jobId)` / `standardThumbnail(jobId)` / `deleteStandard(jobId)` | a standard job's video, a JPEG frame, or delete it |
| `uploadStandard(role, file, mime?)` | upload one standard input yourself |
| `eligibility()` | private-mode eligibility, restriction and strike counts |
| `report(request)` | report a video (no credential sent) |
| `provenance(file)` / `provenanceByDigest(sha256)` | look up a film's public certificate by its hash |

Failures throw `KunoError` with the HTTP `status`, a machine-readable `code`, and the rest of the
error body in `details` (with `reasons` and `restrictedUntil` getters). The package also exports
`verifyReceipt`, `verifyEvidence` and the encryption primitives for independent checks.
`AttestationEvidence.tee` is `mock`, `tdx` or `open`; `verifyEvidence` accepts only `mock` and
`tdx`, so a private job is never sealed to an open-tier miner.

The gateway holds a job's price when it is submitted and refunds it automatically if the job
fails, is canceled or times out.

## Develop

```bash
npm run build
npm test
```
