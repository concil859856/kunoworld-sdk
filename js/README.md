# @kunoworld/sdk

The JavaScript client for KunoWorld. It encrypts prompts and reference media in the browser or
in Node.js, to a GPU enclave whose attestation evidence it checks first; verifies the
enclave-signed receipt; and decrypts the finished video locally. Cryptography uses WebCrypto,
so it runs in modern browsers and Node.js 20+. The package is ES modules only.

> **Development preview.** Workers on development gateways use simulated attestation and may
> return placeholder video. The TDX and NVIDIA checks below are built and tested against Intel's real sample quotes and
> NVIDIA's real signing certificates, but no live confidential GPU worker has run yet. Prices are placeholders that
> haven't been set (`models()` may return `pricing_placeholder: true`).

## Who this is for

**API keys are for developers**, calling KunoWorld from programs they run. People using the
KunoWorld website sign in with their email instead: the site's server keeps the session in an
HttpOnly cookie and forwards the studio's requests, so no key or token ever reaches the page.
Never put an API key in a web page or a frontend build variable.

A website of your own can do the same with a same-origin proxy that adds credentials on the
server side:

```js
// In the browser. The proxy forwards /api/kuno/* to the gateway with the visitor's credentials.
const kuno = KunoClient.forProxy("/api/kuno");
```

Private jobs are still encrypted in the page, so the proxy only relays ciphertext.

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

// The golden manifest lists the enclave measurements you trust. Pin it, or pin the subnet owner's public key
// (`ownerPublicKey`) so the gateway's copy is used only once the owner's signature on it checks out.
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

Never put an API key in a web page or a frontend build variable.

## Private or Standard

Every job has a privacy mode, set with `privacy`. In both modes the video is stored on
KunoWorld's object storage (Cloudflare R2) **until you delete it**; nothing expires on its own.

- `"private"` (the default) is everything above: encrypted in this process to an attested
  confidential enclave, and opened only with the handle's `outputKey`. Nobody at KunoWorld can
  read it, and nobody can recover a lost key: a lost handle means a lost video. Private jobs only
  ever run on confidential-tier miners.
- `"standard"` sends the prompt and inputs to KunoWorld readable. **KunoWorld and the GPU provider
  can see the video and your prompt.** There is no client-side encryption and no key to keep; the
  job can run on any miner, and only your account's credentials can fetch the video again.

KunoWorld operators can open a video only when it is reported as child sexual abuse material (or
sexual content involving a minor) or is under a legal hold, and every such view is logged. There
is no sampled review. All NSFW content is banned in both modes.

```js
const job = await kuno.submit({ prompt: "A paper boat crosses a rain puddle", model: "ltx-2.5-fast", privacy: "standard" });
const { video, receipt } = await kuno.wait(job);   // downloads the stored video and checks it against the receipt's digest

const [latest] = await kuno.listStandard();         // this account's standard jobs, newest first
const poster = await kuno.standardThumbnail(latest.job_id);

await kuno.delete(job.jobId);                       // either mode: deletes the stored content for good
```

`delete` removes a private job's sealed files, or a standard job's video, prompt, inputs and
preview. The charge record and the receipt stay.

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
| `content_policy` (422) | a standard job breaks the content policy (all NSFW is banned); not created, nothing charged |
| `over_budget` (before sending) | the gateway's quote is over `maxPriceUsd`; nothing was read, uploaded, sealed or charged. `err.details` has `price_usd` and `max_price_usd` |
| `invalid_budget` (before sending) | `maxPriceUsd` isn't an amount of zero or more |
| `quote_mismatch` (before sending) | the gateway quoted other params than the job about to be sent (routing changed in between); try again |
| `invalid_shots` / `invalid_inputs` (before sending a quote) | a quote for a storyboard without shots, shots on another mode, or shots with inputs |
| `safety_blocked` | the in-enclave content check stopped the job; it counts as a strike unless the blocked text was the enclave's own (an enhanced prompt or a plan) |
| `bad_output` | the video didn't match its receipt, so the job failed and was refunded |
| `deleted` / `removed` (410) | the video was deleted by its owner, or removed after review |
| `key_not_accepted` (422) | a report carried an `output_key` but its reason isn't `csam` or `sexual_minor` |
| `content_not_reviewable` (403) | operator API: the item can't be opened (not a CSAM/sexual-minor report, no matching legal hold) |
| `gone` (410) | a retired endpoint or credential, such as a `kwt_` studio token |
| `share_unavailable` (410, or 409 when making one) | a share link stopped working, or this video can't be shared right now |
| `too_many_shares` (409) | 20 working links per video, or 1000 per account; revoke some first |
| `invalid_expiry` (422) | a share link's expiry isn't between a minute and ten years ahead |
| `rate_limited` (429) | too many requests to public share links from this network; try again in a minute |
| `missing_key` | a private share link had no `#k=` key, and none was passed |
| `decrypt_failed` | a private video didn't open with the key given |
| `invalid_key` | an output key isn't 32 bytes of base64url (checked before a link is made) |

`ERROR_CODES` maps these codes to a sentence, `err.explanation` reads it for an error, and
`err.isContentPolicy` is true for `content_policy` and `safety_blocked`.

The rest of an error body is on `err.details`. An indefinite restriction (until an operator
reviews the account) has `restrictedUntil` 253402300799, in year 9999; it is never null while an
account is restricted.

### Reporting a video

```js
await kuno.report({ content_digest: sha256, reason: "copyright", details: "This is my film." });
```

Reports are sent without your API key. `reason` is one of `csam`, `sexual_minor`,
`nonconsensual_intimate`, `violent_extremism`, `harassment`, `copyright` or `other`; identify
the video with `content_digest`, `job_id` or `url`. `output_key` is accepted only for `csam` and
`sexual_minor` reports, for a private video you were given with its key: it lets a reviewer open
that one video, and the view is logged.

## Share links

A share link lets anyone who has it watch one of your finished videos, without an account. There
are no links until you make one, and each can be revoked or given an expiry.

```js
const link = await kuno.shares.create(job);       // a JobHandle or StandardJobHandle, or a job id
console.log(link.url);                             // https://kunoworld.com/s/<token>#k=<key> for a private handle

const weekLong = await kuno.shares.create(job, { expiresAt: new Date(Date.now() + 7 * 86400_000) });

const links = await kuno.shares.list({ jobId: job.jobId });   // newest first, with status and viewCount
await kuno.shares.revoke(links[0].shareId);
```

- **Anyone with the link can watch.** The token is 32 random bytes and KunoWorld stores only its
  hash, so `create` is the only time you get `token`, `urlPath` and `url`; `list` can't show them
  again.
- **A private link carries the key in its fragment.** For a private video the gateway serves only
  the sealed file. The video's output key goes after `#k=` in the link, and browsers never send
  the fragment, so KunoWorld never receives the key. Given a `JobHandle`, `create` adds it
  (`keyIncluded: true`). Given only a job id it can't: `keyIncluded` is false, and
  `shareUrlWithKey(link.url, handle.outputKey)` adds it. `urlPath` never carries the key.
- **A Standard link** has no key: the gateway serves the video itself.
- **When a link stops working.** Once revoked; once past `expiresAt` (Unix seconds or a `Date`,
  from a minute to ten years ahead; leave it out for a link that lasts until revoked); and
  whenever the video is deleted, removed after review or can't be played for another reason, or
  the account is closed. Viewers then get `410 share_unavailable`, the same answer in every case.
  `list()` tells you which in `status`: `active`, `revoked`, `expired`, `video_deleted`,
  `video_removed`, `account_closed` or `unavailable`. Revoking stops KunoWorld serving the video;
  it can't take back a copy, or a private video's key, that someone already has.
- **Limits.** 20 working links per video and 1000 per account (`too_many_shares`). Views are
  counted (`viewCount`); nothing about a viewer is stored. The public routes are rate-limited
  per network, 60 requests a minute by default (`rate_limited`); `open` makes two.

Opening a link needs no account, and no API key is sent:

```js
const viewer = new KunoClient();                          // no apiKey
const about = await viewer.shares.get(url);               // privacy, profileId, dates, receipt, and the fragment's key
const { video, receipt } = await viewer.shares.open(url); // or open(linkWithoutKey, key)
```

`get` and `open` take a full link, a `/s/<token>` path or a bare token. Only the token is sent, to
this client's `baseUrl`; the key never is. For a private link, `open` checks the sealed file
against the receipt's `output_digest`, verifies the receipt's signature, decrypts the video here
and checks its SHA-256 against `content_digest`; for a Standard link it checks the SHA-256. It
throws `missing_key` when a private link has no key (nothing is downloaded), `decrypt_failed` for
the wrong key and `integrity` when anything doesn't match. The signing key arrives from the
gateway with the link, so the check proves the video matches a receipt signed by that key; for your
own videos, `result(handle)` checks against the key you attested when you submitted.

### Calls that need the website

A few account features use the website's email sign-in and have no SDK methods: syncing private
video keys between your devices (`/v1/me/keyvault/…`) and the website's own routes under
`/v1/me/…`, such as `/v1/me/shares`. API keys get `401` there. Elements need key sync set up on the
website, but `kuno.elements` itself works with an API key and an Elements key. Share links don't need them:
`kuno.shares` uses the API-key routes (`/v1/videos/{id}/shares`, `/v1/account/shares`), which
also accept a web session through a same-origin proxy (`KunoClient.forProxy`).

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

## Storyboards: long videos from chained shots

A storyboard is one job of 2 or more shots. One worker renders them one after another, inside one enclave, and delivers
one stitched video with one receipt. Give `shots`; `prompt` is the scene every shot shares (characters, place, style)
and may be empty. Each shot has its own prompt and length, and a `join` that says how it starts:

| `join` | What the shot starts from |
|---|---|
| `continue` | the end of the shot before, picture and sound: one unbroken take |
| `cut` | the sound of the shot before only: a new picture over the same voice and room tone |
| `fresh` | nothing: a new shot, nothing carried over |

The first shot is always `fresh`; leave `join` out and later shots `continue`.

```js
const job = await kuno.submit({
  model: "ltx-2.5-fast",
  prompt: "A small blue fishing boat and its old skipper, early morning, soft light.",
  resolution: "720p",
  shots: [
    { prompt: "The boat leaves the harbor.", durationS: 5 },
    { prompt: "Gulls follow it out to sea.", durationS: 5, join: "continue" },
    { prompt: "Close on the skipper's hands hauling in the net.", durationS: 6, join: "cut" },
  ],
});

const { video } = await kuno.wait(job, {
  onProgress: (status) => {
    const at = storyboardStage(status.stage);          // `shot 2/3` while it renders, then the usual stages
    if (at) console.log(`Shot ${at.shot} of ${at.shots}`);
  },
});
```

- **Which models.** Profiles whose `limits.storyboard` is set: today `ltx-2.5-fast`, 2 to 12 shots
  (`max_shots`) and at most 120 s stitched (`max_total_s`). Each shot keeps to the profile's own duration limits. A
  storyboard takes no `inputs`.
- **Length.** A `continue` or `cut` shot repeats the last frames of the shot before, and they are trimmed from the video:
  17 frames each (about 0.7 s at 24 fps), so three 5 s shots joined make 13.71 s, not 15. The SDK sets
  `params.duration_s` to the stitched length exactly; `storyboardDurationS(profile, shots, fps)` and
  `storyboardFrames` compute it (`shots` as `{ duration_s, join }`).
- **Prompts.** The model sees `shotPrompt(scene, shot.prompt)`: the scene, a blank line, then the shot's prompt. Each of
  those must fit the profile's `max_prompt_chars`, and no shot prompt may be empty. In Private mode the scene and every
  shot prompt are sealed; in Standard mode the body carries `shots: [{ prompt }]` beside `params.shots`. Shot *i* (from
  0) renders with seed `(seed + i) mod 2^31`.
- **Price.** You pay the per-second rate for the stitched length, with the fps multiplier. The long-clip multiplier and
  the workers' serving envelopes look at the longest shot, since shots render one at a time (`renderDurationS(params)`);
  `priceQuote`, `envelopeFits` and routing do the same. `kuno.quote({ model: "ltx-2.5-fast", shots, resolution: "720p" })`
  asks the gateway for the exact price without sending a prompt ([Prices, quotes and budgets](#prices-quotes-and-budgets)),
  and `maxPriceUsd` caps it.
- **Checked before sending.** `submit` refuses a storyboard that breaks these rules with `invalid_params`, before
  anything is sealed or sent; `validateStoryboard(profile, params)` runs the same checks with kuno_protocol's messages.
- **Not verified yet.** Storyboards carry no step commitment, so validators don't step-audit them yet.

`params.shots` exists only on storyboards, so every other job's encrypted request is byte-for-byte what it was.

## Plans from a brief (Director)

`kuno.plan(...)` has a storyboard written for you: a scene and 2 to 12 shots, each with a `beat` (a short label), a
prompt, a length and a join, fitted to `targetS` seconds (4 to 120). The planner is the small language model bundled
with LTX-2.5, run inside a confidential worker, so nothing renders and the plan is a first draft: read it, edit it, have
shots rewritten, then render it as a storyboard.

```js
import { planToShots } from "@kunoworld/sdk";

const { plan, receipt } = await kuno.plan({
  brief: 'A 30-second ad for a small coffee roastery, warm and handmade. End on "Roasted this morning."',
  targetS: 30,
  style: "35mm film, warm",           // model: "ltx-2.5-fast" and privacy: "private" by default
});
console.log(plan.title, plan.duration_s, plan.repairs);   // every change code made to what the planner wrote

plan.shots[3].prompt += " The camera slowly pushes in.";
const { plan: revised } = await kuno.revisePlan(plan, "darker, at night", { shots: [2] });   // shot 2 only

const job = await kuno.submit({
  prompt: revised.scene,
  shots: planToShots(revised),        // [{ prompt, durationS, join }]: the same specs and stitched length
  model: revised.profile_id, resolution: revised.resolution, aspectRatio: revised.aspect_ratio,
  fps: revised.fps, audio: revised.audio,
});
```

- **`Plan`** is Plan v1: `profile_id`, `resolution`, `aspect_ratio`, `fps`, `audio`, `target_s`, `duration_s` (the
  shots' exact stitched length), `title`, `scene`, `shots: [{ beat, prompt, duration_s, join }]`, `notes`, `repairs` and
  `planner`. `planStoryboardParams(plan)` is the storyboard's params; `planShotSpecs`, `restitchPlan(profile, plan)`
  (after editing lengths) and `parsePlan(json)` help around it.
- **Private** (the default) routes only to attested workers whose route entry lists `plan/1` (`PLAN_FEATURE`), asks for
  shots no longer than the longest those workers render at this size and frame rate (`options.plan.max_shot_s`, the
  rule the storyboard is routed by), and seals the brief and style here. `planResult` downloads the sealed plan, checks
  it against the enclave-signed receipt, decrypts it, refuses anything but padded plan JSON (`openPlan`), checks
  `content_digest` and runs `validatePlan`. The gateway sees the target length, the frame, the price, the status and
  the receipt; never the brief or the plan. No worker that writes plans: `plans_unavailable`, before anything is sent.
- **Standard** (`privacy: "standard"`) sends the brief to `POST /v1/standard/plans`, readable by KunoWorld, and reads
  the stored plan back from `GET /v1/standard/plans/{jobId}`, checked against the receipt's `content_digest`.
- **Revisions.** `revisePlan(plan, instruction, { shots })` is a new plan job with the same frame and target: with
  `shots` (numbered from 1) only those shots are rewritten and only their lengths move. The plan may be edited first: it
  is sent with exactly Plan v1's fields and its stitched length measured again, and one that breaks the rules is refused
  as `invalid_plan` before anything is sent.
- **Price.** Flat, whatever the length: `kuno.quote({ model: "ltx-2.5-fast", mode: "plan", durationS: 30 })` asks the
  gateway (`breakdown.planUsd`), `priceQuote(profile, { mode: "plan", resolution, duration_s, fps }, privacy)` or
  `planPriceUsd(profile, privacy)` estimate it here, and `maxPriceUsd` on `plan` and `revisePlan` works as for videos.
  `plan_failed` (the planner wrote nothing usable) and `safety_blocked` are refunded.
- **Waiting.** Plans take seconds to about a minute (stages `planning`, then `checking`). `submitPlan` returns a
  `PlanHandle` (a Private one holds the output key: store it like a password), and `waitPlan(handle)` finishes it.
- **Checks shared with Python.** `planContext`, `fitPlan`, `validatePlan`, `briefQuotes`, `missingQuotes`, `openPlan` and
  `encodePlan` port `kuno_protocol.plans`, and the shared `plans` vectors pin them.

## Prices, quotes and budgets

`kuno.quote(request)` asks the gateway for the exact price of a job before anything is encrypted or sent
(`POST /v1/quote`). It routes the request as the job would be routed (fallbacks, licence regions, capacity), fills in the
same defaults `submit` does, and prices those params with the function that charges the job. A `GenerateRequest` can
be passed as it is: only its shape is read, and its prompt, shot prompts and files never leave this process.

```js
const quote = await kuno.quote({
  model: "ltx-2.5-fast",
  resolution: "720p",
  shots: [{ durationS: 5 }, { durationS: 5 }, { durationS: 5, join: "cut" }],
});
console.log(quote.priceUsd, quote.profileId, quote.fallbackReason);   // 1.645 ltx-2.5-fast null
console.log(quote.breakdown);   // usdPerSecond, billableSeconds (stitched), fpsMultiplier, longClipMultiplier, minJobUsd…
console.log(quote.params);      // the GenerationParams priced
console.log(quote.balanceUsd, quote.balanceCovers, quote.placeholder);
```

- **What it takes.** `model`, `family`, `mode`, `durationS`, `shots` (`{ durationS, join }`, or `ShotSpec`s),
  `resolution`, `aspectRatio`, `fps`, `audio`, `privacy`, and `inputRoles` (or `inputs`, whose files aren't read) for
  the inputs the job will send. The mode follows from those roles as `submit` infers it; without any, the inputs the
  mode needs are assumed. `mode: "plan"` with `durationS` (the target) quotes a plan: flat, with `breakdown.planUsd` and
  `usdPerSecond` null. `plan` quotes rendering that plan as its storyboard.
- **Refusals** carry the code the job itself would get: `invalid_params`, `privacy_mode_unavailable`,
  `region_restricted`, `model_disabled`, `no_capacity` (with `max_duration_s` when no worker's hardware fits),
  `private_mode_not_eligible` and `account_restricted`. A shape that can't be a job is refused before sending
  (`invalid_shots`, `invalid_inputs`, `invalid_privacy`).
- **A quote holds nothing.** The price is taken when the job is accepted. If routing or prices change in between, the
  job is priced again the same way. `priceQuote(profile, params)` estimates a price locally from `models()`, without
  routing.

**Budgets.** Pass `maxPriceUsd` in a request to `submit` or `generate` (videos and storyboards, Private or Standard), to
`plan` or `submitPlan`, or in the options of `revisePlan` or `submitRevision`. After routing and filling in the params,
the client has the gateway quote exactly those params, and throws `over_budget` when the price is over the limit:
no input is read or uploaded, no worker is picked, nothing is sealed, submitted or charged, and `err.details` has
`price_usd` and `max_price_usd`. A price equal to the limit goes ahead, and the handle keeps the quote as `quote`. A
quote for other params than the job (routing changed in between) is `quote_mismatch`; a limit that isn't an amount of
zero or more is `invalid_budget`, before anything is sent. The Python SDK's `max_price_usd` works the same way.

```js
try {
  const job = await kuno.submit({ prompt, model: "ltx-2.5-fast", durationS: 10, maxPriceUsd: 1.0 });
  console.log(`Quoted $${job.quote.priceUsd}`);
} catch (err) {
  if (err instanceof KunoError && err.code === "over_budget") console.log(`It would cost $${err.details.price_usd}`);
  else throw err;
}
```

## Elements: reusable characters, products, locations and voices

An Element is a named character, product, location, style or voice you reuse across videos: 1 to 4 images (or one
voice clip), a short description the prompt can use ("Mara: a woman in her 60s with short silver hair and a green
raincoat"), and, for a real person, a consent record. **Everything about it is encrypted in this process** before it
reaches KunoWorld, which stores only ciphertext and can't open it.

**The rules.** No public figures and no one under 18. A real person must be you, or must have given you permission,
and their consent record says who, when and for what. Sexual content is banned, as everywhere on KunoWorld. Every write
affirms these rules (`affirmRules: true`), and the gateway refuses a write without it.

**The key.** Elements are encrypted with an *Elements key*, derived from the key sync master key the website holds, so
your other devices open them once key sync is unlocked there. A program gets the key as text from the studio's Elements
page and keeps it with its other secrets:

```js
import { KunoClient, parseElementsKey } from "@kunoworld/sdk";

const kuno = new KunoClient({ apiKey: process.env.KUNO_API_KEY });
const key = parseElementsKey(process.env.KUNO_ELEMENTS_KEY);   // "kwek1.<account id>.<key id>.<key>"

const mara = await kuno.elements.create(key, {
  kind: "character",                                   // character | product | location | style | voice
  name: "Mara",
  description: "a woman in her 60s with short silver hair and a green raincoat",
  consent: { subject: "Mara Jones", relationship: "permission", grantedOn: "2026-09-01",
             use: "Videos made on KunoWorld", affirmedAt: Math.floor(Date.now() / 1000) },
  files: [{ data: portraitBytes, mime: "image/jpeg" }],
}, { affirmRules: true });

const { elements, unreadable } = await kuno.elements.list(key);
```

The Elements key opens Elements only: it is HKDF-SHA256 of the master key, which it can't be turned back into, so it
opens no video key. **Rotating key sync replaces it**: writes with the old one fail with `vault_changed`, and
`list` reports Elements it can't open in `unreadable` (`key_rotated`). Get the new key from the studio.

**Using one in a video.** `attach` opens the Element's files here and returns an ordinary request: the files become
inputs in the roles you choose, and each Element's description is added to the prompt on its own line. A Private job
then seals them to the enclave like any input; a Standard job uploads them readable, so KunoWorld and the GPU provider
can see them.

```js
const request = await kuno.elements.attach(
  { prompt: "She walks along the pier at dusk.", model: "ltx-2.5-fast" },
  [{ element: mara, role: "first_frame" }],             // file: 0 by default; a keyframe takes timeS
);
const job = await kuno.submit(request);
```

- **Which roles.** `elementRoles(element, profile)` lists what an Element's files can be on a model: images as
  `first_frame`, `last_frame` or `keyframe` on LTX-2.5, or `reference_image` on MiniMax H3 Director
  (`file: "all"` adds every image); a voice as `reference_audio` on MiniMax H3 Director (`h3-reference`) only. H3 is licensed only in
  some regions (`available_in_region` on `models()`); elsewhere a voice is stored for later and its description still
  works. Leave `role` out to use only the description.
- **Storyboards** take descriptions only, added to the scene: their shots take no inputs.
- **Withdrawn consent.** Set `consent.withdrawnAt` with `update`; `attach` then refuses the Element
  (`consent_withdrawn`). Deleting it removes it for good.

`update(key, element, draft)` without `files` keeps the files and their key; with `files` it replaces all of them under
a new key. It names the revision it read, so a change from another device in between fails with `element_changed`.
`delete(elementId)` removes the record and files. `file(element, position)` downloads and opens one file, checking it
against the digest in the record.

**Limits.** 200 Elements and 2 GiB per account; 4 images or one voice clip (up to 30 seconds) each; 15 MB per file; a
name of 80 characters and a description of 1,000. 60 changes a minute. `elementDraftProblems(draft)` returns the
problems with a draft as sentences before anything is sent.

**What KunoWorld sees.** That the account has Elements, their random ids, revisions and times, how many files each has,
their padded sizes, and when they are downloaded. Not their kind, name, description, consent record or pictures. The
formats are in `platform/gateway/ELEMENTS.md`.

## Routing and fallbacks

Before submitting, the client asks the gateway which model will serve the request. The owner's
model switch, licence regions (MiniMax H3 is not licensed everywhere) and capacity can route a
job to a compatible fallback, and the client adapts duration, resolution, aspect ratio and frame
rate to it. The handle and the result carry `profileId` and `fallbackReason`
(`region`, `switched_off` or `capacity`); show them, so people know which model made the film.

## The job handle is a secret

`submit` returns a `JobHandle` containing `outputKey`, the only key that decrypts the result.
Store it like a password, and back it up: KunoWorld can't recover it, and the encrypted video is
kept until you delete it but opens only with this key. With it you can fetch and decrypt the film later:

```js
const result = await kuno.result(handle);
```

## Client reference

`new KunoClient({ apiKey, baseUrl, manifest, ownerPublicKey, country, fetch, credentials, nvidiaTrustedSpki,
tdxAllowedTcbStatuses })` — `baseUrl` defaults to `https://api.kunoworld.com` and may be a same-origin path in a
browser; `apiKey` is optional (leave it out behind a proxy); `fetch` replaces the transport; `country` is for
development gateways only. `KunoClient.forProxy(baseUrl, opts?)` is the keyless form for a same-origin proxy. A `kwt_`
studio token is refused with `gone`.

Verification options:
- `manifest` pins the golden manifest. `ownerPublicKey` (base64 Ed25519) instead fetches `/v1/manifest/signed` and
  uses it only if the subnet owner signed it. Without either, the gateway's manifest is trusted.
- A TDX worker is accepted only with the `endorsements` the gateway relays: its quote must pass full Intel DCAP
  verification (via `@phala/dcap-qvl`, Intel's root pinned) with a TCB status in `tdxAllowedTcbStatuses` (default
  `UpToDate`), and its GPUs' NVIDIA attestation tokens must be signed under NVIDIA's attestation intermediate, pinned
  by SPKI hash. `nvidiaTrustedSpki` replaces that pin when NVIDIA rotates the intermediate (the current one is valid to
  2029-12-08).
- The same checks are exported: `verifyEvidence(evidence, manifest, { endorsements })`, `verifyTdxQuoteSignature`,
  `verifyGpuEndorsements`, `verifySignedManifest`.

| Method | What it does |
|---|---|
| `models(maxAgeMs = 15000)` | model profiles, availability and the switch; cached for 15 s |
| `manifest()` | the golden manifest the gateway serves |
| `route(mode, model?, family?, privacy?, fit?)` | which profile and enclaves would serve a request; `fit` (`resolution`, `aspectRatio`, `fps`, `durationS`) lists only workers whose hardware can fit it (their serving envelope). `submit` sends the request's own fields |
| `submit(request, onStage?)` | private: route, verify evidence, encrypt, upload; returns a `JobHandle`. Standard (`privacy: "standard"`): upload inputs, create; returns a `StandardJobHandle`. `onStage` reports `routing`, `verifying`, `encrypting`, `uploading`, `submitting`. With `maxPriceUsd`, `over_budget` before anything is sent when the quote is over it; the handle keeps the `quote` |
| `generate(request, { onStage, ...waitOptions })` | `submit` then `wait` |
| `wait(handle, { onProgress, signal, pollMs, timeoutMs })` | poll to completion, then fetch the video (verified and decrypted for private jobs) |
| `result(handle, status?)` | fetch a finished job's video |
| `plan(request, { onStage, ...waitOptions })` / `submitPlan(request, onStage?)` | a storyboard plan from `{ brief, targetS, model?, resolution?, aspectRatio?, fps?, audio?, style?, privacy?, seed?, maxPriceUsd? }`: waited for and checked (`PlanResult`: `plan`, `json`, `receipt`), or its `PlanHandle` |
| `revisePlan(plan, instruction?, { shots, brief, style, privacy, seed, maxPriceUsd, ...waitOptions })` / `submitRevision(...)` | the plan rewritten: only the listed shots, or all of them |
| `quote(request)` | the gateway's exact price for such a job now, as a `Quote`: `priceUsd`, `profileId`, `fallbackReason`, `params`, `breakdown`, `placeholder`, `balanceUsd`, `balanceCovers`. Never sends a prompt or file |
| `waitPlan(handle, waitOptions)` / `planResult(handle, status?)` | wait for a plan job, or open a finished one |
| `status(jobId)` / `list(limit = 50)` | job status (including `privacy`), or your recent jobs |
| `cancel(jobId)` | request cancellation. Stopping polling does not cancel a job |
| `delete(jobId)` | delete a job's stored content, in either mode (`DELETE /v1/videos/{id}`) |
| `listStandard(limit = 50)` / `standardHandle(row)` | your standard jobs, and a handle to wait on one |
| `standardVideo(jobId)` / `standardThumbnail(jobId)` / `deleteStandard(jobId)` | a standard job's video, a JPEG frame, or delete it (same as `delete`) |
| `uploadStandard(role, file, mime?)` | upload one standard input yourself |
| `eligibility()` | private-mode eligibility, restriction and strike counts |
| `report(request)` | report a video (no credential sent) |
| `provenance(file)` / `provenanceByDigest(sha256)` | look up a film's public certificate by its hash |
| `shares.create(handleOrJobId, { expiresAt }?)` | make a share link; `url` carries a private handle's key as `#k=…` |
| `shares.list({ jobId, limit }?)` / `shares.revoke(shareId)` | your links with `status` and `viewCount`, or stop one |
| `shares.get(link)` / `shares.open(link, key?)` | public (no credential): a link's details, or its video checked and decrypted |
| `elements.create(key, draft, { affirmRules: true, elementId? })` | seal and store a new Element |
| `elements.list(key)` / `elements.get(key, elementId)` / `elements.rows()` | open your Elements (`unreadable` lists any this key can't), one Element, or the stored ciphertext |
| `elements.update(key, element, draft, { affirmRules: true })` / `elements.delete(elementId)` | replace an Element (keeping its files when `draft.files` is left out), or delete it |
| `elements.file(element, position?)` / `elements.attach(request, uses)` | one opened file, or a request with Elements' files as inputs and their descriptions in the prompt |

`shareUrlWithKey(url, outputKey)` adds a private video's key to a link, and `parseShareLink(link)`
returns `{ token, key }`.

Element helpers: `deriveElementsKey`, `parseElementsKey` / `formatElementsKey`, `elementRoles`, `elementPromptLine`,
`addElementLines`, `elementDraftProblems`, `consentWithdrawn`, and the sealing primitives (`sealElement`, `openElement`,
`wrapElementKey`, `rewrapElementKey` for a key sync rotation) with `ELEMENT_RULES` and `ELEMENT_LIMITS`.

Storyboard helpers mirror kuno_protocol: `storyboardDurationS`, `storyboardFrames`, `storyboardTrimFrames`, `numFrames`,
`shotPrompt`, `renderDurationS`, `validateStoryboard` and `storyboardStage` (see "Storyboards"). Plan helpers: `planToShots`,
`planStoryboardParams`, `planShotSpecs`, `restitchPlan`, `planPriceUsd`, `planContext`, `fitPlan`, `validatePlan`,
`briefQuotes`, `missingQuotes`, `parsePlan`, `encodePlan`, `openPlan` and `planOutputLabel` (see "Plans from a brief").

Failures throw `KunoError` with the HTTP `status`, a machine-readable `code`, and the rest of the
error body in `details` (with `reasons` and `restrictedUntil` getters). The package also exports
`verifyReceipt`, `verifyEvidence` and the encryption primitives for independent checks.
`AttestationEvidence.tee` is `mock`, `tdx` or `open`; `verifyEvidence` accepts only `mock` and
`tdx`, so a private job is never sealed to an open-tier miner.

The gateway holds a job's price when it is submitted and refunds it automatically if the job
fails, is blocked (`safety_blocked`), is canceled or times out. `quote(request)` asks the gateway for it exactly;
`priceUsd(profile, params, privacy)` and `priceQuote` estimate it from a profile: `pricing.usd_per_second` is the Private
price and `pricing.standard_usd_per_second` the lower Standard one, the fps multiplier (and, in
Private mode, the long-clip multiplier) applies to the whole job, and no job costs less than
`pricing.min_job_usd`. A profile without a Standard price is Private-only (`privacyModes(profile)`
is `["private"]`), and a Standard request for it fails with `privacy_mode_unavailable`; every
profile has one today. All prices are placeholders.

## Develop

```bash
npm run build
npm test
```
