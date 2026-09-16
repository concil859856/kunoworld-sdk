# kunoworld

The Python client for KunoWorld. It encrypts prompts and reference media on your machine, to a
GPU enclave whose attestation evidence it checks first; verifies the enclave-signed receipt;
and decrypts the finished video locally. Requires Python 3.10+.

> **Development preview.** Workers on development gateways use simulated attestation and may
> return placeholder video. Real TDX and NVIDIA evidence verification is not built yet. Prices
> are placeholders that haven't been set (`models()` may include `"pricing_placeholder": true`).

**API keys are for developers**, calling KunoWorld from programs they run; create one on your
account page. People using the KunoWorld website sign in with their email instead, and the site
never hands their browser a key or token.

## Install

Neither `kunoworld` nor its dependency `kuno-protocol` is on PyPI yet. `kuno-protocol` lives in
the subnet repository.

In the KunoWorld development workspace, `uv sync` installs both. Elsewhere, install them from
source side by side:

```bash
uv pip install -e /path/to/kunoworld-subnet/protocol -e /path/to/kunoworld-sdk/python
```

## Generate a video

```python
import os
from kunoworld import KunoClient
from kuno_protocol.attestation import GoldenManifest

# The golden manifest lists the enclave measurements you trust. Pin it, or pin the subnet owner's public key
# (owner_public_key=) so the gateway's copy is used only once the owner's signature on it checks out.
manifest = GoldenManifest.model_validate_json(open("trusted-manifest.json").read())

kuno = KunoClient(os.environ["KUNO_API_KEY"], os.environ["KUNO_GATEWAY_URL"], manifest=manifest)

result = kuno.generate(
    "Paper lanterns drift inside a vast spiral library. A slow camera push.",
    model="ltx-2.5-fast",
    duration_s=5,
)
result.save("my-world.mp4")
with open("my-world.receipt.json", "w") as file:
    file.write(result.receipt.model_dump_json(indent=2))
print(result.profile_id, result.fallback_reason, result.content_digest)
```

Without `manifest=` or `owner_public_key=`, the client falls back to the manifest the gateway serves and warns you.

A TDX worker is accepted only with the `endorsements` the gateway relays next to its evidence: the quote must pass full
Intel DCAP verification (dcap-qvl, Intel's root pinned) and its GPUs' NVIDIA attestation tokens must be signed under
NVIDIA's pinned attestation intermediate (`kuno_protocol.endorsements`). Nothing about the hardware is taken on the
gateway's word.

## Private or Standard

Every job has a privacy mode, set with `privacy=`. In both modes the video is stored on
KunoWorld's object storage (Cloudflare R2) **until you delete it**; nothing expires on its own.

- `"private"` (the default) is everything above: encrypted on your machine to an attested
  confidential enclave, and opened only with the job's output key. Nobody at KunoWorld can read
  it, and nobody can recover a lost key: a lost key means a lost video. Private jobs only ever run
  on confidential-tier miners.
- `"standard"` sends the prompt and inputs to KunoWorld readable. **KunoWorld and the GPU provider
  can see the video and your prompt.** There is no client-side encryption and no key to keep; the
  job can run on any miner, and only your account's credentials can fetch the video again.

KunoWorld operators can open a video only when it is reported as child sexual abuse material (or
sexual content involving a minor) or is under a legal hold, and every such view is logged. There
is no sampled review. All NSFW content is banned in both modes.

```python
result = kuno.generate("A paper boat crosses a rain puddle", model="ltx-2.5-fast", privacy="standard")
result.save("boat.mp4")        # checked against the receipt's content digest
print(result.privacy)          # "standard"

for row in kuno.standard_videos():          # this account's standard jobs, newest first
    print(row["job_id"], row["status"])
job = kuno.standard_job(row["job_id"])
open("poster.jpg", "wb").write(job.thumbnail())

kuno.delete(row["job_id"])                  # either mode: deletes the stored content for good
```

`kuno.delete(job_id)` (or `job.delete()` on a `VideoJob` or `StandardVideoJob`) removes a private
job's sealed files, or a standard job's video, prompt, inputs and preview. The charge record and
the receipt stay.

With `wait=False`, a standard `generate` returns a `StandardVideoJob` (`status`, `wait`, `result`,
`cancel`, `thumbnail`, `delete`, `export`). Its export holds no secrets. Every `JobStatus` carries
`privacy`.

### Account requirements and errors

Private mode needs an account in good standing: by default at least one credited top-up or
operator credit, no active restriction and fewer than 2 blocked jobs in 30 days.
`kuno.eligibility()` returns `{"private_mode": {"eligible", "reasons"}, "restricted_until",
"strikes_24h", "strikes_7d"}`.

| `KunoError.code` | What happened |
|---|---|
| `private_mode_not_eligible` (403) | this account can't make private jobs yet; `err.reasons` lists why |
| `account_restricted` (403) | too many blocked jobs; nothing can be made in either mode until `err.restricted_until` (Unix seconds) |
| `upload_blocked` (422) | a standard upload matched the content scan |
| `scan_unavailable` (503) | the upload scanner couldn't be reached; nothing was charged, try again |
| `unsupported_media` (422) | the gateway didn't recognize an upload's type (it reads the bytes, not the content-type) |
| `content_policy` (422) | a standard job breaks the content policy (all NSFW is banned); not created, nothing charged |
| `safety_blocked` | the in-enclave content check stopped the job; it counts as a strike |
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

`ERROR_CODES` maps these codes to a sentence; `err.explanation` reads it, and
`err.is_content_policy` is true for `content_policy` and `safety_blocked`.

The rest of an error body is on `err.details`. An indefinite restriction (until an operator
reviews the account) has `restricted_until` 253402300799, in year 9999; it is never `None` while
an account is restricted. Rows from `standard_videos()` also carry `deleted`.

### Reporting a video

```python
report_id = kuno.report("copyright", content_digest=sha256, details="This is my film.")
```

Reports are sent without your API key. The reason is one of `csam`, `sexual_minor`,
`nonconsensual_intimate`, `violent_extremism`, `harassment`, `copyright` or `other`; identify the
video with `content_digest`, `job_id` or `url`. `output_key` is accepted only for `csam` and
`sexual_minor` reports (the client refuses others with `key_not_accepted` before sending), for a
private video you were given with its key: it lets a reviewer open that one video, and the view is
logged.

## Share links

A share link lets anyone who has it watch one of your finished videos, without an account. There
are no links until you make one, and each can be revoked or given an expiry.

```python
from datetime import datetime, timedelta, timezone

link = kuno.shares.create(job)            # a VideoJob or StandardVideoJob, or a job id
print(link["url"])                        # https://kunoworld.com/s/<token>#k=<key> for a private VideoJob

week_long = kuno.shares.create(job, expires_at=datetime.now(timezone.utc) + timedelta(days=7))

links = kuno.shares.list(job_id=job.job_id)   # newest first, with status and view_count
kuno.shares.revoke(links[0]["share_id"])
```

- **Anyone with the link can watch.** The token is 32 random bytes and KunoWorld stores only its
  hash, so `create` is the only time you get `token`, `url_path` and `url`; `list` can't show them
  again.
- **A private link carries the key in its fragment.** For a private video the gateway serves only
  the sealed file. The video's output key goes after `#k=` in the link, and browsers never send
  the fragment, so KunoWorld never receives the key. Given a `VideoJob`, `create` adds it
  (`key_included` is `True`). Given only a job id it can't: `key_included` is `False`, and
  `share_url_with_key(link["url"], job.output_key)` adds it (the raw bytes, or
  `export()["output_key"]`). `url_path` never carries the key.
- **A Standard link** has no key: the gateway serves the video itself.
- **When a link stops working.** Once revoked; once past `expires_at` (Unix seconds or a
  `datetime`, from a minute to ten years ahead; a naive datetime is local time; `None` means until
  revoked); and whenever the video is deleted, removed after review or can't be played for another
  reason, or the account is closed. Viewers then get `410 share_unavailable`, the same answer in
  every case. `list()` tells you which in `status`: `active`, `revoked`, `expired`,
  `video_deleted`, `video_removed`, `account_closed` or `unavailable`. Revoking stops KunoWorld
  serving the video; it can't take back a copy, or a private video's key, that someone already has.
- **Limits.** 20 working links per video and 1000 per account (`too_many_shares`). Views are
  counted (`view_count`); nothing about a viewer is stored. The public routes are rate-limited per
  network, 60 requests a minute by default (`rate_limited`); `open` makes two.

Opening a link needs no account, and no API key is sent:

```python
viewer = KunoClient("", "https://api.kunoworld.com")   # public routes never send a key, so none is needed
about = viewer.shares.get(url)       # privacy, profile_id, dates, receipt, and the fragment's "key"
result = viewer.shares.open(url)     # or open(link_without_key, key=...)
result.save("shared.mp4")
```

`get` and `open` take a full link, a `/s/<token>` path or a bare token. Only the token is sent, to
the client's `base_url`; the key never is. `open` returns a `GenerationResult`. For a private link
it checks the sealed file against the receipt's `output_digest`, verifies the receipt's signature,
decrypts the video here and checks its SHA-256 against `content_digest`; for a Standard link it
checks the SHA-256. It raises `missing_key` when a private link has no key (nothing is
downloaded), `decrypt_failed` for the wrong key and `integrity` when anything doesn't match. The
signing key arrives from the gateway with the link, so the check proves the video matches a receipt
signed by that key; for your own videos, `job.result()` checks against the key you attested when
you submitted.

### Calls that need the website

A few account features use the website's email sign-in and have no SDK methods: syncing private
video keys between your devices (`/v1/me/keyvault/...`) and the website's own routes under
`/v1/me/...`, such as `/v1/me/shares`. API keys get `401` there. Share links don't need them:
`kuno.shares` uses the API-key routes (`/v1/videos/{id}/shares`, `/v1/account/shares`).

## Inputs and modes

`generate` takes reference media as keyword arguments, and infers the mode from them when you
don't pass `mode`:

```python
from pathlib import Path

result = kuno.generate(
    "A blown-glass flower turns slowly under soft studio light.",
    model="ltx-2.5-fast",
    first_frame=Path("flower.png"),
    duration_s=5,
)
```

The inputs are `first_frame`, `last_frame`, `keyframes` (pairs of source and time in
seconds), `reference_images`, `reference_videos`, `reference_audio`, `source_video` and
`source_audio`. Settings are `duration_s`, `resolution`, `aspect_ratio`, `fps`, `audio`,
`seed` and `negative_prompt`. Which modes and inputs a model accepts, and its limits, come
from `kuno.profile("ltx-2.5-fast")`; read them instead of assuming.

## Routing and fallbacks

Before submitting, the client asks the gateway which model will serve the request. The owner's
model switch, licence regions (MiniMax H3 is not licensed everywhere) and capacity can route a
job to a compatible fallback, and the client adapts the settings to it. `result.profile_id` and
`result.fallback_reason` (`region`, `switched_off` or `capacity`) say what happened; show them.

## Long jobs, and resuming them

Pass `wait=False` to get a `VideoJob` back immediately:

```python
job = kuno.generate("…", model="h3-turbo", duration_s=8, wait=False)
saved = job.export()          # contains the output decryption key: store it like a password

# later, even in another process
from kunoworld import VideoJob
job = VideoJob.restore(kuno, saved)
result = job.wait(timeout=1800, on_progress=lambda status: print(status.status))
```

`job.status()` and `job.cancel()` are there too. Stopping `wait` does not cancel a job. For
full control, `kuno.prepare(...)` builds and encrypts a request without sending it, and
`kuno.submit(prepared)` sends it.

## Client reference

`KunoClient(api_key, base_url="https://api.kunoworld.com", *, manifest=None, owner_public_key=None, country=None,
timeout=60.0, transport=None, nvidia_trusted_spki=None)` — `owner_public_key` (base64 or bytes) checks the owner's
signature on the gateway's manifest; `nvidia_trusted_spki` replaces NVIDIA's pinned attestation intermediate when
NVIDIA rotates it; `country` is for development gateways only. Call `close()` when you are done.

| Method | What it does |
|---|---|
| `models()` / `profile(profile_id)` | model profiles, availability and the switch |
| `manifest()` | the golden manifest in use |
| `route(mode, model=None, family=None, privacy="private", *, resolution=None, aspect_ratio=None, fps=None, duration_s=None)` | which profile and enclaves would serve a request; the size, frame rate and duration list only workers whose hardware can fit them (their serving envelope). `generate`, `prepare` and `submit_standard` send the request's own |
| `generate(prompt, ..., privacy="private")` | private: route, verify, encrypt, submit; standard: upload, create. Waits by default |
| `prepare(...)` / `submit(prepared)` | the private path, in two steps |
| `submit_standard(prompt, ...)` / `upload_standard(role, data, mime)` | the standard path, in pieces |
| `delete(job_id)` | delete a job's stored content, in either mode |
| `standard_videos(limit=50)` / `standard_job(job_id)` | your standard jobs, and a handle on one |
| `eligibility()` | private-mode eligibility, restriction and strike counts |
| `report(reason, ...)` | report a video (no credential sent) |
| `provenance(video)` / `provenance_by_digest(sha256)` | look up a film's public certificate |
| `shares.create(job, expires_at=None)` | make a share link; `url` carries a private `VideoJob`'s key as `#k=...` |
| `shares.list(job_id=None, limit=100)` / `shares.revoke(share_id)` | your links with `status` and `view_count`, or stop one |
| `shares.get(link)` / `shares.open(link, key=None)` | public (no credential): a link's details, or its video checked and decrypted |

`share_url_with_key(url, output_key)` adds a private video's key to a link, and
`parse_share_link(link)` returns `(token, key)`.

Failures raise `KunoError` with `status`, `code`, `message` and `details` (the rest of the error
body, with `reasons` and `restricted_until` properties). The gateway holds a job's price
when it is submitted and refunds it automatically if the job fails, is blocked (`safety_blocked`),
is canceled or times out. A profile's `pricing.usd_per_second` is the Private price and
`pricing.standard_usd_per_second` the lower Standard one (`kuno_protocol` computes a job's price
with `profile.price_usd(params, privacy)`). A profile without a Standard price is Private-only, and a
Standard request for it fails with `privacy_mode_unavailable`; every profile has one today. All prices are placeholders.
