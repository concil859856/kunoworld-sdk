# kunoworld

The Python client for KunoWorld. It encrypts prompts and reference media on your machine, to a
GPU enclave whose attestation evidence it checks first; verifies the enclave-signed receipt;
and decrypts the finished video locally. Requires Python 3.10+.

> **Development preview.** Workers on development gateways use simulated attestation and may
> return placeholder video. Real TDX and NVIDIA evidence verification is not built yet.

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

# The golden manifest lists the enclave measurements you trust. Get it from your operator
# through a trusted channel and pin it, rather than trusting whatever the gateway serves.
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

Without `manifest=`, the client falls back to the manifest the gateway serves and warns you to pin one.

## Private or Standard

Every job has a privacy mode, set with `privacy=`:

- `"private"` (the default) is everything above: encrypted on your machine to an attested
  confidential enclave, and opened only with the job's output key. Nobody at KunoWorld can read
  it. Private jobs only ever run on confidential-tier miners.
- `"standard"` sends the prompt and inputs to KunoWorld readable. **KunoWorld and the GPU provider
  can see the video and your prompt.** There is no client-side encryption and no key to keep; the
  job can run on any miner, and KunoWorld keeps the video, prompt and inputs (30 days by default)
  so your API key can fetch them again.

```python
result = kuno.generate("A paper boat crosses a rain puddle", model="ltx-2.5-fast", privacy="standard")
result.save("boat.mp4")        # checked against the receipt's content digest
print(result.privacy)          # "standard"

for row in kuno.standard_videos():          # this account's standard jobs, newest first
    print(row["job_id"], row["status"])
job = kuno.standard_job(row["job_id"])
open("poster.jpg", "wb").write(job.thumbnail())
job.delete()                                # deletes the stored video, prompt and inputs
```

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
| `safety_blocked` | the in-enclave content check stopped the job; it counts as a strike |
| `bad_output` | the video didn't match its receipt, so the job failed and was refunded |
| `expired` / `deleted` / `removed` (410) | a standard video or thumbnail is past retention, was deleted, or was removed after review |

The rest of an error body is on `err.details`. An indefinite restriction (until an operator
reviews the account) has `restricted_until` 253402300799, in year 9999; it is never `None` while
an account is restricted. Rows from `standard_videos()` also carry `expires_at` and `deleted`.

### Reporting a video

```python
report_id = kuno.report("copyright", content_digest=sha256, details="This is my film.")
```

Reports are sent without your API key. The reason is one of `csam`, `sexual_minor`,
`nonconsensual_intimate`, `violent_extremism`, `harassment`, `copyright` or `other`; identify the
video with `content_digest`, `job_id` or `url`. Pass `output_key` only for a private video you were
given with its key and want reviewed: it opens that one video.

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

`KunoClient(api_key, base_url="https://api.kunoworld.com", *, manifest=None, country=None,
timeout=60.0, transport=None)` — `country` is for development gateways only. Call `close()`
when you are done.

| Method | What it does |
|---|---|
| `models()` / `profile(profile_id)` | model profiles, availability and the switch |
| `manifest()` | the golden manifest in use |
| `route(mode, model=None, family=None, privacy="private")` | which profile and enclaves would serve a request |
| `generate(prompt, ..., privacy="private")` | private: route, verify, encrypt, submit; standard: upload, create. Waits by default |
| `prepare(...)` / `submit(prepared)` | the private path, in two steps |
| `submit_standard(prompt, ...)` / `upload_standard(role, data, mime)` | the standard path, in pieces |
| `standard_videos(limit=50)` / `standard_job(job_id)` | your standard jobs, and a handle on one |
| `eligibility()` | private-mode eligibility, restriction and strike counts |
| `report(reason, ...)` | report a video (no credential sent) |
| `provenance(video)` / `provenance_by_digest(sha256)` | look up a film's public certificate |

Failures raise `KunoError` with `status`, `code`, `message` and `details` (the rest of the error
body, with `reasons` and `restricted_until` properties). The gateway holds a job's price
when it is submitted and refunds it automatically if the job fails, is canceled or times out.
