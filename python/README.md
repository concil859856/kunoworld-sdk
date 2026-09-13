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
| `route(mode, model=None, family=None)` | which profile and enclaves would serve a request |
| `generate(prompt, ...)` | route, verify, encrypt, submit and (by default) wait |
| `prepare(...)` / `submit(prepared)` | the same, in two steps |
| `provenance(video)` / `provenance_by_digest(sha256)` | look up a film's public certificate |

Failures raise `KunoError` with `status`, `code` and `message`. The gateway holds a job's price
when it is submitted and refunds it automatically if the job fails, is canceled or times out.
