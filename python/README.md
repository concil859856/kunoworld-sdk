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
| `invalid_params` (422, or before sending) | the request doesn't fit the model's limits, including a storyboard's shots and stitched length |
| `over_budget` (before sending) | the gateway's quote is over `max_price_usd`; nothing was uploaded, sealed or charged. `err.details` has `price_usd` and `max_price_usd` |
| `invalid_budget` (before sending) | `max_price_usd` isn't an amount of zero or more |
| `quote_mismatch` (before sending) | the gateway quoted other params than the job about to be sent (routing changed in between); try again |
| `invalid_shots` (422, or before sending) | a storyboard without one non-empty prompt per shot, or `shots` on a job that isn't a storyboard |
| `prompt_too_long` (422, or before sending) | a prompt, or a storyboard's scene and one shot's prompt together, is over the model's limit |
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
| `rules_not_affirmed` (422, or before sending) | an Element write without `affirm_rules=True` |
| `invalid_element` (before sending) | an Element draft breaks the rules (name, description, kind, files or consent record), or a use of one doesn't fit the request |
| `consent_withdrawn` (before sending) | the person in an Element withdrew consent, so `attach` refuses it |
| `no_vault` / `vault_changed` (409) | key sync is off, or its keys were rotated since this Elements key was derived: get the current key from the studio |
| `element_exists` / `element_changed` (409) | the Element id is taken, or another device changed the Element since it was read |
| `elements_full` / `storage_full` (409) | 200 Elements, or 2 GiB of their files, per account |

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

## Storyboards (long videos from chained shots)

A storyboard is one job of 2 or more shots that one worker renders one after another and returns as one stitched video,
with one receipt. Pass `shots` to `generate` and the mode is `storyboard`; `prompt` is then the scene every shot shares
(characters, place, style) and may be `""`. Only `ltx-2.5-fast` offers it today: at most 12 shots and 120 s stitched
(`kuno.profile("ltx-2.5-fast").limits.storyboard`).

```python
from kunoworld import Shot

result = kuno.generate(
    "A small blue fishing boat with a red stripe, in a quiet harbor. Soft morning light, 35 mm film.",
    shots=[
        Shot("The boat leaves the harbor, gulls circling.", duration_s=5),
        Shot("It passes the lighthouse at the end of the breakwater.", duration_s=5),                 # join="continue"
        Shot("Close on the fisherman at the wheel, humming to himself.", duration_s=4, join="cut"),
        Shot("Night: the boat's lamp alone on a dark sea.", duration_s=6, join="fresh"),
    ],
    model="ltx-2.5-fast",
    resolution="720p",
)
result.save("harbor.mp4")
```

- **`Shot(prompt, duration_s=None, join=None)`.** Each shot keeps to the model's own clip limits (2 to 20 s in 1 s steps
  at 24 or 25 fps, up to 10 s at 48 or 50); `duration_s=None` is 5 s. The model sees the scene, a blank line and the
  shot's prompt, and that must fit `limits.max_prompt_chars` (`prompt_too_long`).
- **`join`** says what a shot starts from. `"continue"`: the previous shot's last frames and sound, so the take goes on
  unbroken. `"cut"`: only the sound, so a new picture over the same voice and room tone. `"fresh"`: nothing. The first
  shot is always `"fresh"`; `join=None` is `"fresh"` for the first shot and `"continue"` after it.
- **Length.** The client computes `duration_s` from the shots (`kuno_protocol.profiles.storyboard_duration_s`): a
  `continue` or `cut` shot repeats the previous shot's last 17 frames, which are trimmed, so the video is a little
  shorter than the shots added up. Don't pass `duration_s` with `shots` (`invalid_params`). Storyboards take no
  inputs (`invalid_inputs`), and every shot needs a prompt (`invalid_shots`).
- **Private and Standard.** In Private mode the shot prompts are sealed with the scene, as the prompt is. In Standard
  mode they are sent as `shots` next to `prompt`; the gateway checks each one against the content policy and returns
  them wherever it returns the prompt (`standard_videos()`).
- **Routing.** Shots render one at a time, so the client asks `/v1/route` for the longest shot (`duration_s`) and picks a
  worker that fits it, however long the stitched video is.
- **Price.** You pay the model's per-second rate for the stitched seconds. `kuno.quote("ltx-2.5-fast", shots=[...],
  resolution="720p")` asks the gateway for the exact price ([Prices, quotes and budgets](#prices-quotes-and-budgets));
  `kuno.estimate_price(...)`, with the same arguments, computes it locally from the published prices. Three 5 s shots
  with two joins are 13.708 s: $1.645 Private at 720p.
- **Seeds.** Shot *i* (from 0) renders with seed `(seed + i) mod 2^31`.
- **Not verified yet.** Storyboards carry no step commitment, so validators don't step-audit them.

## Plans from a brief (Director)

`kuno.plan(brief, target_s=...)` has a storyboard written for you: a scene and 2 to 12 shots, each with a beat (a short
label), a prompt, a length and a join, fitted to `target_s` seconds (4 to 120). The planner is the small language model
bundled with LTX-2.5, run inside a confidential worker, so nothing renders and the plan is a first draft: read it, edit
it, have shots rewritten, then render it as the storyboard above.

```python
plan = kuno.plan(
    'A 30-second ad for a small coffee roastery, warm and handmade. End on "Roasted this morning."',
    target_s=30, style="35mm film, warm",                 # model="ltx-2.5-fast", privacy="private" by default
)
print(plan.title, plan.duration_s, plan.repairs)          # 30.375 s; every change code made to the planner's text
for shot in plan.shots:
    print(shot.beat, shot.duration_s, shot.join, shot.prompt)

plan.shots[3].prompt += " The camera slowly pushes in."   # edit freely
plan = kuno.revise_plan(plan, "darker, at night", shots=[2])   # rewrite shot 2 only; the rest comes back unchanged
video = kuno.generate(plan=plan, max_price_usd=5)          # renders exactly this storyboard
```

- **`Plan`** is Plan v1 (`kuno_protocol.plans.Plan`): `profile_id`, `resolution`, `aspect_ratio`, `fps`, `audio`,
  `target_s`, `duration_s` (the shots' exact stitched length), `title`, `scene`, `shots`, `notes`, `repairs` and
  `planner`, plus `job_id`, `receipt` and `privacy`. `plan.to_shots()` gives the `Shot`s; `plan.to_json()` its canonical
  JSON, which `Plan.model_validate_json` reads back.
- **`generate(plan=plan)`** renders it as a storyboard: the scene is the prompt, the shots are the shots, and the plan's
  model, size, frame rate and sound are the job's. Pass no prompt, shots or `duration_s` with it; a model, resolution,
  aspect ratio or fps given must be the plan's (`invalid_params`). `quote(plan=plan)` and `estimate_price(plan=plan)`
  price the render.
- **`revise_plan(plan, instruction, shots=None)`** is a new plan job with the same frame and target. With `shots`
  (numbered from 1) only those shots are rewritten, and only their lengths move; without, the whole plan is. Edited shot
  lengths are measured again before it is sent; a plan that breaks the rules is refused as `invalid_plan` first. It
  takes a `Plan`, its dict or its JSON, and keeps the plan's privacy unless you pass one.
- **Private** (the default) routes only to attested workers whose `/v1/route` entry lists the `plan/1` feature, and
  seals the brief and style on this machine. The client asks for shots no longer than the longest those workers render
  at this size and frame rate (`options.plan.max_shot_s`), the rule the storyboard is later routed by. It opens the
  sealed plan here, refusing anything but padded plan JSON, and checks it against the enclave-signed receipt and the
  plan rules (`kuno_protocol.plans.validate`). The gateway sees the target length, the frame, the price, the status and
  the receipt; never the brief or the plan. No worker that writes plans: `plans_unavailable`, before anything is sent.
- **Standard** (`privacy="standard"`) sends the brief and style to `POST /v1/standard/plans`, readable by KunoWorld,
  which checks them against the content policy and keeps the plan until you delete it; the client reads it back from
  `GET /v1/standard/plans/{job_id}` and checks it against the receipt's `content_digest`.
- **Price.** A plan costs a flat price whatever its length: `kuno.quote("ltx-2.5-fast", mode="plan", duration_s=30)`
  (`breakdown.plan_usd`), or `estimate_price(..., mode="plan")`. `max_price_usd` works as for videos. A plan the planner
  couldn't write (`plan_failed`) or that was blocked (`safety_blocked`) is refunded.
- **Waiting.** Plans take seconds to about a minute (stages `planning`, then `checking`). `wait=False` returns a
  `PlanJob`; `job.export()` holds a Private job's output key, `PlanJob.restore(kuno, data).wait()` finishes it later.

## Prices, quotes and budgets

`kuno.quote(...)` asks the gateway for the exact price of a job before anything is encrypted or sent
(`POST /v1/quote`). It takes `generate`'s job-shape arguments and no prompt, routes the request as the job would be
routed (fallbacks, licence regions, capacity), fills in the same defaults, and prices those params with the function
that charges the job.

```python
from kunoworld import Shot

quote = kuno.quote("ltx-2.5-fast", shots=[Shot("", 5), Shot("", 5), Shot("", 5, join="cut")], resolution="720p")
print(quote.price_usd, quote.profile_id, quote.fallback_reason)   # 1.645 ltx-2.5-fast None
print(quote.breakdown)      # usd_per_second, billable_seconds (stitched), fps and long-clip multipliers, minimum
print(quote.params)         # the GenerationParams priced
print(quote.balance_usd, quote.balance_covers, quote.placeholder)
```

- **What it takes.** `model`, `family`, `mode`, `duration_s`, `shots` (`Shot`s, whose prompts are never sent, or
  `ShotSpec`s), `resolution`, `aspect_ratio`, `fps`, `audio`, `privacy`, and `input_roles` for the inputs the job will
  send. The mode follows from those roles as `generate` infers it; without any, the inputs the mode needs are assumed.
- **Refusals** carry the code the job itself would get: `invalid_params`, `invalid_shots`, `privacy_mode_unavailable`,
  `region_restricted`, `model_disabled`, `no_capacity` (with `max_duration_s` when no worker's hardware fits),
  `private_mode_not_eligible` and `account_restricted`.
- **A quote holds nothing.** The price is taken when the job is accepted. If routing or prices change in between, the
  job is priced again the same way. `estimate_price` computes a price locally from `/v1/models`, without routing.

**Budgets.** Pass `max_price_usd` to `generate`, `prepare` or `submit_standard`. After routing and filling in the params,
the client has the gateway quote exactly those params, and raises `over_budget` when the price is over the limit:
nothing is uploaded, sealed, submitted or charged, and `err.details` has `price_usd` and `max_price_usd`. A price equal
to the limit goes ahead; `prepared.quote` keeps the quote.

```python
try:
    job = kuno.generate(prompt, model="ltx-2.5-fast", duration_s=10, max_price_usd=1.00, wait=False)
except KunoError as err:
    if err.code == "over_budget":
        print(f"It would cost ${err.details['price_usd']}")
```

## Elements: reusable characters, products, locations, styles and voices

An Element is a named character, product, location, style or voice you reuse across videos: 1 to 4 images (or one
voice clip), a short description the prompt can use ("Mara: a woman in her 60s with short silver hair and a green
raincoat"), and, for a real person, a consent record. **Everything about it is encrypted on this machine** before it
reaches KunoWorld, which stores only ciphertext and can't open it. These are the JavaScript SDK's Elements, byte for
byte: an Element made here opens in the studio and the JavaScript SDK, and theirs open here.

**The rules.** No public figures and no one under 18. A real person must be you, or must have given you permission,
and their consent record says who, when and for what. Sexual content is banned, as everywhere on KunoWorld. Every write
affirms these rules (`affirm_rules=True`, `ELEMENT_RULES`); without it nothing is sent (`rules_not_affirmed`).

**The key.** Elements are encrypted with an *Elements key*, derived from the key sync master key the website holds, so
your other devices open them once key sync is unlocked there. A program gets the key as text from the studio's Elements
page and keeps it with its other secrets:

```python
import os
from kunoworld import ElementConsent, ElementFile, KunoClient, parse_elements_key

kuno = KunoClient(api_key=os.environ["KUNO_API_KEY"])
key = parse_elements_key(os.environ["KUNO_ELEMENTS_KEY"])   # "kwek1.<account id>.<key id>.<key>"

mara = kuno.elements.create(
    key,
    kind="character",                                       # character | product | location | style | voice
    name="Mara",
    description="a woman in her 60s with short silver hair and a green raincoat",
    consent=ElementConsent(subject="Mara Jones", relationship="permission", granted_on="2026-09-01",
                           use="Videos made on KunoWorld"),  # affirmed_at defaults to now
    files=[ElementFile.load("mara.jpg")],                   # the type is read from the bytes
    affirm_rules=True,
)

listed = kuno.elements.list(key)          # listed.elements, listed.unreadable, listed.key_id, listed.stored_bytes
```

The Elements key opens Elements only: it is HKDF-SHA256 of the master key, which it can't be turned back into, so it
opens no video key. **Rotating key sync replaces it**: writes with the old one fail with `vault_changed`, and `list`
reports Elements it can't open in `unreadable` (`key_rotated`). Get the new key from the studio.

**Using one in a video.** `attach` opens the Element's files here and returns the request with them in it, as the
studio's composer does: the files go in as inputs in the roles you choose, and each Element's description is added to
the prompt on its own line. A Private job then seals them to the enclave like any input; a Standard job uploads them
readable, so KunoWorld and the GPU provider can see them.

```python
from kunoworld import ElementUse

request = kuno.elements.attach(
    {"prompt": "She walks along the pier at dusk.", "model": "ltx-2.5-fast"},
    [ElementUse(mara, "first_frame")],                      # file=0 by default; a keyframe needs time_s
)
video = kuno.generate(**request, max_price_usd=2)
```

- **The request.** `attach` takes `generate`'s keyword arguments and fills `first_frame`, `last_frame`, `keyframes`,
  `reference_images` and `reference_audio`; a request with an `inputs` list (for `prepare` or `submit_standard`) gets
  `Input`s appended instead. A single-file role already filled is refused (`invalid_element`), and every use is checked
  before any file is downloaded.
- **Which roles.** `element_roles(element, kuno.profile(model_id))` lists what an Element's files can be on a model:
  images as `first_frame`, `last_frame` or `keyframe` on LTX-2.5, or `reference_image` on MiniMax H3 Director
  (`file="all"` adds every image); a voice as `reference_audio` on MiniMax H3 Director (`h3-reference`) only. H3 is
  licensed only in some regions; elsewhere a voice is stored for later and its description still works. Pass an
  `Element` on its own, or `ElementUse(element)` without a role, to use only the description.
- **Storyboards** take descriptions only, added to the scene: their shots take no inputs. A plan brings its own scene:
  add lines to it with `add_element_lines(plan.scene, [mara])` before rendering.
- **Withdrawn consent.** `kuno.elements.withdraw_consent(key, element, affirm_rules=True)` writes `withdrawn_at` into the
  sealed record; `attach` then refuses the Element (`consent_withdrawn`). Deleting it removes it for good.

`update(key, element, name=..., description=..., consent=..., kind=..., files=None, affirm_rules=True)` changes what is
given and keeps the rest (`consent=None` removes the record). Without `files` it keeps the files and their key; with
`files` it replaces all of them under a new key. It names the revision it read, so a change from another device in
between fails with `element_changed`. `delete(element_id)` removes the record and files, and `file(element, position)`
downloads and opens one file, checking it against the digest in the record.

**Limits.** 200 Elements and 2 GiB per account; 4 images or one voice clip (up to 30 seconds) each; 15 MB per file; a
name of 80 characters and a description of 1,000. 60 changes a minute. `element_draft_problems(kind=..., name=...,
files=...)` returns the problems with a draft as sentences before anything is sent.

**What KunoWorld sees.** That the account has Elements, their random ids, revisions and times, how many files each has,
their padded sizes, and when they are downloaded. Not their kind, name, description, consent record or pictures. The
formats are in `platform/gateway/ELEMENTS.md`; `kunoworld.elements` has the sealing primitives (`derive_elements_key`,
`seal_element`, `open_element`, `wrap_element_key`, `rewrap_element_key` for a key sync rotation, `record_json`). The
record's JSON is written as JavaScript writes it, so its padded size doesn't say which SDK wrote it; consent is written
in the studio's form, with `withdrawnAt` null until it is withdrawn.

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

`job.status()` and `job.cancel()` are there too, and `kuno.status(job_id)` and `kuno.cancel(job_id)` work with the id
alone, in either mode. Stopping `wait` does not cancel a job. For full control, `kuno.prepare(...)` builds and encrypts a
request without sending it, and `kuno.submit(prepared)` sends it.

## Agents (MCP)

`kunoworld-mcp` is a local [MCP](https://modelcontextprotocol.io) server for AI assistants such as Claude Code, Claude
Desktop and Cursor. It runs on your computer and talks to the assistant over stdio, so Private mode works as it does in
your own program: the prompt, shots and images are encrypted here, to an attested confidential GPU, and videos are
decrypted here. KunoWorld runs no hosted MCP server, because a hosted server would receive prompts readable.

**What the assistant can see.** Private mode keeps the prompt and the video from KunoWorld and the GPU provider. It
doesn't keep them from the assistant: the assistant, and whoever provides it, see whatever you type into the
conversation and whatever the tools return (job ids, prices, settings, file paths and receipt digests; never a video's
bytes or its key). The tool descriptions say so too.

### Install

The server is in the `mcp` extra, built on the official MCP Python SDK (1.x, FastMCP):

```bash
uv pip install -e /path/to/kunoworld-subnet/protocol -e '/path/to/kunoworld-sdk/python[mcp]'
```

In the KunoWorld development workspace, `uv sync` installs it as `.venv/bin/kunoworld-mcp`. `uvx` runs it without
installing, from source until the packages are on PyPI:

```bash
uvx --with /path/to/kunoworld-subnet/protocol --from '/path/to/kunoworld-sdk/python[mcp]' kunoworld-mcp
```

### Add it to your assistant

Claude Code:

```bash
claude mcp add --transport stdio kunoworld --env KUNOWORLD_API_KEY=kw_live_... --env KUNOWORLD_MAX_JOB_USD=5 -- \
  uvx --with /path/to/kunoworld-subnet/protocol --from '/path/to/kunoworld-sdk/python[mcp]' kunoworld-mcp
```

Claude Code's project file `.mcp.json`, Claude Desktop's `claude_desktop_config.json` (Settings, Developer, Edit Config)
and Cursor's `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project) take the same entry:

```json
{
  "mcpServers": {
    "kunoworld": {
      "command": "uvx",
      "args": ["--with", "/path/to/kunoworld-subnet/protocol", "--from", "/path/to/kunoworld-sdk/python[mcp]", "kunoworld-mcp"],
      "env": {
        "KUNOWORLD_API_KEY": "kw_live_...",
        "KUNOWORLD_MAX_JOB_USD": "5",
        "KUNOWORLD_OWNER_PUBLIC_KEY": "<the subnet owner's Ed25519 public key, base64>"
      }
    }
  }
}
```

- With the script installed, use `"command": "/path/to/.venv/bin/kunoworld-mcp"` and no `args`. Once the packages are
  published, `"args": ["--from", "kunoworld[mcp]", "kunoworld-mcp"]` will do.
- Desktop apps may not see your shell's `PATH`. If the server doesn't start, give `uvx` as a full path (`which uvx`).
- Don't commit an API key in a project's `.mcp.json`. Claude Code expands `${KUNOWORLD_API_KEY}` there from your
  environment.

### Configuration

| Variable | Default | What it sets |
|---|---|---|
| `KUNOWORLD_API_KEY` | none | an API key from your account page. Without one, only `list_models` works |
| `KUNOWORLD_API_URL` | `https://api.kunoworld.com` | the gateway |
| `KUNOWORLD_PRIVACY` | `private` | the mode a job gets when the assistant doesn't choose one |
| `KUNOWORLD_MAX_JOB_USD` | none | a hard cap on every job's price. The assistant's `max_price_usd` can only lower it. Without the cap, every `generate_video` call needs `max_price_usd` |
| `KUNOWORLD_OUTPUT_DIR` | `~/KunoWorld` | where videos and their receipts are saved |
| `KUNOWORLD_JOBS_DIR` | `~/.kunoworld/jobs` | where job handles are kept |
| `KUNOWORLD_OWNER_PUBLIC_KEY`, `KUNOWORLD_MANIFEST` | none | check workers against the manifest the subnet owner signed, or against a pinned manifest file, instead of trusting the gateway's copy ([Generate a video](#generate-a-video)) |
| `KUNOWORLD_COUNTRY` | none | development gateways only: the country routing assumes |

### Tools

| Tool | What it does |
|---|---|
| `list_models` | models with their modes, durations, sizes, frame rates, storyboard and plan limits, availability, prices per second in both modes and the flat plan price |
| `quote_price` | the exact price of a job, the model that would serve it, the settings priced and a breakdown. The same arguments as `generate_video`, without the prompt; shot prompts aren't sent |
| `generate_video` | quotes, refuses over budget (`max_price_usd`, `KUNOWORLD_MAX_JOB_USD`), then submits and returns the job id; with `wait=true`, waits with progress notifications and saves the video. Takes the prompt, model or family, mode, duration, resolution, aspect ratio, fps, audio, seed, privacy, first-frame, last-frame and reference-image paths, and `shots` for a storyboard, or `plan_id` to render a plan as its storyboard (privacy defaults to the plan's) |
| `plan_video` | writes an editable storyboard from a brief in a confidential worker, at a flat price and under the same budget rule; nothing renders. Takes the brief, `target_s`, model, size, frame rate, sound, style, privacy and `max_price_usd`. Waits by default and returns the plan compactly (title, scene, shots with lengths and joins, stitched length, notes, repairs), its `plan_id`, and `render_price`, the quote for rendering it |
| `revise_plan` | rewrites a plan under an instruction: only the listed `shots`, or all of them. Takes `plan_id`, or the plan itself as `plan_video` returned it (edited or not), and returns a new plan with its own `plan_id` |
| `get_job` | status, stage (`shot 3/8` while a storyboard renders, `planning` or `checking` for a plan), progress, price and any error; a finished plan comes back with the plan and its render price |
| `download_video` | checks the video against its signed receipt, decrypts a Private video here, and saves it with its receipt; returns the path, size, SHA-256 and a receipt summary |
| `cancel_job` | cancels an unfinished job, which is refunded |
| `list_jobs` | the jobs this server started, newest first |

Errors come back as text that starts with the code, such as `over_budget: This video would cost $3.3 (LTX-2.5 Pro,
private), over the $3 limit set by KUNOWORLD_MAX_JOB_USD. ...` or `private_mode_not_eligible: ... (reasons:
no_verified_payment; ...)`.

The `kunoworld-video` skill (`sdk/skills/kunoworld-video` in the SDK repository) teaches an assistant when to use
KunoWorld, how to write prompts for LTX-2.5 and MiniMax H3, and how to plan storyboards.

### Keys, logs and files

- **Job handles stay on this computer.** A Private job's handle holds its output key, the only thing that opens the
  video. The server writes it to `KUNOWORLD_JOBS_DIR/<job_id>.json` before sending the job, in a directory only you can
  open (0700), readable only by you (0600). Handles go nowhere else, and no tool returns a key. Back the directory up
  and guard it like a password: KunoWorld can't recover a lost key.
- **No prompt or brief is stored or logged.** A handle keeps the job's settings, price and status, not its prompt or
  shots. A plan job's handle also keeps the finished plan (its scene and shot prompts, as the worker wrote them), so the
  assistant can revise or render it by `plan_id`; in Private mode that file is its only readable copy outside the
  conversation. The server logs only warnings, to stderr, and none carries a prompt or a key.
- **Videos** are saved readable only by you (0600), as `kunoworld-<job_id>.mp4` or a name the assistant gives, next to
  `<name>.receipt.json`. A different file already there is never overwritten.
- **Attestation.** Without `KUNOWORLD_OWNER_PUBLIC_KEY` or `KUNOWORLD_MANIFEST`, workers are checked against the manifest
  the gateway serves. `generate_video` says which one a Private job was checked against.

### On a development network

In the KunoWorld workspace, `KUNO_MINER_COUNTRY=JP scripts/dev.sh` starts a gateway on port 8080 and a mock worker
(the gateway refuses a worker that offers MiniMax H3 from an unknown country). Point the server at it with
`KUNOWORLD_API_URL=http://127.0.0.1:8080`, `KUNOWORLD_API_KEY` set to `KUNO_DEV_API_KEY` from `data/dev.env`,
`KUNOWORLD_MANIFEST` set to the absolute path of `data/manifest.json`, and `KUNOWORLD_COUNTRY=JP`, the country a
development gateway routes for (MiniMax H3 is licensed there). Mock workers return placeholder video.

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
| `generate(prompt, ..., shots=None, privacy="private", max_price_usd=None, plan=None)` | private: route, verify, encrypt, submit; standard: upload, create. Waits by default. With `shots`, a storyboard; with `plan`, that plan's storyboard; with `max_price_usd`, `over_budget` before anything is sent when the quote is over it |
| `plan(brief, *, target_s, model="ltx-2.5-fast", resolution=None, aspect_ratio=None, fps=None, audio=True, style=None, privacy="private", seed=None, max_price_usd=None, wait=True, timeout=600.0, on_progress=None)` | a storyboard `Plan` written from a brief in a confidential worker (a `PlanJob` with `wait=False`) |
| `revise_plan(plan, instruction="", shots=None, *, brief="", style=None, privacy=None, seed=None, max_price_usd=None, wait=True, ...)` | a plan rewritten under an instruction: only the listed shots, or all of them |
| `quote(model=None, *, family=None, mode=None, duration_s=None, shots=None, resolution=None, aspect_ratio=None, fps=None, audio=True, input_roles=None, privacy="private", plan=None)` | the gateway's exact price for such a job now, as a `Quote`: `price_usd`, `profile_id`, `fallback_reason`, `params`, `breakdown`, `placeholder`, `balance_usd` |
| `estimate_price(model=None, *, duration_s=None, shots=None, resolution=None, aspect_ratio=None, fps=None, privacy="private", mode=None, plan=None)` | what such a job would cost, computed locally from the published prices; a storyboard's stitched seconds, a plan's flat price (`mode="plan"`), or rendering a `plan` |
| `status(job_id)` / `cancel(job_id)` | a job's `JobStatus`, or cancel it (refunded), in either mode |
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
| `elements.create(key, *, kind, name, files, description="", consent=None, affirm_rules=False, element_id=None)` | seal and store a new Element |
| `elements.list(key)` / `elements.get(key, element_id)` / `elements.rows()` | open your Elements (`unreadable` lists any this key can't), one Element, or the stored ciphertext and the vault's `master_key_id` |
| `elements.update(key, element, *, kind=None, name=None, description=None, consent="keep", files=None, affirm_rules=False)` / `elements.withdraw_consent(key, element, *, affirm_rules=False)` / `elements.delete(element_id)` | replace an Element (keeping its files and key when `files` is None), mark its consent withdrawn, or delete it |
| `elements.file(element, position=0)` / `elements.attach(request, uses)` | one opened file, or a request with Elements' files as inputs and their descriptions in the prompt |

`share_url_with_key(url, output_key)` adds a private video's key to a link, and
`parse_share_link(link)` returns `(token, key)`.

Element helpers: `parse_elements_key` / `format_elements_key`, `derive_elements_key`, `element_roles`,
`element_prompt_line`, `add_element_lines`, `element_draft_problems`, `consent_withdrawn`, `ElementFile.load`, and in
`kunoworld.elements` the sealing primitives with `ELEMENT_RULES` and `ELEMENT_LIMITS`.

Failures raise `KunoError` with `status`, `code`, `message` and `details` (the rest of the error
body, with `reasons` and `restricted_until` properties). The gateway holds a job's price
when it is submitted and refunds it automatically if the job fails, is blocked (`safety_blocked`),
is canceled or times out. A profile's `pricing.usd_per_second` is the Private price and
`pricing.standard_usd_per_second` the lower Standard one (`kuno_protocol` computes a job's price
with `profile.price_usd(params, privacy)`). A profile without a Standard price is Private-only, and a
Standard request for it fails with `privacy_mode_unavailable`; every profile has one today. All prices are placeholders.
