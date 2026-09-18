---
name: kunoworld-video
description: Make videos with sound, privately, with KunoWorld (LTX-2.5 and MiniMax H3), including long storyboards of up to 12 shots and 120 s. Use when the user asks to generate, animate or storyboard a video or clip, wants a video made without the provider seeing the prompt or the result, or asks what a video would cost. Covers quoting before spending, Private vs Standard mode, writing prompts for LTX-2.5 and H3, planning storyboard shots and joins (yourself, or with a plan written from a brief inside the enclave), and the content rules. Works through the kunoworld MCP tools or the kunoworld Python SDK.
---

# KunoWorld video

KunoWorld renders video with native audio on GPUs in attested confidential enclaves. Models: `ltx-2.5-fast`,
`ltx-2.5-pro`, `ltx-2.5-4k` (Lightricks LTX-2.5) and `h3-turbo`, `h3`, `h3-reference` (MiniMax H3). Call `list_models`
for current limits, availability and prices rather than assuming them. Prices are placeholders during the preview.

## Private or Standard

- **Private** (default): the prompt, shots, images and video are encrypted on the user's computer to an attested GPU
  enclave. KunoWorld and the GPU provider can't see them. Needs an account in good standing with a credited top-up. A
  lost job handle (output key) means a lost video.
- **Standard**: cheaper, and most jobs can run on any GPU. KunoWorld and the GPU provider can see the prompt, inputs
  and video. Choose it only when the user agrees to that.
- **Either way, you see the conversation.** Private mode doesn't hide anything from you, the assistant, or from your
  provider: you see what the user types and what the tools return. Say so if the user assumes otherwise.

## Spend only what the user agreed

1. Pick the model and settings (`list_models`).
2. `quote_price` with the same arguments you'll generate with. It routes the job as a real one and returns the exact
   `price_usd`, the model that would serve it (`fallback_reason` when it isn't the one asked for), the settings priced
   and a breakdown.
3. Tell the user the price, the model and the privacy mode. Wait for agreement unless they already set a budget.
4. `generate_video` with `max_price_usd` set to the agreed amount. It quotes again and refuses (`over_budget`) without
   creating or charging anything if the price went up. `KUNOWORLD_MAX_JOB_USD` in the server's configuration caps every
   job, and only the user can raise it.
5. Follow the job with `get_job` every 15 to 30 s (renders take minutes), then `download_video`. It verifies the signed
   receipt, decrypts a Private video locally and returns the file path. Failed, blocked and canceled jobs are refunded.

A quote refusal names the problem the job would hit: `invalid_params` (duration, size, fps), `no_capacity` (with
`max_duration_s`: shorten the clip or shot), `region_restricted` (MiniMax H3 isn't licensed in the US, EU, UK or South
Korea; use LTX-2.5), `private_mode_not_eligible` (offer Standard, or the user tops up).

## Choosing a model

| Need | Model |
|---|---|
| Most text or image to video, keyframes, 24 to 50 fps | `ltx-2.5-fast` (2 to 20 s; 10 s at 48 or 50 fps) |
| Anything longer than one clip, a sequence of shots | `ltx-2.5-fast` storyboard |
| Higher quality LTX, a negative prompt, audio-driven video | `ltx-2.5-pro` (up to 10 s) |
| 1440p or 2160p | `ltx-2.5-4k` |
| Rich multilingual dialogue, 768p, 5 to 14 s, where licensed | `h3-turbo` (cheapest) or `h3` |
| Reference images, video edit or extension | `h3-reference` (MiniMax H3 Director) |

Where H3 isn't licensed, a request for it falls back to LTX-2.5; say so and use LTX-2.5 prompting.

## Prompts

- **LTX-2.5:** one paragraph of plain prose, about 200 words at most. Say what the subject does in order, the setting,
  the light, the camera move and the style ("35 mm film", "photorealistic"). Describe the sound, and put spoken lines in
  quotes. Details: [references/prompting.md](references/prompting.md).
- **MiniMax H3:** its own sections (`integrated_multimodal_description:`, `overall_soundscape:`,
  `non_diegetic_music:`) with `[Shot n]` cuts and dialogue tags. Details: [references/prompting.md](references/prompting.md).
- **With a first frame:** describe the motion from that image, not the image itself.

## Storyboards

One job: 2 to 12 shots rendered in order on one worker and stitched into one video with one receipt, up to 120 s.
LTX-2.5 Fast only, and no image inputs. Pass `prompt` as the scene every shot shares (characters, place, style) and
`shots`, each with its own `prompt`, `duration_s` and `join`:

- `continue`: the same take goes on from the previous shot's last frames and sound. The join can't be seen.
- `cut`: a new picture over the same voice and room tone.
- `fresh`: nothing carried over, a new scene.

Keep shots to 11 s or less at 720p, the most today's 96 GB workers take (4 s at 1080p); a longer shot needs larger
workers, and the quote says `no_capacity` when none is online. Each `continue` or `cut` join trims 17 frames (about
0.7 s at 24 fps), so the video is a little shorter than its shots added up, and the price is for the stitched seconds.
While it renders, `get_job` shows `shot 3/8`. Planning and examples: [references/storyboards.md](references/storyboards.md).

### A plan from a brief

`plan_video` has a confidential worker write the storyboard from the user's brief: a title, a scene and 2 to 12 shots
with prompts, lengths and joins, fitted to `target_s` (4 to 120 s). Nothing renders. It's optional: you can write the
shots yourself as above, which costs nothing and keeps the brief out of another model.

1. A plan costs a flat price whatever its length (`list_models` shows `plan.usd`), under the same budget rule:
   `max_price_usd` or the server's cap. Tell the user before planning.
2. `plan_video` waits (plans take seconds to about a minute) and returns the plan, its `plan_id`, and `render_price`,
   the quote for rendering it. With `wait=false`, follow it with `get_job`.
3. Show the user the scene and the shots, the stitched length, `repairs` (what the code changed, such as shots
   shortened to fit) and the render price. The planner is a small model: its plans are first drafts, and it nearly
   always picks `cut` joins; suggest `continue` where one unbroken take suits the story.
4. To change it, `revise_plan` with `plan_id`, an instruction and, for single shots, `shots` (numbered from 1); the
   other shots come back unchanged. To edit text yourself, pass the edited plan as `plan` to `revise_plan`, or render your
   edit with `generate_video` using its `scene` as `prompt` and its `shots`.
5. Render with `generate_video` and `plan_id` (and `max_price_usd` at the agreed render price). It renders in the plan's
   privacy mode unless told otherwise.

In Private mode the brief is sealed on the user's computer and the plan is opened there; the finished plan is kept in
the local job store so it can be revised or rendered by id. `plan_failed` means the planner wrote nothing usable: it is
refunded, so rephrase the brief (shorter, concrete, with the length and what happens) and try again.

## Content rules (both modes)

- **No sexual content or nudity**, of anyone, real or fictional. Nothing that sexualizes minors, ever.
- **Real people:** don't show a real, identifiable person without their consent, and never in intimate or sexual
  imagery. Don't make a real person appear to say or do something they didn't in a way meant to, or likely to, deceive.
  No content for fraud, scams or election manipulation.
- No harassment, threats, incitement to violence, or infringement of someone's intellectual property, privacy or
  publicity rights.
- Every prompt and shot is checked: by the gateway in Standard mode (`content_policy`, before the job exists), inside
  the enclave in Private mode (`safety_blocked`, refunded). Either costs nothing but counts as a strike (except a block of text the enclave's own model wrote, such as an enhanced prompt or a plan), and repeated
  strikes restrict the account. Don't reword a blocked prompt to slip past the check; decline the request instead.
- MiniMax H3's licence requires that its videos shared publicly are clearly disclosed as machine-generated. Suggest the
  same for any AI video the user publishes.

## Without MCP: the Python SDK

```python
from kunoworld import KunoClient, Shot

kuno = KunoClient(api_key, owner_public_key=OWNER_KEY)
shots = [Shot("The boat leaves the harbor.", 5), Shot("Close on the skipper, humming.", 4, join="cut")]
quote = kuno.quote("ltx-2.5-fast", shots=shots, resolution="720p")          # prompts are not sent
result = kuno.generate("A small blue fishing boat, 35 mm film.", model="ltx-2.5-fast", shots=shots,
                       resolution="720p", max_price_usd=quote.price_usd)     # over_budget if the price rose
result.save("harbor.mp4")
```

`generate(..., wait=False)` returns a job whose `export()` holds the output key: store it like a password.
