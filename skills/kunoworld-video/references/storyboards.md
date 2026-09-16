# Planning a KunoWorld storyboard

A storyboard is one job: 2 to 12 shots rendered one after another by one worker, inside one enclave, joined from each
shot's final latents and delivered as one video with one receipt. It can't be assembled from separate jobs, because the
joins need latents that never leave the enclave. `ltx-2.5-fast` only, no image inputs, at most 120 s stitched.

## The request

`generate_video` (or the SDK's `generate`) with:

- `prompt`: **the scene**, what every shot shares: the characters and how they look, the place, the period, the look
  ("35 mm film", "photorealistic"). It may be empty.
- `shots`: in order, each `{prompt, duration_s, join}`.
  - `prompt`: what happens in this shot: action, camera, sound, dialogue.
  - `duration_s`: whole seconds, 2 to 20 at 24 or 25 fps (10 at 48 or 50). Default 5.
  - `join`: `fresh` for the first shot (the default), `continue` after it by default, or `cut`.
- `resolution`, `aspect_ratio`, `fps`, `seed` as for a clip. No `duration_s`: the length comes from the shots.

The model sees, for each shot, the scene, a blank line, then the shot's prompt, and that must fit 4,000 characters
(`prompt_too_long`). Shot *i* (from 0) uses seed `seed + i`.

## Joins

| Join | The shot starts from | Use it for |
|---|---|---|
| `continue` | the previous shot's last frames and matching sound, held fixed while it renders | one unbroken take: the camera keeps rolling while the action, light or place moves on |
| `cut` | the sound only, carried from the shots joined before it | a new angle or place over the same voice, music or room tone |
| `fresh` | nothing | a new scene, a time jump, a change of style |

What KunoWorld's first storyboard renders on a GPU (2026-09-16) showed:
- **`continue` joins can't be seen.** A 35 s take of 8 x 5 s shots kept the same boat, dock and horizon while the
  prompts moved from golden hour to dusk to night, with the light following the prompts and no jump at a join.
- **A `cut` or `fresh` shot can change style freely,** so restate the medium in the scene: a shot that didn't ask for a
  photograph came out as an illustration.
- **A voice over many cuts isn't proven.** Over 4 shots a narrator's pitch held; over 8 it wandered. Keep one speaker's
  lines within a run of `continue` shots where the voice matters, describe the voice the same way in every shot, and
  treat long `cut` chains with dialogue as experimental.
- **Audio at `continue` joins was mostly smooth;** a few joins may click.

## Lengths and price

- **Stitched length.** LTX renders `8k + 1` frames: `frames(d) = 8 × round(d × fps / 8) + 1`. Each `continue` or `cut`
  shot repeats the previous shot's last 17 frames, which are trimmed. So `stitched = (Σ frames(d) − 17 × joined shots) / fps`.
  At 24 fps, three 5 s shots with two joins are 329 frames, 13.708 s.
- **Price** is the per-second rate for the stitched seconds, with the fps multiplier: $1.645 Private at 720p for that
  example (placeholder prices). `quote_price` with the same `shots` returns it exactly.
- **Shot length is limited by the workers online, not only the model.** A storyboard renders one shot at a time, so a
  worker only has to fit the longest shot. Today's 96 GB workers (RTX PRO 6000) take 720p shots up to 11 s (5 s at 50
  fps) and 1080p 16:9 shots up to 4 s; longer shots need larger GPUs. If `quote_price` says `no_capacity` with
  `max_duration_s`, split the longest shots.
- **Time.** On an RTX PRO 6000 a 5 s 720p shot took about 14 s, and 8 x 5 s shots (35 s of video) about 2 minutes. Poll
  `get_job` meanwhile: its stage reads `shot 3/8`.

## Writing the shots

1. **Put identity in the scene.** Name each character's look ("a small blue fishing boat with a red stripe", "an old
   skipper in a yellow raincoat") once in `prompt`, and refer to them the same way in the shots.
2. **One beat per shot.** A 3 to 6 s shot holds one action and one camera move.
3. **Say the camera move** in each shot ("camera follows slowly", "close-up", "the camera pulls back").
4. **Carry the sound on purpose:** in `continue` runs, keep naming the ongoing ambience ("the engine humming"); on a
   `cut`, say what continues ("the same narrator says: ...").
5. **Keep durations 3 to 6 s** unless a shot needs more, and under the worker limit above.

## Examples

Adapted from two shot lists rendered on a GPU, with what the shots shared moved into the scene.

**One seamless take**, 4 x 5 s, `continue` joins, 18 s:

```json
{
  "prompt": "A small blue fishing boat returning to harbor at golden hour. Photorealistic, 35 mm film.",
  "shots": [
    {"prompt": "The boat heads into the harbor, gulls circling overhead, gentle waves, the low hum of its engine, wide shot.", "duration_s": 5},
    {"prompt": "The boat glides past the stone lighthouse at the harbor entrance, gulls calling, the engine humming, camera follows slowly.", "duration_s": 5, "join": "continue"},
    {"prompt": "The boat slows beside a wooden dock, ripples spreading across calm water, gulls landing on the dock posts, the engine idling.", "duration_s": 5, "join": "continue"},
    {"prompt": "The engine falls quiet and the boat rocks gently at the dock as the sun touches the horizon, soft lapping water.", "duration_s": 5, "join": "continue"}
  ],
  "resolution": "720p"
}
```

**A narrated sequence**, 4 x 5 s, cuts and a continue, 18 s:

```json
{
  "prompt": "A potter's studio with soft daylight. A calm, warm male narrator with a low voice. Photorealistic.",
  "shots": [
    {"prompt": "A potter's hands shape wet clay on a spinning wheel. The narrator says: \"Every bowl begins as a lump of clay and a little patience.\"", "duration_s": 5},
    {"prompt": "Close-up of the clay rising into a smooth cylinder between wet fingers. The same narrator says: \"Keep your hands wet, and let the wheel do the work.\"", "duration_s": 5, "join": "cut"},
    {"prompt": "The camera slowly pulls back as the potter's hands thin the rim of the bowl. The same narrator says: \"Slow down near the rim, where the wall is thinnest.\"", "duration_s": 5, "join": "continue"},
    {"prompt": "A row of finished bowls drying on a wooden shelf by a sunny window. The same narrator says: \"Tomorrow, they go into the kiln.\"", "duration_s": 5, "join": "cut"}
  ],
  "resolution": "720p"
}
```
