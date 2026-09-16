# Writing prompts for KunoWorld's models

The MCP tools send the prompt exactly as written, so write the finished prompt yourself. (LTX-2.5 Fast and Pro can also
run LTX's own prompt enhancer inside the enclave, with the Python SDK's `options={"enhance_prompt": True}`. MiniMax's
hosted H3 enhancer is never used: it would read the prompt.)

## LTX-2.5 (`ltx-2.5-fast`, `ltx-2.5-pro`, `ltx-2.5-4k`)

**Form.** One paragraph of plain, concrete prose, in the order things happen. Lightricks advises keeping it within
about 200 words; KunoWorld's limit is 4,000 characters. Write sentences, not lists of tags.

**Cover, in roughly this order:**
1. **Subject and action:** who or what, doing what, in sequence ("walks to the window, pauses, then turns back").
2. **Setting:** place, time of day, weather.
3. **Light and look:** "soft morning light", "neon reflections on wet asphalt", and the medium: "photorealistic",
   "35 mm film", "hand-drawn animation". State the medium every time: in a GPU test, a shot that didn't ask for a
   photograph came out as an illustration.
4. **Camera:** there are no camera controls, so write the move: "static shot", "slow push-in", "tracking shot following
   the cyclist", "handheld", "aerial view", "the camera pulls back to reveal the valley".
5. **Sound:** audio is generated with the picture. Name what is heard: ambience, effects, music, silence.
6. **Speech:** quote the exact words and say who speaks and how: `A calm older woman says: "We leave at dawn."` For
   lip-synced dialogue, stay at 24 or 25 fps and keep each line short enough to fit the clip.

**Several shots in one clip.** Write them as prose, naming each cut ("A hard cut to a close-up of her hands"),
re-establishing framing and re-identifying the characters after it, and saying whether the sound carries on. Two to four
shots in one clip at most; for more, use a storyboard.

**From a first frame** (`first_frame_path`, mode `image_to_video`): the image fixes the opening composition. Describe
what moves and how the camera behaves from there, and keep the subject consistent with the image. With a last frame too
(`first_last_frame`), describe the transition between the two.

**Negative prompts** are only for `ltx-2.5-pro` (the Python SDK's `negative_prompt`); the other models don't take one.

**Durations** are whole seconds: 2 to 20 s on Fast at 24 or 25 fps (10 s at 48 or 50), up to 10 s on Pro and 4K. 48
and 50 fps cost 1.5x; use them for fast motion, not dialogue.

**Example (Fast, 8 s, 720p):**

> A red vintage bicycle leans against a whitewashed wall in a narrow Greek alley at midday. A grey cat jumps onto the
> saddle, sniffs the handlebar basket and settles into a sunny patch. Photorealistic, 35 mm film, strong shadows. Static
> shot at the cat's eye level, then a slow push-in on its face as it closes its eyes. Distant church bells, a scooter
> passing in a nearby street, the cat's soft purr.

## MiniMax H3 (`h3-turbo`, `h3`, `h3-reference`)

Only where MiniMax H3 is licensed (not the US, EU, UK or South Korea). 768p, 24 fps, 5 to 14 s, sound always on, no
negative prompt, up to 7,000 characters. H3 follows MiniMax's structured prompt format, from the `h3-prompt-writing`
guides in the MiniMax-H3 repository; use its section names exactly.

**Sections:**

```
integrated_multimodal_description: [Shot 1] <what we see and hear, camera, light, style>
[Shot 2] At 00:04.500, the camera cuts to <the next shot>
overall_soundscape: <ambience and effects across the video>
non_diegetic_music: <1 to 3 sentences about the score, or N/A>
```

- **Shots:** `[Shot 1]` has no timestamp; each later shot starts with `At MM:SS.mmm, the camera cuts to ...`, with times
  increasing and inside the duration. With a first or last frame, H3 favours a single shot.
- **Dialogue:** wrap spoken lines in dialogue tags with the language, `<d>[English] We leave at dawn.</d>`, and name
  speakers `(S1)`, `(S2)`. H3 is most reliable in Arabic, Chinese, English, French, German, Italian, Japanese, Korean,
  Portuguese, Russian and Spanish.
- **Camera vocabulary:** Zoom In, Zoom Out, Arc Shot, Tracking Shot, Static Shot, push-in, truck left or right.
- **From a first frame:** begin the prompt with `For the target video, at 0.00 seconds into the target video,
  <Picture 1> (from [Shot 1]) is fully referenced.` and a blank line, then the sections.
- **References (`h3-reference`, H3 Director):** the order of the files sets their labels (`<Picture 1>`, `<Video 1>`,
  `<Audio 1>`). Declare what each is for in a `subject_definitions:` section, and how closely to keep it in
  `retention_analysis:` (`fully_preserved`, `partially_preserved`, `attribute_transfer`, `weak_reference`; for audio
  `fully_copy`, `partially_copy`, `reference`), before `detailed_description:`, `overall_soundscape:` and
  `non_diegetic_music:`.

**Example (H3 Turbo, 10 s):**

```
integrated_multimodal_description: [Shot 1] Wide shot of a night market in Taipei after rain, lanterns reflected in
puddles, steam rising from food stalls. A young street vendor (S1) flips scallion pancakes and calls out to the crowd:
<d>[English] Fresh and hot, two for one!</d> Photorealistic, handheld, warm tungsten light.
[Shot 2] At 00:06.000, the camera cuts to a close-up of a pancake sizzling on the griddle, oil popping.
overall_soundscape: Crowd chatter, sizzling oil, scooters passing on wet asphalt.
non_diegetic_music: N/A
```
