/**
 * Plans (Director): a storyboard written from a brief inside the enclave (PROTOCOL.md "Plans (Director)").
 *
 * A port of the parts of `kuno_protocol.plans` a client needs, checked against the shared `plans` vectors:
 *
 *   planContext   the limits a plan is written and fitted to (the job's frame, target and longest shot)
 *   fitPlan       durations snapped to the grid and caps, then moved until the stitched length is within 0.5 s of the
 *                 target; on a revision only the rewritten shots move (`fit`)
 *   validatePlan  every rule a delivered plan keeps (`validate`)
 *   briefQuotes   the phrases a brief puts in quotation marks, and which of them no shot contains (`missing_quotes`)
 *   openPlan      the sealed output: decrypted, form 2 framing only, parsed (`open_plan`)
 *
 * Text lengths count Unicode code points, whitespace is ECMAScript's `\s`, and seconds in repair notes have at most three
 * decimals, exactly as the Python module writes them.
 */

import { decryptBlob, DecryptionError, PAYLOAD_V2, payloadVersion, unpadPayload } from "./crypto.js";
import { canonicalJson } from "./encoding.js";
import { KunoError } from "./errors.js";
import type { GenerationParams, ModelProfile, PrivacyMode, ShotJoin, ShotSpec } from "./types.js";

/** Plan v1's version, the prompt version and the feature a worker registers when it writes plans. */
export const PLAN_VERSION = 1;
export const PLAN_PROMPT_VERSION = "plan/1";
export const PLAN_FEATURE = "plan/1";
/** The key of the plan options in a sealed payload's `options`. */
export const PLAN_OPTION = "plan";
/** The failure code of a plan the planner couldn't write: refunded, and not the worker's fault. */
export const PLAN_FAILED = "plan_failed";

export const PLAN_TITLE_MAX_CHARS = 80;
export const PLAN_BEAT_MAX_CHARS = 60;
export const PLAN_NOTES_MAX_CHARS = 400;
export const PLAN_SCENE_MAX_CHARS = 1000;
/** The fit stops once the stitched length is this close to the target. */
export const PLAN_TARGET_TOLERANCE_S = 0.5;
const QUOTE_MIN_CHARS = 2;
const QUOTE_MAX_CHARS = 200;
const EPSILON = 1e-6;

/** One shot of a plan: a label for the card, what the model renders after the scene, its length and its join. */
export interface PlannedShot {
  beat: string;
  prompt: string;
  duration_s: number;
  join: ShotJoin;
}

/** Plan v1, as the enclave delivers it (`kuno_protocol.plans.Plan`). */
export interface Plan {
  v: 1;
  profile_id: string;
  resolution: string;
  aspect_ratio: string;
  fps: number;
  audio: boolean;
  /** The length asked for: the plan job's `duration_s`. */
  target_s: number;
  /** The shots' stitched length, exactly: the storyboard's `duration_s`. */
  duration_s: number;
  title: string;
  /** What every shot shares; the storyboard's prompt. */
  scene: string;
  shots: PlannedShot[];
  notes: string;
  /** Every change code made to what the planner wrote, in words. */
  repairs: string[];
  planner: { model: string; prompt_version: string };
}

/** A revision: rewrite the listed shots (numbered from 1), or the whole plan, under an instruction. */
export interface PlanRevision {
  plan: Plan;
  instruction?: string;
  shots?: number[] | null;
}

/** `options.plan` of a plan job's sealed payload. Every field is optional. */
export interface PlanOptions {
  v?: 1;
  style?: string | null;
  /** The longest shot to plan: the longest a routable worker's envelope serves at this size and frame rate. */
  max_shot_s?: number | null;
  min_shots?: number;
  max_shots?: number | null;
  revise?: PlanRevision | null;
}

/** What a plan is written and fitted to. */
export interface PlanContext {
  profile: ModelProfile;
  resolution: string;
  aspectRatio: string;
  fps: number;
  audio: boolean;
  targetS: number;
  minShotS: number;
  maxShotS: number;
  minShots: number;
  maxShots: number;
  style: string | null;
  promptVersion: string;
}

/** A plan, or options for one, break a rule. Its `code` is `invalid_plan`. */
function planError(message: string): KunoError {
  return new KunoError(0, "invalid_plan", message);
}

// ------------------------------------------------------------------ small helpers, as kuno_protocol.plans writes them

const codePoints = (text: string): number => [...text].length;
/** Python's round(x, 6) for the grid values this module handles. */
const round6 = (x: number): number => Number(x.toFixed(6));
/** Python's `{x:g}` for the small numbers here. */
const g = (x: number): string => String(Number(x));

/** Seconds with at most three decimals, rounded half up on the double: the same digits as `_seconds`. */
export function planSeconds(value: number): string {
  const n = Math.floor(value * 1000 + 0.5);
  const whole = Math.floor(n / 1000);
  const fraction = n - whole * 1000;
  return fraction === 0 ? String(whole) : `${whole}.${String(fraction).padStart(3, "0")}`.replace(/0+$/, "");
}

function shotsText(indices: Iterable<number>): string {
  const numbers = [...new Set(indices)].sort((a, b) => a - b).map((i) => String(i + 1));
  if (numbers.length === 1) return `shot ${numbers[0]}`;
  return `shots ${numbers.slice(0, -1).join(", ")} and ${numbers[numbers.length - 1]}`;
}

function profileMaxDuration(profile: Pick<ModelProfile, "limits">, fps: number): number {
  const lim = profile.limits;
  return Math.min(lim.max_duration_s, lim.max_duration_s_by_fps?.[String(fps)] ?? lim.max_duration_s);
}

function stepOf(profile: Pick<ModelProfile, "limits">): number {
  return profile.limits.duration_step_s || 1;
}

function gridFloor(value: number, profile: Pick<ModelProfile, "limits">): number {
  const lim = profile.limits;
  const steps = Math.floor((value - lim.min_duration_s) / stepOf(profile) + 1e-9);
  return round6(lim.min_duration_s + steps * stepOf(profile));
}

function trimFrames(profile: Pick<ModelProfile, "name" | "limits">): number {
  const board = profile.limits.storyboard;
  if (!board) throw planError(`${profile.name} does not make storyboards`);
  return 1 + 8 * ((board.overlap_latent_frames ?? 3) - 1);
}

function frames(profile: Pick<ModelProfile, "family">, durationS: number, fps: number): number {
  if (profile.family === "minimax-h3") return Math.min(345, 17 * Math.ceil((24 * durationS - 5) / 17) + 5);
  const x = (durationS * fps) / 8;
  const r = Math.round(x);
  const even = Math.abs(x % 1) === 0.5 && r % 2 !== 0 ? r - 1 : r;
  return 8 * Math.max(1, even) + 1;
}

/** The shots' stitched length (`profiles.storyboard_duration_s`). */
function stitchedS(profile: Pick<ModelProfile, "name" | "family" | "limits">, shots: ShotSpec[], fps: number): number {
  const trim = trimFrames(profile);
  return shots.reduce((sum, shot) => sum + frames(profile, shot.duration_s, fps) - (shot.join !== "fresh" ? trim : 0), 0) / fps;
}

function modelPrompt(scene: string, prompt: string): string {
  const s = scene.trim();
  return s ? `${s}\n\n${prompt.trim()}` : prompt.trim();
}

// ------------------------------------------------------------------ context

/**
 * The context for a plan job's params (`plan_context`). The longest shot is the profile's limit at this frame rate,
 * lowered to `options.max_shot_s` when set, else to `servedMaxS` (a worker's own envelope), then snapped down to the
 * duration grid. Throws `invalid_plan` for options that leave no plan possible.
 */
export function planContext(
  profile: ModelProfile,
  params: Pick<GenerationParams, "resolution" | "aspect_ratio" | "fps" | "audio" | "duration_s">,
  options: PlanOptions = {},
  servedMaxS: number | null = null,
): PlanContext {
  const lim = profile.limits;
  const board = lim.storyboard;
  if (!board) throw planError(`${profile.name} does not make storyboards`);
  let cap = profileMaxDuration(profile, params.fps);
  if (options.max_shot_s != null) cap = Math.min(cap, options.max_shot_s);
  else if (servedMaxS != null) cap = Math.min(cap, servedMaxS);
  cap = gridFloor(cap, profile);
  if (cap < lim.min_duration_s - EPSILON) {
    throw planError(`the longest shot can't be shorter than ${profile.name}'s shortest, ${g(lim.min_duration_s)} s`);
  }
  const minShots = options.min_shots ?? 2;
  const maxShots = options.max_shots == null ? board.max_shots : Math.min(board.max_shots, options.max_shots);
  if (minShots > maxShots) throw planError(`min_shots is more than the ${maxShots} shots a plan may have`);
  const style = options.style ? cleanSpace(options.style) : "";
  return {
    profile,
    resolution: params.resolution,
    aspectRatio: params.aspect_ratio,
    fps: params.fps,
    audio: params.audio,
    targetS: params.duration_s,
    minShotS: lim.min_duration_s,
    maxShotS: cap,
    minShots,
    maxShots,
    style: style || null,
    promptVersion: lim.plan?.prompt_version ?? PLAN_PROMPT_VERSION,
  };
}

function matches(context: PlanContext, plan: Plan): boolean {
  return (
    plan.profile_id === context.profile.id &&
    plan.resolution === context.resolution &&
    plan.aspect_ratio === context.aspectRatio &&
    plan.fps === context.fps &&
    plan.audio === context.audio
  );
}

// ------------------------------------------------------------------ durations

/** The nearest duration on the profile's grid (half up), within the context's shortest and longest shot. */
export function snapPlanDuration(value: number, context: PlanContext): number {
  const lim = context.profile.limits;
  const steps = Math.floor((value - lim.min_duration_s) / stepOf(context.profile) + 0.5);
  const snapped = round6(lim.min_duration_s + steps * stepOf(context.profile));
  return Math.min(Math.max(snapped, context.minShotS), context.maxShotS);
}

function snapNote(index: number, before: number, after: number, context: PlanContext): string {
  const number = index + 1;
  if (before > context.maxShotS + EPSILON) {
    return `shot ${number} shortened from ${planSeconds(before)} s to ${planSeconds(after)} s, the longest shot this plan allows`;
  }
  if (before < context.minShotS - EPSILON) {
    return `shot ${number} lengthened from ${planSeconds(before)} s to ${planSeconds(after)} s, the shortest shot ${context.profile.name} renders`;
  }
  return `shot ${number}'s length rounded from ${planSeconds(before)} s to ${planSeconds(after)} s`;
}

/**
 * Durations that keep to the grid and caps and bring the stitched length within 0.5 s of the target, changing only the
 * `movable` shots (default: all), and what changed, in words (`fit`). Each movable duration is snapped; then while the
 * plan is short the shortest growable shot (first on ties) gains a step, and while it is long or over the storyboard's
 * `max_total_s` the longest (first on ties) loses one, unless that would make it short while within `max_total_s`.
 */
export function fitPlan<T extends Pick<PlannedShot, "duration_s" | "join">>(
  shots: T[],
  context: PlanContext,
  movable: Iterable<number> | null = null,
): { shots: T[]; repairs: string[] } {
  const count = shots.length;
  const moving = [...new Set(movable === null ? shots.map((_, i) => i) : movable)].filter((i) => i >= 0 && i < count).sort((a, b) => a - b);
  const joins = shots.map((shot) => shot.join);
  let durations = shots.map((shot) => Number(shot.duration_s));
  const repairs: string[] = [];
  for (const index of moving) {
    const snapped = snapPlanDuration(durations[index], context);
    if (Math.abs(snapped - durations[index]) > EPSILON) repairs.push(snapNote(index, durations[index], snapped, context));
    durations[index] = snapped;
  }
  const stitched = (values: number[]) =>
    stitchedS(context.profile, values.map((duration_s, i) => ({ duration_s, join: joins[i] })), context.fps);
  const board = context.profile.limits.storyboard!;
  const step = stepOf(context.profile);
  const start = [...durations];
  const before = stitched(durations);
  let current = before;
  const low = context.targetS - PLAN_TARGET_TOLERANCE_S;
  const high = context.targetS + PLAN_TARGET_TOLERANCE_S;
  const ceiling = board.max_total_s;
  while (current < low - EPSILON) {
    const growable = moving.filter((i) => durations[i] + step <= context.maxShotS + EPSILON);
    if (!growable.length) break;
    const index = growable.reduce((best, i) => (durations[i] < durations[best] ? i : best));
    durations[index] = round6(durations[index] + step);
    current = stitched(durations);
  }
  while (current > high + EPSILON || current > ceiling + EPSILON) {
    const shrinkable = moving.filter((i) => durations[i] - step >= context.minShotS - EPSILON);
    if (!shrinkable.length) break;
    const index = shrinkable.reduce((best, i) => (durations[i] > durations[best] ? i : best));
    const trial = [...durations];
    trial[index] = round6(trial[index] - step);
    const after = stitched(trial);
    if (after < low - EPSILON && current <= ceiling + EPSILON) break;
    durations = trial;
    current = after;
  }
  const longer = moving.filter((i) => durations[i] > start[i] + EPSILON);
  const shorter = moving.filter((i) => durations[i] < start[i] - EPSILON);
  const changes = ([[longer, "lengthened"], [shorter, "shortened"]] as const)
    .filter(([indices]) => indices.length)
    .map(([indices, verb]) => `${shotsText(indices)} ${verb}`);
  if (changes.length) repairs.push(`the shots ran ${planSeconds(before)} s; ${changes.join(" and ")} to reach ${planSeconds(current)} s`);
  if (current < low - EPSILON) {
    repairs.push(
      `the plan runs ${planSeconds(current)} s of its ${planSeconds(context.targetS)} s target: the shots that may change are at ` +
        `the longest this plan allows, ${planSeconds(context.maxShotS)} s`,
    );
  } else if (current > high + EPSILON) {
    repairs.push(
      `the plan runs ${planSeconds(current)} s against its ${planSeconds(context.targetS)} s target: the shots that may change ` +
        `are at the shortest, ${planSeconds(context.minShotS)} s`,
    );
  }
  const movingSet = new Set(moving);
  return { shots: shots.map((shot, i) => (movingSet.has(i) ? { ...shot, duration_s: durations[i] } : shot)), repairs };
}

// ------------------------------------------------------------------ validation

/**
 * Every rule a delivered plan keeps (`validate`); throws `invalid_plan` naming the first it breaks. 2 to
 * `storyboard.max_shots` shots with non-blank prompts, the first join `fresh`; each duration on the grid within the
 * profile's limits at this fps; `duration_s` exactly the stitched length and within `max_total_s`; every shot's prompt with
 * the scene within `max_prompt_chars`; title, scene, notes and beats within their limits. With a context, also its frame,
 * target, longest shot and shot count.
 */
export function validatePlan(plan: Plan, profile: ModelProfile, context: PlanContext | null = null): void {
  const lim = profile.limits;
  const board = lim.storyboard;
  if (!board) throw planError(`${profile.name} does not make storyboards`);
  if (plan.profile_id !== profile.id) throw planError(`the plan is for ${plan.profile_id}, not ${profile.id}`);
  if (!Array.isArray(plan.shots) || plan.shots.length < 2 || plan.shots.length > board.max_shots) {
    throw planError(`a plan needs between 2 and ${board.max_shots} shots`);
  }
  let cap = profileMaxDuration(profile, plan.fps);
  if (context) {
    if (!matches(context, plan) || Math.abs(plan.target_s - context.targetS) > EPSILON) {
      throw planError("the plan's frame or target differs from the job's");
    }
    if (plan.shots.length > context.maxShots) throw planError(`the plan has more than ${context.maxShots} shots`);
    cap = Math.min(cap, context.maxShotS);
  }
  for (const [name, value, limit] of [
    ["title", plan.title, PLAN_TITLE_MAX_CHARS],
    ["scene", plan.scene, PLAN_SCENE_MAX_CHARS],
    ["notes", plan.notes, PLAN_NOTES_MAX_CHARS],
  ] as const) {
    if (typeof value !== "string" || codePoints(value) > limit) throw planError(`the ${name} is longer than ${limit} characters`);
  }
  plan.shots.forEach((shot, i) => {
    const number = i + 1;
    if (typeof shot.prompt !== "string" || !shot.prompt.trim()) throw planError(`shot ${number} has no prompt`);
    if (typeof shot.beat !== "string" || codePoints(shot.beat) > PLAN_BEAT_MAX_CHARS) {
      throw planError(`shot ${number}'s beat is longer than ${PLAN_BEAT_MAX_CHARS} characters`);
    }
    if (shot.duration_s > cap + EPSILON) throw planError(`shot ${number} is longer than ${g(cap)} s`);
    if (codePoints(modelPrompt(plan.scene, shot.prompt)) > lim.max_prompt_chars) {
      throw planError(`shot ${number}'s prompt, with the scene, is longer than ${lim.max_prompt_chars} characters`);
    }
  });
  // validate_params on the storyboard the plan renders as.
  const sizes = lim.sizes[plan.resolution];
  if (!sizes?.[plan.aspect_ratio]) throw planError(`${profile.name} doesn't render ${plan.resolution} at ${plan.aspect_ratio}`);
  if (!lim.fps.includes(plan.fps)) throw planError(`fps must be one of ${lim.fps.join(", ")}`);
  if (plan.audio && !lim.audio) throw planError(`${profile.name} cannot generate audio`);
  if (plan.shots[0].join !== "fresh") throw planError("a storyboard's first shot must be fresh: there is nothing before it to join");
  const trim = trimFrames(profile);
  plan.shots.forEach((shot, i) => {
    const what = `shot ${i + 1}'s duration`;
    if (!["fresh", "continue", "cut"].includes(shot.join)) throw planError(`shot ${i + 1}'s join is fresh, continue or cut`);
    if (!(typeof shot.duration_s === "number" && lim.min_duration_s <= shot.duration_s && shot.duration_s <= lim.max_duration_s)) {
      throw planError(`${what} must be between ${g(lim.min_duration_s)} and ${g(lim.max_duration_s)} seconds`);
    }
    const steps = (shot.duration_s - lim.min_duration_s) / stepOf(profile);
    if (Math.abs(steps - Math.round(steps)) > 1e-6) throw planError(`${what} must be in ${g(stepOf(profile))}-second steps`);
    const fpsMax = lim.max_duration_s_by_fps?.[String(plan.fps)];
    if (fpsMax !== undefined && shot.duration_s > fpsMax) throw planError(`at ${plan.fps} fps, ${what} must be at most ${g(fpsMax)} seconds`);
    if (shot.join !== "fresh" && frames(profile, shot.duration_s, plan.fps) <= trim) {
      throw planError(`shot ${i + 1} is too short to join: it would keep no frames after its ${trim}-frame overlap`);
    }
  });
  const expected = stitchedS(profile, planShotSpecs(plan), plan.fps);
  if (expected > board.max_total_s + 1e-6) {
    throw planError(`a storyboard's stitched video must be at most ${g(board.max_total_s)} seconds, these shots make ${expected.toFixed(3)}`);
  }
  if (Math.abs(plan.duration_s - expected) > 1e-6) throw planError(`a storyboard's duration_s must be its stitched length, ${expected} seconds`);
}

// ------------------------------------------------------------------ a plan as a storyboard

/** The shots as the gateway sees them: each one's length and join. */
export function planShotSpecs(plan: Pick<Plan, "shots">): ShotSpec[] {
  return plan.shots.map((shot) => ({ duration_s: shot.duration_s, join: shot.join }));
}

/** The shots as `generate({ prompt: plan.scene, shots })` takes them: the same specs and stitched length as the plan. */
export function planToShots(plan: Pick<Plan, "shots">): Array<{ prompt: string; durationS: number; join: ShotJoin }> {
  return plan.shots.map((shot) => ({ prompt: shot.prompt, durationS: shot.duration_s, join: shot.join }));
}

/** The public params of the storyboard a plan renders as. */
export function planStoryboardParams(plan: Plan): GenerationParams {
  return {
    profile_id: plan.profile_id,
    mode: "storyboard",
    duration_s: plan.duration_s,
    resolution: plan.resolution,
    aspect_ratio: plan.aspect_ratio,
    fps: plan.fps,
    audio: plan.audio,
    input_roles: [],
    shots: planShotSpecs(plan),
  };
}

/**
 * The plan with `duration_s` recomputed from its shots, for a plan whose shot lengths were edited by hand. A plan whose
 * shots can't be measured is returned as it is, for `validatePlan` to name the problem.
 */
export function restitchPlan(profile: ModelProfile, plan: Plan): Plan {
  try {
    const stitched = stitchedS(profile, planShotSpecs(plan), plan.fps);
    return Number.isFinite(stitched) && stitched !== plan.duration_s ? { ...plan, duration_s: stitched } : plan;
  } catch {
    return plan;
  }
}

/** A plan job's flat price in a privacy mode (`pricing.plan_usd` / `standard_plan_usd`), or null where it isn't sold. */
export function planPriceUsd(profile: Pick<ModelProfile, "pricing">, privacy: PrivacyMode = "private"): number | null {
  const flat = privacy === "private" ? profile.pricing.plan_usd : profile.pricing.standard_plan_usd;
  return typeof flat === "number" ? Math.round(flat * 10000) / 10000 : null;
}

// ------------------------------------------------------------------ brief quotes

const QUOTE_PATTERNS: RegExp[] = [
  /"([^"\n]+)"/g,
  /“([^“”\n]+)”/g,
  /„([^“”„\n]+)[“”]/g,
  /«([^«»\n]+)»/g,
  /»([^«»\n]+)«/g,
  /(?<![A-Za-z0-9])‘([^‘’\n]+)’(?![A-Za-z0-9])/g,
  /(?<![A-Za-z0-9'])'(?![\t\n\v\f\r ])([^'\n]+?)(?<![\t\n\v\f\r ])'(?![A-Za-z0-9])/g,
];
// diffusers' LTX-2 `_UNICODE_REPLACEMENTS`: curly quotes, dashes, no-break space, prime and minus.
const UNICODE_REPLACEMENTS: Record<string, string> = {
  "‘": "'",
  "’": "'",
  "“": '"',
  "”": '"',
  "—": "-",
  "–": "-",
  " ": " ",
  "′": "'",
  "−": "-",
};
const REPLACEABLE = /[‘’“”—– ′−]/g;
const QUOTE_TRIM = " .,!?;:\"'";

function trimChars(text: string, chars: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && chars.includes(text[start])) start++;
  while (end > start && chars.includes(text[end - 1])) end--;
  return text.slice(start, end);
}

function cleanSpace(text: string): string {
  return trimChars(text.replace(/\s+/g, " "), " ");
}

function quoteKey(text: string): string {
  return trimChars(cleanSpace(text.normalize("NFKC").replace(REPLACEABLE, (c) => UNICODE_REPLACEMENTS[c]).toLowerCase()), QUOTE_TRIM);
}

/** The phrases a brief puts in quotation marks, in order of appearance, each once: a slogan, or a line to be spoken. */
export function briefQuotes(brief: string): string[] {
  const found: Array<[number, string]> = [];
  for (const pattern of QUOTE_PATTERNS) {
    for (const match of brief.matchAll(pattern)) {
      const phrase = cleanSpace(match[1]);
      const size = codePoints(quoteKey(phrase));
      if (size >= QUOTE_MIN_CHARS && size <= QUOTE_MAX_CHARS) found.push([match.index ?? 0, phrase]);
    }
  }
  const phrases: string[] = [];
  for (const [, phrase] of found.sort((a, b) => a[0] - b[0])) {
    if (phrases.every((seen) => quoteKey(phrase) !== quoteKey(seen))) phrases.push(phrase);
  }
  return phrases;
}

/**
 * The brief's quoted phrases that appear in none of the prompts, compared after NFKC, the diffusers quote mapping,
 * lower-casing, collapsed whitespace and trimmed end punctuation (`missing_quotes`).
 */
export function missingQuotes(brief: string, prompts: Iterable<string>): string[] {
  const keys = [...prompts].map(quoteKey);
  return briefQuotes(brief).filter((phrase) => !keys.some((key) => key.includes(quoteKey(phrase))));
}

// ------------------------------------------------------------------ output

/** The blob label a plan job's output is sealed under. */
export function planOutputLabel(jobId: string): string {
  return `${jobId}/output/plan`;
}

/** A plan's JSON as the enclave delivers it: canonical JSON. The receipt's `content_digest` is its SHA-256. */
export function encodePlan(plan: Plan): Uint8Array {
  return canonicalJson(plan);
}

const PLAN_KEYS = ["aspect_ratio", "audio", "duration_s", "fps", "notes", "planner", "profile_id", "repairs", "resolution", "scene", "shots", "target_s", "title", "v"];
const SHOT_KEYS = ["beat", "duration_s", "join", "prompt"];

/** Parses Plan v1 JSON, refusing unknown or missing fields and wrong types (`Plan.model_validate_json`). */
export function parsePlan(json: string | Uint8Array): Plan {
  let value: unknown;
  try {
    value = JSON.parse(typeof json === "string" ? json : new TextDecoder("utf-8", { fatal: true }).decode(json));
  } catch {
    throw planError("the plan is not JSON");
  }
  const plan = value as Plan;
  const keysMatch = (object: unknown, keys: string[], optional: string[] = []) =>
    object !== null &&
    typeof object === "object" &&
    !Array.isArray(object) &&
    Object.keys(object).every((k) => keys.includes(k)) &&
    keys.every((k) => optional.includes(k) || k in (object as object));
  const ok =
    keysMatch(plan, PLAN_KEYS, ["v", "notes", "repairs"]) &&
    (plan.v === undefined || plan.v === 1) &&
    ["profile_id", "resolution", "aspect_ratio", "title", "scene"].every((k) => typeof (plan as unknown as Record<string, unknown>)[k] === "string") &&
    Number.isInteger(plan.fps) &&
    typeof plan.audio === "boolean" &&
    typeof plan.target_s === "number" &&
    typeof plan.duration_s === "number" &&
    (plan.notes === undefined || typeof plan.notes === "string") &&
    (plan.repairs === undefined || (Array.isArray(plan.repairs) && plan.repairs.every((r) => typeof r === "string"))) &&
    keysMatch(plan.planner, ["model", "prompt_version"]) &&
    typeof plan.planner.model === "string" &&
    typeof plan.planner.prompt_version === "string" &&
    Array.isArray(plan.shots) &&
    plan.shots.length <= 64 &&
    plan.shots.every(
      (shot) =>
        keysMatch(shot, SHOT_KEYS) &&
        typeof shot.beat === "string" &&
        typeof shot.prompt === "string" &&
        shot.prompt.length > 0 &&
        typeof shot.duration_s === "number" &&
        ["fresh", "continue", "cut"].includes(shot.join),
    );
  if (!ok) throw planError("the plan is not a Plan v1");
  return { ...plan, v: 1, notes: plan.notes ?? "", repairs: plan.repairs ?? [] };
}

/**
 * A delivered plan and its JSON bytes, whose SHA-256 is the receipt's `content_digest` (`open_plan`): the blob decrypted
 * with the job's output key under `<job_id>/output/plan`, then unpadded, refusing anything but form 2 framing. Throws
 * `DecryptionError` when the blob fails authentication, and `invalid_plan` when it isn't a padded Plan v1.
 */
export function openPlan(outputKey: Uint8Array, jobId: string, blob: Uint8Array): { plan: Plan; json: Uint8Array } {
  const framed = decryptBlob(outputKey, planOutputLabel(jobId), blob);
  if (payloadVersion(framed) !== PAYLOAD_V2) throw planError("the plan output is not padded plan JSON");
  let json: Uint8Array;
  try {
    json = unpadPayload(framed);
  } catch (err) {
    if (err instanceof DecryptionError) throw planError(`the plan output's padding is invalid: ${err.message}`);
    throw err;
  }
  return { plan: parsePlan(json), json };
}
