import { verifyEvidence, verifySignature, verifySignedManifest } from "./attestation.js";
import { decryptBlob, DecryptionError, encryptBlob, openSenderSession, padPayload, sha256Hex } from "./crypto.js";
import {
  addElementLines,
  checkElementUse,
  newElementId,
  openElement,
  openElementFile,
  sealElement,
  type Element,
  type ElementDraft,
  type ElementFileDraft,
  type ElementRow,
  type ElementUse,
  type ElementsKey,
} from "./elements.js";
import { b64d, b64e, canonicalJson, concatBytes, utf8 } from "./encoding.js";
import { ERROR_CODES, KunoError } from "./errors.js";
import {
  encodePlan,
  openPlan,
  parsePlan,
  PLAN_FEATURE,
  PLAN_OPTION,
  planContext,
  planPriceUsd,
  restitchPlan,
  validatePlan,
  type Plan,
  type PlanOptions,
  type PlanRevision,
} from "./plans.js";
import type {
  EnclaveInfo,
  Eligibility,
  GenerationParams,
  GoldenManifest,
  InputRef,
  InputRole,
  JobStatus,
  Mode,
  ModelProfile,
  ModelsResponse,
  PriceQuote,
  PrivacyMode,
  Provenance,
  Receipt,
  ReportRequest,
  RouteFit,
  RouteResponse,
  ServingEnvelope,
  ShotJoin,
  ShotSpec,
  SharedVideo,
  SharedVideoDetails,
  ShareLink,
  ShareStatus,
  ShareSummary,
  StandardUpload,
  StandardVideoSummary,
} from "./types.js";

export { ERROR_CODES, KunoError } from "./errors.js";
export type { KunoErrorCode } from "./errors.js";

export interface GenerateInput {
  role: InputRole;
  file: Blob | Uint8Array;
  /** Keyframes: seconds from the start. */
  timeS?: number;
  strength?: number;
  hint?: string;
  startS?: number;
  endS?: number;
}

/** One shot of a storyboard request. */
export interface GenerateShot {
  /** What happens in this shot. The model sees the request's `prompt` (the shared scene), a blank line, then this. */
  prompt: string;
  /** This shot's rendered length, within the profile's own duration limits. */
  durationS: number;
  /**
   * How it attaches to the shot before: `continue` (one unbroken take), `cut` (a new picture over the same sound) or
   * `fresh` (nothing carried over). Default: `fresh` for the first shot, which must be, and `continue` after it.
   */
  join?: ShotJoin;
}

export interface GenerateRequest {
  /** What to make. For a storyboard: the scene every shot shares (characters, place, style); it may be empty. */
  prompt: string;
  model?: string;
  family?: string;
  mode?: Mode;
  durationS?: number;
  resolution?: string;
  aspectRatio?: string;
  fps?: number;
  audio?: boolean;
  seed?: number;
  negativePrompt?: string;
  inputs?: GenerateInput[];
  options?: Record<string, unknown>;
  /**
   * A storyboard: 2 or more shots rendered one after another by one worker and delivered as one stitched video. Sets
   * `mode` to `storyboard` and takes no `inputs`; `durationS` is ignored, the length comes from the shots.
   */
  shots?: GenerateShot[];
  /**
   * `private` (default): encrypted here to an attested confidential enclave; nobody at KunoWorld
   * can read it. `standard`: sent to KunoWorld readable, so KunoWorld and the GPU provider can see
   * the prompt, inputs and video; no client-side encryption.
   */
  privacy?: PrivacyMode;
}

/** Everything needed to fetch and open a private video later. Store it like a password. */
export interface JobHandle {
  jobId: string;
  outputKey: string;
  signingPublicKey: string;
  enclaveId: string;
  profileId: string;
  fallbackReason: string | null;
  createdAt: number;
  /** Absent on handles saved before standard mode; they are private. */
  privacy?: "private";
}

/** A standard job. It holds no secrets: the account's credentials fetch the video. */
export interface StandardJobHandle {
  privacy: "standard";
  jobId: string;
  enclaveId: string;
  profileId: string;
  fallbackReason: string | null;
  createdAt: number;
}

export type AnyJobHandle = JobHandle | StandardJobHandle;

export function isStandardHandle(handle: AnyJobHandle): handle is StandardJobHandle {
  return handle.privacy === "standard";
}

export interface GenerationResult {
  jobId: string;
  video: Uint8Array;
  receipt: Receipt;
  profileId: string;
  fallbackReason: string | null;
  privacy: PrivacyMode;
}

/** A plan from a brief (PROTOCOL.md "Plans (Director)"): a storyboard's scene and shots, written inside the enclave. */
export interface PlanRequest {
  /** What the video is for, what happens and how it should feel. Words to be spoken or a slogan go in quotes. */
  brief: string;
  /** The stitched length to aim for, in seconds: from the profile's `limits.plan.min_target_s` to `storyboard.max_total_s`. */
  targetS: number;
  /** Default `ltx-2.5-fast`, the profile plans are written for. */
  model?: string;
  resolution?: string;
  aspectRatio?: string;
  fps?: number;
  audio?: boolean;
  /** A look to keep to, e.g. "35mm film, warm". */
  style?: string;
  /** `private` (default): sealed here to an attested enclave that writes plans. `standard`: readable by KunoWorld. */
  privacy?: PrivacyMode;
  seed?: number;
}

/** A revision of a plan: a new plan job with the same frame and target. */
export interface PlanRevisionOptions {
  /** Only rewrite these shots, numbered from 1; the title, scene, notes and other shots come back unchanged. */
  shots?: number[];
  /** The original brief, so the planner can keep its quoted words; may be left out. */
  brief?: string;
  style?: string;
  /** Default: the privacy the plan was made in, else `private`. */
  privacy?: PrivacyMode;
  seed?: number;
}

/** A plan job in flight. A Private one holds its output key, the only key that opens the plan: store it like a password. */
export interface PlanHandle {
  kind: "plan";
  jobId: string;
  privacy: PrivacyMode;
  profileId: string;
  enclaveId: string;
  /** Private only. */
  outputKey?: string;
  signingPublicKey?: string;
  /** The longest shot the plan was asked for, from the routable plan workers' envelopes; the plan is checked against it. */
  maxShotS: number | null;
  fallbackReason: string | null;
  createdAt: number;
}

/** A finished plan, opened and checked against its receipt and the plan rules. */
export interface PlanResult {
  jobId: string;
  plan: Plan;
  /** The plan's JSON as delivered; its SHA-256 is `receipt.body.content_digest`. */
  json: Uint8Array;
  receipt: Receipt;
  privacy: PrivacyMode;
}

export type SubmitStage = "routing" | "verifying" | "encrypting" | "uploading" | "submitting";

export interface WaitOptions {
  onProgress?: (status: JobStatus) => void;
  signal?: AbortSignal;
  pollMs?: number;
  timeoutMs?: number;
}

export interface KunoClientOptions {
  /**
   * A developer API key (`kw_live_…`), for programs you run yourself. Leave it out when `baseUrl`
   * is a same-origin proxy that authenticates for you (the KunoWorld website uses the signed-in
   * session that way); never put an API key in a web page.
   */
  apiKey?: string;
  /**
   * The gateway, e.g. `https://api.kunoworld.com`, or in a browser a same-origin path such as
   * `/api/kuno` that forwards to it.
   */
  baseUrl?: string;
  /** Pin the published golden manifest for zero-trust verification. */
  manifest?: GoldenManifest;
  /**
   * The subnet owner's Ed25519 public key (base64). The gateway's manifest is then used only if the owner signed it,
   * which is zero-trust without pinning a manifest that changes with every image release.
   */
  ownerPublicKey?: string;
  /** Replaces the pinned NVIDIA attestation intermediate (SPKI SHA-256, hex) when NVIDIA rotates it. */
  nvidiaTrustedSpki?: string[];
  /** TCB statuses a TDX platform may report; default `UpToDate` only. */
  tdxAllowedTcbStatuses?: string[];
  /** Development only: pretend to be in another country. */
  country?: string;
  /** Replaces `fetch`, e.g. to add timeouts or route requests through your own transport. */
  fetch?: typeof fetch;
  /** Passed to every fetch. A same-origin proxy relies on the default, `same-origin`, to send its cookie. */
  credentials?: RequestCredentials;
}

const MIME_SIGNATURES: Array<[string, (b: Uint8Array) => boolean]> = [
  ["image/png", (b) => b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47],
  ["image/jpeg", (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff],
  ["image/webp", (b) => ascii(b, 0, 4) === "RIFF" && ascii(b, 8, 12) === "WEBP"],
  ["audio/wav", (b) => ascii(b, 0, 4) === "RIFF" && ascii(b, 8, 12) === "WAVE"],
  ["video/quicktime", (b) => ascii(b, 4, 8) === "ftyp" && ascii(b, 8, 10) === "qt"],
  ["video/mp4", (b) => ascii(b, 4, 8) === "ftyp"],
  ["video/webm", (b) => b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3],
  ["audio/mpeg", (b) => ascii(b, 0, 3) === "ID3" || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0)],
  ["audio/ogg", (b) => ascii(b, 0, 4) === "OggS"],
  ["audio/flac", (b) => ascii(b, 0, 4) === "fLaC"],
];

function ascii(bytes: Uint8Array, start: number, end: number): string {
  return String.fromCharCode(...bytes.subarray(start, end));
}

export function sniffMime(bytes: Uint8Array): string | null {
  return MIME_SIGNATURES.find(([, test]) => test(bytes))?.[0] ?? null;
}

export function inferMode(roles: InputRole[]): Mode {
  const has = (r: InputRole) => roles.includes(r);
  if (has("source_audio")) return "audio_to_video";
  if (has("source_video")) return "video_edit";
  if (has("reference_image") || has("reference_video") || has("reference_audio")) return "reference_to_video";
  if (has("keyframe")) return "keyframes";
  if (has("first_frame") && has("last_frame")) return "first_last_frame";
  if (has("first_frame")) return "image_to_video";
  if (has("last_frame")) return "last_frame";
  return "text_to_video";
}

/** The privacy modes a profile is sold in: `privacy_modes` from /v1/models, else read from its pricing. */
export function privacyModes(profile: ModelProfile): PrivacyMode[] {
  if (profile.privacy_modes) return profile.privacy_modes;
  return profile.pricing.standard_usd_per_second ? ["private", "standard"] : ["private"];
}

/**
 * The params a price depends on. `shots` only for a storyboard, whose longest shot decides the long-clip rule; `mode`
 * `plan` for a plan job's flat price.
 */
export type PricedParams = Pick<GenerationParams, "resolution" | "duration_s" | "fps"> & Partial<Pick<GenerationParams, "shots" | "mode">>;

/**
 * The gateway's price for a job (kuno_protocol `ModelProfile.price_usd`): the per-second rate for the privacy
 * mode x duration x the fps multiplier (and, in Private mode, the long-clip multiplier), never below the profile's
 * minimum charge. A storyboard pays for its stitched `duration_s`; the long-clip rule looks at its longest shot.
 * A plan (`mode: "plan"`) costs the flat `plan_usd` or `standard_plan_usd`, whatever its target length.
 * Null where the profile has no such price: a resolution it doesn't render, Standard on a Private-only profile, or plans on
 * a profile that doesn't write them.
 */
export function priceQuote(
  profile: ModelProfile,
  params: PricedParams,
  privacy: PrivacyMode = "private",
): PriceQuote | null {
  const pricing = profile.pricing;
  if (!privacyModes(profile).includes(privacy)) return null;
  if (params.mode === "plan") {
    const flat = planPriceUsd(profile, privacy);
    return flat === null ? null : { usd: flat, usdPerSecond: 0, multiplier: 1, minimumApplied: false };
  }
  const rate = (privacy === "private" ? pricing.usd_per_second : pricing.standard_usd_per_second)?.[params.resolution];
  if (rate === undefined) return null;
  let multiplier = pricing.fps_multipliers?.[String(params.fps)] ?? 1;
  // A long clip costs more per second to render; a storyboard's shots are rendered one at a time, so its longest counts.
  if (privacy === "private" && pricing.long_clip && renderDurationS(params) > pricing.long_clip.over_s) {
    multiplier *= pricing.long_clip.multiplier;
  }
  const raw = rate * params.duration_s * multiplier;
  const minimum = pricing.min_job_usd ?? 0;
  return { usd: Math.round(Math.max(minimum, raw) * 10000) / 10000, usdPerSecond: rate, multiplier, minimumApplied: raw < minimum };
}

export function priceUsd(
  profile: ModelProfile,
  params: PricedParams,
  privacy: PrivacyMode = "private",
): number | null {
  return priceQuote(profile, params, privacy)?.usd ?? null;
}

/**
 * Whether a job fits a worker's serving envelope (kuno_protocol.envelope): its render duration (`duration_s`, or a
 * storyboard's longest shot, since shots render one at a time) at most the longest the worker serves at the job's
 * resolution, aspect ratio and fps. No envelope, or none for the profile, means the profile's limits.
 */
export function envelopeFits(
  envelope: ServingEnvelope | null | undefined,
  params: Pick<GenerationParams, "profile_id" | "resolution" | "aspect_ratio" | "fps" | "duration_s"> & Partial<Pick<GenerationParams, "shots" | "mode">>,
): boolean {
  const table = envelope?.[params.profile_id];
  if (!table) return true;
  const longest = table[params.resolution]?.[params.aspect_ratio]?.[String(params.fps)];
  return typeof longest === "number" && renderDurationS(params) <= longest + 1e-6;
}

/**
 * The fields `/v1/route` filters workers by, as the caller gave them: the defaults depend on the profile the route picks.
 * A storyboard is filtered by its longest shot, the longest single render a worker has to fit.
 */
function routeFit(req: Pick<GenerateRequest, "resolution" | "aspectRatio" | "fps" | "durationS" | "shots">): RouteFit {
  const durationS = req.shots?.length ? Math.max(...req.shots.map((shot) => shot.durationS)) : req.durationS;
  return { resolution: req.resolution, aspectRatio: req.aspectRatio, fps: req.fps, durationS };
}

// ------------------------------------------------------------ storyboards (kuno_protocol.profiles)

/** Python's round(): halves go to the even neighbour. */
function roundHalfEven(x: number): number {
  const r = Math.round(x);
  return Math.abs(x % 1) === 0.5 && r % 2 !== 0 ? r - 1 : r;
}

/** Frame count a profile actually renders for a duration: MiniMax H3 renders 17n+5 frames at 24 fps (at most 345), LTX-2.5 8k+1. */
export function numFrames(profile: Pick<ModelProfile, "family">, durationS: number, fps: number): number {
  if (profile.family === "minimax-h3") return Math.min(345, 17 * Math.ceil((24 * durationS - 5) / 17) + 5);
  return 8 * Math.max(1, roundHalfEven((durationS * fps) / 8)) + 1;
}

function storyboardLimits(profile: Pick<ModelProfile, "name" | "limits">) {
  const board = profile.limits.storyboard;
  if (!board) throw new KunoError(0, "invalid_params", `${profile.name} does not support storyboard`);
  return board;
}

/**
 * Frames a `continue` or `cut` shot repeats from the shot before, and loses from the stitched video: 1 + 8 × (overlap − 1),
 * 17 for LTX-2.5 Fast. Throws `invalid_params` for a profile without storyboard mode.
 */
export function storyboardTrimFrames(profile: Pick<ModelProfile, "name" | "limits">): number {
  return 1 + 8 * ((storyboardLimits(profile).overlap_latent_frames ?? 3) - 1);
}

/** The stitched video's frame count: every shot's rendered frames, less the repeated head of each joined shot. */
export function storyboardFrames(profile: Pick<ModelProfile, "name" | "family" | "limits">, shots: ShotSpec[], fps: number): number {
  const trim = storyboardTrimFrames(profile);
  return shots.reduce((sum, shot) => sum + numFrames(profile, shot.duration_s, fps) - (shot.join !== "fresh" ? trim : 0), 0);
}

/**
 * What `GenerationParams.duration_s` must be for a storyboard: its stitched frames / fps, exactly (35.375 for eight 5 s
 * shots joined at 24 fps). It is shorter than the shots added up: each joined shot loses its overlap.
 */
export function storyboardDurationS(profile: Pick<ModelProfile, "name" | "family" | "limits">, shots: ShotSpec[], fps: number): number {
  return storyboardFrames(profile, shots, fps) / fps;
}

/** The prompt the model sees for one storyboard shot: the shared scene, a blank line, then the shot's own prompt. */
export function shotPrompt(scene: string, prompt: string): string {
  const s = scene.trim();
  return s ? `${s}\n\n${prompt.trim()}` : prompt.trim();
}

/**
 * The longest single model call a job needs: its duration, or a storyboard's longest shot. Envelopes and the long-clip
 * price use it. A plan renders nothing, so 0: any worker that serves its size and frame rate at all fits it.
 */
export function renderDurationS(params: Pick<GenerationParams, "duration_s"> & Partial<Pick<GenerationParams, "shots" | "mode">>): number {
  if (params.mode === "plan") return 0;
  return params.shots?.length ? Math.max(...params.shots.map((shot) => shot.duration_s)) : params.duration_s;
}

/** The shot a storyboard is rendering, from a job's `stage` (`shot 3/8`), or null for any other stage. */
export function storyboardStage(stage: string | null | undefined): { shot: number; shots: number } | null {
  const match = /^shot (\d+)\/(\d+)$/.exec(stage?.trim() ?? "");
  if (!match) return null;
  const shot = Number(match[1]);
  const shots = Number(match[2]);
  return shot >= 1 && shot <= shots ? { shot, shots } : null;
}

const g = (n: number) => String(Number(n));

function checkDuration(profile: ModelProfile, durationS: number, fps: number, what: string): void {
  const lim = profile.limits;
  const fail = (message: string) => {
    throw new KunoError(0, "invalid_params", message);
  };
  if (!(lim.min_duration_s <= durationS && durationS <= lim.max_duration_s)) {
    fail(`${what} must be between ${g(lim.min_duration_s)} and ${g(lim.max_duration_s)} seconds`);
  }
  const step = lim.duration_step_s || 1;
  const steps = (durationS - lim.min_duration_s) / step;
  if (Math.abs(steps - Math.round(steps)) > 1e-6) fail(`${what} must be in ${g(step)}-second steps`);
  const fpsMax = lim.max_duration_s_by_fps?.[String(fps)];
  if (fpsMax !== undefined && durationS > fpsMax) fail(`at ${fps} fps, ${what} must be at most ${g(fpsMax)} seconds`);
}

/**
 * kuno_protocol's storyboard rules (`validate_params`), with its messages: 2 to `max_shots` shots, each within the
 * profile's own duration limits, the first `fresh`, every joined shot long enough to keep frames after its overlap, a
 * stitched length within `max_total_s`, and `duration_s` exactly that length. Throws `invalid_params`.
 */
export function validateStoryboard(
  profile: ModelProfile,
  params: Pick<GenerationParams, "mode" | "fps" | "duration_s"> & Partial<Pick<GenerationParams, "shots">>,
): void {
  const fail = (message: string): never => {
    throw new KunoError(0, "invalid_params", message);
  };
  if (params.mode !== "storyboard") {
    if (params.shots != null) fail("shots are only for storyboard mode");
    return;
  }
  const board = storyboardLimits(profile);
  const shots = params.shots ?? [];
  if (!(shots.length >= 2 && shots.length <= board.max_shots)) fail(`a storyboard needs between 2 and ${board.max_shots} shots`);
  if (shots[0].join !== "fresh") fail("a storyboard's first shot must be fresh: there is nothing before it to join");
  const trim = storyboardTrimFrames(profile);
  shots.forEach((shot, i) => {
    checkDuration(profile, shot.duration_s, params.fps, `shot ${i + 1}'s duration`);
    if (shot.join !== "fresh" && numFrames(profile, shot.duration_s, params.fps) <= trim) {
      fail(`shot ${i + 1} is too short to join: it would keep no frames after its ${trim}-frame overlap`);
    }
  });
  const expected = storyboardDurationS(profile, shots, params.fps);
  if (expected > board.max_total_s + 1e-6) {
    fail(`a storyboard's stitched video must be at most ${g(board.max_total_s)} seconds, these shots make ${expected.toFixed(3)}`);
  }
  if (Math.abs(params.duration_s - expected) > 1e-6) fail(`a storyboard's duration_s must be its stitched length, ${expected} seconds`);
}

/** The shots as the gateway sees them: each shot's length and join, the first `fresh` and the rest `continue` unless given. */
function shotSpecs(shots: GenerateShot[]): ShotSpec[] {
  return shots.map((shot, i) => ({ duration_s: shot.durationS, join: shot.join ?? (i === 0 ? "fresh" : "continue") }));
}

/** A request's mode, and the request-level storyboard checks that need no profile. Throws `invalid_params`. */
function requestMode(req: GenerateRequest, roles: InputRole[]): Mode {
  const fail = (message: string): never => {
    throw new KunoError(0, "invalid_params", message);
  };
  if (req.shots != null && req.mode !== undefined && req.mode !== "storyboard") fail("shots are only for storyboard mode");
  const mode = req.shots != null ? "storyboard" : req.mode ?? inferMode(roles);
  if (mode !== "storyboard") return mode;
  if (!req.shots || req.shots.length < 2) fail("a storyboard needs at least 2 shots");
  if (roles.length) fail("a storyboard takes no inputs");
  req.shots!.forEach((shot, i) => {
    if (typeof shot.prompt !== "string" || !shot.prompt.trim()) fail(`shot ${i + 1} needs a prompt`);
  });
  return mode;
}

/** The profile-level checks before anything is sealed or sent: the shots' limits and each shot's prompt length with the scene. */
function checkStoryboardRequest(profile: ModelProfile, params: GenerationParams, req: GenerateRequest): void {
  validateStoryboard(profile, params);
  if (params.mode !== "storyboard") return;
  const max = profile.limits.max_prompt_chars;
  req.shots!.forEach((shot, i) => {
    if ([...shotPrompt(req.prompt ?? "", shot.prompt)].length > max) {
      throw new KunoError(0, "invalid_params", `shot ${i + 1}'s prompt, with the scene, must be at most ${max} characters`);
    }
  });
}

/**
 * Same rules as the Python SDK: defaults from the profile; adapt after a fallback. A storyboard (`storyboard` mode, with
 * `req.shots`) gets its `shots` and its stitched `duration_s`; after a fallback each shot is fitted to the duration limits.
 */
export function fitParams(
  profile: ModelProfile,
  mode: Mode,
  roles: InputRole[],
  req: Pick<GenerateRequest, "durationS" | "resolution" | "aspectRatio" | "fps" | "audio" | "shots">,
  fallbackReason: string | null,
): GenerationParams {
  const lim = profile.limits;
  const lenient = fallbackReason !== null;
  let resolution = req.resolution;
  if (resolution === undefined || (lenient && !(resolution in lim.sizes))) resolution = Object.keys(lim.sizes)[0];
  const sizes = lim.sizes[resolution] ?? {};
  let aspect = req.aspectRatio;
  if (aspect === undefined || (lenient && !(aspect in sizes))) aspect = "16:9" in sizes ? "16:9" : Object.keys(sizes)[0] ?? "16:9";
  let fps = req.fps;
  if (fps === undefined || (lenient && !lim.fps.includes(fps))) fps = lim.default_fps;
  // Some profiles render shorter clips at high frame rates (LTX-2.5 Fast goes past 10 s only at 24 or 25 fps).
  const maxDuration = Math.min(lim.max_duration_s, lim.max_duration_s_by_fps?.[String(fps)] ?? lim.max_duration_s);
  let duration = req.durationS;
  if (duration === undefined) duration = Math.min(Math.max(5, lim.min_duration_s), maxDuration);
  else if (lenient) duration = Math.min(Math.max(duration, lim.min_duration_s), maxDuration);
  const params: GenerationParams = {
    profile_id: profile.id,
    mode,
    duration_s: duration,
    resolution,
    aspect_ratio: aspect,
    fps,
    audio: (req.audio ?? true) && lim.audio,
    input_roles: roles,
  };
  if (mode === "storyboard") {
    const shots = shotSpecs(req.shots ?? []).map((shot) =>
      lenient ? { ...shot, duration_s: Math.min(Math.max(shot.duration_s, lim.min_duration_s), maxDuration) } : shot,
    );
    params.shots = shots;
    params.duration_s = storyboardDurationS(profile, shots, fps);
  } else if (mode === "plan") {
    // A plan's duration is the stitched length it aims for, not a clip's: never fitted to the clip limits.
    params.duration_s = req.durationS ?? 30;
  }
  return params;
}

/** Associated data for the HPKE seal. Mirrors `job_aad` in kuno_protocol; `shots` is written only when set, like Python's. */
export function jobAad(jobId: string, enclaveId: string, params: GenerationParams, inputBlobIds: string[]): Uint8Array {
  const { shots, ...rest } = params;
  return canonicalJson({ v: 1, job_id: jobId, enclave_id: enclaveId, params: shots == null ? rest : params, inputs: inputBlobIds });
}

export function verifyReceipt(receipt: Receipt, signingPublicKey: Uint8Array): boolean {
  const message = concatBytes(utf8("kuno/v1/receipt\n"), canonicalJson(receipt.body));
  return verifySignature(b64d(receipt.signature), message, signingPublicKey);
}

/**
 * The longest shot a plan may ask for: the longest any of these workers' envelopes renders at the plan's size and frame
 * rate (a worker without one renders the profile's limits), capped by the profile. The storyboard routes by the same rule.
 */
function longestServedShot(profile: ModelProfile, params: GenerationParams, enclaves: EnclaveInfo[]): number | null {
  const lim = profile.limits;
  const cap = Math.min(lim.max_duration_s, lim.max_duration_s_by_fps?.[String(params.fps)] ?? lim.max_duration_s);
  const served = enclaves
    .map((e) => {
      const table = e.envelope?.[profile.id];
      const longest = table ? table[params.resolution]?.[params.aspect_ratio]?.[String(params.fps)] : cap;
      return typeof longest === "number" ? Math.min(longest, cap) : null;
    })
    .filter((x): x is number => x !== null);
  return served.length ? Math.max(...served) : null;
}

/** A plan with exactly Plan v1's fields: the enclave refuses unknown ones, and an app's own (card ids) stay behind. */
function cleanPlan(plan: Plan): Plan {
  return {
    v: 1,
    profile_id: plan.profile_id,
    resolution: plan.resolution,
    aspect_ratio: plan.aspect_ratio,
    fps: plan.fps,
    audio: plan.audio,
    target_s: plan.target_s,
    duration_s: plan.duration_s,
    title: plan.title ?? "",
    scene: plan.scene ?? "",
    shots: (plan.shots ?? []).map((shot) => ({ beat: shot.beat ?? "", prompt: shot.prompt, duration_s: shot.duration_s, join: shot.join })),
    notes: plan.notes ?? "",
    repairs: [...(plan.repairs ?? [])],
    planner: { model: plan.planner?.model ?? "unknown", prompt_version: plan.planner?.prompt_version ?? "plan/1" },
  };
}

/** `check_revision`: the plan to revise has this job's frame, keeps the rules, and has the shots named. Throws `invalid_plan`. */
function checkRevision(revise: PlanRevision, context: ReturnType<typeof planContext>): void {
  const plan = revise.plan;
  if (
    plan.profile_id !== context.profile.id ||
    plan.resolution !== context.resolution ||
    plan.aspect_ratio !== context.aspectRatio ||
    plan.fps !== context.fps ||
    plan.audio !== context.audio
  ) {
    throw new KunoError(0, "invalid_plan", "The plan to revise has a different profile, size, frame rate or sound than this job.");
  }
  validatePlan(plan, context.profile);
  if (!revise.shots) return;
  if (revise.shots[revise.shots.length - 1] > plan.shots.length) throw new KunoError(0, "invalid_plan", `The plan to revise has ${plan.shots.length} shots.`);
  plan.shots.forEach((shot, i) => {
    if (!revise.shots!.includes(i + 1) && shot.duration_s > context.maxShotS + 1e-6) {
      throw new KunoError(0, "invalid_plan", `Shot ${i + 1}, which stays as it is, is longer than this plan's longest shot, ${context.maxShotS} s.`);
    }
  });
}

async function toBytes(file: Blob | Uint8Array): Promise<Uint8Array> {
  return file instanceof Uint8Array ? file : new Uint8Array(await file.arrayBuffer());
}

// ------------------------------------------------------------ share links

/** A share token and an output key are both 32 bytes written as base64url: 43 characters. */
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;

function outputKeyText(outputKey: string | Uint8Array): string {
  const text = typeof outputKey === "string" ? outputKey : outputKey.length === 32 ? b64e(outputKey) : "";
  if (!BASE64URL_32.test(text)) throw new KunoError(0, "invalid_key", "An output key is 32 bytes, written as base64url (43 characters).");
  return text;
}

/**
 * A private video's share link with its key as the fragment, `#k=…`. Browsers never send a
 * fragment, so the key doesn't reach KunoWorld, but anyone given the whole link can open the
 * video. `outputKey` is a handle's `outputKey` (or the 32 raw bytes). Replaces any fragment.
 */
export function shareUrlWithKey(url: string, outputKey: string | Uint8Array): string {
  const key = outputKeyText(outputKey);
  const hashAt = url.indexOf("#");
  return `${hashAt === -1 ? url : url.slice(0, hashAt)}#k=${key}`;
}

/**
 * A share link's token, and the key from its `#k=` fragment when it has one. Accepts a full link
 * (`https://kunoworld.com/s/<token>#k=<key>`), a path (`/s/<token>`) or a bare token. Anything
 * else throws `not_found` before a request is made.
 */
export function parseShareLink(link: string): { token: string; key: string | null } {
  const text = link.trim();
  const hashAt = text.indexOf("#");
  const beforeHash = hashAt === -1 ? text : text.slice(0, hashAt);
  const path = beforeHash.split("?")[0].replace(/\/+$/, "");
  const token = path.slice(path.lastIndexOf("/") + 1);
  if (!BASE64URL_32.test(token)) throw new KunoError(0, "not_found", "That isn't a valid share link.");
  const key = hashAt === -1 ? null : new URLSearchParams(text.slice(hashAt + 1)).get("k");
  return { token, key: key || null };
}

export interface CreateShareOptions {
  /** When the link stops working: Unix seconds or a Date, from a minute to ten years ahead. Null or absent: until revoked. */
  expiresAt?: number | Date | null;
}

export interface ListSharesOptions {
  /** Only this video's links. */
  jobId?: string;
  /** Default 100; the gateway returns at most 500. */
  limit?: number;
}

/** `kuno.shares`: links that let anyone holding them watch one video. */
export interface ShareLinks {
  /**
   * Makes a link to one of this account's finished videos (`POST /v1/videos/{id}/shares`). Given a
   * private `JobHandle`, `url` carries its key as `#k=…`; given a job id, add it with `shareUrlWithKey`.
   */
  create(target: string | AnyJobHandle, opts?: CreateShareOptions): Promise<ShareLink>;
  /** This account's links, newest first, with each one's `status` and `viewCount`. Tokens aren't kept, so they aren't here. */
  list(opts?: ListSharesOptions): Promise<ShareSummary[]>;
  /** Stops a link for good. Revoking twice is harmless. */
  revoke(shareId: string): Promise<ShareSummary>;
  /** Public, no credential sent: what a link shows (mode, model, dates, receipt), plus its token and fragment key. */
  get(tokenOrUrl: string): Promise<SharedVideoDetails>;
  /**
   * Public, no credential sent: downloads a shared video and checks it against the receipt. A
   * private link needs its key, from the link's fragment or `key`; it is decrypted here.
   */
  open(url: string, key?: string): Promise<SharedVideo>;
}

interface ShareRowWire {
  share_id: string;
  job_id: string;
  privacy: PrivacyMode;
  profile_id: string | null;
  created_at: number;
  expires_at: number | null;
  revoked_at: number | null;
  status: ShareStatus;
  view_count: number;
}

interface ShareLinkWire extends ShareRowWire {
  token: string;
  url_path: string;
  url: string;
}

interface SharedVideoWire {
  privacy: PrivacyMode;
  profile_id: string;
  created_at: number;
  shared_at: number;
  expires_at: number | null;
  content_digest: string;
  receipt: Receipt | null;
  signing_public_key: string | null;
}

function shareSummary(row: ShareRowWire): ShareSummary {
  return {
    shareId: row.share_id,
    jobId: row.job_id,
    privacy: row.privacy,
    profileId: row.profile_id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    status: row.status,
    viewCount: row.view_count,
  };
}

function receiptSignedBy(receipt: Receipt, signingPublicKey: string | null): boolean {
  if (!signingPublicKey) return false;
  try {
    return verifyReceipt(receipt, b64d(signingPublicKey));
  } catch {
    return false;
  }
}

export interface ElementWriteOptions {
  /** The uploader affirms `ELEMENT_RULES` on every write; the gateway refuses one without it. */
  affirmRules: true;
}

/** `kuno.elements.list`: the Elements this key opens, and any it can't. */
export interface ElementList {
  elements: Element[];
  /** Stored Elements that didn't open: `key_rotated` (made under another key sync generation), `decrypt_failed` or `integrity`. */
  unreadable: Array<{ elementId: string; revision: number; reason: string }>;
  /** The vault's current `master_key_id`, or null while key sync is off. A key with another `keyId` is stale. */
  keyId: string | null;
  storedBytes: number;
}

/**
 * `kuno.elements`: reusable characters, products, locations, styles and voices, sealed in this process with an Elements
 * key (elements.ts) so KunoWorld stores only ciphertext. The website derives the key from key sync; a program reads it
 * from the studio's Elements page (`parseElementsKey`).
 */
export interface ElementsApi {
  /** Every stored Element as the gateway holds it (ciphertext), and the vault's current `master_key_id`. */
  rows(): Promise<{ rows: ElementRow[]; keyId: string | null }>;
  list(key: ElementsKey): Promise<ElementList>;
  get(key: ElementsKey, elementId: string): Promise<Element>;
  /** Seals the draft here, uploads the sealed files and stores the Element. */
  create(key: ElementsKey, draft: ElementDraft, opts: ElementWriteOptions & { elementId?: string }): Promise<Element>;
  /**
   * Replaces an Element with a draft. Without `files` its files stay (and so does its key); with them, every file is
   * replaced under a new key. Refused with `element_changed` when another device changed it since `element` was read.
   */
  update(key: ElementsKey, element: Element, draft: Omit<ElementDraft, "files"> & { files?: ElementFileDraft[] }, opts: ElementWriteOptions): Promise<Element>;
  /** Deletes the Element, its record and its files. Deleting one that isn't there is harmless. */
  delete(elementId: string): Promise<void>;
  /** One file, downloaded, opened and checked against the Element's record. */
  file(element: Element, position?: number): Promise<Uint8Array>;
  /**
   * A request with Elements in it: each Element's description added to the prompt (a storyboard's scene) on its own line,
   * and its files added as inputs in the roles given. The files are opened here and then treated like any other input:
   * sealed to the enclave for a Private job, uploaded as they are for a Standard one.
   */
  attach(request: GenerateRequest, uses: ElementUse[]): Promise<GenerateRequest>;
}

export class KunoClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private manifestCache: GoldenManifest | undefined;
  private modelsCache: { at: number; value: ModelsResponse } | undefined;

  /**
   * Share links. `create`, `list` and `revoke` use this client's credential; `get` and `open` are
   * public and send none, so a client without an API key can open any link.
   */
  /** Elements. Every call uses this client's credential: an API key, or the website's session through its proxy. */
  readonly elements: ElementsApi = {
    rows: () => this.elementRows(),
    list: (key) => this.listElements(key),
    get: async (key, elementId) => openElement(key, await this.json<ElementRow>("GET", `/v1/elements/${encodeURIComponent(elementId)}`)),
    create: (key, draft, opts) => this.writeElement(key, opts.elementId ?? newElementId(), null, draft, opts),
    update: (key, element, draft, opts) => this.writeElement(key, element.elementId, element, draft, opts),
    delete: async (elementId) => {
      await this.request("DELETE", `/v1/elements/${encodeURIComponent(elementId)}`);
    },
    file: (element, position) => this.elementFile(element, position),
    attach: (request, uses) => this.attachElements(request, uses),
  };

  readonly shares: ShareLinks = {
    create: (target, opts) => this.createShare(target, opts),
    list: (opts) => this.listShares(opts),
    revoke: (shareId) => this.revokeShare(shareId),
    get: (tokenOrUrl) => this.sharedVideoDetails(tokenOrUrl),
    open: (url, key) => this.openSharedVideo(url, key),
  };

  constructor(private readonly opts: KunoClientOptions = {}) {
    if (opts.apiKey?.startsWith("kwt_")) {
      throw new KunoError(410, "gone", ERROR_CODES.gone);
    }
    this.baseUrl = (opts.baseUrl ?? "https://api.kunoworld.com").replace(/\/+$/, "");
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.manifestCache = opts.manifest;
  }

  /**
   * A client for a same-origin proxy that adds the credentials itself, such as a website that
   * forwards `/api/kuno/*` to the gateway with the visitor's session. No key is held in the page;
   * private jobs are still encrypted here, so the proxy only ever relays ciphertext.
   */
  static forProxy(baseUrl: string, opts: Omit<KunoClientOptions, "apiKey" | "baseUrl"> = {}): KunoClient {
    return new KunoClient({ credentials: "same-origin", ...opts, baseUrl });
  }

  private async request(method: string, path: string, body?: BodyInit, contentType?: string, auth = true): Promise<Response> {
    const headers: Record<string, string> = {};
    if (auth && this.opts.apiKey) headers.authorization = `Bearer ${this.opts.apiKey}`;
    if (this.opts.country) headers["x-kuno-country"] = this.opts.country;
    if (contentType) headers["content-type"] = contentType;
    const init: RequestInit = { method, headers, body };
    if (this.opts.credentials) init.credentials = this.opts.credentials;
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, init);
    if (!response.ok) {
      let detail: Record<string, unknown> = {};
      try {
        const json = (await response.json()) as { detail?: unknown };
        detail =
          typeof json.detail === "object" && json.detail && !Array.isArray(json.detail)
            ? (json.detail as Record<string, unknown>)
            : { message: String(json.detail) };
      } catch {
        /* non-JSON error body */
      }
      const { code, message, ...rest } = detail;
      throw new KunoError(
        response.status,
        typeof code === "string" ? code : "error",
        typeof message === "string" ? message : response.statusText,
        rest,
      );
    }
    return response;
  }

  private async json<T>(method: string, path: string, body?: unknown, auth = true): Promise<T> {
    const response = await this.request(method, path, body === undefined ? undefined : JSON.stringify(body), body === undefined ? undefined : "application/json", auth);
    return (await response.json()) as T;
  }

  async models(maxAgeMs = 15000): Promise<ModelsResponse> {
    if (this.modelsCache && Date.now() - this.modelsCache.at < maxAgeMs) return this.modelsCache.value;
    const value = await this.json<ModelsResponse>("GET", "/v1/models", undefined, false);
    this.modelsCache = { at: Date.now(), value };
    return value;
  }

  async manifest(): Promise<GoldenManifest> {
    if (!this.manifestCache && this.opts.ownerPublicKey) {
      const document = await this.json<unknown>("GET", "/v1/manifest/signed", undefined, false);
      try {
        this.manifestCache = verifySignedManifest(document, b64d(this.opts.ownerPublicKey));
      } catch (err) {
        throw new KunoError(0, "integrity", `The gateway's manifest can't be trusted: ${(err as Error).message}.`);
      }
    }
    this.manifestCache ??= await this.json<GoldenManifest>("GET", "/v1/manifest", undefined, false);
    return this.manifestCache;
  }

  /**
   * Which profile and enclaves would serve a request. The credential is sent when the client has
   * one, so the gateway can refuse private routing to an account that isn't eligible for it.
   * `fit` (resolution, aspect ratio, fps, duration) keeps only workers whose hardware can fit such a
   * request (their serving envelope); an omitted field matches any value.
   */
  async route(mode: Mode, model?: string, family?: string, privacy?: PrivacyMode, fit?: RouteFit): Promise<RouteResponse> {
    const q = new URLSearchParams({ mode });
    if (model) q.set("profile_id", model);
    if (family) q.set("family", family);
    if (privacy === "standard") q.set("privacy", "standard");
    if (fit?.resolution !== undefined) q.set("resolution", fit.resolution);
    if (fit?.aspectRatio !== undefined) q.set("aspect_ratio", fit.aspectRatio);
    if (fit?.fps !== undefined) q.set("fps", String(fit.fps));
    if (fit?.durationS !== undefined) q.set("duration_s", String(fit.durationS));
    return this.json<RouteResponse>("GET", `/v1/route?${q}`);
  }

  /**
   * Private (default): routes, verifies the enclave, encrypts inputs in this process, seals and
   * submits. Standard: uploads the inputs as they are and lets the gateway seal the job.
   */
  submit(req: GenerateRequest & { privacy: "standard" }, onStage?: (stage: SubmitStage) => void): Promise<StandardJobHandle>;
  submit(req: GenerateRequest & { privacy?: "private" }, onStage?: (stage: SubmitStage) => void): Promise<JobHandle>;
  submit(req: GenerateRequest, onStage?: (stage: SubmitStage) => void): Promise<AnyJobHandle>;
  async submit(req: GenerateRequest, onStage?: (stage: SubmitStage) => void): Promise<AnyJobHandle> {
    return req.privacy === "standard" ? this.submitStandard(req, onStage) : this.submitPrivate(req, onStage);
  }

  /** Submits and waits: the one-call path. */
  async generate(req: GenerateRequest, opts: WaitOptions & { onStage?: (stage: SubmitStage) => void } = {}): Promise<GenerationResult> {
    return this.wait(await this.submit(req, opts.onStage), opts);
  }

  private async submitStandard(req: GenerateRequest, onStage?: (stage: SubmitStage) => void): Promise<StandardJobHandle> {
    const inputs = req.inputs ?? [];
    const roles = inputs.map((i) => i.role);
    const mode = requestMode(req, roles);

    onStage?.("routing");
    const route = await this.route(mode, req.model, req.family, "standard", routeFit(req));
    const profile = (await this.models(0)).models.find((m) => m.id === route.profile_id);
    if (!profile) throw new KunoError(404, "unknown_model", `Unknown model ${route.profile_id}.`);
    const params = fitParams(profile, mode, roles, req, route.fallback_reason);
    checkStoryboardRequest(profile, params, req);

    const refs: Array<Record<string, unknown>> = [];
    for (const [index, input] of inputs.entries()) {
      const data = await toBytes(input.file);
      const mime = sniffMime(data);
      if (!mime) throw new KunoError(0, "unsupported_media", `Could not recognize the ${input.role} file type.`);
      onStage?.("uploading");
      const upload = await this.uploadStandard(input.role, data, mime);
      refs.push({
        upload_id: upload.upload_id,
        index,
        role: input.role,
        time_s: input.timeS ?? null,
        strength: input.strength ?? null,
        hint: input.hint ?? null,
        start_s: input.startS ?? null,
        end_s: input.endS ?? null,
      });
    }

    onStage?.("submitting");
    const status = await this.json<JobStatus>("POST", "/v1/standard/videos", {
      job_id: crypto.randomUUID(),
      params,
      // For a storyboard, the scene; each shot's own prompt goes in `shots`, in order.
      prompt: req.prompt,
      negative_prompt: req.negativePrompt ?? null,
      seed: req.seed ?? null,
      options: req.options ?? {},
      inputs: refs,
      ...(params.shots ? { shots: req.shots!.map((shot) => ({ prompt: shot.prompt })) } : {}),
    });
    return {
      privacy: "standard",
      jobId: status.job_id,
      enclaveId: status.enclave_id,
      profileId: status.params?.profile_id ?? profile.id,
      fallbackReason: route.fallback_reason,
      createdAt: status.created_at ?? Date.now() / 1000,
    };
  }

  /**
   * Uploads one standard-mode input as plaintext. The gateway detects the type from the bytes
   * (the content-type sent is informational). Uploads are scanned: a match is `upload_blocked`,
   * and `scan_unavailable` means the scanner couldn't be reached.
   */
  async uploadStandard(role: InputRole, file: Blob | Uint8Array, mime?: string): Promise<StandardUpload> {
    const data = await toBytes(file);
    const type = mime ?? sniffMime(data);
    if (!type) throw new KunoError(0, "unsupported_media", `Could not recognize the ${role} file type.`);
    const response = await this.request("POST", `/v1/standard/uploads?role=${encodeURIComponent(role)}`, new Blob([new Uint8Array(data)]), type);
    return (await response.json()) as StandardUpload;
  }

  private async submitPrivate(req: GenerateRequest, onStage?: (stage: SubmitStage) => void): Promise<JobHandle> {
    const inputs = req.inputs ?? [];
    const roles = inputs.map((i) => i.role);
    const mode = requestMode(req, roles);

    onStage?.("routing");
    const route = await this.route(mode, req.model, req.family, undefined, routeFit(req));
    const profile = (await this.models(0)).models.find((m) => m.id === route.profile_id);
    if (!profile) throw new KunoError(404, "unknown_model", `Unknown model ${route.profile_id}.`);
    const params = fitParams(profile, mode, roles, req, route.fallback_reason);
    checkStoryboardRequest(profile, params, req);

    onStage?.("verifying");
    const enclave = await this.pickEnclave(route, params);

    onStage?.("encrypting");
    const jobId = crypto.randomUUID();
    const session = await openSenderSession(b64d(enclave.hpke_public_key));
    const refs: InputRef[] = [];
    const blobIds: string[] = [];
    for (const [index, input] of inputs.entries()) {
      const data = await toBytes(input.file);
      const mime = sniffMime(data);
      if (!mime) throw new KunoError(0, "unsupported_media", `Could not recognize the ${input.role} file type.`);
      const sealed = encryptBlob(session.inputKey, `${jobId}/input/${index}`, data);
      onStage?.("uploading");
      const uploaded = await this.request("POST", "/v1/blobs", new Blob([new Uint8Array(sealed)]), "application/octet-stream");
      blobIds.push(((await uploaded.json()) as { blob_id: string }).blob_id);
      refs.push({
        index,
        role: input.role,
        mime,
        sha256: await sha256Hex(data),
        size: data.length,
        time_s: input.timeS ?? null,
        strength: input.strength ?? null,
        hint: input.hint ?? null,
        start_s: input.startS ?? null,
        end_s: input.endS ?? null,
      });
    }
    const payload = {
      v: 1,
      // For a storyboard, the scene; each shot's own prompt is sealed in `shots`, in order.
      prompt: req.prompt,
      negative_prompt: req.negativePrompt ?? null,
      seed: req.seed ?? null,
      inputs: refs,
      options: req.options ?? {},
      ...(params.shots ? { shots: req.shots!.map((shot) => ({ prompt: shot.prompt })) } : {}),
    };
    // Padded to a power-of-two bucket, so the request's size doesn't give away the prompt's length.
    let plaintext: Uint8Array;
    try {
      plaintext = padPayload(utf8(JSON.stringify(payload)));
    } catch (err) {
      if (err instanceof RangeError) throw new KunoError(0, "request_too_large", `The request is too large to seal: ${err.message}.`);
      throw err;
    }
    const ciphertext = await session.seal(plaintext, jobAad(jobId, enclave.enclave_id, params, blobIds));

    onStage?.("submitting");
    await this.json("POST", "/v1/videos", {
      job_id: jobId,
      params,
      enclave_id: enclave.enclave_id,
      enc: b64e(session.enc),
      ciphertext: b64e(ciphertext),
      input_blob_ids: blobIds,
    });
    return {
      jobId,
      outputKey: b64e(session.outputKey),
      signingPublicKey: enclave.signing_public_key,
      enclaveId: enclave.enclave_id,
      profileId: profile.id,
      fallbackReason: route.fallback_reason,
      createdAt: Date.now() / 1000,
    };
  }

  private async pickEnclave(route: RouteResponse, params?: GenerationParams): Promise<EnclaveInfo> {
    const manifest = await this.manifest();
    let tooSmall = false;
    for (const enclave of route.enclaves) {
      // The route was filtered by the fields the caller gave; defaults filled in since may not fit every worker listed.
      if (params && !envelopeFits(enclave.envelope, params)) {
        tooSmall = true;
        continue;
      }
      const verdict = verifyEvidence(enclave.evidence, manifest, {
        endorsements: enclave.endorsements,
        nvidiaTrustedSpki: this.opts.nvidiaTrustedSpki,
        tdxAllowedTcbStatuses: this.opts.tdxAllowedTcbStatuses,
      });
      if (
        verdict.ok &&
        verdict.enclaveId === enclave.enclave_id &&
        enclave.evidence.hpke_public_key === enclave.hpke_public_key &&
        enclave.evidence.signing_public_key === enclave.signing_public_key &&
        enclave.evidence.profiles.includes(route.profile_id)
      ) {
        return enclave;
      }
    }
    if (tooSmall) throw new KunoError(503, "no_capacity", "No worker listed can fit this video's size, frame rate and duration right now.");
    throw new KunoError(503, "no_attested_worker", "No worker with valid attestation is available for this model right now.");
  }

  async status(jobId: string): Promise<JobStatus> {
    return this.json<JobStatus>("GET", `/v1/videos/${jobId}`);
  }

  async list(limit = 50): Promise<JobStatus[]> {
    return this.json<JobStatus[]>("GET", `/v1/videos?limit=${limit}`);
  }

  async cancel(jobId: string): Promise<JobStatus> {
    return this.json<JobStatus>("POST", `/v1/videos/${jobId}/cancel`);
  }

  /**
   * Deletes a job's stored content, in either mode: a private job's sealed files, or a standard
   * job's video, prompt, inputs and preview. Videos are kept until their owner deletes them; the
   * charge record and receipt stay. A private job's output key is useless afterwards, so drop it too.
   */
  async delete(jobId: string): Promise<void> {
    await this.request("DELETE", `/v1/videos/${encodeURIComponent(jobId)}`);
  }

  async wait(handle: AnyJobHandle, opts: WaitOptions = {}): Promise<GenerationResult> {
    return this.poll(handle.jobId, opts, 30 * 60 * 1000, "video", (status) => this.result(handle, status));
  }

  private async poll<T>(jobId: string, opts: WaitOptions, timeoutMs: number, what: string, done: (status: JobStatus) => Promise<T>): Promise<T> {
    const deadline = Date.now() + (opts.timeoutMs ?? timeoutMs);
    for (;;) {
      if (opts.signal?.aborted) throw new KunoError(0, "aborted", `Stopped waiting for the ${what}.`);
      const status = await this.status(jobId);
      opts.onProgress?.(status);
      if (status.status === "succeeded") return done(status);
      if (status.status === "failed" || status.status === "canceled") {
        throw new KunoError(0, status.error_code ?? `job_${status.status}`, status.error ?? "The job did not complete.");
      }
      if (Date.now() > deadline) throw new KunoError(0, "timeout", `Job ${jobId} is still ${status.status}.`);
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, opts.pollMs ?? 1000);
        opts.signal?.addEventListener("abort", () => {
          clearTimeout(timer);
          resolve();
        }, { once: true });
      });
    }
  }

  /**
   * Private: downloads the sealed video, checks it against the enclave-signed receipt, decrypts
   * locally. Standard: downloads the stored video and checks it against the receipt's content digest.
   */
  async result(handle: AnyJobHandle, status?: JobStatus): Promise<GenerationResult> {
    status ??= await this.status(handle.jobId);
    if (isStandardHandle(handle)) {
      if (status.status !== "succeeded" || !status.receipt) {
        throw new KunoError(0, "not_ready", `Job ${handle.jobId} is ${status.status}.`);
      }
      const video = await this.standardVideo(handle.jobId);
      if ((await sha256Hex(video)) !== status.receipt.body.content_digest) {
        throw new KunoError(0, "integrity", "The downloaded video does not match the enclave's receipt.");
      }
      return { jobId: handle.jobId, video, receipt: status.receipt, profileId: handle.profileId, fallbackReason: handle.fallbackReason, privacy: "standard" };
    }
    if (status.status !== "succeeded" || !status.receipt || !status.output_blob_id) {
      throw new KunoError(0, "not_ready", `Job ${handle.jobId} is ${status.status}.`);
    }
    const receipt = status.receipt;
    const sealed = new Uint8Array(await (await this.request("GET", `/v1/blobs/${status.output_blob_id}`)).arrayBuffer());
    if ((await sha256Hex(sealed)) !== receipt.body.output_digest) {
      throw new KunoError(0, "integrity", "The downloaded video does not match the enclave's receipt.");
    }
    if (!verifyReceipt(receipt, b64d(handle.signingPublicKey)) || receipt.body.job_id !== handle.jobId) {
      throw new KunoError(0, "integrity", "The receipt was not signed by the attested enclave for this job.");
    }
    let video: Uint8Array;
    try {
      video = decryptBlob(b64d(handle.outputKey), `${handle.jobId}/output/video`, sealed);
    } catch {
      throw new KunoError(0, "decrypt_failed", "This film did not open with the key held in this browser.");
    }
    if ((await sha256Hex(video)) !== receipt.body.content_digest) {
      throw new KunoError(0, "integrity", "The decrypted video does not match the receipt.");
    }
    return { jobId: handle.jobId, video, receipt, profileId: handle.profileId, fallbackReason: handle.fallbackReason, privacy: "private" };
  }

  // ------------------------------------------------------------ plans (Director)

  /**
   * Plans a storyboard from a brief and waits for it: a scene and 2-12 shots fitted to `targetS`, written inside a
   * confidential worker. Nothing renders; edit the plan, then render it with
   * `generate({ prompt: plan.scene, shots: planToShots(plan), model: plan.profile_id, ... })`. A plan costs a flat price
   * (`priceQuote(profile, { mode: "plan", ... })`); `plan_failed` and `safety_blocked` are refunded. A first draft from a
   * small model: read it before rendering.
   */
  async plan(req: PlanRequest, opts: WaitOptions & { onStage?: (stage: SubmitStage) => void } = {}): Promise<PlanResult> {
    return this.waitPlan(await this.submitPlan(req, opts.onStage), opts);
  }

  /**
   * Submits a plan job and returns its handle. Private (default): routes only to attested workers that list `plan/1`,
   * asks for shots no longer than the longest such a worker renders at this size and frame rate, and seals the brief and
   * style here. Standard: `POST /v1/standard/plans`, readable by KunoWorld. Refused before anything is sent: an empty or
   * too long brief (`brief_required`, `prompt_too_long`), a target out of range (`invalid_params`), or no plan worker
   * (`plans_unavailable`).
   */
  async submitPlan(req: PlanRequest, onStage?: (stage: SubmitStage) => void): Promise<PlanHandle> {
    return this.startPlan(req, null, onStage);
  }

  /**
   * Rewrites a plan in the enclave under `instruction` and waits for the new plan. With `shots` (numbered from 1) only
   * those shots are rewritten. The plan may be edited first: its `duration_s` is recomputed from its shots, and it must
   * keep the plan rules (`invalid_plan` otherwise, before anything is sent).
   */
  async revisePlan(
    plan: Plan,
    instruction = "",
    opts: PlanRevisionOptions & WaitOptions & { onStage?: (stage: SubmitStage) => void } = {},
  ): Promise<PlanResult> {
    return this.waitPlan(await this.submitRevision(plan, instruction, opts, opts.onStage), opts);
  }

  /** Submits a revision (see `revisePlan`) and returns its handle. */
  async submitRevision(plan: Plan, instruction = "", opts: PlanRevisionOptions = {}, onStage?: (stage: SubmitStage) => void): Promise<PlanHandle> {
    const req: PlanRequest = {
      brief: opts.brief ?? "",
      targetS: plan.target_s,
      model: plan.profile_id,
      resolution: plan.resolution,
      aspectRatio: plan.aspect_ratio,
      fps: plan.fps,
      audio: plan.audio,
      style: opts.style,
      privacy: opts.privacy,
      seed: opts.seed,
    };
    return this.startPlan(req, { plan, instruction, shots: opts.shots ?? null }, onStage);
  }

  /** Waits for a plan job, then opens and checks the plan (`planResult`). Default timeout 10 minutes. */
  async waitPlan(handle: PlanHandle, opts: WaitOptions = {}): Promise<PlanResult> {
    return this.poll(handle.jobId, opts, 10 * 60 * 1000, "plan", (status) => this.planResult(handle, status));
  }

  /**
   * A finished plan. Private: the sealed output is checked against the enclave-signed receipt, decrypted here, unpadded
   * (form 2 framing only) and checked against the receipt's `content_digest`. Standard: the plan the gateway stored
   * (`GET /v1/standard/plans/{id}`), checked against the same digest. Either way it must pass `validatePlan` for its job.
   */
  async planResult(handle: PlanHandle, status?: JobStatus): Promise<PlanResult> {
    status ??= await this.status(handle.jobId);
    const receipt = status.receipt;
    if (status.status !== "succeeded" || !receipt) throw new KunoError(0, "not_ready", `Job ${handle.jobId} is ${status.status}.`);
    if (status.params.mode !== "plan" || !receipt.body.plan) throw new KunoError(0, "integrity", "This job's receipt doesn't describe a plan.");
    if (receipt.body.job_id !== handle.jobId) throw new KunoError(0, "integrity", "The receipt is for another job.");
    let json: Uint8Array;
    if (handle.privacy === "standard") {
      // The stored plan's bytes: exactly the JSON the receipt's content_digest covers.
      json = new Uint8Array(await (await this.request("GET", `/v1/standard/plans/${encodeURIComponent(handle.jobId)}`)).arrayBuffer());
      let document: unknown;
      try {
        document = JSON.parse(new TextDecoder().decode(json));
      } catch {
        throw new KunoError(0, "integrity", "The gateway's stored plan isn't JSON.");
      }
      const wrapped = document as { plan?: unknown; shots?: unknown } | null;
      if (wrapped && typeof wrapped.plan === "object" && wrapped.plan !== null && wrapped.shots === undefined) {
        // A gateway that wraps the plan in the job's details: the plan's canonical JSON is what was digested.
        try {
          json = encodePlan(parsePlan(JSON.stringify(wrapped.plan)));
        } catch {
          throw new KunoError(0, "integrity", "The gateway's stored plan isn't a Plan v1.");
        }
      }
    } else {
      if (!status.output_blob_id || !handle.outputKey || !handle.signingPublicKey) throw new KunoError(0, "not_ready", `Job ${handle.jobId} has no output yet.`);
      const sealed = new Uint8Array(await (await this.request("GET", `/v1/blobs/${status.output_blob_id}`)).arrayBuffer());
      if ((await sha256Hex(sealed)) !== receipt.body.output_digest) {
        throw new KunoError(0, "integrity", "The downloaded plan does not match the enclave's receipt.");
      }
      if (!verifyReceipt(receipt, b64d(handle.signingPublicKey))) {
        throw new KunoError(0, "integrity", "The receipt was not signed by the attested enclave for this job.");
      }
      try {
        json = openPlan(b64d(handle.outputKey), handle.jobId, sealed).json;
      } catch (err) {
        if (err instanceof DecryptionError) throw new KunoError(0, "decrypt_failed", "The plan didn't open with this handle's output key.");
        throw new KunoError(0, "integrity", `The enclave's output isn't a sealed plan: ${(err as Error).message}.`);
      }
    }
    if ((await sha256Hex(json)) !== receipt.body.content_digest) {
      throw new KunoError(0, "integrity", "The plan does not match the receipt's content digest.");
    }
    let plan: Plan;
    try {
      plan = parsePlan(json);
    } catch {
      throw new KunoError(0, "integrity", "The plan isn't a Plan v1.");
    }
    const profile = (await this.models()).models.find((m) => m.id === status.params.profile_id);
    if (!profile) throw new KunoError(404, "unknown_model", `Unknown model ${status.params.profile_id}.`);
    try {
      validatePlan(plan, profile, planContext(profile, status.params, { max_shot_s: handle.maxShotS }));
    } catch (err) {
      throw new KunoError(0, "integrity", `The delivered plan breaks the plan rules: ${(err as Error).message}.`);
    }
    const info = receipt.body.plan;
    if (info.shots !== plan.shots.length || Math.abs(info.duration_s - plan.duration_s) > 1e-6) {
      throw new KunoError(0, "integrity", "The plan doesn't match the shots and length its receipt describes.");
    }
    return { jobId: handle.jobId, plan, json, receipt, privacy: handle.privacy };
  }

  private async startPlan(req: PlanRequest, revision: PlanRevision | null, onStage?: (stage: SubmitStage) => void): Promise<PlanHandle> {
    const privacy: PrivacyMode = req.privacy ?? "private";
    if (privacy !== "private" && privacy !== "standard") throw new KunoError(0, "invalid_privacy", 'privacy must be "private" or "standard".');
    if (typeof req.brief !== "string" || (!revision && !req.brief.trim())) throw new KunoError(0, "brief_required", ERROR_CODES.brief_required);
    if (typeof req.targetS !== "number" || !Number.isFinite(req.targetS)) throw new KunoError(0, "invalid_params", "targetS is the plan's length in seconds.");

    onStage?.("routing");
    const fit = { resolution: req.resolution, aspectRatio: req.aspectRatio, fps: req.fps };
    const route = await this.route("plan", req.model ?? "ltx-2.5-fast", undefined, privacy, fit);
    const profile = (await this.models(0)).models.find((m) => m.id === route.profile_id);
    if (!profile) throw new KunoError(404, "unknown_model", `Unknown model ${route.profile_id}.`);
    const limits = profile.limits.plan;
    const board = profile.limits.storyboard;
    if (!profile.modes.includes("plan") || !limits || !board) throw new KunoError(0, "invalid_params", `${profile.name} doesn't write plans.`);
    const params = fitParams(profile, "plan", [], { ...req, durationS: req.targetS }, route.fallback_reason);
    const fail = (code: string, message: string): never => {
      throw new KunoError(0, code, message);
    };
    if (!(limits.min_target_s <= params.duration_s && params.duration_s <= board.max_total_s)) {
      fail("invalid_params", `a plan's target duration must be between ${limits.min_target_s} and ${board.max_total_s} seconds`);
    }
    if (!profile.limits.sizes[params.resolution]?.[params.aspect_ratio]) fail("invalid_params", `${profile.name} doesn't render ${params.resolution} at ${params.aspect_ratio}`);
    if (!profile.limits.fps.includes(params.fps)) fail("invalid_params", `fps must be one of ${profile.limits.fps.join(", ")}`);
    const maxBrief = limits.max_brief_chars ?? 4000;
    const maxStyle = limits.max_style_chars ?? 500;
    if ([...req.brief].length > maxBrief) fail("prompt_too_long", `A brief is limited to ${maxBrief.toLocaleString("en-US")} characters on ${profile.name}.`);
    if (req.style && [...req.style].length > maxStyle) fail("prompt_too_long", `A style is limited to ${maxStyle.toLocaleString("en-US")} characters on ${profile.name}.`);

    // Only workers that list plan/1 can open a plan job: an older one would leave it to time out.
    const fitting = route.enclaves.filter((e) => e.features?.includes(PLAN_FEATURE) && envelopeFits(e.envelope, params));
    if (privacy === "private" && !fitting.length) {
      const unlisted = route.enclaves.length > 0 && route.enclaves.every((e) => e.features === undefined);
      throw new KunoError(
        503,
        "plans_unavailable",
        unlisted
          ? "This gateway doesn't say which workers write plans, so the brief wasn't sent: a worker that can't write plans would leave the job to time out. Nothing was charged."
          : `No confidential worker that writes plans for ${profile.name} at this size is online right now. Nothing was sent or charged.`,
      );
    }
    const maxShotS = longestServedShot(profile, params, fitting);

    let revise: PlanRevision | null = null;
    if (revision) {
      const numbers = revision.shots == null ? null : [...new Set(revision.shots)].sort((a, b) => a - b);
      if (numbers && (!numbers.length || numbers.some((n) => !Number.isInteger(n) || n < 1))) fail("invalid_plan", "Shots to revise are numbered from 1.");
      revise = { plan: cleanPlan(restitchPlan(profile, cleanPlan(revision.plan))), instruction: revision.instruction ?? "", shots: numbers };
    }
    const options: PlanOptions = { v: 1, min_shots: 2 };
    if (req.style) options.style = req.style;
    if (maxShotS !== null) options.max_shot_s = maxShotS;
    if (revise) options.revise = revise;
    let context;
    try {
      context = planContext(profile, params, options);
    } catch (err) {
      throw new KunoError(503, "no_capacity", `No worker can plan shots for this size and frame rate: ${(err as Error).message}.`);
    }
    if (revise) checkRevision(revise, context);

    if (privacy === "standard") {
      onStage?.("submitting");
      const { style: _style, ...rest } = options;
      const status = await this.json<JobStatus>("POST", "/v1/standard/plans", {
        job_id: crypto.randomUUID(),
        params,
        brief: req.brief,
        ...(req.style ? { style: req.style } : {}),
        options: rest,
        ...(req.seed !== undefined ? { seed: req.seed } : {}),
      });
      return {
        kind: "plan", jobId: status.job_id, privacy: "standard", profileId: status.params?.profile_id ?? profile.id, enclaveId: status.enclave_id ?? "",
        maxShotS, fallbackReason: route.fallback_reason, createdAt: status.created_at ?? Date.now() / 1000,
      };
    }

    onStage?.("verifying");
    const enclave = await this.pickEnclave({ ...route, enclaves: fitting }, params);
    onStage?.("encrypting");
    const jobId = crypto.randomUUID();
    const session = await openSenderSession(b64d(enclave.hpke_public_key));
    const payload = { v: 1, prompt: req.brief, negative_prompt: null, seed: req.seed ?? null, inputs: [], options: { [PLAN_OPTION]: options } };
    let plaintext: Uint8Array;
    try {
      plaintext = padPayload(utf8(JSON.stringify(payload)));
    } catch (err) {
      if (err instanceof RangeError) throw new KunoError(0, "request_too_large", `The request is too large to seal: ${err.message}.`);
      throw err;
    }
    const ciphertext = await session.seal(plaintext, jobAad(jobId, enclave.enclave_id, params, []));
    onStage?.("submitting");
    await this.json("POST", "/v1/videos", { job_id: jobId, params, enclave_id: enclave.enclave_id, enc: b64e(session.enc), ciphertext: b64e(ciphertext), input_blob_ids: [] });
    return {
      kind: "plan", jobId, privacy: "private", profileId: profile.id, enclaveId: enclave.enclave_id, outputKey: b64e(session.outputKey),
      signingPublicKey: enclave.signing_public_key, maxShotS, fallbackReason: route.fallback_reason, createdAt: Date.now() / 1000,
    };
  }

  // ------------------------------------------------------------ standard library

  /** This account's standard jobs, newest first. */
  async listStandard(limit = 50): Promise<StandardVideoSummary[]> {
    return this.json<StandardVideoSummary[]>("GET", `/v1/standard/videos?limit=${limit}`);
  }

  /** A standard job's video (`not_ready` until it succeeds; `deleted` or `removed` once it's gone). */
  async standardVideo(jobId: string): Promise<Uint8Array> {
    return new Uint8Array(await (await this.request("GET", `/v1/standard/videos/${encodeURIComponent(jobId)}/video`)).arrayBuffer());
  }

  /** A JPEG frame of a standard job's video. */
  async standardThumbnail(jobId: string): Promise<Uint8Array> {
    return new Uint8Array(await (await this.request("GET", `/v1/standard/videos/${encodeURIComponent(jobId)}/thumbnail`)).arrayBuffer());
  }

  /** Deletes the stored video, prompt and inputs of a standard job. Same effect as `delete`, which works in both modes. */
  async deleteStandard(jobId: string): Promise<void> {
    await this.request("DELETE", `/v1/standard/videos/${encodeURIComponent(jobId)}`);
  }

  /** A handle for a standard job listed by `listStandard`, to wait on or fetch it. */
  standardHandle(summary: Pick<StandardVideoSummary, "job_id" | "profile_id" | "created_at">): StandardJobHandle {
    return { privacy: "standard", jobId: summary.job_id, enclaveId: "", profileId: summary.profile_id, fallbackReason: null, createdAt: summary.created_at };
  }

  // ------------------------------------------------------------ account safety

  /** Whether this account may make private jobs, and any restriction or strikes. */
  async eligibility(): Promise<Eligibility> {
    return this.json<Eligibility>("GET", "/v1/account/eligibility");
  }

  /** Public: report a video. No credential is sent. */
  async report(req: ReportRequest): Promise<{ report_id: string }> {
    return this.json<{ report_id: string }>("POST", "/v1/reports", req, false);
  }

  /** Public: look up the certificate for a video file by its SHA-256. */
  async provenance(file: Blob | Uint8Array): Promise<Provenance> {
    return this.provenanceByDigest(await sha256Hex(await toBytes(file)));
  }

  /** Public: the same lookup when you already have the digest (e.g. a /verify?sha256=… link). */
  async provenanceByDigest(contentDigest: string): Promise<Provenance> {
    return this.json<Provenance>("GET", `/v1/provenance/${encodeURIComponent(contentDigest.toLowerCase())}`, undefined, false);
  }

  // ------------------------------------------------------------ Elements (see `elements`)

  private async elementRows(): Promise<{ rows: ElementRow[]; keyId: string | null }> {
    const rows: ElementRow[] = [];
    let cursor: string | null = null;
    let keyId: string | null = null;
    do {
      const q = new URLSearchParams({ limit: "200" });
      if (cursor) q.set("cursor", cursor);
      const page: { elements: ElementRow[]; next_cursor: string | null; master_key_id: string | null } = await this.json("GET", `/v1/elements?${q}`);
      rows.push(...page.elements);
      keyId = page.master_key_id;
      cursor = page.next_cursor;
    } while (cursor);
    return { rows, keyId };
  }

  private async listElements(key: ElementsKey): Promise<ElementList> {
    const { rows, keyId } = await this.elementRows();
    const list: ElementList = { elements: [], unreadable: [], keyId, storedBytes: rows.reduce((n, r) => n + r.files_bytes, 0) };
    for (const row of rows) {
      if (row.master_key_id !== key.keyId) {
        list.unreadable.push({ elementId: row.element_id, revision: row.revision, reason: "key_rotated" });
        continue;
      }
      try {
        list.elements.push(openElement(key, row));
      } catch (err) {
        list.unreadable.push({ elementId: row.element_id, revision: row.revision, reason: err instanceof KunoError ? err.code : "decrypt_failed" });
      }
    }
    return list;
  }

  private async writeElement(
    key: ElementsKey,
    elementId: string,
    current: Element | null,
    draft: Omit<ElementDraft, "files"> & { files?: ElementFileDraft[] },
    opts: ElementWriteOptions,
  ): Promise<Element> {
    if (opts?.affirmRules !== true) throw new KunoError(0, "rules_not_affirmed", "Affirm the Elements rules (ELEMENT_RULES) to store an Element.");
    const keep = current !== null && draft.files === undefined;
    const sealed = keep
      ? sealElement(key, elementId, { ...draft, files: [] }, { elementKey: current.elementKey, keepFiles: current.files })
      : sealElement(key, elementId, { ...draft, files: draft.files ?? [] });
    const fileBlobIds: string[] = [];
    for (const file of sealed.files) {
      const uploaded = await this.request("POST", "/v1/blobs", new Blob([new Uint8Array(file)]), "application/octet-stream");
      fileBlobIds.push(((await uploaded.json()) as { blob_id: string }).blob_id);
    }
    const row = await this.json<ElementRow>("PUT", `/v1/elements/${encodeURIComponent(elementId)}`, {
      master_key_id: key.keyId,
      expected_revision: current?.revision ?? null,
      meta: sealed.meta,
      affirm_rules: true,
      ...(keep ? {} : { wrapped_key: sealed.wrappedKey, file_blob_ids: fileBlobIds }),
    });
    return openElement(key, row);
  }

  private async elementFile(element: Element, position = 0): Promise<Uint8Array> {
    const info = element.files[position];
    if (!info) throw new KunoError(0, "invalid_element", `${element.name} has no file ${position}.`);
    const response = await this.request("GET", `/v1/elements/${encodeURIComponent(element.elementId)}/files/${position}`);
    return openElementFile(element.elementKey, element.elementId, position, new Uint8Array(await response.arrayBuffer()), info);
  }

  private async attachElements(request: GenerateRequest, uses: ElementUse[]): Promise<GenerateRequest> {
    const storyboard = request.mode === "storyboard" || Boolean(request.shots?.length);
    const inputs = [...(request.inputs ?? [])];
    // Every use is checked before any file is downloaded, so a refused one costs nothing.
    const planned = uses.map((use) => ({ use, positions: checkElementUse(use, storyboard) }));
    for (const { use, positions } of planned) {
      for (const position of positions) {
        inputs.push({ role: use.role!, file: await this.elementFile(use.element, position), timeS: use.timeS });
      }
    }
    return {
      ...request,
      prompt: addElementLines(request.prompt ?? "", uses.map((use) => use.element)),
      ...(inputs.length ? { inputs } : {}),
    };
  }

  // ------------------------------------------------------------ share links (see `shares`)

  private async createShare(target: string | AnyJobHandle, opts: CreateShareOptions = {}): Promise<ShareLink> {
    const jobId = typeof target === "string" ? target : target.jobId;
    // Check a handle's key before the link exists, so a bad key can't leave a link behind.
    const outputKey = typeof target !== "string" && !isStandardHandle(target) ? outputKeyText(target.outputKey) : null;
    const given = opts.expiresAt;
    const expiresAt = given instanceof Date ? given.getTime() / 1000 : given ?? null;
    if (expiresAt !== null && (typeof expiresAt !== "number" || !Number.isFinite(expiresAt))) {
      throw new KunoError(0, "invalid_expiry", ERROR_CODES.invalid_expiry);
    }
    const row = await this.json<ShareLinkWire>("POST", `/v1/videos/${encodeURIComponent(jobId)}/shares`, { expires_at: expiresAt });
    const link: ShareLink = { ...shareSummary(row), token: row.token, urlPath: row.url_path, url: row.url, keyIncluded: false };
    if (outputKey !== null && row.privacy === "private") {
      link.url = shareUrlWithKey(row.url, outputKey);
      link.keyIncluded = true;
    }
    return link;
  }

  private async listShares(opts: ListSharesOptions = {}): Promise<ShareSummary[]> {
    const q = new URLSearchParams();
    if (opts.jobId) q.set("job_id", opts.jobId);
    q.set("limit", String(opts.limit ?? 100));
    return (await this.json<ShareRowWire[]>("GET", `/v1/account/shares?${q}`)).map(shareSummary);
  }

  private async revokeShare(shareId: string): Promise<ShareSummary> {
    return shareSummary(await this.json<ShareRowWire>("DELETE", `/v1/account/shares/${encodeURIComponent(shareId)}`));
  }

  private async sharedVideoDetails(tokenOrUrl: string): Promise<SharedVideoDetails> {
    const { token, key } = parseShareLink(tokenOrUrl);
    const d = await this.json<SharedVideoWire>("GET", `/v1/shares/${token}`, undefined, false);
    return {
      privacy: d.privacy,
      profileId: d.profile_id,
      createdAt: d.created_at,
      sharedAt: d.shared_at,
      expiresAt: d.expires_at,
      contentDigest: d.content_digest,
      receipt: d.receipt,
      signingPublicKey: d.signing_public_key,
      token,
      key,
    };
  }

  private async openSharedVideo(url: string, key?: string): Promise<SharedVideo> {
    const details = await this.sharedVideoDetails(url);
    const outputKey = key || details.key;
    const isPrivate = details.privacy === "private";
    if (isPrivate && !outputKey) throw new KunoError(0, "missing_key", ERROR_CODES.missing_key);
    const receipt = details.receipt;
    if (!receipt?.body || receipt.body.content_digest !== details.contentDigest) {
      throw new KunoError(0, "integrity", "The link's receipt doesn't describe this video.");
    }
    const response = await this.request("GET", `/v1/shares/${details.token}/video`, undefined, undefined, false);
    const data = new Uint8Array(await response.arrayBuffer());
    const opened = (video: Uint8Array): SharedVideo => ({
      privacy: isPrivate ? "private" : "standard",
      video,
      receipt,
      contentDigest: details.contentDigest,
      profileId: details.profileId ?? receipt.body.profile_id,
    });
    if (!isPrivate) {
      if ((await sha256Hex(data)) !== details.contentDigest) {
        throw new KunoError(0, "integrity", "The shared video does not match its receipt.");
      }
      return opened(data);
    }
    if ((await sha256Hex(data)) !== receipt.body.output_digest) {
      throw new KunoError(0, "integrity", "The shared video does not match the enclave's receipt.");
    }
    if (!receiptSignedBy(receipt, details.signingPublicKey)) {
      throw new KunoError(0, "integrity", "The receipt was not signed by the enclave that made this video.");
    }
    let video: Uint8Array;
    try {
      const keyBytes = b64d(outputKey as string);
      if (keyBytes.length !== 32) throw new Error("an output key is 32 bytes");
      // The label binds the blob to the signed receipt's job: a blob sealed for another job doesn't open.
      video = decryptBlob(keyBytes, `${receipt.body.job_id}/output/video`, data);
    } catch {
      throw new KunoError(0, "decrypt_failed", "This video didn't open with the link's key.");
    }
    if ((await sha256Hex(video)) !== details.contentDigest) {
      throw new KunoError(0, "integrity", "The decrypted video does not match the receipt.");
    }
    return opened(video);
  }
}
