/** Wire types mirroring kuno_protocol (Python). */

import type { Endorsements } from "./endorsements.js";

export type Mode =
  | "text_to_video"
  | "image_to_video"
  | "last_frame"
  | "first_last_frame"
  | "keyframes"
  | "reference_to_video"
  | "video_edit"
  | "extend_video"
  | "audio_to_video"
  | "retake"
  | "storyboard";

export type InputRole =
  | "first_frame"
  | "last_frame"
  | "keyframe"
  | "reference_image"
  | "reference_video"
  | "reference_audio"
  | "source_video"
  | "source_audio";

export type JobState = "queued" | "running" | "succeeded" | "failed" | "canceled";

/**
 * Who can read a job. `private` (the default) is end to end encrypted to a confidential-tier
 * enclave; `standard` is sent to KunoWorld readable, so KunoWorld and the GPU provider can see it.
 * The mode is not part of GenerationParams: those are the encryption's associated data.
 */
export type PrivacyMode = "private" | "standard";

/** Attestation evidence kinds. `open` is a no-TEE miner, which only ever serves standard jobs. */
export type TeeKind = "mock" | "tdx" | "open";

/**
 * How a storyboard shot attaches to the one before it (PROTOCOL.md, "Storyboards"). `continue` carries the previous
 * shot's last latent frames and its sound into this one: one unbroken take. `cut` carries only the sound: a new picture
 * over the same voice and room tone. `fresh` carries nothing. The first shot is always `fresh`.
 */
export type ShotJoin = "fresh" | "continue" | "cut";

/** One storyboard shot as the gateway sees it: its length and its join. Its prompt is sealed. */
export interface ShotSpec {
  duration_s: number;
  join: ShotJoin;
}

/** What a profile's storyboard mode accepts. Each shot also keeps to the profile's own duration limits. */
export interface StoryboardLimits {
  max_shots: number;
  /** The stitched video's longest length. */
  max_total_s: number;
  /**
   * A `continue` or `cut` shot's first latent frames repeat the previous shot's last ones and are trimmed from the video
   * (LTX-2.5: 1 + 8 × (overlap − 1) frames, and the matching audio). 3 when absent.
   */
  overlap_latent_frames?: number;
}

export interface InputGroup {
  roles: InputRole[];
  max: number;
}

export interface Limits {
  min_duration_s: number;
  max_duration_s: number;
  duration_step_s: number;
  sizes: Record<string, Record<string, [number, number]>>;
  fps: number[];
  default_fps: number;
  audio: boolean;
  max_inputs: Partial<Record<InputRole, number>>;
  input_groups: InputGroup[];
  max_total_inputs: number | null;
  visual_required_with_audio: boolean;
  max_prompt_chars: number;
  negative_prompt: boolean;
  prompt_enhancer: boolean;
  seed: boolean;
  /** fps -> a lower duration cap at that frame rate (LTX-2.5 Fast goes past 10 s only at 24 or 25 fps). */
  max_duration_s_by_fps?: Record<string, number>;
  /** Set where the profile offers storyboard mode. */
  storyboard?: StoryboardLimits | null;
}

/** A profile's prices. Every price is a placeholder while `pricing_placeholder` is true. */
export interface Pricing {
  /** The Private price per second, per resolution. Private is the default mode. */
  usd_per_second: Record<string, number>;
  /** The Standard price per second, per resolution; null or absent where the profile is Private-only. */
  standard_usd_per_second?: Record<string, number> | null;
  /** No job costs less than this, after multipliers. */
  min_job_usd?: number;
  /** A multiplier on the whole job once its duration exceeds `over_s`. */
  long_clip?: { over_s: number; multiplier: number } | null;
  /** fps -> a multiplier on the whole job. */
  fps_multipliers?: Record<string, number>;
}

/**
 * GPU-cost weights for miner pay: a job's VCU is per_output_second[resolution] × fps_multiplier[fps]
 * × (1 + duration_slope × max(0, seconds − 5)) × seconds. Validators use them; customers never pay by them.
 */
export interface VcuWeights {
  per_output_second: Record<string, number>;
  duration_slope?: number;
  fps_multiplier?: Record<string, number>;
  note?: string | null;
}

/** What a job costs, from `priceQuote`. */
export interface PriceQuote {
  usd: number;
  /** The per-second rate for the resolution and privacy mode, before multipliers. */
  usdPerSecond: number;
  /** The fps and long-clip multipliers, together. */
  multiplier: number;
  /** True when the profile's minimum charge set the price. */
  minimumApplied: boolean;
}

export interface ModelProfile {
  id: string;
  family: "minimax-h3" | "ltx-2.5" | string;
  name: string;
  tagline: string;
  variant: string;
  checkpoint: string;
  runtime: string;
  modes: Mode[];
  limits: Limits;
  hardware_class: string;
  gpus_per_worker: number;
  steps: number;
  license: { name: string; url: string; attribution: string | null; region_policy: string | null };
  pricing: Pricing;
  /** Present on /v1/models responses: the privacy modes the profile is sold in (Private always). */
  privacy_modes?: PrivacyMode[];
  /** Miner pay weights (verified video compute units); gateways from before them send `vcu_per_output_second`. */
  vcu_weights?: VcuWeights;
  vcu_per_output_second?: number;
  timeout_s: number;
  /** Present on /v1/models responses. */
  enabled?: boolean;
  available_in_region?: boolean;
  workers?: number;
}

export interface SwitchConfig {
  version: number;
  issued_at: number;
  mode: "h3" | "ltx" | "both" | "auto";
  default_family: string;
  disabled_profiles: string[];
  h3_authorized_everywhere: boolean;
  emission_split: Record<string, number>;
  /** Capacity pay: share of serving miner emission paid for ready, attested GPUs (0 pays none). */
  capacity_share?: number;
  /** Capacity pay: family -> GPUs the network wants paid. */
  capacity_targets?: Record<string, number>;
  /** Capacity pay: continuous verified uptime before a GPU's run counts. */
  capacity_min_uptime_s?: number;
}

export interface ModelsResponse {
  country: string | null;
  /** Distinct attested workers online, counted once even when one serves several profiles. */
  workers_online: number;
  switch: SwitchConfig;
  models: ModelProfile[];
  /** True while the listed prices are placeholders that haven't been set yet. */
  pricing_placeholder?: boolean;
}

export interface GenerationParams {
  profile_id: string;
  mode: Mode;
  /** For a storyboard: the stitched video's length, `storyboardDurationS` of its shots, exactly. */
  duration_s: number;
  resolution: string;
  aspect_ratio: string;
  fps: number;
  audio: boolean;
  input_roles: InputRole[];
  /**
   * Storyboard mode only, every shot in order. Left out of every other job, so their encryption's associated data stays
   * byte-identical to clients from before storyboards.
   */
  shots?: ShotSpec[];
}

export interface InputRef {
  index: number;
  role: InputRole;
  mime: string;
  sha256: string;
  size: number;
  time_s?: number | null;
  strength?: number | null;
  hint?: string | null;
  start_s?: number | null;
  end_s?: number | null;
}

export interface VideoInfo {
  duration_s: number;
  width: number;
  height: number;
  fps: number;
  frames: number;
  audio: boolean;
}

export interface ReceiptBody {
  v: 1;
  job_id: string;
  enclave_id: string;
  profile_id: string;
  image_digest: string;
  params_digest: string;
  input_digest: string;
  output_digest: string;
  output_bytes: number;
  content_digest: string;
  attestation_digest: string;
  started_at: number;
  finished_at: number;
  gpu_seconds: number;
  video: VideoInfo;
  miner_hotkey: string | null;
}

export interface Receipt {
  body: ReceiptBody;
  signature: string;
}

export interface JobStatus {
  job_id: string;
  status: JobState;
  /** What the worker is doing; `shot 3/8` while a storyboard renders its shots (`storyboardStage` reads it). */
  stage: string | null;
  progress: number;
  params: GenerationParams;
  enclave_id: string;
  price_usd: number;
  created_at: number;
  updated_at: number;
  output_blob_id: string | null;
  receipt: Receipt | null;
  /** Machine-readable failure reason (e.g. safety_blocked, timeout); `error` is the human message. */
  error_code: string | null;
  error: string | null;
  /** Gateways from before standard mode omit it; a missing value means `private`. */
  privacy?: PrivacyMode;
}

export interface AttestationEvidence {
  tee: TeeKind;
  quote: string;
  gpu_evidence: string | null;
  nonce: string;
  hpke_public_key: string;
  signing_public_key: string;
  image_digest: string;
  profiles: string[];
  hardware: Record<string, string | number>;
  created_at: number;
}

export interface AllowedMeasurement {
  platform: "mock" | "tdx";
  image_digest: string;
  profiles: string[];
  mrtd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  // Absent on entries signed before GPU modes: then any mode and count pass, as before.
  gpu_mode?: GpuCcMode | null;
  gpus_per_enclave?: number | null;
  nvswitches_per_enclave?: number | null;
}

/** NVIDIA confidential-computing mode: one GPU per VM, Hopper Protected PCIe, or Blackwell multi-GPU. */
export type GpuCcMode = "spt" | "ppcie" | "mpt";

export interface GoldenManifest {
  version: number;
  issued_at: number;
  allowed: AllowedMeasurement[];
  mock_quote_keys: string[];
  max_evidence_age_s: number;
}

export interface EnclaveInfo {
  enclave_id: string;
  miner_hotkey: string | null;
  tee: TeeKind;
  image_digest: string;
  hpke_public_key: string;
  signing_public_key: string;
  profiles: string[];
  hardware: Record<string, string | number>;
  evidence: AttestationEvidence;
  capacity: number;
  inflight: number;
  status: string;
  verified_at: number;
  last_seen: number;
  /** What the worker's hardware can fit, for the profiles it can't serve in full; null or absent: full limits. */
  envelope?: ServingEnvelope | null;
  /** What Intel and NVIDIA signed for `evidence` (endorsements.ts); null for simulated workers and older gateways. */
  endorsements?: Endorsements | null;
}

/** resolution -> aspect ratio -> fps -> the longest duration_s served. A size or frame rate left out is not served. */
export type EnvelopeTable = Record<string, Record<string, Record<string, number>>>;
/** profile id -> its table (kuno_protocol.envelope). A profile left out serves its full limits. */
export type ServingEnvelope = Record<string, EnvelopeTable>;

/** Optional request fields `/v1/route` filters workers by. */
export interface RouteFit {
  resolution?: string;
  aspectRatio?: string;
  fps?: number;
  durationS?: number;
}

export interface RouteResponse {
  profile_id: string;
  requested_profile_id: string | null;
  fallback_reason: "region" | "switched_off" | "capacity" | null;
  enclaves: EnclaveInfo[];
}

/** `POST /v1/standard/uploads` */
export interface StandardUpload {
  upload_id: string;
  sha256: string;
  size: number;
  mime: string;
}

/** One row of `GET /v1/standard/videos`: this account's standard jobs, newest first. */
export interface StandardVideoSummary {
  job_id: string;
  status: JobState;
  profile_id: string;
  params: GenerationParams;
  prompt: string;
  created_at: number;
  finished_at: number | null;
  has_video: boolean;
  error_code: string | null;
  /** Deleted by the owner or removed after review; the row stays for billing. Nothing expires on its own. */
  deleted: boolean;
}

/** `GET /v1/account/eligibility` (API key or web session) and `GET /v1/me/eligibility` (web session). */
export interface Eligibility {
  private_mode: { eligible: boolean; reasons: string[] };
  /**
   * Unix seconds; null when the account isn't restricted. A restriction that lasts until an
   * operator reviews the account is 253402300799 (the last second of year 9999).
   */
  restricted_until: number | null;
  strikes_24h: number;
  strikes_7d: number;
}

export type ReportReason =
  | "csam"
  | "sexual_minor"
  | "nonconsensual_intimate"
  | "violent_extremism"
  | "harassment"
  | "copyright"
  | "other";

/** `POST /v1/reports`: identify the video by at least one of content_digest, job_id or url. */
export interface ReportRequest {
  content_digest?: string;
  job_id?: string;
  url?: string;
  reason: ReportReason;
  details?: string;
  /**
   * Base64url output key of a private video, so that one video can be reviewed. Accepted only when
   * `reason` is `csam` or `sexual_minor`; otherwise the gateway answers `422 key_not_accepted`.
   */
  output_key?: string;
  contact_email?: string;
}

export interface Provenance {
  receipt: Receipt;
  signature_valid: boolean;
  model: { id: string; name: string; attribution: string | null };
  enclave: {
    enclave_id: string;
    tee: string;
    image_digest: string;
    hardware: Record<string, string | number>;
    evidence: AttestationEvidence;
  };
}

/**
 * Where a share link stands, from its owner's view. The public answer for anything but `active`
 * is the same `410 share_unavailable`. `unavailable` covers a video that can't be played for any
 * other reason (including a preservation hold) without saying which.
 */
export type ShareStatus = "active" | "revoked" | "expired" | "video_deleted" | "video_removed" | "account_closed" | "unavailable";

/** One of this account's share links: `shares.list()` and `shares.revoke()`. The token is never here. */
export interface ShareSummary {
  shareId: string;
  jobId: string;
  privacy: PrivacyMode;
  profileId: string | null;
  /** Unix seconds. */
  createdAt: number;
  /** Unix seconds, or null for a link that works until revoked. */
  expiresAt: number | null;
  revokedAt: number | null;
  status: ShareStatus;
  viewCount: number;
}

/** A link just made by `shares.create()`. The token is shown only now; KunoWorld stores only its hash. */
export interface ShareLink extends ShareSummary {
  /** 32 random bytes, base64url (43 characters). Anyone holding it can watch the video. */
  token: string;
  /** `/s/<token>`, never with a key. */
  urlPath: string;
  /** The website's link. For a private video it carries the key as `#k=…` when `keyIncluded` is true. */
  url: string;
  /**
   * Private links: whether `url` already carries the video's key. False when the link was made
   * from a job id alone; add the key with `shareUrlWithKey(url, handle.outputKey)`. Always false
   * for Standard links, which need no key.
   */
  keyIncluded: boolean;
}

/** What anyone holding a link learns, from `shares.get()`: nothing about the account. */
export interface SharedVideoDetails {
  privacy: PrivacyMode;
  profileId: string;
  /** When the video was made (Unix seconds). */
  createdAt: number;
  /** When the link was made (Unix seconds). */
  sharedAt: number;
  expiresAt: number | null;
  /** SHA-256 of the video (the MP4), as in the receipt. */
  contentDigest: string;
  receipt: Receipt | null;
  /** Base64url Ed25519 key of the enclave that signed the receipt. */
  signingPublicKey: string | null;
  /** The link's token. */
  token: string;
  /** The key from the link's `#k=` fragment, when the link had one. Never sent anywhere. */
  key: string | null;
}

/** A shared video opened and checked by `shares.open()`. */
export interface SharedVideo {
  privacy: PrivacyMode;
  video: Uint8Array;
  receipt: Receipt;
  contentDigest: string;
  profileId: string;
}
