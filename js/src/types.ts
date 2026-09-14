/** Wire types mirroring kuno_protocol (Python). */

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
  | "retake";

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
  pricing: { usd_per_second: Record<string, number> };
  vcu_per_output_second: number;
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
  duration_s: number;
  resolution: string;
  aspect_ratio: string;
  fps: number;
  audio: boolean;
  input_roles: InputRole[];
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
}

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
