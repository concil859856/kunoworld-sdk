import { verifyEvidence, verifySignature } from "./attestation.js";
import { decryptBlob, encryptBlob, openSenderSession, sha256Hex } from "./crypto.js";
import { b64d, b64e, canonicalJson, concatBytes, utf8 } from "./encoding.js";
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
  PrivacyMode,
  Provenance,
  Receipt,
  ReportRequest,
  RouteResponse,
  SharedVideo,
  SharedVideoDetails,
  ShareLink,
  ShareStatus,
  ShareSummary,
  StandardUpload,
  StandardVideoSummary,
} from "./types.js";

/**
 * A failed request. `code` is the gateway's machine-readable reason. `details` holds the rest of
 * the error body, for example `reasons` on `private_mode_not_eligible` or `restricted_until` on
 * `account_restricted`.
 */
export class KunoError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "KunoError";
  }

  /** Why private mode isn't available (`private_mode_not_eligible`). */
  get reasons(): string[] {
    const r = this.details.reasons;
    return Array.isArray(r) ? r.filter((x): x is string => typeof x === "string") : [];
  }

  /** Unix seconds until which the account is restricted (`account_restricted`), or null. */
  get restrictedUntil(): number | null {
    return typeof this.details.restricted_until === "number" ? this.details.restricted_until : null;
  }

  /** The request broke the content policy: `content_policy` (Standard) or `safety_blocked` (Private, in the enclave). */
  get isContentPolicy(): boolean {
    return this.code === "content_policy" || this.code === "safety_blocked";
  }

  /** What this code means, when it's one the gateway documents; otherwise null. */
  get explanation(): string | null {
    return ERROR_CODES[this.code as KunoErrorCode] ?? null;
  }
}

/**
 * Error codes callers commonly branch on, and what each means. The gateway may send others;
 * `KunoError.code` is always the raw string.
 */
export const ERROR_CODES = {
  unauthorized: "The API key (or web session) was missing, unknown or revoked.",
  gone: "This endpoint or credential was retired. Studio tokens (kwt_…) no longer work: use an API key, or a same-origin proxy that holds a web session.",
  content_policy: "The request breaks the content policy, so the job wasn't created. All NSFW content is banned in both modes. Nothing was charged.",
  safety_blocked: "The content check inside the enclave blocked the request before rendering. It counts as a strike.",
  content_not_reviewable: "Operators only: this item's content can't be opened, because it isn't a report of child sexual abuse material or sexual content involving a minor, and no matching legal hold covers it.",
  key_not_accepted: "An output_key can be attached to a report only when the reason is csam or sexual_minor.",
  private_mode_not_eligible: "This account can't make private jobs yet; see `reasons`.",
  account_restricted: "The account is restricted; see `restricted_until`.",
  upload_blocked: "A Standard upload was refused by the scan.",
  insufficient_balance: "The balance doesn't cover the job's price.",
  not_found: "No such job, blob or video on this account, or no such share link.",
  deleted: "The owner deleted this video.",
  removed: "The video was removed after a review under the content policy.",
  not_ready: "The job hasn't finished yet.",
  integrity: "What came back didn't match the enclave-signed receipt.",
  decrypt_failed: "The video didn't open with this handle's output key, or with a share link's key.",
  share_unavailable: "The share link no longer works (revoked, expired, video deleted or removed, or account closed; the public answer never says which), or, when making one, the video can't be shared right now.",
  missing_key: "A private share link needs the video's key: the #k=… part of the link, or pass it separately.",
  too_many_shares: "Too many working share links: 20 per video and 1000 per account. Revoke some first.",
  invalid_expiry: "A share link's expiry must be between a minute and ten years from now, in Unix seconds, or null.",
  rate_limited: "Too many requests from this network to public share links. Try again in a minute.",
} as const;

export type KunoErrorCode = keyof typeof ERROR_CODES;

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

export interface GenerateRequest {
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

export function priceUsd(profile: ModelProfile, resolution: string, durationS: number): number | null {
  const rate = profile.pricing.usd_per_second[resolution];
  return rate === undefined ? null : Math.round(rate * durationS * 10000) / 10000;
}

/** Same rules as the Python SDK: defaults from the profile; adapt after a fallback. */
export function fitParams(
  profile: ModelProfile,
  mode: Mode,
  roles: InputRole[],
  req: Pick<GenerateRequest, "durationS" | "resolution" | "aspectRatio" | "fps" | "audio">,
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
  let duration = req.durationS;
  if (duration === undefined) duration = Math.min(Math.max(5, lim.min_duration_s), lim.max_duration_s);
  else if (lenient) duration = Math.min(Math.max(duration, lim.min_duration_s), lim.max_duration_s);
  return {
    profile_id: profile.id,
    mode,
    duration_s: duration,
    resolution,
    aspect_ratio: aspect,
    fps,
    audio: (req.audio ?? true) && lim.audio,
    input_roles: roles,
  };
}

export function jobAad(jobId: string, enclaveId: string, params: GenerationParams, inputBlobIds: string[]): Uint8Array {
  return canonicalJson({ v: 1, job_id: jobId, enclave_id: enclaveId, params, inputs: inputBlobIds });
}

export function verifyReceipt(receipt: Receipt, signingPublicKey: Uint8Array): boolean {
  const message = concatBytes(utf8("kuno/v1/receipt\n"), canonicalJson(receipt.body));
  return verifySignature(b64d(receipt.signature), message, signingPublicKey);
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

export class KunoClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private manifestCache: GoldenManifest | undefined;
  private modelsCache: { at: number; value: ModelsResponse } | undefined;

  /**
   * Share links. `create`, `list` and `revoke` use this client's credential; `get` and `open` are
   * public and send none, so a client without an API key can open any link.
   */
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
    this.manifestCache ??= await this.json<GoldenManifest>("GET", "/v1/manifest", undefined, false);
    return this.manifestCache;
  }

  /**
   * Which profile and enclaves would serve a request. The credential is sent when the client has
   * one, so the gateway can refuse private routing to an account that isn't eligible for it.
   */
  async route(mode: Mode, model?: string, family?: string, privacy?: PrivacyMode): Promise<RouteResponse> {
    const q = new URLSearchParams({ mode });
    if (model) q.set("profile_id", model);
    if (family) q.set("family", family);
    if (privacy === "standard") q.set("privacy", "standard");
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
    const mode = req.mode ?? inferMode(roles);

    onStage?.("routing");
    const route = await this.route(mode, req.model, req.family, "standard");
    const profile = (await this.models(0)).models.find((m) => m.id === route.profile_id);
    if (!profile) throw new KunoError(404, "unknown_model", `Unknown model ${route.profile_id}.`);
    const params = fitParams(profile, mode, roles, req, route.fallback_reason);

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
      prompt: req.prompt,
      negative_prompt: req.negativePrompt ?? null,
      seed: req.seed ?? null,
      options: req.options ?? {},
      inputs: refs,
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
    const mode = req.mode ?? inferMode(roles);

    onStage?.("routing");
    const route = await this.route(mode, req.model, req.family);
    const profile = (await this.models(0)).models.find((m) => m.id === route.profile_id);
    if (!profile) throw new KunoError(404, "unknown_model", `Unknown model ${route.profile_id}.`);
    const params = fitParams(profile, mode, roles, req, route.fallback_reason);

    onStage?.("verifying");
    const enclave = await this.pickEnclave(route);

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
      prompt: req.prompt,
      negative_prompt: req.negativePrompt ?? null,
      seed: req.seed ?? null,
      inputs: refs,
      options: req.options ?? {},
    };
    const ciphertext = await session.seal(utf8(JSON.stringify(payload)), jobAad(jobId, enclave.enclave_id, params, blobIds));

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

  private async pickEnclave(route: RouteResponse): Promise<EnclaveInfo> {
    const manifest = await this.manifest();
    for (const enclave of route.enclaves) {
      const verdict = verifyEvidence(enclave.evidence, manifest);
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
    const deadline = Date.now() + (opts.timeoutMs ?? 30 * 60 * 1000);
    for (;;) {
      if (opts.signal?.aborted) throw new KunoError(0, "aborted", "Stopped waiting for the video.");
      const status = await this.status(handle.jobId);
      opts.onProgress?.(status);
      if (status.status === "succeeded") return this.result(handle, status);
      if (status.status === "failed" || status.status === "canceled") {
        throw new KunoError(0, status.error_code ?? `job_${status.status}`, status.error ?? "The job did not complete.");
      }
      if (Date.now() > deadline) throw new KunoError(0, "timeout", `Job ${handle.jobId} is still ${status.status}.`);
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
