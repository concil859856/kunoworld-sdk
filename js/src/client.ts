import { verifyEvidence, verifySignature } from "./attestation.js";
import { decryptBlob, encryptBlob, openSenderSession, sha256Hex } from "./crypto.js";
import { b64d, b64e, canonicalJson, concatBytes, utf8 } from "./encoding.js";
import type {
  EnclaveInfo,
  GenerationParams,
  GoldenManifest,
  InputRef,
  InputRole,
  JobStatus,
  Mode,
  ModelProfile,
  ModelsResponse,
  Provenance,
  Receipt,
  RouteResponse,
} from "./types.js";

export class KunoError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "KunoError";
  }
}

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
}

/** Everything needed to fetch and open a video later. Store it like a password. */
export interface JobHandle {
  jobId: string;
  outputKey: string;
  signingPublicKey: string;
  enclaveId: string;
  profileId: string;
  fallbackReason: string | null;
  createdAt: number;
}

export interface GenerationResult {
  jobId: string;
  video: Uint8Array;
  receipt: Receipt;
  profileId: string;
  fallbackReason: string | null;
}

export type SubmitStage = "routing" | "verifying" | "encrypting" | "uploading" | "submitting";

export interface KunoClientOptions {
  apiKey?: string;
  baseUrl?: string;
  /** Pin the published golden manifest for zero-trust verification. */
  manifest?: GoldenManifest;
  /** Development only: pretend to be in another country. */
  country?: string;
  fetch?: typeof fetch;
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

export class KunoClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private manifestCache: GoldenManifest | undefined;
  private modelsCache: { at: number; value: ModelsResponse } | undefined;

  constructor(private readonly opts: KunoClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? "https://api.kunoworld.com").replace(/\/$/, "");
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.manifestCache = opts.manifest;
  }

  private async request(method: string, path: string, body?: BodyInit, contentType?: string, auth = true): Promise<Response> {
    const headers: Record<string, string> = {};
    if (auth && this.opts.apiKey) headers.authorization = `Bearer ${this.opts.apiKey}`;
    if (this.opts.country) headers["x-kuno-country"] = this.opts.country;
    if (contentType) headers["content-type"] = contentType;
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, { method, headers, body });
    if (!response.ok) {
      let detail: { code?: string; message?: string } = {};
      try {
        const json = (await response.json()) as { detail?: unknown };
        detail = typeof json.detail === "object" && json.detail ? (json.detail as typeof detail) : { message: String(json.detail) };
      } catch {
        /* non-JSON error body */
      }
      throw new KunoError(response.status, detail.code ?? "error", detail.message ?? response.statusText);
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

  async route(mode: Mode, model?: string, family?: string): Promise<RouteResponse> {
    const q = new URLSearchParams({ mode });
    if (model) q.set("profile_id", model);
    if (family) q.set("family", family);
    return this.json<RouteResponse>("GET", `/v1/route?${q}`, undefined, false);
  }

  /** Routes, verifies the enclave, encrypts inputs in this process, seals and submits. */
  async submit(req: GenerateRequest, onStage?: (stage: SubmitStage) => void): Promise<JobHandle> {
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

  async wait(
    handle: JobHandle,
    opts: { onProgress?: (status: JobStatus) => void; signal?: AbortSignal; pollMs?: number; timeoutMs?: number } = {},
  ): Promise<GenerationResult> {
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

  /** Downloads the sealed video, checks it against the enclave-signed receipt, decrypts locally. */
  async result(handle: JobHandle, status?: JobStatus): Promise<GenerationResult> {
    status ??= await this.status(handle.jobId);
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
    return { jobId: handle.jobId, video, receipt, profileId: handle.profileId, fallbackReason: handle.fallbackReason };
  }

  /** Public: look up the certificate for a video file by its SHA-256. */
  async provenance(file: Blob | Uint8Array): Promise<Provenance> {
    return this.provenanceByDigest(await sha256Hex(await toBytes(file)));
  }

  /** Public: the same lookup when you already have the digest (e.g. a /verify?sha256=… link). */
  async provenanceByDigest(contentDigest: string): Promise<Provenance> {
    return this.json<Provenance>("GET", `/v1/provenance/${encodeURIComponent(contentDigest.toLowerCase())}`, undefined, false);
  }
}
