/**
 * Enclave attestation checks, mirroring kuno_protocol.attestation.
 *
 * Mock evidence (development) is fully verified. Intel TDX evidence is verified in full here, without trusting the
 * gateway that served it: the quote's signature chain to Intel's root and its TCB status (with the Intel collateral the
 * gateway relays), the GPUs' NVIDIA-signed attestation results under NVIDIA's pinned intermediate, the REPORTDATA
 * binding of keys, nonce and GPU evidence, and the measurements against the golden manifest. TDX evidence without
 * those endorsements is refused rather than half-checked (endorsements.ts).
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";

import { b64d, canonicalJson, concatBytes, fromHex, toHex, utf8 } from "./encoding.js";
import {
  type EndorsementOptions,
  type Endorsements,
  type QuoteCheck,
  verifyGpuEndorsements,
  verifyTdxQuoteSignature,
} from "./endorsements.js";
import type { AttestationEvidence, GoldenManifest } from "./types.js";

export interface Verdict {
  ok: boolean;
  enclaveId: string;
  reasons: string[];
  /** The quote's signature verified: against a manifest key (mock) or Intel's root with relayed collateral (TDX). */
  signatureVerified: boolean;
  measurements: Record<string, string>;
  /** TDX: the platform's TCB status and the GPUs NVIDIA attested, once both verified. */
  tcbStatus?: string;
  gpuCount?: number;
}

export interface VerifyOptions extends EndorsementOptions {
  expectedNonce?: Uint8Array;
  /** What the gateway relayed with the evidence (`enclave.endorsements`). Required for TDX evidence. */
  endorsements?: Endorsements | null;
  /** Replaces Intel DCAP verification of the quote, e.g. with a verifier you run yourself. Tests use it too. */
  tdxQuoteVerifier?: (quote: Uint8Array, collateral: Record<string, string> | null, opts: EndorsementOptions) => QuoteCheck;
}

const MEASUREMENT_KEYS = ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"] as const;

export function enclaveIdFor(hpkePublicKey: Uint8Array, signingPublicKey: Uint8Array): string {
  return toHex(sha256(concatBytes(hpkePublicKey, signingPublicKey))).slice(0, 32);
}

/** The nonce GPU evidence must be collected for, so evidence cannot be borrowed from another machine. */
export function gpuNonceFor(nonce: Uint8Array, hpkePublicKey: Uint8Array, signingPublicKey: Uint8Array): Uint8Array {
  const binding = sha256(concatBytes(hpkePublicKey, signingPublicKey));
  return sha256(concatBytes(utf8("kuno/v1/gpu"), nonce, binding));
}

export function reportDataFor(
  nonce: Uint8Array,
  hpkePublicKey: Uint8Array,
  signingPublicKey: Uint8Array,
  gpuEvidence: Uint8Array | null,
): Uint8Array {
  const binding = sha256(concatBytes(hpkePublicKey, signingPublicKey));
  return sha512(concatBytes(utf8("kuno/v1/report"), nonce, binding, sha256(gpuEvidence ?? new Uint8Array())));
}

/** Byte offsets of the TD report body in a DCAP v4 quote (after the 48-byte header). */
const TDX_FIELDS: Array<[string, number]> = [
  ["tee_tcb_svn", 16], ["mrseam", 48], ["mrsignerseam", 48], ["seamattributes", 8], ["tdattributes", 8],
  ["xfam", 8], ["mrtd", 48], ["mrconfigid", 48], ["mrowner", 48], ["mrownerconfig", 48],
  ["rtmr0", 48], ["rtmr1", 48], ["rtmr2", 48], ["rtmr3", 48], ["reportdata", 64],
];

/** TD report fields of a DCAP v4 or v5 TD quote (v5 adds a body descriptor: TD report 1.0 or 1.5). No signature check. */
export function parseTdxQuote(quote: Uint8Array): Record<string, string> {
  const bodyLen = TDX_FIELDS.reduce((n, [, size]) => n + size, 0);
  if (quote.length < 48) throw new Error("quote too short for a TDX quote");
  const view = new DataView(quote.buffer, quote.byteOffset, quote.length);
  const version = view.getUint16(0, true);
  if ((version !== 4 && version !== 5) || view.getUint32(4, true) !== 0x81) throw new Error("not a TDX v4/v5 quote");
  let offset = 48;
  if (version === 5) {
    if (quote.length < 54 || ![2, 3].includes(view.getUint16(48, true))) throw new Error("v5 quote body is not a TD report");
    offset += 6;
  }
  if (quote.length < offset + bodyLen) throw new Error(`quote too short for a TDX v${version} quote`);
  const fields: Record<string, string> = {};
  for (const [name, size] of TDX_FIELDS) {
    fields[name] = toHex(quote.subarray(offset, offset + size));
    offset += size;
  }
  return fields;
}

export function verifyEvidence(evidence: AttestationEvidence, manifest: GoldenManifest, opts: VerifyOptions = {}): Verdict {
  const reasons: string[] = [];
  let hpke: Uint8Array, sign: Uint8Array, nonce: Uint8Array, quote: Uint8Array, gpu: Uint8Array | null;
  try {
    hpke = b64d(evidence.hpke_public_key);
    sign = b64d(evidence.signing_public_key);
    nonce = fromHex(evidence.nonce);
    quote = b64d(evidence.quote);
    gpu = evidence.gpu_evidence ? b64d(evidence.gpu_evidence) : null;
  } catch {
    return { ok: false, enclaveId: "", reasons: ["malformed evidence encoding"], signatureVerified: false, measurements: {} };
  }
  const verdict: Verdict = { ok: false, enclaveId: enclaveIdFor(hpke, sign), reasons, signatureVerified: false, measurements: {} };
  if (hpke.length !== 32 || sign.length !== 32) reasons.push("keys must be 32-byte X25519 / Ed25519 public keys");
  if (opts.expectedNonce && toHex(opts.expectedNonce) !== evidence.nonce) reasons.push("nonce does not match the challenge");
  const now = opts.now ?? Date.now() / 1000;
  if (now - evidence.created_at > manifest.max_evidence_age_s) reasons.push("evidence is older than the manifest allows");

  let reportData: string | null = null;
  if (evidence.tee === "mock") {
    try {
      const doc = JSON.parse(new TextDecoder().decode(quote)) as { body: { measurements: Record<string, string>; report_data: string }; signature: string };
      const message = concatBytes(utf8("kuno/v1/mock-quote\n"), canonicalJson(doc.body));
      const signature = b64d(doc.signature);
      if (manifest.mock_quote_keys.some((k) => safeVerify(signature, message, b64d(k)))) {
        verdict.signatureVerified = true;
        verdict.measurements = doc.body.measurements;
        reportData = doc.body.report_data;
      } else {
        reasons.push("mock quote not signed by a key in the manifest");
      }
    } catch {
      reasons.push("malformed mock quote");
    }
  } else if (evidence.tee === "tdx") {
    try {
      const fields = parseTdxQuote(quote);
      verdict.measurements = Object.fromEntries(MEASUREMENT_KEYS.map((k) => [k, fields[k]]));
      reportData = fields.reportdata;
      if (parseInt(fields.tdattributes.slice(0, 2), 16) & 0x01) reasons.push("TD runs in debug mode, so the host can read its memory");
      if (!gpu) reasons.push("GPU evidence is required on TDX workers");
    } catch (err) {
      reasons.push((err as Error).message);
    }
    if (Object.keys(verdict.measurements).length) {
      const endorsements = opts.endorsements;
      if (!endorsements) {
        reasons.push("no endorsements were relayed, so the quote's Intel signature and the GPUs' NVIDIA attestation can't be checked");
      } else {
        const quoteCheck = (opts.tdxQuoteVerifier ?? verifyTdxQuoteSignature)(quote, endorsements.tdx_collateral, { ...opts, now });
        if (quoteCheck.ok) {
          verdict.signatureVerified = true;
          verdict.tcbStatus = quoteCheck.status;
        } else {
          reasons.push(`TDX quote rejected: ${quoteCheck.detail}`);
        }
        if (gpu) {
          const gpuCheck = verifyGpuEndorsements(gpu, gpuNonceFor(nonce, hpke, sign), endorsements, {
            maxTokenAgeS: manifest.max_evidence_age_s,
            ...opts,
            now,
          });
          if (gpuCheck.ok) verdict.gpuCount = gpuCheck.gpuCount;
          else reasons.push(`GPU evidence rejected: ${gpuCheck.detail}`);
        }
      }
    }
  } else {
    reasons.push(`unsupported TEE ${String(evidence.tee)}`);
  }

  if (reportData !== null && reportData !== toHex(reportDataFor(nonce, hpke, sign, gpu))) {
    reasons.push("REPORTDATA does not bind this nonce, these keys and this GPU evidence");
  }
  if (Object.keys(verdict.measurements).length) {
    const allowed = manifest.allowed.find(
      (a) =>
        a.platform === evidence.tee &&
        a.image_digest === evidence.image_digest &&
        MEASUREMENT_KEYS.every((k) => verdict.measurements[k] === a[k]),
    );
    if (!allowed) reasons.push("measurements are not in the golden manifest");
    else {
      if (!evidence.profiles.every((p) => allowed.profiles.includes(p))) reasons.push("image is not approved for all claimed profiles");
      reasons.push(...gpuEntryProblems(allowed, gpu));
    }
  }
  verdict.ok = reasons.length === 0;
  return verdict;
}

/**
 * The manifest entry's GPU mode and counts against what the GPU evidence declares (kuno_protocol.attestation does the
 * same with the counts NVIDIA's verifier attested). The declaration is bound by REPORTDATA; this SDK doesn't verify
 * NVIDIA's signatures itself. Entries signed before these fields accept any mode and count.
 */
function gpuEntryProblems(entry: GoldenManifest["allowed"][number], gpu: Uint8Array | null): string[] {
  if (entry.gpu_mode == null && entry.gpus_per_enclave == null && entry.nvswitches_per_enclave == null) return [];
  let doc: { gpus?: unknown[]; switches?: unknown[]; cc?: { mode?: string; devtools?: boolean } };
  try {
    doc = gpu ? (JSON.parse(new TextDecoder().decode(gpu)) as typeof doc) : {};
  } catch {
    return ["GPU evidence is malformed"];
  }
  const problems: string[] = [];
  if (doc.cc?.devtools) problems.push("the GPUs are in CC devtools mode");
  if (entry.gpu_mode != null && doc.cc?.mode !== entry.gpu_mode) {
    problems.push(`the GPU evidence declares ${doc.cc?.mode ?? "no GPU mode"}, but the manifest entry requires ${entry.gpu_mode}`);
  }
  const gpus = Array.isArray(doc.gpus) ? doc.gpus.length : 0;
  if (entry.gpus_per_enclave != null && gpus !== entry.gpus_per_enclave) {
    problems.push(`the evidence carries ${gpus} GPU(s), but the manifest entry requires ${entry.gpus_per_enclave} per enclave`);
  }
  const switches = Array.isArray(doc.switches) ? doc.switches.length : 0;
  if (entry.nvswitches_per_enclave != null && switches !== entry.nvswitches_per_enclave) {
    problems.push(`the evidence carries ${switches} NVSwitch(es), but the manifest entry requires ${entry.nvswitches_per_enclave} per enclave`);
  }
  return problems;
}

const OPTIONAL_ENTRY_FIELDS = ["gpu_mode", "gpus_per_enclave", "nvswitches_per_enclave"];

/** kuno_protocol.attestation.GoldenManifest.signed_fields: fields added after signing started are left out when unset. */
export function manifestSignedFields(manifest: Record<string, unknown>): Record<string, unknown> {
  const fields: Record<string, unknown> = { ...manifest };
  if (fields.open_tier === null || fields.open_tier === undefined) delete fields.open_tier;
  const digests = fields.model_digests as Record<string, unknown> | undefined | null;
  if (!digests || Object.keys(digests).length === 0) delete fields.model_digests;
  if (Array.isArray(fields.allowed)) {
    fields.allowed = fields.allowed.map((entry: Record<string, unknown>) => {
      const copy = { ...entry };
      for (const name of OPTIONAL_ENTRY_FIELDS) if (copy[name] === null || copy[name] === undefined) delete copy[name];
      return copy;
    });
  }
  return fields;
}

/**
 * The manifest from `GET /v1/manifest/signed`, returned only if the subnet owner's Ed25519 key signed it. Verifies the
 * document as received, so fields this SDK doesn't know about are still covered by the signature.
 */
export function verifySignedManifest(document: unknown, ownerPublicKey: Uint8Array): GoldenManifest {
  const doc = document as { manifest?: Record<string, unknown>; signature?: string | null } | null;
  if (!doc || typeof doc !== "object" || !doc.manifest || typeof doc.manifest !== "object" || typeof doc.signature !== "string") {
    throw new Error("not an owner-signed manifest");
  }
  const message = concatBytes(utf8("kuno/v1/manifest\n"), canonicalJson(manifestSignedFields(doc.manifest)));
  let signature: Uint8Array;
  try {
    signature = b64d(doc.signature);
  } catch {
    throw new Error("not an owner-signed manifest");
  }
  if (!safeVerify(signature, message, ownerPublicKey)) throw new Error("the manifest is not signed by the subnet owner's key");
  return doc.manifest as unknown as GoldenManifest;
}

function safeVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

export { safeVerify as verifySignature };
