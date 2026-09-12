/**
 * Enclave attestation checks, mirroring kuno_protocol.attestation.
 *
 * Mock evidence (development) is fully verified. For Intel TDX the SDK verifies the
 * measurements against the golden manifest and the REPORTDATA key binding; the quote's
 * Intel signature chain and NVIDIA GPU evidence are verified by validators and the
 * gateway (browsers cannot fetch DCAP collateral). `signatureVerified` reports which.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";

import { b64d, canonicalJson, concatBytes, fromHex, toHex, utf8 } from "./encoding.js";
import type { AttestationEvidence, GoldenManifest } from "./types.js";

export interface Verdict {
  ok: boolean;
  enclaveId: string;
  reasons: string[];
  signatureVerified: boolean;
  measurements: Record<string, string>;
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

export function parseTdxQuote(quote: Uint8Array): Record<string, string> {
  const bodyLen = TDX_FIELDS.reduce((n, [, size]) => n + size, 0);
  if (quote.length < 48 + bodyLen) throw new Error("quote too short for a TDX v4 quote");
  const view = new DataView(quote.buffer, quote.byteOffset, quote.length);
  if (view.getUint16(0, true) !== 4 || view.getUint32(4, true) !== 0x81) throw new Error("not a TDX v4 quote");
  const fields: Record<string, string> = {};
  let offset = 48;
  for (const [name, size] of TDX_FIELDS) {
    fields[name] = toHex(quote.subarray(offset, offset + size));
    offset += size;
  }
  return fields;
}

export function verifyEvidence(
  evidence: AttestationEvidence,
  manifest: GoldenManifest,
  opts: { expectedNonce?: Uint8Array; now?: number } = {},
): Verdict {
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
      if (!gpu) reasons.push("GPU evidence is required on TDX workers");
    } catch (err) {
      reasons.push((err as Error).message);
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
    else if (!evidence.profiles.every((p) => allowed.profiles.includes(p))) reasons.push("image is not approved for all claimed profiles");
  }
  verdict.ok = reasons.length === 0;
  return verdict;
}

function safeVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

export { safeVerify as verifySignature };
