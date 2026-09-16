/**
 * Endorsements: checking an enclave's hardware evidence with what Intel and NVIDIA signed, whoever relayed it.
 * Mirrors kuno_protocol.endorsements, which explains the design; in short:
 *
 * - `tdx_collateral` is Intel's DCAP collateral for the quote's platform. `@phala/dcap-qvl` (the JavaScript port of the
 *   dcap-qvl the gateway uses) verifies the quote with it against Intel's SGX root CA, which it pins.
 * - `nvidia` holds NVIDIA Remote Attestation Service answers for the GPUs and NVSwitches, and the JWKS entries that sign
 *   them. Each entry's certificate must be issued by NVIDIA's attestation intermediate, pinned here by SPKI hash.
 *
 * A relay can withhold either (the check fails) but can't forge them. It can serve older Intel collateral that hasn't
 * expired, so a platform revoked since then passes until that collateral's nextUpdate (about a month at most).
 */

import { p384 } from "@noble/curves/nist.js";
import { verify as verifyDcapQuote } from "@phala/dcap-qvl";

import { b64d, utf8 } from "./encoding.js";
import { directlyIssuedBy, parseCertificate, spkiSha256 } from "./x509.js";

/** SHA-256 of the DER SubjectPublicKeyInfo of "NVIDIA Attestation Service GPU Intermediate 004" (valid to 2029-12-08). */
export const NRAS_INTERMEDIATE_SPKI_SHA256: readonly string[] = ["fd32837f954e2c45db073105166dfe6985ae0480bb113fba63b091a75affe896"];
export const DEFAULT_TCB_STATUSES: readonly string[] = ["UpToDate"];
const DEFAULT_MAX_TOKEN_AGE_S = 3600;
const LEEWAY_S = 60;

export interface NvidiaJwk {
  kid: string;
  kty?: string;
  crv?: string;
  x?: string;
  y?: string;
  x5c?: string[];
}

export interface NvidiaResult {
  device: "gpu" | "switch";
  /** NRAS's answer as NVIDIA signed it: `[["JWT", overall], {"GPU-0": token, ...}]`. */
  answer: unknown;
  keys: NvidiaJwk[];
}

export interface Endorsements {
  v: 1;
  tdx_collateral: Record<string, string> | null;
  nvidia: NvidiaResult[];
}

export interface EndorsementOptions {
  now?: number;
  /** Replaces the NRAS intermediate pin when NVIDIA rotates it. */
  nvidiaTrustedSpki?: readonly string[];
  /** TCB statuses a platform may report; default UpToDate only, as the gateway's default. */
  tdxAllowedTcbStatuses?: readonly string[];
  maxTokenAgeS?: number;
}

// ---------------------------------------------------------------- Intel

export interface QuoteCheck {
  ok: boolean;
  detail: string;
  status?: string;
}

/** Full DCAP verification of a TD quote against relayed Intel collateral: signature chain, CRLs, QE identity, TCB. */
export function verifyTdxQuoteSignature(quote: Uint8Array, collateral: Record<string, string> | null, opts: EndorsementOptions = {}): QuoteCheck {
  if (!collateral) return { ok: false, detail: "no Intel collateral was relayed for this quote" };
  const now = Math.floor(opts.now ?? Date.now() / 1000);
  let status: string;
  try {
    status = verifyDcapQuote(quote, collateral as never, now).status;
  } catch (err) {
    return { ok: false, detail: `DCAP verification failed: ${(err as Error).message ?? String(err)}` };
  }
  const allowed = opts.tdxAllowedTcbStatuses ?? DEFAULT_TCB_STATUSES;
  if (!allowed.includes(status)) return { ok: false, detail: `TCB status ${status} is not accepted (allowed: ${allowed.join(", ")})`, status };
  return { ok: true, detail: `TCB status ${status}`, status };
}

// ---------------------------------------------------------------- NVIDIA

function b64urlJson(part: string): unknown {
  return JSON.parse(new TextDecoder().decode(b64d(part)));
}

/** The P-384 point a JWKS entry names, once its x5c is [signing certificate, pinned intermediate] valid at `at`. */
export function pinnedNrasKey(jwk: NvidiaJwk, at: number, trustedSpki: readonly string[] = NRAS_INTERMEDIATE_SPKI_SHA256): Uint8Array {
  if (!Array.isArray(jwk.x5c) || jwk.x5c.length !== 2) {
    throw new Error("an NRAS signing key must carry its certificate and the intermediate that issued it (x5c of two)");
  }
  let leaf, intermediate;
  try {
    [leaf, intermediate] = jwk.x5c.map((c) => parseCertificate(b64d(c)));
  } catch {
    throw new Error("malformed certificate in an NRAS signing key");
  }
  if (!trustedSpki.includes(spkiSha256(intermediate))) throw new Error("the NRAS signing key does not chain to NVIDIA's pinned attestation intermediate");
  if (!directlyIssuedBy(leaf, intermediate)) throw new Error("the NRAS signing certificate is not signed by the pinned intermediate");
  for (const [name, cert] of [["signing certificate", leaf], ["intermediate", intermediate]] as const) {
    if (at < cert.notBefore || at > cert.notAfter) throw new Error(`the NRAS ${name} was not valid when the token was issued`);
  }
  if (leaf.publicKey.kind !== "p384" || leaf.publicKey.point.length !== 97 || leaf.publicKey.point[0] !== 4) {
    throw new Error("the NRAS signing certificate does not hold a P-384 key");
  }
  const point = leaf.publicKey.point;
  if (jwk.x !== undefined && (!same(b64d(jwk.x), point.subarray(1, 49)) || !same(b64d(jwk.y ?? ""), point.subarray(49)))) {
    throw new Error("the JWKS entry's key is not the key its certificate holds");
  }
  return point;
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** An ES384 NRAS token's claims, verified with a relayed JWKS entry under the pinned intermediate. */
export function verifyEndorsedToken(token: string, keys: NvidiaJwk[], opts: EndorsementOptions = {}): Record<string, unknown> {
  const now = opts.now ?? Date.now() / 1000;
  const parts = typeof token === "string" ? token.split(".") : [];
  if (parts.length !== 3) throw new Error("malformed token");
  let header: Record<string, unknown>, claims: Record<string, unknown>;
  try {
    header = b64urlJson(parts[0]) as Record<string, unknown>;
    claims = b64urlJson(parts[1]) as Record<string, unknown>;
  } catch {
    throw new Error("malformed token");
  }
  if (!header || header.alg !== "ES384") throw new Error("unexpected token algorithm");
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) throw new Error("token claims are not an object");
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error(`no relayed signing key ${JSON.stringify(header.kid)}`);
  const issued = claims.iat ?? claims.nbf;
  if (typeof issued !== "number") throw new Error("token carries no issue time");
  const point = pinnedNrasKey(jwk, issued, opts.nvidiaTrustedSpki);
  const signature = b64d(parts[2]);
  // NRAS doesn't normalize S, so high-S signatures are valid here (lowS: false); p384 hashes with SHA-384.
  if (signature.length !== 96 || !p384.verify(signature, utf8(`${parts[0]}.${parts[1]}`), point, { lowS: false })) {
    throw new Error("token signature is invalid");
  }
  if (issued > now + LEEWAY_S) throw new Error("token is issued in the future");
  if (now - issued > (opts.maxTokenAgeS ?? DEFAULT_MAX_TOKEN_AGE_S)) throw new Error("token is older than a client accepts");
  if (typeof claims.exp === "number" && now > claims.exp + LEEWAY_S) throw new Error("token has expired");
  return claims;
}

function splitDetachedEat(answer: unknown): [string, Record<string, string>] {
  if (
    Array.isArray(answer) && answer.length === 2 && Array.isArray(answer[0]) && answer[0].length === 2 && answer[0][0] === "JWT" &&
    typeof answer[0][1] === "string" && answer[1] && typeof answer[1] === "object" && !Array.isArray(answer[1]) &&
    Object.values(answer[1]).every((v) => typeof v === "string")
  ) {
    return [answer[0][1], answer[1] as Record<string, string>];
  }
  throw new Error("unexpected NRAS response shape");
}

function claimProblems(claims: Record<string, unknown>, device: "gpu" | "switch"): string[] {
  const label = device === "gpu" ? "GPU" : "NVSwitch";
  const problems: string[] = [];
  if (String(claims.measres ?? "").toLowerCase() !== "success") {
    problems.push(`runtime measurements do not match NVIDIA's reference values (measres=${JSON.stringify(claims.measres)})`);
  }
  if (claims.dbgstat !== "disabled" && claims.dbgstat !== false) problems.push(`${label} debug is not confirmed disabled (dbgstat=${JSON.stringify(claims.dbgstat)})`);
  if (claims.secboot !== true) problems.push(`${label} secure boot is not confirmed`);
  for (const name of [`x-nvidia-${device}-attestation-report-nonce-match`, `x-nvidia-${device}-attestation-report-signature-verified`]) {
    if (claims[name] !== true) problems.push(`${name} is not true`);
  }
  return problems;
}

/** kuno_protocol.nvidia.check_nras_answer: the claims NRAS signed for `count` devices of one kind, and what's wrong. */
function checkNrasAnswer(result: NvidiaResult, gpuNonceHex: string, count: number, opts: EndorsementOptions) {
  const noun = result.device === "gpu" ? "GPU" : "NVSwitch";
  let overall: Record<string, unknown>;
  const perDevice: Array<[string, Record<string, unknown>]> = [];
  try {
    const [overallToken, detached] = splitDetachedEat(result.answer);
    overall = verifyEndorsedToken(overallToken, result.keys, opts);
    for (const name of Object.keys(detached).sort()) perDevice.push([name, verifyEndorsedToken(detached[name], result.keys, opts)]);
  } catch (err) {
    return { claims: null, problems: [`NRAS verification failed: ${(err as Error).message}`] };
  }
  const problems: string[] = [];
  if (overall["x-nvidia-overall-att-result"] !== true) problems.push("NRAS overall attestation result is not true");
  if (String(overall.eat_nonce ?? "").toLowerCase() !== gpuNonceHex) problems.push("NRAS token is for a different nonce");
  if (perDevice.length !== count) problems.push(`NRAS attested ${perDevice.length} ${noun}(s) but the evidence holds ${count}`);
  for (const [name, claims] of perDevice) {
    if ("eat_nonce" in claims && String(claims.eat_nonce).toLowerCase() !== gpuNonceHex) problems.push(`${name}: token is for a different nonce`);
    problems.push(...claimProblems(claims, result.device).map((p) => `${name}: ${p}`));
  }
  return { claims: perDevice.map(([, c]) => c), problems };
}

interface GpuBundle {
  format?: string;
  nonce?: string;
  gpus?: Array<{ arch?: string }>;
  cc?: { mode?: string; devtools?: boolean } | null;
  switches?: Array<{ arch?: string }> | null;
}

/** kuno_protocol.nvidia._bundle_problems: the evidence's own nonce, architectures and declared mode. */
function bundleProblems(bundle: GpuBundle, gpuNonceHex: string): string | null {
  if (bundle.format !== "kuno/v1/nvidia-gpu" || !Array.isArray(bundle.gpus) || bundle.gpus.length === 0) return "not kuno/v1/nvidia-gpu evidence";
  if (String(bundle.nonce ?? "").toLowerCase() !== gpuNonceHex) return "GPU evidence was collected for a different nonce";
  const gpuArchs = new Set(bundle.gpus.map((g) => g.arch));
  if (gpuArchs.size !== 1) return "GPUs of mixed architectures must be attested separately";
  const switches = Array.isArray(bundle.switches) ? bundle.switches : [];
  if (switches.length && new Set(switches.map((s) => s.arch)).size !== 1) return "NVSwitches of mixed architectures must be attested separately";
  const cc = bundle.cc;
  if (!cc) return switches.length ? "the evidence carries NVSwitch evidence but declares no GPU confidential-computing mode" : null;
  const problems: string[] = [];
  if (cc.mode === "ppcie") {
    if (gpuArchs.size !== 1 || !gpuArchs.has("HOPPER")) problems.push("Protected PCIe mode exists only on Hopper GPUs");
    if (!switches.length) problems.push("Protected PCIe mode needs evidence from the VM's NVSwitches");
  } else if (switches.length) {
    problems.push(`${cc.mode} mode keeps the NVSwitches out of the VM, yet the evidence carries NVSwitch evidence`);
  }
  if (cc.mode === "mpt" && (gpuArchs.size !== 1 || !gpuArchs.has("BLACKWELL"))) problems.push("multi-GPU passthrough CC exists only on Blackwell GPUs");
  return problems.join("; ") || null;
}

export interface GpuCheck {
  ok: boolean;
  detail: string;
  gpuCount: number;
  switchCount: number;
}

/** The GPU evidence bound into the quote, checked against the NRAS answers relayed with it. */
export function verifyGpuEndorsements(gpuEvidence: Uint8Array, gpuNonce: Uint8Array, endorsements: Endorsements | null, opts: EndorsementOptions = {}): GpuCheck {
  const fail = (detail: string): GpuCheck => ({ ok: false, detail, gpuCount: 0, switchCount: 0 });
  let bundle: GpuBundle;
  try {
    bundle = JSON.parse(new TextDecoder().decode(gpuEvidence)) as GpuBundle;
  } catch {
    return fail("not kuno/v1/nvidia-gpu evidence");
  }
  const nonceHex = Array.from(gpuNonce, (b) => b.toString(16).padStart(2, "0")).join("");
  const refused = bundleProblems(bundle, nonceHex);
  if (refused) return fail(refused);
  const gpuResult = endorsements?.nvidia?.find((r) => r.device === "gpu");
  if (!gpuResult) return fail("no NVIDIA attestation result was relayed for the GPUs");
  const gpus = checkNrasAnswer(gpuResult, nonceHex, bundle.gpus!.length, opts);
  if (!gpus.claims || gpus.problems.length) return fail(gpus.problems.join("; "));
  let switchCount = 0;
  const switches = Array.isArray(bundle.switches) ? bundle.switches : [];
  if (switches.length) {
    const switchResult = endorsements?.nvidia?.find((r) => r.device === "switch");
    if (!switchResult) return fail("no NVIDIA attestation result was relayed for the NVSwitches");
    const checked = checkNrasAnswer(switchResult, nonceHex, switches.length, opts);
    if (!checked.claims || checked.problems.length) return fail(checked.problems.map((p) => `NVSwitch evidence: ${p}`).join("; "));
    switchCount = checked.claims.length;
  }
  return { ok: true, detail: `${gpus.claims.length} GPU(s) attested by NRAS, checked under NVIDIA's pinned intermediate`, gpuCount: gpus.claims.length, switchCount };
}
