/**
 * KunoWorld JavaScript SDK.
 *
 *   const kuno = new KunoClient({ apiKey });
 *   const job = await kuno.submit({ prompt: "A lighthouse keeper lights the lamp at dusk", model: "h3-turbo" });
 *   const { video, receipt } = await kuno.wait(job);
 *
 * Prompts and media are encrypted in this process to a GPU enclave whose attestation
 * is checked first; the platform only relays ciphertext.
 */

export * from "./types.js";
export { KunoClient, KunoError, fitParams, inferMode, jobAad, priceUsd, sniffMime, verifyReceipt } from "./client.js";
export type { GenerateInput, GenerateRequest, GenerationResult, JobHandle, KunoClientOptions, SubmitStage } from "./client.js";
export { enclaveIdFor, parseTdxQuote, reportDataFor, verifyEvidence } from "./attestation.js";
export type { Verdict } from "./attestation.js";
export { DecryptionError, decryptBlob, encryptBlob, openSenderSession, sha256Hex } from "./crypto.js";
export { b64d, b64e, canonicalJson, fromHex, toHex } from "./encoding.js";
