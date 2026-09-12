/**
 * Client-side encryption, byte-compatible with kuno_protocol.crypto and kuno_protocol.blobs.
 *
 * Jobs: HPKE (RFC 9180) DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305,
 * info "kuno/v1/job". The context exports an input key (for uploaded media) and an
 * output key (the only key that opens the finished video).
 *
 * Blobs: "KUNOB1" | version | chunk_size:u32be | prefix:7, then ChaCha20-Poly1305 chunks
 * with nonce prefix | index:u32be | final:u8 and the header as AAD.
 */

import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { concatBytes, toHex, utf8 } from "./encoding.js";

const HPKE_INFO = utf8("kuno/v1/job");
const EXPORT_INPUT = utf8("kuno/v1/input-key");
const EXPORT_OUTPUT = utf8("kuno/v1/output-key");
const MAGIC = utf8("KUNOB1");
const VERSION = 1;
const HEADER_LEN = 18;
const TAG_LEN = 16;
export const DEFAULT_CHUNK = 1 << 20;
const MAX_CHUNK = 64 << 20;

export class DecryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DecryptionError";
  }
}

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

export interface SenderSession {
  enc: Uint8Array;
  inputKey: Uint8Array;
  outputKey: Uint8Array;
  seal(plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
}

export async function openSenderSession(enclavePublicKey: Uint8Array): Promise<SenderSession> {
  const recipientPublicKey = await suite.kem.deserializePublicKey(enclavePublicKey);
  const ctx = await suite.createSenderContext({ recipientPublicKey, info: HPKE_INFO });
  const inputKey = new Uint8Array(await ctx.export(EXPORT_INPUT, 32));
  const outputKey = new Uint8Array(await ctx.export(EXPORT_OUTPUT, 32));
  let sealed = false;
  return {
    enc: new Uint8Array(ctx.enc),
    inputKey,
    outputKey,
    async seal(plaintext, aad) {
      if (sealed) throw new Error("a sender session seals exactly one request");
      sealed = true;
      return new Uint8Array(await ctx.seal(plaintext, aad));
    },
  };
}

function blobKey(baseKey: Uint8Array, label: string): Uint8Array {
  return hkdf(sha256, baseKey, undefined, utf8(`kuno/v1/blob/${label}`), 32);
}

function nonce(prefix: Uint8Array, index: number, final: boolean): Uint8Array {
  const n = new Uint8Array(12);
  n.set(prefix, 0);
  new DataView(n.buffer).setUint32(7, index, false);
  n[11] = final ? 1 : 0;
  return n;
}

export function encryptBlob(baseKey: Uint8Array, label: string, plaintext: Uint8Array, chunkSize = DEFAULT_CHUNK): Uint8Array {
  if (chunkSize <= 0 || chunkSize > MAX_CHUNK) throw new Error("chunk size out of range");
  const key = blobKey(baseKey, label);
  const prefix = crypto.getRandomValues(new Uint8Array(7));
  const header = new Uint8Array(HEADER_LEN);
  header.set(MAGIC, 0);
  header[6] = VERSION;
  new DataView(header.buffer).setUint32(7, chunkSize, false);
  header.set(prefix, 11);
  const count = Math.max(1, Math.ceil(plaintext.length / chunkSize));
  const parts: Uint8Array[] = [header];
  for (let i = 0; i < count; i++) {
    const chunk = plaintext.subarray(i * chunkSize, (i + 1) * chunkSize);
    parts.push(chacha20poly1305(key, nonce(prefix, i, i === count - 1), header).encrypt(chunk));
  }
  return concatBytes(...parts);
}

export function decryptBlob(baseKey: Uint8Array, label: string, blob: Uint8Array): Uint8Array {
  if (blob.length < HEADER_LEN + TAG_LEN) throw new DecryptionError("blob too short");
  const header = blob.subarray(0, HEADER_LEN);
  const chunkSize = new DataView(header.buffer, header.byteOffset, HEADER_LEN).getUint32(7, false);
  const magicOk = MAGIC.every((b, i) => header[i] === b);
  if (!magicOk || header[6] !== VERSION || chunkSize <= 0 || chunkSize > MAX_CHUNK) {
    throw new DecryptionError("not a KunoWorld blob");
  }
  const prefix = header.slice(11, 18);
  const key = blobKey(baseKey, label);
  const body = blob.subarray(HEADER_LEN);
  const step = chunkSize + TAG_LEN;
  const count = Math.ceil(body.length / step);
  const parts: Uint8Array[] = [];
  try {
    for (let i = 0; i < count; i++) {
      const piece = body.subarray(i * step, (i + 1) * step);
      parts.push(chacha20poly1305(key, nonce(prefix, i, i === count - 1), header).decrypt(piece));
    }
  } catch {
    throw new DecryptionError("blob failed authentication (wrong key, label, or tampered/truncated data)");
  }
  return concatBytes(...parts);
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  if (globalThis.crypto?.subtle) {
    const copy = new Uint8Array(data);
    return toHex(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", copy)));
  }
  return toHex(sha256(data));
}
