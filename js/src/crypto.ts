/**
 * Client-side encryption, byte-compatible with kuno_protocol.crypto and kuno_protocol.blobs.
 *
 * Jobs: HPKE (RFC 9180) DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305,
 * info "kuno/v1/job". The context exports an input key (for uploaded media) and an
 * output key (the only key that opens the finished video).
 *
 * Blobs: "KUNOB1" | version | chunk_size:u32be | prefix:7, then ChaCha20-Poly1305 chunks
 * with nonce prefix | index:u32be | final:u8 and the header as AAD.
 *   version 1: the chunks carry the plaintext.
 *   version 2 (written by default): the chunks carry length:u64be | plaintext | zeros, padded to
 *   padme(8 + length) bytes (PADMÉ, Nikitin et al., PoPETs 2019, arXiv:1806.03160), so a blob's
 *   size reveals only its size bucket. Both versions decrypt.
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
/** Unpadded blobs: still decrypted, no longer written by default. */
export const BLOB_V1 = 1;
/** Blobs padded to a PADMÉ size bucket. */
export const BLOB_V2 = 2;
export type BlobVersion = typeof BLOB_V1 | typeof BLOB_V2;
export const DEFAULT_BLOB_VERSION: BlobVersion = BLOB_V2;
const HEADER_LEN = 18;
const TAG_LEN = 16;
const PREFIX_LEN = 7;
const LENGTH_LEN = 8;
const TWO_32 = 2 ** 32;
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

/**
 * PADMÉ (Nikitin et al. 2019, Algorithm 1): rounds `length` up so its low E−S bits are zero, where
 * E = ⌊log2 length⌋ and S = ⌊log2 E⌋ + 1. Integer arithmetic only, so it is exact up to 2^53.
 */
export function padme(length: number): number {
  if (!Number.isSafeInteger(length) || length < 0) throw new RangeError("length must be a non-negative safe integer");
  if (length < 2) return length;
  const exponent = length.toString(2).length - 1;
  const bits = exponent.toString(2).length;
  const step = 2 ** (exponent - bits);
  return Math.ceil(length / step) * step;
}

/** Length of a version 2 stream (length prefix, plaintext, padding) for a plaintext of this size. */
export function paddedStreamLength(plaintextLength: number): number {
  return padme(LENGTH_LEN + plaintextLength);
}

/** Size of the blob `encryptBlob` produces: what the gateway, the miner and receipts see. */
export function sealedBlobSize(plaintextLength: number, chunkSize = DEFAULT_CHUNK, version: BlobVersion = DEFAULT_BLOB_VERSION): number {
  checkVersion(version);
  const stream = version === BLOB_V1 ? plaintextLength : paddedStreamLength(plaintextLength);
  return HEADER_LEN + stream + TAG_LEN * Math.max(1, Math.ceil(stream / chunkSize));
}

/** The format version a blob declares, or null if it is not a KunoWorld blob. Unauthenticated. */
export function blobVersion(blob: Uint8Array): number | null {
  if (blob.length < HEADER_LEN || !MAGIC.every((b, i) => blob[i] === b)) return null;
  return blob[6];
}

function checkVersion(version: number): asserts version is BlobVersion {
  if (version !== BLOB_V1 && version !== BLOB_V2) throw new Error(`unknown blob version ${version}`);
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

function padStream(plaintext: Uint8Array): Uint8Array {
  const stream = new Uint8Array(paddedStreamLength(plaintext.length)); // zero-filled
  const view = new DataView(stream.buffer);
  view.setUint32(0, Math.floor(plaintext.length / TWO_32), false);
  view.setUint32(4, plaintext.length >>> 0, false);
  stream.set(plaintext, LENGTH_LEN);
  return stream;
}

function unpadStream(stream: Uint8Array): Uint8Array {
  if (stream.length < LENGTH_LEN) throw new DecryptionError("padded blob is too short to hold its length");
  const view = new DataView(stream.buffer, stream.byteOffset, stream.byteLength);
  const high = view.getUint32(0, false);
  const end = LENGTH_LEN + high * TWO_32 + view.getUint32(4, false);
  if (high >= 2 ** 20 || end > stream.length) throw new DecryptionError("padded blob declares more plaintext than it holds");
  if (padme(end) !== stream.length) throw new DecryptionError("padded blob is not padded to its size bucket");
  for (let i = end; i < stream.length; i++) {
    if (stream[i] !== 0) throw new DecryptionError("padded blob has non-zero padding");
  }
  return stream.slice(LENGTH_LEN, end);
}

/** Seals `plaintext` under `label`. Writes the padded format (version 2) unless version 1 is asked for. */
export function encryptBlob(
  baseKey: Uint8Array,
  label: string,
  plaintext: Uint8Array,
  chunkSize = DEFAULT_CHUNK,
  version: BlobVersion = DEFAULT_BLOB_VERSION,
): Uint8Array {
  checkVersion(version);
  const stream = version === BLOB_V2 ? padStream(plaintext) : plaintext;
  return sealStreamWithPrefix(baseKey, label, stream, chunkSize, version, crypto.getRandomValues(new Uint8Array(PREFIX_LEN)));
}

/**
 * Internal: encrypts an already framed stream under a given nonce prefix. Exported from this module (not from the
 * package index) only so the protocol vectors can be reproduced byte for byte. Never reuse a prefix under one key.
 */
export function sealStreamWithPrefix(
  baseKey: Uint8Array,
  label: string,
  stream: Uint8Array,
  chunkSize: number,
  version: BlobVersion,
  prefix: Uint8Array,
): Uint8Array {
  if (chunkSize <= 0 || chunkSize > MAX_CHUNK) throw new Error("chunk size out of range");
  if (prefix.length !== PREFIX_LEN) throw new Error("nonce prefix must be 7 bytes");
  const key = blobKey(baseKey, label);
  const header = new Uint8Array(HEADER_LEN);
  header.set(MAGIC, 0);
  header[6] = version;
  new DataView(header.buffer).setUint32(7, chunkSize, false);
  header.set(prefix, 11);
  const count = Math.max(1, Math.ceil(stream.length / chunkSize));
  const parts: Uint8Array[] = [header];
  for (let i = 0; i < count; i++) {
    const chunk = stream.subarray(i * chunkSize, (i + 1) * chunkSize);
    parts.push(chacha20poly1305(key, nonce(prefix, i, i === count - 1), header).encrypt(chunk));
  }
  return concatBytes(...parts);
}

/** Opens a version 1 or version 2 blob and returns the original plaintext. */
export function decryptBlob(baseKey: Uint8Array, label: string, blob: Uint8Array): Uint8Array {
  if (blob.length < HEADER_LEN + TAG_LEN) throw new DecryptionError("blob too short");
  const header = blob.subarray(0, HEADER_LEN);
  const version = header[6];
  const chunkSize = new DataView(header.buffer, header.byteOffset, HEADER_LEN).getUint32(7, false);
  const magicOk = MAGIC.every((b, i) => header[i] === b);
  if (!magicOk || (version !== BLOB_V1 && version !== BLOB_V2) || chunkSize <= 0 || chunkSize > MAX_CHUNK) {
    throw new DecryptionError("not a KunoWorld blob");
  }
  const prefix = header.slice(11, 18);
  const key = blobKey(baseKey, label);
  const body = blob.subarray(HEADER_LEN);
  const step = chunkSize + TAG_LEN;
  const count = Math.ceil(body.length / step);
  const authError = () => new DecryptionError("blob failed authentication (wrong key, label, or tampered/truncated data)");
  if (body.length - (count - 1) * step < TAG_LEN) throw authError();
  const stream = new Uint8Array(body.length - count * TAG_LEN);
  let offset = 0;
  try {
    for (let i = 0; i < count; i++) {
      const piece = body.subarray(i * step, (i + 1) * step);
      const plain = chacha20poly1305(key, nonce(prefix, i, i === count - 1), header).decrypt(piece);
      stream.set(plain, offset);
      offset += plain.length;
    }
  } catch {
    throw authError();
  }
  return version === BLOB_V1 ? stream : unpadStream(stream);
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  if (globalThis.crypto?.subtle) {
    const copy = new Uint8Array(data);
    return toHex(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", copy)));
  }
  return toHex(sha256(data));
}
