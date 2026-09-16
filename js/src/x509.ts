/**
 * Just enough X.509 to check NVIDIA's attestation-service signing certificates: a strict DER reader, the few
 * certificate fields that check needs, and RSASSA-PKCS1-v1_5 with SHA-256 verification.
 *
 * Kept in the SDK rather than pulled from a general X.509 library because the shape checked is narrow and fixed:
 * an RSA-2048 intermediate signing a P-384 certificate with sha256WithRSAEncryption. Anything else is refused.
 * PKCS#1 v1.5 is verified by rebuilding the expected encoded message and comparing it whole, never by parsing
 * the decrypted block, which is what signature-forgery attacks on v1.5 exploit.
 */

import { sha256 } from "@noble/hashes/sha2.js";

import { concatBytes, fromHex, toHex } from "./encoding.js";

interface Tlv {
  tag: number;
  /** The whole element: tag, length and contents. */
  raw: Uint8Array;
  contents: Uint8Array;
}

function readTlv(bytes: Uint8Array, offset: number): Tlv {
  if (offset + 2 > bytes.length) throw new Error("truncated DER");
  const tag = bytes[offset];
  if ((tag & 0x1f) === 0x1f) throw new Error("multi-byte DER tags are not supported");
  let length = bytes[offset + 1];
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) throw new Error("unsupported DER length");
    if (offset + 2 + count > bytes.length) throw new Error("truncated DER");
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[offset + 2 + i];
    if (length < 0x80 || (count > 1 && bytes[offset + 2] === 0)) throw new Error("non-minimal DER length");
    header += count;
  }
  const end = offset + header + length;
  if (end > bytes.length) throw new Error("truncated DER");
  return { tag, raw: bytes.subarray(offset, end), contents: bytes.subarray(offset + header, end) };
}

function children(parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let offset = 0; offset < parent.contents.length; ) {
    const child = readTlv(parent.contents, offset);
    out.push(child);
    offset += child.raw.length;
  }
  return out;
}

function expect(tlv: Tlv | undefined, tag: number, what: string): Tlv {
  if (!tlv || tlv.tag !== tag) throw new Error(`malformed certificate: ${what}`);
  return tlv;
}

const SEQUENCE = 0x30;
const OID_RSA_ENCRYPTION = "06092a864886f70d010101";
const OID_SHA256_WITH_RSA = "06092a864886f70d01010b";
const OID_EC_PUBLIC_KEY = "06072a8648ce3d0201";
const OID_SECP384R1 = "06052b81040022";

export interface Certificate {
  tbs: Uint8Array;
  signatureAlgorithm: string;
  signature: Uint8Array;
  issuer: Uint8Array;
  subject: Uint8Array;
  notBefore: number;
  notAfter: number;
  /** The DER SubjectPublicKeyInfo, as hashed for pinning. */
  spki: Uint8Array;
  publicKey: { kind: "rsa"; n: bigint; e: bigint } | { kind: "p384"; point: Uint8Array } | { kind: "other" };
}

function parseTime(tlv: Tlv): number {
  const text = new TextDecoder().decode(tlv.contents);
  let match: RegExpMatchArray | null;
  if (tlv.tag === 0x17 && (match = text.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/))) {
    const year = Number(match[1]);
    return Date.UTC(year < 50 ? 2000 + year : 1900 + year, Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6])) / 1000;
  }
  if (tlv.tag === 0x18 && (match = text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/))) {
    return Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6])) / 1000;
  }
  throw new Error("malformed certificate: validity time");
}

function unsigned(bytes: Uint8Array): bigint {
  return bytes.length ? BigInt(`0x${toHex(bytes)}`) : 0n;
}

function bitString(tlv: Tlv): Uint8Array {
  if (tlv.tag !== 0x03 || tlv.contents[0] !== 0) throw new Error("malformed certificate: bit string");
  return tlv.contents.subarray(1);
}

export function parseCertificate(der: Uint8Array): Certificate {
  const top = readTlv(der, 0);
  if (top.tag !== SEQUENCE || top.raw.length !== der.length) throw new Error("malformed certificate");
  const [tbsTlv, algTlv, sigTlv] = children(top);
  const tbs = expect(tbsTlv, SEQUENCE, "tbsCertificate");
  const fields = children(tbs);
  const offset = fields[0]?.tag === 0xa0 ? 1 : 0; // [0] EXPLICIT version
  const issuer = expect(fields[offset + 2], SEQUENCE, "issuer");
  const validity = children(expect(fields[offset + 3], SEQUENCE, "validity"));
  const subject = expect(fields[offset + 4], SEQUENCE, "subject");
  const spkiTlv = expect(fields[offset + 5], SEQUENCE, "subjectPublicKeyInfo");
  const [spkiAlg, spkiKey] = children(spkiTlv);
  const spkiAlgFields = children(expect(spkiAlg, SEQUENCE, "key algorithm"));
  const keyOid = toHex(spkiAlgFields[0]?.raw ?? new Uint8Array());
  let publicKey: Certificate["publicKey"] = { kind: "other" };
  if (keyOid === OID_RSA_ENCRYPTION) {
    const [n, e] = children(readTlv(bitString(spkiKey), 0));
    publicKey = { kind: "rsa", n: unsigned(expect(n, 0x02, "RSA modulus").contents), e: unsigned(expect(e, 0x02, "RSA exponent").contents) };
  } else if (keyOid === OID_EC_PUBLIC_KEY && toHex(spkiAlgFields[1]?.raw ?? new Uint8Array()) === OID_SECP384R1) {
    publicKey = { kind: "p384", point: bitString(spkiKey) };
  }
  const outerAlg = children(expect(algTlv, SEQUENCE, "signature algorithm"));
  return {
    tbs: tbs.raw,
    signatureAlgorithm: toHex(outerAlg[0]?.raw ?? new Uint8Array()),
    signature: bitString(expect(sigTlv, 0x03, "signature")),
    issuer: issuer.raw,
    subject: subject.raw,
    notBefore: parseTime(validity[0]),
    notAfter: parseTime(validity[1]),
    spki: spkiTlv.raw,
    publicKey,
  };
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
}

// DigestInfo for SHA-256, with and without the NULL parameters RFC 8017 lets signers omit.
const DIGEST_INFO_SHA256 = [fromHex("3031300d060960864801650304020105000420"), fromHex("302f300b0609608648016503040201" + "0420")];

/** RSASSA-PKCS1-v1_5 with SHA-256, by rebuilding the encoded message the signature must decrypt to. */
export function verifyRsaSha256(key: { n: bigint; e: bigint }, signature: Uint8Array, message: Uint8Array): boolean {
  const k = (key.n.toString(16).length + 1) >> 1;
  if (k < 256 || signature.length !== k) return false; // RSA-2048 or larger, signature exactly k bytes
  const s = unsigned(signature);
  if (s >= key.n) return false;
  const decrypted = fromHex(modPow(s, key.e, key.n).toString(16).padStart(k * 2, "0"));
  const digest = sha256(message);
  return DIGEST_INFO_SHA256.some((prefix) => {
    const t = concatBytes(prefix, digest);
    const expected = concatBytes(new Uint8Array([0x00, 0x01]), new Uint8Array(k - t.length - 3).fill(0xff), new Uint8Array([0x00]), t);
    let diff = 0;
    for (let i = 0; i < k; i++) diff |= expected[i] ^ decrypted[i];
    return diff === 0;
  });
}

/** Whether `issuer` signed `cert` (sha256WithRSAEncryption) and names match (RFC 5280 name chaining). */
export function directlyIssuedBy(cert: Certificate, issuer: Certificate): boolean {
  if (toHex(cert.issuer) !== toHex(issuer.subject)) return false;
  if (cert.signatureAlgorithm !== OID_SHA256_WITH_RSA || issuer.publicKey.kind !== "rsa") return false;
  return verifyRsaSha256(issuer.publicKey, cert.signature, cert.tbs);
}

export function spkiSha256(cert: Certificate): string {
  return toHex(sha256(cert.spki));
}
