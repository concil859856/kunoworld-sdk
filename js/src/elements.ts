/**
 * Elements: reusable characters, products, locations, styles and voices, encrypted here before they reach KunoWorld.
 * The gateway's half is platform/gateway/src/kuno_gateway/elements.py; the contract is platform/gateway/ELEMENTS.md.
 *
 * Keys:
 * - **Elements key.** HKDF-SHA256 of the account's key sync master key, salt "kuno/elements/v1", info
 *   "elements-key|<account_id>". The website derives it from the master key its browser unlocked; a program gets it from
 *   the studio as text (`kwek1.<account id>.<master key id>.<key>`, see `parseElementsKey`). It opens Elements only:
 *   HKDF is one-way, so it can't open the master key or any video key. A key sync rotation replaces it.
 * - **Element key.** 32 random bytes per Element, new whenever its files are uploaded. `wrapped_key` is base64url of
 *   "KVE1" | 12-byte IV | AES-256-GCM(element key) with its 16-byte tag, under the Elements key, with associated data
 *   "KVE1|kuno/elements/element-key|<account_id>|<element_id>".
 *
 * Sealed with the element key, as KUNOB1 version 2 blobs (crypto.ts), so each size is padded:
 * - the record (`meta`): kind, name, description, consent and each file's type, size and SHA-256, as JSON framed and
 *   padded like a sealed request (`padPayload`: a power of two from 4 KiB, here at most 16 KiB), label
 *   "element/<element_id>/meta";
 * - each file: label "element/<element_id>/file/<position>".
 *
 * Using an Element changes nothing about a job: its images and voice clip become ordinary inputs (sealed again to the
 * enclave for a Private job, uploaded as they are for a Standard one) and its description joins the prompt.
 */

import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { decryptBlob, encryptBlob, padPayload, unpadPayload } from "./crypto.js";
import { b64d, b64e, concatBytes, toHex, utf8 } from "./encoding.js";
import { KunoError } from "./errors.js";
import type { InputRole, ModelProfile } from "./types.js";

export type ElementKind = "character" | "product" | "location" | "style" | "voice";

export const ELEMENT_KINDS: readonly ElementKind[] = ["character", "product", "location", "style", "voice"];

/** What every write affirms (the gateway refuses a write without `affirm_rules`). Sexual content is banned platform-wide. */
export const ELEMENT_RULES =
  "No public figures and no one under 18. A real person must be you, or must have given you permission. Sexual content is banned.";

export const ELEMENT_LIMITS = {
  maxElements: 200,
  maxImages: 4,
  /** Per file before sealing; sealed and padded it stays under the gateway's 16 MiB. */
  maxFileBytes: 15 * 1024 * 1024,
  maxAccountBytes: 2 * 1024 * 1024 * 1024,
  maxNameChars: 80,
  maxDescriptionChars: 1000,
  maxConsentChars: 200,
  /** A voice clip's longest length; 5 to 15 seconds works best. */
  maxVoiceSeconds: 30,
} as const;

export const ELEMENT_IMAGE_TYPES = ["image/png", "image/jpeg", "image/webp"] as const;
export const ELEMENT_AUDIO_TYPES = ["audio/wav", "audio/mpeg", "audio/ogg", "audio/flac"] as const;

/** The input roles an Element's files can fill. Its description works with every model. */
export const ELEMENT_IMAGE_ROLES: readonly InputRole[] = ["first_frame", "last_frame", "keyframe", "reference_image"];
export const ELEMENT_VOICE_ROLES: readonly InputRole[] = ["reference_audio"];

const KEY_MAGIC = utf8("KVE1");
const IV_LEN = 12;
const WRAPPED_LEN = 4 + IV_LEN + 32 + 16;
const META_MAX_PADDED = 16 * 1024;
const ID = /^[0-9a-f]{32}$/;
const TEXT_KEY = /^kwek1\.([A-Za-z0-9_-]{1,64})\.([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$/;

/** The key that opens an account's Elements, and the key sync generation it came from. */
export interface ElementsKey {
  accountId: string;
  /** The vault's `master_key_id` when this key was derived. Writes name it; after a rotation it is stale. */
  keyId: string;
  key: Uint8Array;
}

/** A real person's permission to appear as a character or a voice. Sealed with the rest of the record. */
export interface ElementConsent {
  /** The person, as they'd name themselves. */
  subject: string;
  /** `self`: the uploader is this person. `permission`: this person gave the uploader permission. */
  relationship: "self" | "permission";
  /** When they gave it, YYYY-MM-DD. */
  grantedOn: string;
  /** What they agreed to, in their words or yours. */
  use: string;
  /** When the uploader affirmed this record, Unix seconds. */
  affirmedAt: number;
  /** Set when the person withdrew it: the Element can't be used in new videos. */
  withdrawnAt?: number | null;
}

export interface ElementFileInfo {
  mime: string;
  /** Bytes before sealing. */
  size: number;
  /** SHA-256 of the file before sealing, hex: checked when it is opened. */
  sha256: string;
  name?: string;
  width?: number;
  height?: number;
  durationS?: number;
}

/** What `meta` holds once opened. */
export interface ElementRecord {
  v: 1;
  elementId: string;
  kind: ElementKind;
  name: string;
  description: string;
  consent: ElementConsent | null;
  files: ElementFileInfo[];
}

/** An Element as the gateway stores it. */
export interface ElementRow {
  element_id: string;
  revision: number;
  master_key_id: string;
  wrapped_key: string;
  meta: string;
  files: Array<{ position: number; size: number; sha256: string }>;
  files_bytes: number;
  created_at: number;
  updated_at: number;
}

/** An opened Element. `elementKey` opens its files; keep it like the Elements key. */
export interface Element extends ElementRecord {
  revision: number;
  keyId: string;
  wrappedKey: string;
  createdAt: number;
  updatedAt: number;
  elementKey: Uint8Array;
}

export interface ElementFileDraft {
  data: Uint8Array;
  mime: string;
  name?: string;
  width?: number;
  height?: number;
  durationS?: number;
}

/** A new Element, or everything an Element should become. */
export interface ElementDraft {
  kind: ElementKind;
  name: string;
  description?: string;
  consent?: ElementConsent | null;
  files: ElementFileDraft[];
}

function invalid(message: string): KunoError {
  return new KunoError(0, "invalid_element", message);
}

function random(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** 32 lowercase hex characters: a new Element's id. */
export function newElementId(): string {
  return toHex(random(16));
}

function checkId(elementId: string): void {
  if (!ID.test(elementId)) throw invalid("An element id is 32 lowercase hex characters.");
}

// ---------------------------------------------------------------- keys

/** The Elements key for a key sync master key (32 bytes) and its `master_key_id`. */
export function deriveElementsKey(masterKey: Uint8Array, accountId: string, masterKeyId: string): ElementsKey {
  if (masterKey.length !== 32) throw invalid("A key sync master key is 32 bytes.");
  if (!ID.test(masterKeyId)) throw invalid("A master_key_id is 32 lowercase hex characters.");
  return { accountId, keyId: masterKeyId, key: hkdf(sha256, masterKey, utf8("kuno/elements/v1"), utf8(`elements-key|${accountId}`), 32) };
}

/** The Elements key as text for a program's secret store: `kwek1.<account id>.<master key id>.<base64url key>`. */
export function formatElementsKey(key: ElementsKey): string {
  return `kwek1.${key.accountId}.${key.keyId}.${b64e(key.key)}`;
}

export function parseElementsKey(text: string): ElementsKey {
  const match = TEXT_KEY.exec(text.trim());
  if (!match) throw invalid("That isn't an Elements key. It starts with kwek1. and comes from the studio's Elements page.");
  return { accountId: match[1], keyId: match[2], key: b64d(match[3]) };
}

const keyAad = (accountId: string, elementId: string) => utf8(`KVE1|kuno/elements/element-key|${accountId}|${elementId}`);

export function wrapElementKey(key: ElementsKey, elementId: string, elementKey: Uint8Array): string {
  checkId(elementId);
  if (elementKey.length !== 32) throw invalid("An element key is 32 bytes.");
  const iv = random(IV_LEN);
  return b64e(concatBytes(KEY_MAGIC, iv, gcm(key.key, iv, keyAad(key.accountId, elementId)).encrypt(elementKey)));
}

export function unwrapElementKey(key: ElementsKey, elementId: string, wrapped: string): Uint8Array {
  let raw: Uint8Array;
  try {
    raw = b64d(wrapped);
  } catch {
    throw new KunoError(0, "decrypt_failed", "This Element's key is damaged.");
  }
  if (raw.length !== WRAPPED_LEN || !KEY_MAGIC.every((b, i) => raw[i] === b)) {
    throw new KunoError(0, "decrypt_failed", "This Element's key is damaged.");
  }
  try {
    return gcm(key.key, raw.subarray(4, 4 + IV_LEN), keyAad(key.accountId, elementId)).decrypt(raw.subarray(4 + IV_LEN));
  } catch {
    throw new KunoError(0, "decrypt_failed", "This Element doesn't open with this Elements key. Your keys may have been rotated.");
  }
}

/** For a key sync rotation: the same element key, wrapped under the new Elements key. */
export function rewrapElementKey(oldKey: ElementsKey, newKey: ElementsKey, elementId: string, wrapped: string): string {
  return wrapElementKey(newKey, elementId, unwrapElementKey(oldKey, elementId, wrapped));
}

// ---------------------------------------------------------------- records and files

const printable = (text: string) => !/[ -]/.test(text);

/** What `elementDraftProblems` reads about each file: its type, size before sealing and, for a voice, its length. */
export interface ElementFileCheck {
  mime: string;
  size: number;
  durationS?: number;
}

/** Problems with a draft, as sentences; empty when it can be saved. The studio shows these next to the form. */
export function elementDraftProblems(draft: Omit<ElementDraft, "files"> & { files: ElementFileCheck[] }): string[] {
  const out: string[] = [];
  const name = draft.name?.trim() ?? "";
  if (!ELEMENT_KINDS.includes(draft.kind)) out.push(`An Element is one of: ${ELEMENT_KINDS.join(", ")}.`);
  if (!name) out.push("Give it a name.");
  else if ([...name].length > ELEMENT_LIMITS.maxNameChars || !printable(name)) out.push(`A name is at most ${ELEMENT_LIMITS.maxNameChars} characters, on one line.`);
  if ([...(draft.description ?? "")].length > ELEMENT_LIMITS.maxDescriptionChars) {
    out.push(`A description is at most ${ELEMENT_LIMITS.maxDescriptionChars.toLocaleString("en-US")} characters.`);
  }
  const files = draft.files ?? [];
  if (draft.kind === "voice") {
    if (files.length !== 1) out.push("A voice is one audio clip.");
    else if (!(ELEMENT_AUDIO_TYPES as readonly string[]).includes(files[0].mime)) out.push("A voice clip is WAV, MP3, Ogg or FLAC.");
    else if ((files[0].durationS ?? 0) > ELEMENT_LIMITS.maxVoiceSeconds) out.push(`A voice clip is at most ${ELEMENT_LIMITS.maxVoiceSeconds} seconds.`);
  } else {
    if (files.length < 1 || files.length > ELEMENT_LIMITS.maxImages) out.push(`Add 1 to ${ELEMENT_LIMITS.maxImages} images.`);
    if (files.some((f) => !(ELEMENT_IMAGE_TYPES as readonly string[]).includes(f.mime))) out.push("Images are PNG, JPEG or WebP.");
  }
  if (files.some((f) => f.size > ELEMENT_LIMITS.maxFileBytes)) out.push("Each file is at most 15 MB.");
  const consent = draft.consent;
  if (consent) {
    if (draft.kind !== "character" && draft.kind !== "voice") out.push("Only characters and voices carry a consent record.");
    const subject = consent.subject?.trim() ?? "";
    if (!subject || [...subject].length > ELEMENT_LIMITS.maxConsentChars || !printable(subject)) out.push("Say who gave consent.");
    if (consent.relationship !== "self" && consent.relationship !== "permission") out.push("Say whether this is you or someone who gave you permission.");
    if (!/^\d{4}-\d{2}-\d{2}$/.test(consent.grantedOn ?? "")) out.push("Say when consent was given.");
    if ([...(consent.use ?? "")].length > ELEMENT_LIMITS.maxConsentChars) out.push(`Say what they agreed to in at most ${ELEMENT_LIMITS.maxConsentChars} characters.`);
    if (typeof consent.affirmedAt !== "number") out.push("Confirm the consent record.");
  }
  return out;
}

function checkDraft(draft: Omit<ElementDraft, "files">, files: ElementFileCheck[]): void {
  const problems = elementDraftProblems({ ...draft, files });
  if (problems.length) throw invalid(problems.join(" "));
}

function fileInfo(file: ElementFileDraft): ElementFileInfo {
  const info: ElementFileInfo = { mime: file.mime, size: file.data.length, sha256: toHex(sha256(file.data)) };
  if (file.name) info.name = file.name.slice(0, 200);
  if (file.width) info.width = file.width;
  if (file.height) info.height = file.height;
  if (file.durationS) info.durationS = file.durationS;
  return info;
}

/** The record for a draft, with each file's size and digest filled in. */
export function elementRecord(elementId: string, draft: Omit<ElementDraft, "files">, files: ElementFileInfo[]): ElementRecord {
  checkId(elementId);
  return {
    v: 1,
    elementId,
    kind: draft.kind,
    name: draft.name.trim(),
    description: (draft.description ?? "").trim(),
    consent: draft.consent ?? null,
    files,
  };
}

export function sealElementRecord(elementKey: Uint8Array, record: ElementRecord): string {
  const json = utf8(JSON.stringify(record));
  if (json.length + 5 > META_MAX_PADDED) throw invalid("This Element's details are too long to store. Shorten the description.");
  return b64e(encryptBlob(elementKey, `element/${record.elementId}/meta`, padPayload(json)));
}

export function openElementRecord(elementKey: Uint8Array, elementId: string, meta: string): ElementRecord {
  let record: ElementRecord;
  try {
    record = JSON.parse(new TextDecoder().decode(unpadPayload(decryptBlob(elementKey, `element/${elementId}/meta`, b64d(meta))))) as ElementRecord;
  } catch {
    throw new KunoError(0, "decrypt_failed", "This Element's details didn't open with its key.");
  }
  if (record?.v !== 1 || record.elementId !== elementId || !ELEMENT_KINDS.includes(record.kind) || !Array.isArray(record.files)) {
    throw new KunoError(0, "integrity", "This Element's details are malformed.");
  }
  return record;
}

export function sealElementFile(elementKey: Uint8Array, elementId: string, position: number, data: Uint8Array): Uint8Array {
  return encryptBlob(elementKey, `element/${elementId}/file/${position}`, data);
}

/** Opens a sealed file and checks it is the one the record lists. */
export function openElementFile(elementKey: Uint8Array, elementId: string, position: number, sealed: Uint8Array, info?: ElementFileInfo): Uint8Array {
  let data: Uint8Array;
  try {
    data = decryptBlob(elementKey, `element/${elementId}/file/${position}`, sealed);
  } catch {
    throw new KunoError(0, "decrypt_failed", "This Element's file didn't open with its key.");
  }
  if (info && toHex(sha256(data)) !== info.sha256) {
    throw new KunoError(0, "integrity", "This Element's file isn't the one its details list.");
  }
  return data;
}

/** Everything a write sends, sealed: a new element key when there are files, the record, and the sealed files. */
export function sealElement(
  key: ElementsKey,
  elementId: string,
  draft: ElementDraft,
  opts: { elementKey?: Uint8Array; keepFiles?: ElementFileInfo[] } = {},
): { elementKey: Uint8Array; wrappedKey: string | null; meta: string; files: Uint8Array[]; record: ElementRecord } {
  checkId(elementId);
  const keep = opts.keepFiles;
  if (keep) {
    // The files stay sealed under the key they have, so the record is sealed under it too.
    if (!opts.elementKey) throw invalid("Keeping an Element's files needs its element key.");
    checkDraft(draft, keep);
    const record = elementRecord(elementId, draft, keep);
    return { elementKey: opts.elementKey, wrappedKey: null, meta: sealElementRecord(opts.elementKey, record), files: [], record };
  }
  checkDraft(draft, draft.files.map((f) => ({ mime: f.mime, size: f.data.length, durationS: f.durationS })));
  const elementKey = random(32);
  const record = elementRecord(elementId, draft, draft.files.map(fileInfo));
  return {
    elementKey,
    wrappedKey: wrapElementKey(key, elementId, elementKey),
    meta: sealElementRecord(elementKey, record),
    files: draft.files.map((file, position) => sealElementFile(elementKey, elementId, position, file.data)),
    record,
  };
}

/** Opens a stored Element with the Elements key. */
export function openElement(key: ElementsKey, row: ElementRow): Element {
  const elementKey = unwrapElementKey(key, row.element_id, row.wrapped_key);
  const record = openElementRecord(elementKey, row.element_id, row.meta);
  if (record.files.length !== row.files.length) throw new KunoError(0, "integrity", "This Element's files don't match its details.");
  return {
    ...record,
    revision: row.revision,
    keyId: row.master_key_id,
    wrappedKey: row.wrapped_key,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    elementKey,
  };
}

// ---------------------------------------------------------------- using an Element

/** The line an Element adds to a prompt: "Mara: a woman in her 60s …", or its name alone. */
export function elementPromptLine(element: Pick<ElementRecord, "name" | "description">): string {
  const name = element.name.trim();
  const description = element.description.trim().replace(/\s+/g, " ");
  return description ? `${name}: ${description}` : name;
}

/** The prompt with each Element's line added on its own line, unless the prompt already holds it. */
export function addElementLines(prompt: string, elements: Array<Pick<ElementRecord, "name" | "description">>): string {
  let out = prompt.trimEnd();
  for (const element of elements) {
    const line = elementPromptLine(element);
    if (line && !out.includes(line)) out = out ? `${out}\n${line}` : line;
  }
  return out;
}

/** Whether a consent record stops the Element being used. */
export function consentWithdrawn(element: Pick<ElementRecord, "consent">): boolean {
  return Boolean(element.consent?.withdrawnAt);
}

/**
 * The roles this Element's files can fill on a profile: images as first or last frames and keyframes where the profile
 * has those modes, or as reference images; a voice clip as reference audio. Empty means the description only.
 */
export function elementRoles(element: Pick<ElementRecord, "kind">, profile: Pick<ModelProfile, "modes" | "limits">): InputRole[] {
  const max = (role: InputRole) => profile.limits.max_inputs?.[role] ?? 0;
  const has = (...modes: ModelProfile["modes"]) => modes.some((m) => profile.modes.includes(m));
  if (element.kind === "voice") return has("reference_to_video") && max("reference_audio") > 0 ? ["reference_audio"] : [];
  const roles: InputRole[] = [];
  if (has("image_to_video", "first_last_frame") && max("first_frame") > 0) roles.push("first_frame");
  if (has("last_frame", "first_last_frame") && max("last_frame") > 0) roles.push("last_frame");
  if (has("keyframes") && max("keyframe") > 0) roles.push("keyframe");
  if (has("reference_to_video") && max("reference_image") > 0) roles.push("reference_image");
  return roles;
}

/** One Element in a request: which file, as what. Leave `role` out to add only its description. */
export interface ElementUse {
  element: Element;
  role?: InputRole;
  /** Which file (by position), or "all" for every image as reference images. Default 0. */
  file?: number | "all";
  /** A keyframe's time, in seconds. */
  timeS?: number;
}

export function checkElementUse(use: ElementUse, storyboard: boolean): number[] {
  const { element, role } = use;
  if (consentWithdrawn(element)) throw new KunoError(0, "consent_withdrawn", `Consent for ${element.name} was withdrawn, so it can't be used in new videos.`);
  if (!role) return [];
  if (storyboard) throw invalid("A storyboard uses an Element's description only: its shots take no images or audio.");
  const allowed = element.kind === "voice" ? ELEMENT_VOICE_ROLES : ELEMENT_IMAGE_ROLES;
  if (!allowed.includes(role)) {
    throw invalid(element.kind === "voice" ? "A voice is used as reference audio." : `An image Element can't be used as ${role}.`);
  }
  const positions = use.file === "all" ? element.files.map((_, i) => i) : [use.file ?? 0];
  if (use.file === "all" && role !== "reference_image") throw invalid('file: "all" is for reference images.');
  if (positions.some((p) => !Number.isInteger(p) || p < 0 || p >= element.files.length)) throw invalid(`${element.name} has no such file.`);
  return positions;
}
