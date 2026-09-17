"""Elements: reusable characters, products, locations, styles and voices, encrypted on this machine before they reach
KunoWorld. The gateway's half is platform/gateway/src/kuno_gateway/elements.py; the contract is platform/gateway/ELEMENTS.md.
This is a port of the JavaScript SDK's `elements.ts`, byte for byte: an Element sealed here opens there and the other way
round, and the same key, draft and randomness seal to the same bytes in both.

Keys:

* **Elements key.** HKDF-SHA256 of the account's key sync master key, salt "kuno/elements/v1", info
  "elements-key|<account_id>". The website derives it from the master key its browser unlocked; a program gets it from
  the studio as text (`kwek1.<account id>.<master key id>.<key>`, see `parse_elements_key`). It opens Elements only:
  HKDF is one-way, so it can't open the master key or any video key. A key sync rotation replaces it.
* **Element key.** 32 random bytes per Element, new whenever its files are uploaded. `wrapped_key` is base64url of
  "KVE1" | 12-byte IV | AES-256-GCM(element key) with its 16-byte tag, under the Elements key, with associated data
  "KVE1|kuno/elements/element-key|<account_id>|<element_id>".

Sealed with the element key, as `kuno_protocol.blobs` version 2 blobs, so each size is padded:

* the record (`meta`): kind, name, description, consent and each file's type, size and SHA-256, as JSON framed and
  padded like a sealed request (`pad_payload`: a power of two from 4 KiB, here at most 16 KiB), label
  "element/<element_id>/meta". The JSON is written as JavaScript's `JSON.stringify` writes it (`_js_json`), with the
  studio's key order, so a record's padded size doesn't say which SDK wrote it;
* each file: label "element/<element_id>/file/<position>".

Using an Element changes nothing about a job: its images and voice clip become ordinary inputs (sealed again to the
enclave for a Private job, uploaded as they are for a Standard one) and its description joins the prompt.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Literal, Mapping, Sequence
from urllib.parse import quote

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from kuno_protocol.blobs import decrypt_blob, encrypt_blob
from kuno_protocol.canonical import b64d, b64e, sha256_hex
from kuno_protocol.crypto import DecryptionError
from kuno_protocol.media import sniff_mime
from kuno_protocol.profiles import InputRole, Mode, ModelProfile
from kuno_protocol.sealed_payload import pad_payload, unpad_payload

from .client import Input, KunoError, Source

if TYPE_CHECKING:
    from .client import KunoClient

ElementKind = Literal["character", "product", "location", "style", "voice"]

ELEMENT_KINDS: tuple[ElementKind, ...] = ("character", "product", "location", "style", "voice")

# What every write affirms (the gateway refuses a write without `affirm_rules`). Sexual content is banned platform-wide.
ELEMENT_RULES = (
    "No public figures and no one under 18. A real person must be you, or must have given you permission. Sexual content is banned."
)


@dataclass(frozen=True)
class ElementLimits:
    max_elements: int = 200
    max_images: int = 4
    # Per file before sealing; sealed and padded it stays under the gateway's 16 MiB.
    max_file_bytes: int = 15 * 1024 * 1024
    max_account_bytes: int = 2 * 1024 * 1024 * 1024
    max_name_chars: int = 80
    max_description_chars: int = 1000
    max_consent_chars: int = 200
    # A voice clip's longest length; 5 to 15 seconds works best.
    max_voice_seconds: float = 30


ELEMENT_LIMITS = ElementLimits()

ELEMENT_IMAGE_TYPES = ("image/png", "image/jpeg", "image/webp")
ELEMENT_AUDIO_TYPES = ("audio/wav", "audio/mpeg", "audio/ogg", "audio/flac")

# The input roles an Element's files can fill. Its description works with every model.
ELEMENT_IMAGE_ROLES = (InputRole.FIRST_FRAME, InputRole.LAST_FRAME, InputRole.KEYFRAME, InputRole.REFERENCE_IMAGE)
ELEMENT_VOICE_ROLES = (InputRole.REFERENCE_AUDIO,)

_KEY_MAGIC = b"KVE1"
_IV_LEN = 12
_WRAPPED_LEN = 4 + _IV_LEN + 32 + 16
_META_MAX_PADDED = 16 * 1024
_ID = re.compile(r"[0-9a-f]{32}")
_TEXT_KEY = re.compile(r"kwek1\.([A-Za-z0-9_-]{1,64})\.([0-9a-f]{32})\.([A-Za-z0-9_-]{43})")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
# JavaScript's whitespace, which `String.prototype.trim` removes and `\s` matches: not the same set as Python's.
_JS_SPACE = "\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
_JS_TRIM = re.compile(f"^[{_JS_SPACE}]+|[{_JS_SPACE}]+\\Z")
_JS_SPACES = re.compile(f"[{_JS_SPACE}]+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class ElementsKey:
    """The key that opens an account's Elements, and the key sync generation it came from. `key_id` is the vault's
    `master_key_id` when the key was derived: writes name it, and after a rotation it is stale."""

    account_id: str
    key_id: str
    key: bytes = field(repr=False)


@dataclass(frozen=True)
class ElementConsent:
    """A real person's permission to appear as a character or a voice, sealed with the rest of the record.

    `subject` names the person as they'd name themselves; `relationship` is `"self"` (the uploader is this person) or
    `"permission"` (this person gave the uploader permission); `granted_on` is when, `YYYY-MM-DD`; `use` is what they
    agreed to. `affirmed_at` (Unix seconds) is when the uploader affirmed the record, now by default. `withdrawn_at` is
    set when the person withdrew it: the Element can't be used in new videos."""

    subject: str
    relationship: Literal["self", "permission"]
    granted_on: str
    use: str = ""
    affirmed_at: float = field(default_factory=lambda: int(time.time()))
    withdrawn_at: float | None = None


@dataclass(frozen=True)
class ElementFileInfo:
    """One file as the record lists it: its type, its size and SHA-256 (hex) before sealing, checked when it is opened."""

    mime: str
    size: int
    sha256: str
    name: str | None = None
    width: int | None = None
    height: int | None = None
    duration_s: float | None = None


@dataclass(frozen=True)
class ElementFile:
    """A file for a new Element or a replacement: PNG, JPEG or WebP pictures, or one WAV, MP3, Ogg or FLAC voice clip."""

    data: bytes = field(repr=False)
    mime: str
    name: str | None = None
    width: int | None = None
    height: int | None = None
    duration_s: float | None = None

    @classmethod
    def load(cls, source: Source, *, name: str | None = None, **extra: Any) -> ElementFile:
        """A file from a path or bytes, its type read from the bytes. A path's file name is kept as `name`."""
        data = source if isinstance(source, bytes) else Path(source).read_bytes()
        mime = sniff_mime(data)
        if mime is None:
            raise KunoError(0, "unsupported_media", "Could not recognize the file type.")
        if name is None and not isinstance(source, bytes):
            name = Path(source).name
        return cls(data=data, mime=mime, name=name, **extra)


@dataclass(frozen=True)
class ElementRecord:
    """What `meta` holds once opened."""

    element_id: str
    kind: ElementKind
    name: str
    description: str
    consent: ElementConsent | None
    files: tuple[ElementFileInfo, ...]
    v: int = 1


@dataclass(frozen=True)
class Element:
    """An opened Element. `element_key` opens its files: keep it like the Elements key."""

    element_id: str
    kind: ElementKind
    name: str
    description: str
    consent: ElementConsent | None
    files: tuple[ElementFileInfo, ...]
    revision: int
    key_id: str
    wrapped_key: str = field(repr=False)
    created_at: float
    updated_at: float
    element_key: bytes = field(repr=False)

    @property
    def record(self) -> ElementRecord:
        return ElementRecord(self.element_id, self.kind, self.name, self.description, self.consent, self.files)


@dataclass(frozen=True)
class SealedElement:
    """Everything a write sends: the element key (kept here), its wrapped form (None when files are kept), the sealed record
    and the sealed files, in order."""

    element_key: bytes = field(repr=False)
    wrapped_key: str | None
    meta: str
    files: list[bytes] = field(repr=False)
    record: ElementRecord


@dataclass(frozen=True)
class UnreadableElement:
    """A stored Element that didn't open: `key_rotated` (made under another key sync generation), `decrypt_failed` or
    `integrity`."""

    element_id: str
    revision: int
    reason: str


@dataclass(frozen=True)
class ElementList:
    """`client.elements.list`: the Elements this key opens, any it can't, the vault's current `master_key_id` (None while
    key sync is off; a key with another `key_id` is stale) and the sealed bytes stored."""

    elements: list[Element]
    unreadable: list[UnreadableElement]
    key_id: str | None
    stored_bytes: int


@dataclass(frozen=True)
class ElementUse:
    """One Element in a request: which file, as what. Leave `role` out to add only its description. `file` is a position,
    or `"all"` for every image as reference images. A keyframe needs its `time_s`."""

    element: Element
    role: InputRole | str | None = None
    file: int | Literal["all"] = 0
    time_s: float | None = None


def _invalid(message: str) -> KunoError:
    return KunoError(0, "invalid_element", message)


def new_element_id() -> str:
    """32 lowercase hex characters: a new Element's id."""
    return os.urandom(16).hex()


def _check_id(element_id: str) -> None:
    if not isinstance(element_id, str) or not _ID.fullmatch(element_id):
        raise _invalid("An element id is 32 lowercase hex characters.")


# ---------------------------------------------------------------- keys


def derive_elements_key(master_key: bytes, account_id: str, master_key_id: str) -> ElementsKey:
    """The Elements key for a key sync master key (32 bytes) and its `master_key_id`."""
    if len(master_key) != 32:
        raise _invalid("A key sync master key is 32 bytes.")
    if not isinstance(master_key_id, str) or not _ID.fullmatch(master_key_id):
        raise _invalid("A master_key_id is 32 lowercase hex characters.")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"kuno/elements/v1", info=f"elements-key|{account_id}".encode())
    return ElementsKey(account_id, master_key_id, hkdf.derive(bytes(master_key)))


def format_elements_key(key: ElementsKey) -> str:
    """The Elements key as text for a program's secret store: `kwek1.<account id>.<master key id>.<base64url key>`."""
    return f"kwek1.{key.account_id}.{key.key_id}.{b64e(key.key)}"


def parse_elements_key(text: str) -> ElementsKey:
    """An Elements key from its text, as the studio's Elements page gives it."""
    match = _TEXT_KEY.fullmatch(_js_trim(text)) if isinstance(text, str) else None
    if not match:
        raise _invalid("That isn't an Elements key. It starts with kwek1. and comes from the studio's Elements page.")
    return ElementsKey(match[1], match[2], b64d(match[3]))


def _key_aad(account_id: str, element_id: str) -> bytes:
    return f"KVE1|kuno/elements/element-key|{account_id}|{element_id}".encode()


def wrap_element_key(key: ElementsKey, element_id: str, element_key: bytes) -> str:
    _check_id(element_id)
    if len(element_key) != 32:
        raise _invalid("An element key is 32 bytes.")
    iv = os.urandom(_IV_LEN)
    return b64e(_KEY_MAGIC + iv + AESGCM(key.key).encrypt(iv, bytes(element_key), _key_aad(key.account_id, element_id)))


def unwrap_element_key(key: ElementsKey, element_id: str, wrapped: str) -> bytes:
    damaged = KunoError(0, "decrypt_failed", "This Element's key is damaged.")
    try:
        raw = b64d(wrapped)
    except (ValueError, TypeError):
        raise damaged from None
    if len(raw) != _WRAPPED_LEN or raw[:4] != _KEY_MAGIC:
        raise damaged
    try:
        return AESGCM(key.key).decrypt(raw[4 : 4 + _IV_LEN], raw[4 + _IV_LEN :], _key_aad(key.account_id, element_id))
    except (InvalidTag, ValueError):
        raise KunoError(
            0, "decrypt_failed", "This Element doesn't open with this Elements key. Your keys may have been rotated."
        ) from None


def rewrap_element_key(old_key: ElementsKey, new_key: ElementsKey, element_id: str, wrapped: str) -> str:
    """For a key sync rotation: the same element key, wrapped under the new Elements key."""
    return wrap_element_key(new_key, element_id, unwrap_element_key(old_key, element_id, wrapped))


# ---------------------------------------------------------------- JSON as JavaScript writes it


def _js_trim(text: str) -> str:
    return _JS_TRIM.sub("", text)


def _js_slice(text: str, units: int) -> str:
    """`text.slice(0, units)`: JavaScript counts UTF-16 code units, and may cut a pair in half."""
    encoded = text.encode("utf-16-le", "surrogatepass")
    return text if len(encoded) <= 2 * units else encoded[: 2 * units].decode("utf-16-le", "surrogatepass")


def _js_truthy(value: Any) -> bool:
    return bool(value) and not (isinstance(value, float) and math.isnan(value))


def _js_number(value: int | float) -> str:
    """A number as `JSON.stringify` writes it (ECMAScript Number::toString): 5.0 is "5", 1e-7 is "1e-7"."""
    if isinstance(value, int):
        return str(value)
    if not math.isfinite(value):
        return "null"
    if value == 0:
        return "0"
    mantissa, _, exponent = repr(abs(value)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = (whole + fraction).lstrip("0")
    point = len(whole) + int(exponent or 0) - (len(whole + fraction) - len(digits))
    digits = digits.rstrip("0")
    count = len(digits)
    if count <= point <= 21:
        text = digits + "0" * (point - count)
    elif 0 < point <= 21:
        text = f"{digits[:point]}.{digits[point:]}"
    elif -6 < point <= 0:
        text = f"0.{'0' * -point}{digits}"
    else:
        power = point - 1
        text = f"{digits[0]}{'.' + digits[1:] if count > 1 else ''}e{'+' if power >= 0 else '-'}{abs(power)}"
    return ("-" if value < 0 else "") + text


_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def _js_json(value: Any) -> str:
    """`JSON.stringify(value)` for the JSON values a record holds, keys in the order given."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _js_number(value)
    if isinstance(value, str):
        # Python escapes as JavaScript does (short forms, then \u00xx), except a lone surrogate, which JavaScript escapes.
        return _LONE_SURROGATE.sub(lambda m: f"\\u{ord(m.group()):04x}", json.dumps(value, ensure_ascii=False))
    if isinstance(value, Mapping):
        return "{" + ",".join(f"{_js_json(str(k))}:{_js_json(v)}" for k, v in value.items()) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_js_json(item) for item in value) + "]"
    raise TypeError(f"{type(value).__name__} is not JSON")


def _consent_json(consent: ElementConsent) -> dict[str, Any]:
    # The studio's order, with withdrawnAt written null until consent is withdrawn.
    return {
        "subject": consent.subject,
        "relationship": consent.relationship,
        "grantedOn": consent.granted_on,
        "use": consent.use,
        "affirmedAt": consent.affirmed_at,
        "withdrawnAt": consent.withdrawn_at,
    }


def _file_json(info: ElementFileInfo) -> dict[str, Any]:
    data: dict[str, Any] = {"mime": info.mime, "size": info.size, "sha256": info.sha256}
    for key, value in (("name", info.name), ("width", info.width), ("height", info.height), ("durationS", info.duration_s)):
        if _js_truthy(value):
            data[key] = value
    return data


def record_json(record: ElementRecord) -> bytes:
    """A record's JSON, exactly as the JavaScript SDK writes it for the same record."""
    return _js_json({
        "v": record.v,
        "elementId": record.element_id,
        "kind": record.kind,
        "name": record.name,
        "description": record.description,
        "consent": None if record.consent is None else _consent_json(record.consent),
        "files": [_file_json(info) for info in record.files],
    }).encode()


def _read_consent(data: Any) -> ElementConsent | None:
    if data is None:
        return None
    if not isinstance(data, Mapping):
        raise KunoError(0, "integrity", "This Element's details are malformed.")
    return ElementConsent(
        subject=data.get("subject"), relationship=data.get("relationship"), granted_on=data.get("grantedOn"),
        use=data.get("use", ""), affirmed_at=data.get("affirmedAt"), withdrawn_at=data.get("withdrawnAt"),
    )


def _read_file_info(data: Any) -> ElementFileInfo:
    if not isinstance(data, Mapping):
        raise KunoError(0, "integrity", "This Element's details are malformed.")
    return ElementFileInfo(
        mime=data.get("mime"), size=data.get("size"), sha256=data.get("sha256"), name=data.get("name"),
        width=data.get("width"), height=data.get("height"), duration_s=data.get("durationS"),
    )


# ---------------------------------------------------------------- records and files


def _size(file: Any) -> int:
    size = getattr(file, "size", None)
    return len(file.data) if size is None else size


def element_draft_problems(
    *,
    kind: str,
    name: str,
    description: str | None = "",
    consent: ElementConsent | None = None,
    files: Sequence[ElementFile | ElementFileInfo] = (),
) -> list[str]:
    """Problems with a draft, as sentences; empty when it can be saved. The same sentences the studio shows next to its
    form. `files` are `ElementFile`s, or `ElementFileInfo`s when the files are kept."""
    out: list[str] = []
    limits = ELEMENT_LIMITS
    trimmed = _js_trim(name) if isinstance(name, str) else ""
    if kind not in ELEMENT_KINDS:
        out.append(f"An Element is one of: {', '.join(ELEMENT_KINDS)}.")
    if not trimmed:
        out.append("Give it a name.")
    elif len(trimmed) > limits.max_name_chars or _CONTROL.search(trimmed):
        out.append(f"A name is at most {limits.max_name_chars} characters, on one line.")
    if len(description or "") > limits.max_description_chars:
        out.append(f"A description is at most {limits.max_description_chars:,} characters.")
    files = list(files or ())
    if kind == "voice":
        if len(files) != 1:
            out.append("A voice is one audio clip.")
        elif files[0].mime not in ELEMENT_AUDIO_TYPES:
            out.append("A voice clip is WAV, MP3, Ogg or FLAC.")
        elif (files[0].duration_s or 0) > limits.max_voice_seconds:
            out.append(f"A voice clip is at most {limits.max_voice_seconds:g} seconds.")
    else:
        if not 1 <= len(files) <= limits.max_images:
            out.append(f"Add 1 to {limits.max_images} images.")
        if any(f.mime not in ELEMENT_IMAGE_TYPES for f in files):
            out.append("Images are PNG, JPEG or WebP.")
    if any(_size(f) > limits.max_file_bytes for f in files):
        out.append("Each file is at most 15 MB.")
    if consent:
        if kind not in ("character", "voice"):
            out.append("Only characters and voices carry a consent record.")
        subject = _js_trim(consent.subject) if isinstance(consent.subject, str) else ""
        if not subject or len(subject) > limits.max_consent_chars or _CONTROL.search(subject):
            out.append("Say who gave consent.")
        if consent.relationship not in ("self", "permission"):
            out.append("Say whether this is you or someone who gave you permission.")
        if not isinstance(consent.granted_on, str) or not _DATE.fullmatch(consent.granted_on):
            out.append("Say when consent was given.")
        if len(consent.use or "") > limits.max_consent_chars:
            out.append(f"Say what they agreed to in at most {limits.max_consent_chars} characters.")
        if isinstance(consent.affirmed_at, bool) or not isinstance(consent.affirmed_at, (int, float)):
            out.append("Confirm the consent record.")
    return out


def _file_info(file: ElementFile) -> ElementFileInfo:
    return ElementFileInfo(
        mime=file.mime, size=len(file.data), sha256=sha256_hex(file.data),
        name=_js_slice(file.name, 200) if _js_truthy(file.name) else None,
        width=file.width if _js_truthy(file.width) else None,
        height=file.height if _js_truthy(file.height) else None,
        duration_s=file.duration_s if _js_truthy(file.duration_s) else None,
    )


def element_record(
    element_id: str,
    *,
    kind: ElementKind,
    name: str,
    description: str | None = "",
    consent: ElementConsent | None = None,
    files: Sequence[ElementFileInfo] = (),
) -> ElementRecord:
    """The record for a draft whose files are already described."""
    _check_id(element_id)
    return ElementRecord(element_id, kind, _js_trim(name), _js_trim(description or ""), consent or None, tuple(files))


def seal_element_record(element_key: bytes, record: ElementRecord) -> str:
    data = record_json(record)
    if len(data) + 5 > _META_MAX_PADDED:
        raise _invalid("This Element's details are too long to store. Shorten the description.")
    return b64e(encrypt_blob(element_key, f"element/{record.element_id}/meta", pad_payload(data)))


def open_element_record(element_key: bytes, element_id: str, meta: str) -> ElementRecord:
    try:
        data = json.loads(unpad_payload(decrypt_blob(element_key, f"element/{element_id}/meta", b64d(meta))).decode("utf-8", "replace"))
    except (DecryptionError, ValueError, TypeError):
        raise KunoError(0, "decrypt_failed", "This Element's details didn't open with its key.") from None
    version = data.get("v") if isinstance(data, dict) else None
    if (
        isinstance(version, bool) or version != 1 or data.get("elementId") != element_id
        or data.get("kind") not in ELEMENT_KINDS or not isinstance(data.get("files"), list)
    ):
        raise KunoError(0, "integrity", "This Element's details are malformed.")
    return ElementRecord(
        element_id=element_id, kind=data["kind"], name=data.get("name"), description=data.get("description"),
        consent=_read_consent(data.get("consent")), files=tuple(_read_file_info(f) for f in data["files"]),
    )


def seal_element_file(element_key: bytes, element_id: str, position: int, data: bytes) -> bytes:
    return encrypt_blob(element_key, f"element/{element_id}/file/{position}", data)


def open_element_file(element_key: bytes, element_id: str, position: int, sealed: bytes, info: ElementFileInfo | None = None) -> bytes:
    """Opens a sealed file and checks it is the one the record lists."""
    try:
        data = decrypt_blob(element_key, f"element/{element_id}/file/{position}", sealed)
    except DecryptionError:
        raise KunoError(0, "decrypt_failed", "This Element's file didn't open with its key.") from None
    if info is not None and sha256_hex(data) != info.sha256:
        raise KunoError(0, "integrity", "This Element's file isn't the one its details list.")
    return data


def seal_element(
    key: ElementsKey,
    element_id: str,
    *,
    kind: ElementKind,
    name: str,
    description: str | None = "",
    consent: ElementConsent | None = None,
    files: Sequence[ElementFile] = (),
    element_key: bytes | None = None,
    keep_files: Sequence[ElementFileInfo] | None = None,
) -> SealedElement:
    """Everything a write sends, sealed: a new element key when there are files, the record, and the sealed files. With
    `keep_files` (the Element's own) the files stay sealed under the key they have, `element_key`, and so does the record."""
    _check_id(element_id)
    draft = {"kind": kind, "name": name, "description": description, "consent": consent}
    if keep_files is not None:
        if element_key is None:
            raise _invalid("Keeping an Element's files needs its element key.")
        _check_draft(draft, keep_files)
        record = element_record(element_id, files=keep_files, **draft)
        return SealedElement(element_key, None, seal_element_record(element_key, record), [], record)
    files = list(files)
    _check_draft(draft, files)
    # The order the JavaScript SDK draws its randomness in: the element key, the wrap's IV, the record's and each file's nonce prefix.
    new_key = os.urandom(32)
    record = element_record(element_id, files=[_file_info(f) for f in files], **draft)
    return SealedElement(
        element_key=new_key,
        wrapped_key=wrap_element_key(key, element_id, new_key),
        meta=seal_element_record(new_key, record),
        files=[seal_element_file(new_key, element_id, position, f.data) for position, f in enumerate(files)],
        record=record,
    )


def _check_draft(draft: Mapping[str, Any], files: Sequence[ElementFile | ElementFileInfo]) -> None:
    problems = element_draft_problems(files=files, **draft)
    if problems:
        raise _invalid(" ".join(problems))


def open_element(key: ElementsKey, row: Mapping[str, Any]) -> Element:
    """Opens a stored Element (a row as the gateway returns it) with the Elements key."""
    element_key = unwrap_element_key(key, row["element_id"], row["wrapped_key"])
    record = open_element_record(element_key, row["element_id"], row["meta"])
    if len(record.files) != len(row.get("files") or ()):
        raise KunoError(0, "integrity", "This Element's files don't match its details.")
    return Element(
        element_id=record.element_id, kind=record.kind, name=record.name, description=record.description,
        consent=record.consent, files=record.files, revision=row["revision"], key_id=row["master_key_id"],
        wrapped_key=row["wrapped_key"], created_at=row.get("created_at"), updated_at=row.get("updated_at"),
        element_key=element_key,
    )


# ---------------------------------------------------------------- using an Element


def element_prompt_line(element: Element | ElementRecord) -> str:
    """The line an Element adds to a prompt: "Mara: a woman in her 60s ...", or its name alone."""
    name = _js_trim(element.name)
    description = _JS_SPACES.sub(" ", _js_trim(element.description or ""))
    return f"{name}: {description}" if description else name


def add_element_lines(prompt: str, elements: Iterable[Element | ElementRecord]) -> str:
    """The prompt with each Element's line added on its own line, unless the prompt already holds it."""
    out = re.sub(f"[{_JS_SPACE}]+\\Z", "", prompt or "")
    for element in elements:
        line = element_prompt_line(element)
        if line and line not in out:
            out = f"{out}\n{line}" if out else line
    return out


def consent_withdrawn(element: Element | ElementRecord) -> bool:
    """Whether a consent record stops the Element being used."""
    return element.consent is not None and _js_truthy(element.consent.withdrawn_at)


def element_roles(element: Element | ElementRecord, profile: ModelProfile) -> list[InputRole]:
    """The roles this Element's files can fill on a profile: images as first or last frames and keyframes where the
    profile has those modes, or as reference images; a voice clip as reference audio. Empty means the description only."""
    most = profile.limits.max_inputs

    def has(*modes: Mode) -> bool:
        return any(mode in profile.modes for mode in modes)

    if element.kind == "voice":
        return [InputRole.REFERENCE_AUDIO] if has(Mode.REFERENCE_TO_VIDEO) and most.get(InputRole.REFERENCE_AUDIO, 0) > 0 else []
    roles = []
    if has(Mode.IMAGE_TO_VIDEO, Mode.FIRST_LAST_FRAME) and most.get(InputRole.FIRST_FRAME, 0) > 0:
        roles.append(InputRole.FIRST_FRAME)
    if has(Mode.LAST_FRAME, Mode.FIRST_LAST_FRAME) and most.get(InputRole.LAST_FRAME, 0) > 0:
        roles.append(InputRole.LAST_FRAME)
    if has(Mode.KEYFRAMES) and most.get(InputRole.KEYFRAME, 0) > 0:
        roles.append(InputRole.KEYFRAME)
    if has(Mode.REFERENCE_TO_VIDEO) and most.get(InputRole.REFERENCE_IMAGE, 0) > 0:
        roles.append(InputRole.REFERENCE_IMAGE)
    return roles


def check_element_use(use: ElementUse, storyboard: bool) -> list[int]:
    """The file positions a use takes, after the checks that need nothing downloaded. Raises `consent_withdrawn` or
    `invalid_element`."""
    element = use.element
    if consent_withdrawn(element):
        raise KunoError(0, "consent_withdrawn", f"Consent for {element.name} was withdrawn, so it can't be used in new videos.")
    if not use.role:
        return []
    if storyboard:
        raise _invalid("A storyboard uses an Element's description only: its shots take no images or audio.")
    voice = element.kind == "voice"
    try:
        role = InputRole(use.role)
    except ValueError:
        role = None
    if role not in (ELEMENT_VOICE_ROLES if voice else ELEMENT_IMAGE_ROLES):
        shown = role.value if role is not None else use.role
        raise _invalid("A voice is used as reference audio." if voice else f"An image Element can't be used as {shown}.")
    chosen = 0 if use.file is None else use.file
    if chosen == "all" and role is not InputRole.REFERENCE_IMAGE:
        raise _invalid('file="all" is for reference images.')
    positions = list(range(len(element.files))) if chosen == "all" else [chosen]
    if any(isinstance(p, bool) or not isinstance(p, int) or not 0 <= p < len(element.files) for p in positions):
        raise _invalid(f"{element.name} has no such file.")
    return positions


# generate()'s keyword for each role an Element's file can fill, and whether it takes one file or a list.
_GENERATE_KEYWORDS: dict[InputRole, tuple[str, bool]] = {
    InputRole.FIRST_FRAME: ("first_frame", False),
    InputRole.LAST_FRAME: ("last_frame", False),
    InputRole.KEYFRAME: ("keyframes", True),
    InputRole.REFERENCE_IMAGE: ("reference_images", True),
    InputRole.REFERENCE_AUDIO: ("reference_audio", True),
}


class Elements:
    """`client.elements`: reusable characters, products, locations, styles and voices, sealed on this machine with an
    Elements key so KunoWorld stores only ciphertext. A program reads the key from the studio's Elements page
    (`parse_elements_key`). Every call uses the client's API key."""

    def __init__(self, client: KunoClient):
        self._client = client

    def rows(self) -> tuple[list[dict[str, Any]], str | None]:
        """Every stored Element as the gateway holds it (ciphertext), and the vault's current `master_key_id`."""
        rows: list[dict[str, Any]] = []
        cursor: str | None = None
        key_id: str | None = None
        while True:
            params: dict[str, Any] = {"limit": 200}
            if cursor:
                params["cursor"] = cursor
            page = self._client._request("GET", "/v1/elements", params=params).json()
            rows.extend(page["elements"])
            key_id, cursor = page.get("master_key_id"), page.get("next_cursor")
            if not cursor:
                return rows, key_id

    def list(self, key: ElementsKey) -> ElementList:
        """The Elements this key opens. Any it can't are listed in `unreadable` with the reason."""
        rows, key_id = self.rows()
        elements, unreadable = [], []
        for row in rows:
            if row["master_key_id"] != key.key_id:
                unreadable.append(UnreadableElement(row["element_id"], row["revision"], "key_rotated"))
                continue
            try:
                elements.append(open_element(key, row))
            except (KunoError, KeyError, TypeError, ValueError) as exc:
                reason = exc.code if isinstance(exc, KunoError) else "decrypt_failed"
                unreadable.append(UnreadableElement(row["element_id"], row["revision"], reason))
        return ElementList(elements, unreadable, key_id, sum(row.get("files_bytes", 0) for row in rows))

    def get(self, key: ElementsKey, element_id: str) -> Element:
        return open_element(key, self._client._request("GET", f"/v1/elements/{quote(element_id, safe='')}").json())

    def create(
        self,
        key: ElementsKey,
        *,
        kind: ElementKind,
        name: str,
        files: Sequence[ElementFile],
        description: str = "",
        consent: ElementConsent | None = None,
        affirm_rules: bool = False,
        element_id: str | None = None,
    ) -> Element:
        """Seals a new Element here, uploads its sealed files and stores it. `affirm_rules=True` affirms `ELEMENT_RULES`,
        which every write must; without it nothing is sent (`rules_not_affirmed`)."""
        draft = {"kind": kind, "name": name, "description": description, "consent": consent}
        return self._write(key, element_id or new_element_id(), None, draft, list(files), affirm_rules)

    def update(
        self,
        key: ElementsKey,
        element: Element,
        *,
        kind: ElementKind | None = None,
        name: str | None = None,
        description: str | None = None,
        consent: ElementConsent | None | Literal["keep"] = "keep",
        files: Sequence[ElementFile] | None = None,
        affirm_rules: bool = False,
    ) -> Element:
        """Replaces an Element: what isn't given stays as `element` has it (`consent=None` removes the record). Without
        `files` its files stay, and so does its key; with them, every file is replaced under a new key. Refused with
        `element_changed` when another device changed it since `element` was read."""
        draft = {
            "kind": element.kind if kind is None else kind,
            "name": element.name if name is None else name,
            "description": element.description if description is None else description,
            "consent": element.consent if consent == "keep" else consent,
        }
        return self._write(key, element.element_id, element, draft, None if files is None else list(files), affirm_rules)

    def withdraw_consent(self, key: ElementsKey, element: Element, *, affirm_rules: bool = False, at: float | None = None) -> Element:
        """Marks the person's consent withdrawn (now, or `at`): the Element can't be used in new videos after this. Deleting
        it removes it for good."""
        if element.consent is None:
            raise _invalid(f"{element.name} has no consent record to withdraw.")
        withdrawn = ElementConsent(
            element.consent.subject, element.consent.relationship, element.consent.granted_on, element.consent.use,
            element.consent.affirmed_at, int(time.time()) if at is None else at,
        )
        return self.update(key, element, consent=withdrawn, affirm_rules=affirm_rules)

    def delete(self, element_id: str) -> None:
        """Deletes the Element, its record and its files. Deleting one that isn't there is harmless."""
        self._client._request("DELETE", f"/v1/elements/{quote(element_id, safe='')}")

    def file(self, element: Element, position: int = 0) -> bytes:
        """One file, downloaded, opened and checked against the Element's record."""
        if isinstance(position, bool) or not isinstance(position, int) or not 0 <= position < len(element.files):
            raise _invalid(f"{element.name} has no file {position}.")
        sealed = self._client._request("GET", f"/v1/elements/{quote(element.element_id, safe='')}/files/{position}").content
        return open_element_file(element.element_key, element.element_id, position, sealed, element.files[position])

    def attach(self, request: Mapping[str, Any], uses: Iterable[ElementUse | Element]) -> dict[str, Any]:
        """A request with Elements in it, as the studio's composer adds them: each Element's description added to the
        prompt (a storyboard's scene) on its own line, and its files added as inputs in the roles given. The files are
        opened here and then treated like any other input: sealed to the enclave for a Private job, uploaded as they are
        for a Standard one.

        `request` is `generate`'s keyword arguments (`{"prompt": ..., "model": ...}`): files go into `first_frame`,
        `last_frame`, `keyframes`, `reference_images` and `reference_audio`. With an `inputs` list (`prepare`,
        `submit_standard`) they are appended to it as `Input`s instead. An `Element` alone adds its description only.
        Every use is checked before any file is downloaded."""
        out = dict(request)
        if out.get("plan") is not None:
            raise KunoError(
                0, "invalid_params",
                "A plan brings its own scene: add Elements' lines to it with add_element_lines(plan.scene, elements) before rendering.",
            )
        mode = out.get("mode")
        storyboard = bool(out.get("shots")) or (mode is not None and str(getattr(mode, "value", mode)) == Mode.STORYBOARD.value)
        normalized = [use if isinstance(use, ElementUse) else ElementUse(use) for use in uses]
        planned = [(use, check_element_use(use, storyboard)) for use in normalized]
        as_inputs = "inputs" in out
        taken = {name for name, many in _GENERATE_KEYWORDS.values() if not many and out.get(name) is not None}
        for use, positions in planned:
            if not positions:
                continue
            role = InputRole(use.role)
            if role is InputRole.KEYFRAME and use.time_s is None:
                raise _invalid(f"A keyframe needs its time: ElementUse({use.element.name!r}, 'keyframe', time_s=...).")
            name, many = _GENERATE_KEYWORDS[role]
            if not as_inputs and not many:
                if name in taken or len(positions) > 1:
                    raise _invalid(f"The request already has a {role.value}.")
                taken.add(name)
        inputs = list(out.get("inputs") or ())
        for use, positions in planned:
            for position in positions:
                data = self.file(use.element, position)
                role = InputRole(use.role)
                if as_inputs:
                    inputs.append(Input.load(role, data, time_s=use.time_s))
                    continue
                name, many = _GENERATE_KEYWORDS[role]
                if not many:
                    out[name] = data
                elif role is InputRole.KEYFRAME:
                    out[name] = [*(out.get(name) or ()), (data, use.time_s)]
                else:
                    out[name] = [*(out.get(name) or ()), data]
        if as_inputs:
            out["inputs"] = inputs
        out["prompt"] = add_element_lines(out.get("prompt") or "", [use.element for use in normalized])
        return out

    def _write(
        self,
        key: ElementsKey,
        element_id: str,
        current: Element | None,
        draft: Mapping[str, Any],
        files: list[ElementFile] | None,
        affirm_rules: bool,
    ) -> Element:
        if affirm_rules is not True:
            raise KunoError(0, "rules_not_affirmed", "Affirm the Elements rules (ELEMENT_RULES) to store an Element.")
        keep = current is not None and files is None
        if keep:
            sealed = seal_element(key, element_id, element_key=current.element_key, keep_files=current.files, **draft)
        else:
            sealed = seal_element(key, element_id, files=files or [], **draft)
        blob_ids = [self._client._request("POST", "/v1/blobs", content=data).json()["blob_id"] for data in sealed.files]
        body: dict[str, Any] = {
            "master_key_id": key.key_id,
            "expected_revision": None if current is None else current.revision,
            "meta": sealed.meta,
            "affirm_rules": True,
        }
        if not keep:
            body["wrapped_key"] = sealed.wrapped_key
            body["file_blob_ids"] = blob_ids
        row = self._client._request("PUT", f"/v1/elements/{quote(element_id, safe='')}", json=body).json()
        return open_element(key, row)


__all__ = [
    "ELEMENT_AUDIO_TYPES",
    "ELEMENT_IMAGE_ROLES",
    "ELEMENT_IMAGE_TYPES",
    "ELEMENT_KINDS",
    "ELEMENT_LIMITS",
    "ELEMENT_RULES",
    "ELEMENT_VOICE_ROLES",
    "Element",
    "ElementConsent",
    "ElementFile",
    "ElementFileInfo",
    "ElementKind",
    "ElementLimits",
    "ElementList",
    "ElementRecord",
    "ElementUse",
    "Elements",
    "ElementsKey",
    "SealedElement",
    "UnreadableElement",
    "add_element_lines",
    "check_element_use",
    "consent_withdrawn",
    "derive_elements_key",
    "element_draft_problems",
    "element_prompt_line",
    "element_record",
    "element_roles",
    "format_elements_key",
    "new_element_id",
    "open_element",
    "open_element_file",
    "open_element_record",
    "parse_elements_key",
    "record_json",
    "rewrap_element_key",
    "seal_element",
    "seal_element_file",
    "seal_element_record",
    "unwrap_element_key",
    "wrap_element_key",
]
