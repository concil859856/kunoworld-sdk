"""Elements in the Python SDK (kunoworld.elements), a port of the JavaScript SDK's elements.ts: the Elements key derived from
key sync, element keys wrapped and records and files sealed and padded exactly as the JavaScript SDK seals them (the
shared vectors in data/elements_sdk_vectors.json, and a live round trip through the built JavaScript SDK when node is
here), the draft rules, and the client against a fake gateway: only ciphertext and ids sent, files kept or replaced,
rotation re-wraps, consent withdrawn, and Elements attached to a request as ordinary inputs plus prompt lines, then
sealed to the enclave or uploaded like any other input."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import uuid
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from kuno_fake_network import API_KEY, API_URL, PROFILES, FakeNetwork, detail
from kuno_protocol.blobs import blob_version, decrypt_blob
from kuno_protocol.canonical import b64d, b64e, sha256_hex
from kuno_protocol.profiles import InputRole
from kuno_protocol.sealed_payload import unpad_payload
from kunoworld import (
    ELEMENT_RULES,
    ERROR_CODES,
    ElementConsent,
    ElementFile,
    ElementUse,
    Input,
    KunoClient,
    KunoError,
    Shot,
    add_element_lines,
    consent_withdrawn,
    derive_elements_key,
    element_draft_problems,
    element_prompt_line,
    element_roles,
    format_elements_key,
    open_element,
    parse_elements_key,
    rewrap_element_key,
    seal_element,
)
from kunoworld.elements import (
    ElementFileInfo,
    open_element_file,
    open_element_record,
    record_json,
    unwrap_element_key,
    wrap_element_key,
)

DATA = Path(__file__).parent / "data"
VECTORS = json.loads((DATA / "elements_sdk_vectors.json").read_text())
JS_SDK = Path(__file__).resolve().parents[2] / "js"
ACCOUNT = "0123456789abcdef0123456789abcdef"
PNG = b"\x89PNG\r\n\x1a\n" + b"a green raincoat" * 30
WAV = b"RIFF\x00\x00\x00\x00WAVEfmt " + bytes(400)
CONSENT = ElementConsent("Mara Jones", "permission", "2026-09-01", "Videos made on KunoWorld", affirmed_at=1789600000)
MARA = dict(
    kind="character",
    name="Mara",
    description="a woman in her 60s with short silver hair and a green raincoat",
    consent=CONSENT,
    files=[ElementFile(PNG, "image/png", name="mara.png", width=512, height=512)],
)


def fresh_key(key_id: str | None = None):
    import os

    return derive_elements_key(os.urandom(32), ACCOUNT, key_id or uuid.uuid4().hex)


def refused(code: str):
    return pytest.raises(KunoError, match=rf"^{re.escape(code)}:")


class Counter:
    """The vectors' randomness: the byte stream 0, 1, 2, ..., 255, 0, ... in the order it is drawn."""

    def __init__(self) -> None:
        self.n = 0

    def __call__(self, size: int) -> bytes:
        out = bytes((self.n + i) % 256 for i in range(size))
        self.n += size
        return out


def vector_key():
    return derive_elements_key(b64d(VECTORS["master_key"]), VECTORS["account_id"], VECTORS["master_key_id"])


def vector_draft(draft: dict) -> dict:
    files = {name: b64d(data) for name, data in VECTORS["files"].items()}
    c = draft["consent"]
    return dict(
        kind=draft["kind"], name=draft["name"], description=draft["description"],
        consent=None if c is None else ElementConsent(c["subject"], c["relationship"], c["grantedOn"], c["use"], c["affirmedAt"], c["withdrawnAt"]),
        files=[
            ElementFile(files[f["file"]], f["mime"], name=f.get("name"), width=f.get("width"), height=f.get("height"), duration_s=f.get("durationS"))
            for f in draft.get("files", [])
        ],
    )


# ---------------------------------------------------------------- one format, two SDKs


def test_the_javascript_sdk_seals_exactly_the_bytes_this_sdk_seals(monkeypatch):
    key = vector_key()
    assert b64e(key.key) == VECTORS["elements_key"] and format_elements_key(key) == VECTORS["elements_key_text"]
    sealed = []
    for case in VECTORS["deterministic"]:
        draft = vector_draft(case["draft"])
        monkeypatch.setattr("os.urandom", Counter())
        if "keep_files_of" in case:
            kept = sealed[case["keep_files_of"]]
            draft.pop("files")
            made = seal_element(key, case["element_id"], element_key=kept.element_key, keep_files=kept.record.files, **draft)
        else:
            made = seal_element(key, case["element_id"], **draft)
        monkeypatch.undo()
        sealed.append(made)
        assert b64e(made.element_key) == case["element_key"], case["name"]
        assert made.wrapped_key == case["wrapped_key"], case["name"]
        assert made.meta == case["meta"], case["name"]
        assert [b64e(f) for f in made.files] == case["sealed_files"], case["name"]
        assert record_json(made.record).decode() == case["record_json"], case["name"]
    # JavaScript's trim, not Python's: U+FEFF goes, a trailing U+001C stays. A file name cut at 200 UTF-16 units.
    assert sealed[0].record.name == "Mára Jó \U0001F3AC"
    assert sealed[0].record.description.startswith("A harbour keeper\u2028") and sealed[0].record.description.endswith("smiling\x1c")
    assert sealed[0].record.files[0].name == "a" + "\U0001F3AC" * 99 + "\ud83c"
    assert sealed[0].record.files[1].width is None and sealed[1].record.files[0].duration_s == 8.5
    assert sealed[2].record.consent.withdrawn_at == 1790000000.5 and sealed[2].wrapped_key is None and sealed[2].files == []


@pytest.mark.parametrize("who", ["sealed_by_javascript", "sealed_by_python"])
def test_elements_sealed_by_either_sdk_open_here(who):
    made = VECTORS[who]
    key = vector_key()
    element = open_element(key, made["row"])
    # Opened and written again, the record is the same JSON byte for byte.
    assert record_json(element.record).decode() == made["record_json"]
    assert (element.name, element.consent.subject, element.consent.relationship) == ("Mára Jó \U0001F3AC", "Mára Jó", "self")
    assert (element.revision, element.key_id, element.kind, len(element.files)) == (1, VECTORS["master_key_id"], "character", 2)
    for position, name in enumerate(made["files"]):
        data = open_element_file(element.element_key, element.element_id, position, b64d(made["sealed_files"][position]), element.files[position])
        assert data == b64d(VECTORS["files"][name])


def test_the_vectors_are_the_same_file_in_both_sdks():
    theirs = JS_SDK / "test" / "data" / "elements_sdk_vectors.json"
    if not theirs.exists():
        pytest.skip("the JavaScript SDK isn't next to this one")
    assert theirs.read_bytes() == (DATA / "elements_sdk_vectors.json").read_bytes()


def test_an_element_sealed_the_way_the_gateway_tests_seal_one_opens_here():
    path = JS_SDK / "test" / "data" / "elements_vector.json"
    if not path.exists():
        pytest.skip("the JavaScript SDK isn't next to this one")
    vector = json.loads(path.read_text())
    key = derive_elements_key(b64d(vector["master_key"]), vector["account_id"], vector["master_key_id"])
    assert b64e(key.key) == vector["elements_key"]
    element = open_element(key, vector["row"])
    assert b64e(element.element_key) == vector["element_key"]
    written = json.loads(record_json(element.record))
    # This SDK writes consent in the studio's form, with withdrawnAt null until consent is withdrawn.
    assert written["consent"].pop("withdrawnAt") is None and written == vector["record"]
    file = open_element_file(element.element_key, element.element_id, 0, b64d(vector["sealed_file_0"]), element.files[0])
    assert file == b64d(vector["file_0"]) and len(b64d(vector["row"]["meta"])) == vector["meta_sealed_bytes"]


NODE_ROUND_TRIP = """
import { readFileSync } from "node:fs";
const sdk = await import(process.argv[1]);
const input = JSON.parse(readFileSync(0, "utf8"));
const key = sdk.parseElementsKey(input.key);
const element = sdk.openElement(key, input.row);
const opened = input.sealed_files.map((f, i) => sdk.b64e(sdk.openElementFile(element.elementKey, element.elementId, i, sdk.b64d(f), element.files[i])));
const recordJson = (elementKey, id, meta) => new TextDecoder().decode(sdk.unpadPayload(sdk.decryptBlob(elementKey, `element/${id}/meta`, sdk.b64d(meta))));
const id = sdk.newElementId();
const consent = { subject: "Noor Åberg", relationship: "self", grantedOn: "2026-09-10", use: "Narration", affirmedAt: 1789900000, withdrawnAt: null };
const sealed = sdk.sealElement(key, id, { kind: "voice", name: " Noor ✓ ", description: "a low, calm voice\\n", consent, files: [{ data: sdk.b64d(input.voice), mime: "audio/wav", name: "noor.wav", durationS: 12.25 }] });
const row = { element_id: id, revision: 3, master_key_id: key.keyId, wrapped_key: sealed.wrappedKey, meta: sealed.meta, files: [{ position: 0, size: 1, sha256: "0" }], files_bytes: 1, created_at: 1, updated_at: 2 };
process.stdout.write(JSON.stringify({
  record: recordJson(element.elementKey, element.elementId, input.row.meta),
  reserialized: JSON.stringify(sdk.openElementRecord(element.elementKey, element.elementId, input.row.meta)),
  opened, row, sealed_files: sealed.files.map(sdk.b64e), sealed_record: recordJson(sealed.elementKey, id, sealed.meta),
}));
"""


@pytest.mark.skipif(
    shutil.which("node") is None or not (JS_SDK / "dist" / "index.js").exists(), reason="node and a built sdk/js are needed"
)
def test_a_live_round_trip_through_the_javascript_sdk():
    key = fresh_key()
    element_id = uuid.uuid4().hex
    sealed = seal_element(key, element_id, **{**MARA, "files": [*MARA["files"], ElementFile(PNG + b"side", "image/png")]})
    row = {"element_id": element_id, "revision": 1, "master_key_id": key.key_id, "wrapped_key": sealed.wrapped_key, "meta": sealed.meta,
           "files": [{"position": 0}, {"position": 1}], "files_bytes": 0, "created_at": 1, "updated_at": 1}
    request = {"key": format_elements_key(key), "row": row, "sealed_files": [b64e(f) for f in sealed.files], "voice": b64e(WAV)}
    run = subprocess.run(
        ["node", "--input-type=module", "-e", NODE_ROUND_TRIP, (JS_SDK / "dist" / "index.js").as_uri()],
        input=json.dumps(request), capture_output=True, text=True, timeout=60,
    )
    assert run.returncode == 0, run.stderr
    answer = json.loads(run.stdout)
    # Python sealed it; JavaScript opened it, and writes its record back to the same bytes.
    assert answer["record"] == answer["reserialized"] == record_json(sealed.record).decode()
    assert [b64d(f) for f in answer["opened"]] == [PNG, PNG + b"side"]
    # JavaScript sealed it; it opens here, to the same record.
    voice = open_element(key, answer["row"])
    assert record_json(voice.record).decode() == answer["sealed_record"]
    assert (voice.name, voice.description, voice.consent.subject, voice.files[0].duration_s) == ("Noor ✓", "a low, calm voice", "Noor Åberg", 12.25)
    assert open_element_file(voice.element_key, voice.element_id, 0, b64d(answer["sealed_files"][0]), voice.files[0]) == WAV


# ---------------------------------------------------------------- keys, sealing and rules


def test_the_elements_key_is_bound_to_its_account_and_travels_as_text():
    import os

    master = os.urandom(32)
    key = derive_elements_key(master, ACCOUNT, "f" * 32)
    assert derive_elements_key(master, "another-account", "f" * 32).key != key.key and len(key.key) == 32
    written = format_elements_key(key)
    assert re.fullmatch(r"kwek1\.0123456789abcdef0123456789abcdef\.f{32}\.[A-Za-z0-9_-]{43}", written)
    assert parse_elements_key(f" {written}\n") == key and key.key.hex() not in repr(key)
    for bad in ["", "kwek1..", written.replace("kwek1", "kwek2"), written[:-1], f"{written}\nx", None]:
        with refused("invalid_element"):
            parse_elements_key(bad)  # type: ignore[arg-type]
    with pytest.raises(KunoError, match="32 bytes"):
        derive_elements_key(bytes(16), ACCOUNT, "f" * 32)
    with refused("invalid_element"):
        derive_elements_key(master, ACCOUNT, "F" * 32)


def test_an_element_key_opens_only_for_its_account_and_element_and_a_rotation_rewraps_the_same_key():
    import os

    key, element_id, element_key = fresh_key(), uuid.uuid4().hex, os.urandom(32)
    wrapped = wrap_element_key(key, element_id, element_key)
    assert len(b64d(wrapped)) == 64 and b64d(wrapped)[:4] == b"KVE1"
    assert unwrap_element_key(key, element_id, wrapped) == element_key
    for attempt in (
        lambda: unwrap_element_key(key, uuid.uuid4().hex, wrapped),
        lambda: unwrap_element_key(replace(key, account_id="someone-else"), element_id, wrapped),
        lambda: unwrap_element_key(key, element_id, "not base64!"),
        lambda: unwrap_element_key(key, element_id, b64e(element_key)),
    ):
        with refused("decrypt_failed"):
            attempt()
    rotated = fresh_key()
    rewrapped = rewrap_element_key(key, rotated, element_id, wrapped)
    assert unwrap_element_key(rotated, element_id, rewrapped) == element_key
    with refused("decrypt_failed"):
        unwrap_element_key(key, element_id, rewrapped)


def test_sealing_pads_the_record_and_every_file_and_nothing_readable_is_left():
    key, element_id = fresh_key(), uuid.uuid4().hex
    sealed = seal_element(key, element_id, **MARA)
    meta = b64d(sealed.meta)
    assert blob_version(meta) == 2 and len(meta) == 4386
    assert len(unpad_payload(decrypt_blob(sealed.element_key, f"element/{element_id}/meta", meta))) < 4096
    assert len(sealed.files) == 1 and blob_version(sealed.files[0]) == 2
    assert sealed.record.files[0].sha256 == sha256_hex(PNG)
    everything = (sealed.meta + (sealed.wrapped_key or "") + b64e(sealed.files[0])).encode() + sealed.files[0] + meta
    for plain in (b"Mara", b"raincoat", b"character", b"a green raincoat"):
        assert plain not in everything
    assert sealed.element_key.hex() not in repr(sealed)
    # A record past 4 KiB of JSON takes the next bucket, 8 KiB: 18 + padme(8 + 8192) + 16 bytes sealed.
    named = ElementFile(PNG, "image/png", name="é" * 200)
    longer = seal_element(key, element_id, **{**MARA, "description": "é" * 1000, "consent": replace(CONSENT, use="é" * 200), "files": [named] * 4})
    assert len(b64d(longer.meta)) == 8738
    # A file that isn't the one the record lists is refused.
    other = seal_element(key, element_id, **{**MARA, "files": [ElementFile(WAV, "image/png")]}).files[0]
    with pytest.raises(KunoError) as wrong:
        open_element_file(sealed.element_key, element_id, 0, other, sealed.record.files[0])
    assert wrong.value.code in ("integrity", "decrypt_failed")
    with refused("integrity"):
        open_element_file(sealed.element_key, element_id, 0, seal_element_file_for(sealed.element_key, element_id, WAV), sealed.record.files[0])
    with refused("decrypt_failed"):
        open_element_record(bytes(32), element_id, sealed.meta)


def seal_element_file_for(element_key: bytes, element_id: str, data: bytes) -> bytes:
    from kunoworld.elements import seal_element_file

    return seal_element_file(element_key, element_id, 0, data)


def check(**draft) -> str:
    return " ".join(element_draft_problems(**draft))


def test_drafts_follow_the_elements_rules():
    assert element_draft_problems(**MARA) == []
    assert element_draft_problems(**{**MARA, "consent": None}) == [], "a character need not be a real person"
    assert element_draft_problems(kind="voice", name="Narrator", files=[ElementFile(WAV, "audio/wav", duration_s=12)]) == []
    voice = dict(kind="voice", name="Narrator")
    cases = [
        ({**MARA, "name": " "}, "Give it a name"),
        ({**MARA, "name": "x" * 81}, "at most 80 characters"),
        ({**MARA, "name": "two\nlines"}, "on one line"),
        ({**MARA, "description": "x" * 1001}, "at most 1,000 characters"),
        ({**MARA, "files": []}, "Add 1 to 4 images"),
        ({**MARA, "files": MARA["files"] * 5}, "Add 1 to 4 images"),
        ({**MARA, "files": [ElementFile(WAV, "audio/wav")]}, "PNG, JPEG or WebP"),
        ({**voice, "files": [ElementFile(PNG, "image/png")]}, "WAV, MP3, Ogg or FLAC"),
        ({**voice, "files": [ElementFile(WAV, "audio/wav", duration_s=31)]}, "at most 30 seconds"),
        ({**voice, "files": []}, "A voice is one audio clip"),
        ({"kind": "product", "name": "Mug", "files": MARA["files"], "consent": CONSENT}, "Only characters and voices"),
        ({**MARA, "consent": replace(CONSENT, subject="")}, "who gave consent"),
        ({**MARA, "consent": replace(CONSENT, relationship="friend")}, "someone who gave you permission"),
        ({**MARA, "consent": replace(CONSENT, granted_on="last week")}, "when consent was given"),
        ({**MARA, "consent": replace(CONSENT, granted_on="\u0662\u0660\u0662\u0666-09-01")}, "when consent was given"),
        ({**MARA, "consent": replace(CONSENT, use="x" * 201)}, "at most 200 characters"),
        ({**MARA, "consent": replace(CONSENT, affirmed_at=None)}, "Confirm the consent record"),
        ({**MARA, "kind": "celebrity"}, "one of: character, product"),
    ]
    for draft, message in cases:
        assert message in check(**draft), message
    big = ElementFileInfo("image/png", 15 * 1024 * 1024 + 1, "0" * 64)
    assert "at most 15 MB" in check(kind="style", name="Grain", files=[big])
    with refused("invalid_element"):
        seal_element(fresh_key(), uuid.uuid4().hex, **{**MARA, "files": []})
    with refused("invalid_element"):
        seal_element(fresh_key(), "not-an-id", **MARA)


def test_which_models_can_use_an_elements_files_and_the_lines_they_add():
    character, location, voice = (type("E", (), {"kind": kind})() for kind in ("character", "location", "voice"))
    FF, LF, KF, RI, RA = (InputRole.FIRST_FRAME, InputRole.LAST_FRAME, InputRole.KEYFRAME, InputRole.REFERENCE_IMAGE, InputRole.REFERENCE_AUDIO)
    assert element_roles(character, PROFILES["ltx-2.5-fast"]) == [FF, LF, KF]
    assert element_roles(location, PROFILES["ltx-2.5-4k"]) == [FF, KF]
    assert element_roles(character, PROFILES["h3-turbo"]) == [FF, LF]
    assert element_roles(character, PROFILES["h3-reference"]) == [RI]
    assert element_roles(voice, PROFILES["h3-reference"]) == [RA]
    assert element_roles(voice, PROFILES["ltx-2.5-fast"]) == [], "LTX-2.5 takes no reference audio: the voice is kept for later"

    line = type("E", (), {})
    mara, harbour = line(), line()
    mara.name, mara.description = " Mara ", "a woman\n in her 60s "
    harbour.name, harbour.description = "Harbour", ""
    assert element_prompt_line(mara) == "Mara: a woman in her 60s" and element_prompt_line(harbour) == "Harbour"
    silver = line()
    silver.name, silver.description = "Mara", "silver hair"
    once = add_element_lines("A walk at dusk. \n", [silver])
    assert once == "A walk at dusk.\nMara: silver hair"
    assert add_element_lines(once, [silver]) == once, "a line already there isn't added twice"
    assert add_element_lines("", [harbour]) == "Harbour"


# ---------------------------------------------------------------- the client against a fake gateway


class ElementsGateway:
    """Stores what the SDK sends, like the gateway: uploads by id, Elements by id with revisions, listed a page at a time.
    Refuses readable uploads and fields the route doesn't define."""

    def __init__(self, blobs: dict[str, bytes] | None = None, page_size: int = 200):
        self.blobs: dict[str, bytes] = {} if blobs is None else blobs
        self.elements: dict[str, dict] = {}
        self.calls: list[httpx.Request] = []
        self.master_key_id: str | None = None
        self.page_size = page_size

    def client(self) -> KunoClient:
        return KunoClient(API_KEY, API_URL, transport=httpx.MockTransport(self))

    def paths(self) -> list[str]:
        return [f"{r.method} {r.url.path}" for r in self.calls]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        path, method = request.url.path, request.method
        if (method, path) == ("POST", "/v1/blobs"):
            if not request.content.startswith(b"KUNOB1"):
                return detail(400, "not_encrypted")
            blob_id = uuid.uuid4().hex
            self.blobs[blob_id] = request.content
            return httpx.Response(201, json={"blob_id": blob_id, "sha256": sha256_hex(request.content), "size": len(request.content)})
        if (method, path) == ("GET", "/v1/elements"):
            ids = sorted(self.elements)
            cursor = request.url.params.get("cursor")
            start = ids.index(cursor) if cursor else 0
            limit = min(int(request.url.params.get("limit", 100)), self.page_size)
            page = ids[start : start + limit]
            following = ids[start + limit] if start + limit < len(ids) else None
            return httpx.Response(200, json={"master_key_id": self.master_key_id, "elements": [self.elements[i]["row"] for i in page], "next_cursor": following})
        match = re.fullmatch(r"/v1/elements/([0-9a-f]{32})(?:/files/(\d+))?", path)
        if not match:
            return detail(404, "not_found")
        element_id, position = match.groups()
        current = self.elements.get(element_id)
        if position is not None:
            return httpx.Response(200, content=self.blobs[current["files"][int(position)]]) if current else detail(404, "not_found")
        if method == "GET":
            return httpx.Response(200, json=current["row"]) if current else detail(404, "not_found")
        if method == "DELETE":
            self.elements.pop(element_id, None)
            return httpx.Response(204)
        put = json.loads(request.content)
        if set(put) - {"master_key_id", "expected_revision", "wrapped_key", "meta", "file_blob_ids", "affirm_rules"} or put.get("affirm_rules") is not True:
            return detail(422, "invalid")
        if put["master_key_id"] != self.master_key_id:
            return detail(409, "vault_changed", master_key_id=self.master_key_id)
        if (current is not None) if put["expected_revision"] is None else (current is None or current["row"]["revision"] != put["expected_revision"]):
            return detail(409, "element_changed")
        files = put.get("file_blob_ids") or current["files"]
        row = {
            "element_id": element_id, "revision": (current["row"]["revision"] if current else 0) + 1, "master_key_id": self.master_key_id,
            "wrapped_key": put.get("wrapped_key") or current["row"]["wrapped_key"], "meta": put["meta"],
            "files": [{"position": i, "size": len(self.blobs[b]), "sha256": sha256_hex(self.blobs[b])} for i, b in enumerate(files)],
            "files_bytes": sum(len(self.blobs[b]) for b in files), "created_at": 1.0, "updated_at": 2.0,
        }
        self.elements[element_id] = {"row": row, "files": files}
        return httpx.Response(200 if current else 201, json=row)


@pytest.fixture
def gateway() -> ElementsGateway:
    return ElementsGateway(page_size=1)


def keyed(gateway: ElementsGateway):
    key = fresh_key()
    gateway.master_key_id = key.key_id
    return key


def test_create_list_replace_and_delete_send_only_ciphertext_and_ids(gateway):
    key, kuno = keyed(gateway), gateway.client()
    with refused("rules_not_affirmed"):
        kuno.elements.create(key, **MARA)
    assert gateway.calls == [], "nothing is sent before the rules are affirmed"

    made = kuno.elements.create(key, **MARA, affirm_rules=True)
    assert (made.revision, made.name, made.consent, made.key_id) == (1, "Mara", CONSENT, key.key_id)
    upload, put = gateway.calls
    assert upload.url.path == "/v1/blobs" and upload.headers["authorization"] == f"Bearer {API_KEY}"
    sent = json.loads(put.content)
    assert sorted(sent) == ["affirm_rules", "expected_revision", "file_blob_ids", "master_key_id", "meta", "wrapped_key"]
    assert sent["expected_revision"] is None
    for call in gateway.calls:
        for plain in (b"Mara", b"raincoat", b"character", b"Mara Jones", b"permission"):
            assert plain not in call.content, (plain, call.url.path)
    assert kuno.elements.file(made) == PNG
    assert made.element_key.hex() not in repr(made)

    # A rename keeps the files and the key: no uploads, no wrapped key.
    gateway.calls.clear()
    renamed = kuno.elements.update(key, made, name="Mara (older)", affirm_rules=True)
    assert gateway.paths() == [f"PUT /v1/elements/{made.element_id}"]
    assert sorted(json.loads(gateway.calls[0].content)) == ["affirm_rules", "expected_revision", "master_key_id", "meta"]
    assert (renamed.revision, renamed.name, renamed.description, renamed.consent) == (2, "Mara (older)", made.description, CONSENT)
    assert renamed.element_key == made.element_key and kuno.elements.file(renamed) == PNG
    with refused("rules_not_affirmed"):
        kuno.elements.update(key, renamed, name="x")

    # A stale copy is refused; new files come with a new key.
    with refused("element_changed"):
        kuno.elements.update(key, made, name="Mara", affirm_rules=True)
    side = PNG + b"\x01\x02\x03"
    replaced = kuno.elements.update(key, renamed, files=[ElementFile(PNG, "image/png"), ElementFile.load(side)], consent=None, affirm_rules=True)
    assert len(replaced.files) == 2 and replaced.consent is None and replaced.element_key != made.element_key
    assert kuno.elements.file(replaced, 1) == side
    with refused("invalid_element"):
        kuno.elements.file(replaced, 2)

    # Tampered storage doesn't open quietly.
    stored = gateway.elements[made.element_id]
    gateway.blobs[stored["files"][1]] = seal_element(key, made.element_id, **{**MARA, "files": [ElementFile(PNG, "image/png")]}).files[0]
    with pytest.raises(KunoError) as tampered:
        kuno.elements.file(replaced, 1)
    assert tampered.value.code in ("decrypt_failed", "integrity")

    # Another device lists and opens them, a page at a time; one made under an older key sync generation is unreadable.
    second = kuno.elements.create(key, kind="voice", name="Narrator", files=[ElementFile(WAV, "audio/wav", duration_s=8)], affirm_rules=True)
    listed = kuno.elements.list(key)
    assert sorted(e.name for e in listed.elements) == ["Mara (older)", "Narrator"] and listed.unreadable == []
    assert listed.key_id == key.key_id and listed.stored_bytes == sum(e["row"]["files_bytes"] for e in gateway.elements.values())
    assert gateway.paths().count("GET /v1/elements") >= 2
    gateway.elements[second.element_id]["row"]["master_key_id"] = uuid.uuid4().hex
    assert [u.reason for u in kuno.elements.list(key).unreadable] == ["key_rotated"]
    stranger = kuno.elements.list(fresh_key(key.key_id))
    assert sorted(u.reason for u in stranger.unreadable) == ["decrypt_failed", "key_rotated"]

    assert kuno.elements.get(key, made.element_id).name == "Mara (older)"
    kuno.elements.delete(made.element_id)
    assert made.element_id not in gateway.elements
    with refused("not_found"):
        kuno.elements.get(key, made.element_id)


def test_a_rotation_rewraps_what_rows_returns_and_the_old_key_stops_writing(gateway):
    key, kuno = keyed(gateway), gateway.client()
    made = kuno.elements.create(key, **MARA, affirm_rules=True)
    rotated = fresh_key()
    rows, key_id = kuno.elements.rows()
    assert key_id == key.key_id and [r["element_id"] for r in rows] == [made.element_id]
    rewrapped = [(r["element_id"], rewrap_element_key(key, rotated, r["element_id"], r["wrapped_key"])) for r in rows]
    # What the gateway's rotation does with them:
    gateway.master_key_id = rotated.key_id
    for element_id, wrapped in rewrapped:
        gateway.elements[element_id]["row"].update(wrapped_key=wrapped, master_key_id=rotated.key_id)
    opened = kuno.elements.get(rotated, made.element_id)
    assert opened.element_key == made.element_key and kuno.elements.file(opened) == PNG
    with refused("vault_changed"):
        kuno.elements.create(key, **MARA, affirm_rules=True)
    assert ERROR_CODES["vault_changed"] and ERROR_CODES["rules_not_affirmed"] and ELEMENT_RULES.startswith("No public figures")


def test_withdrawn_consent_is_written_into_the_record_and_stops_the_element_being_used(gateway):
    key, kuno = keyed(gateway), gateway.client()
    made = kuno.elements.create(key, **MARA, affirm_rules=True)
    withdrawn = kuno.elements.withdraw_consent(key, made, affirm_rules=True, at=1789700000)
    assert consent_withdrawn(withdrawn) and not consent_withdrawn(made)
    assert kuno.elements.get(key, made.element_id).consent.withdrawn_at == 1789700000
    gateway.calls.clear()
    with refused("consent_withdrawn"):
        kuno.elements.attach({"prompt": "A walk."}, [withdrawn])
    assert gateway.calls == [] and ERROR_CODES["consent_withdrawn"]
    product = kuno.elements.create(key, kind="product", name="Mug", files=MARA["files"], affirm_rules=True)
    with refused("invalid_element"):
        kuno.elements.withdraw_consent(key, product, affirm_rules=True)


def test_attach_adds_each_elements_line_to_the_prompt_and_its_files_as_inputs(gateway):
    key, kuno = keyed(gateway), gateway.client()
    side = PNG + b"\x09"
    character = kuno.elements.create(key, **{**MARA, "files": [ElementFile(PNG, "image/png"), ElementFile(side, "image/png")]}, affirm_rules=True)
    voice = kuno.elements.create(key, kind="voice", name="Narrator", description="a low, calm voice", files=[ElementFile(WAV, "audio/wav")], affirm_rules=True)

    request = kuno.elements.attach({"prompt": "She walks along the pier.", "model": "ltx-2.5-fast"}, [ElementUse(character, "first_frame", file=1)])
    assert request == {"prompt": f"She walks along the pier.\n{element_prompt_line(character)}", "model": "ltx-2.5-fast", "first_frame": side}

    references = kuno.elements.attach(
        {"prompt": "", "model": "h3-reference", "reference_images": [PNG]},
        [ElementUse(character, InputRole.REFERENCE_IMAGE, file="all"), ElementUse(voice, "reference_audio")],
    )
    assert references["reference_images"] == [PNG, PNG, side] and references["reference_audio"] == [WAV]
    assert references["prompt"] == f"{element_prompt_line(character)}\n{element_prompt_line(voice)}"
    keyframes = kuno.elements.attach({"prompt": "Dusk.", "keyframes": [(PNG, 0.0)]}, [ElementUse(character, "keyframe", time_s=4.0)])
    assert keyframes["keyframes"] == [(PNG, 0.0), (PNG, 4.0)]

    # prepare() and submit_standard() take inputs: the files join them as Inputs.
    listed = kuno.elements.attach({"prompt": "x", "inputs": [Input.load(InputRole.LAST_FRAME, PNG)]}, [ElementUse(character, "first_frame")])
    assert [(i.role, i.data, i.mime) for i in listed["inputs"]] == [(InputRole.LAST_FRAME, PNG, "image/png"), (InputRole.FIRST_FRAME, PNG, "image/png")]

    # A storyboard takes descriptions only, into its scene; an Element on its own is its description.
    board = {"prompt": "A harbour town.", "shots": [Shot("Morning.", 5), Shot("Noon.", 5)]}
    scene = kuno.elements.attach(board, [character])
    assert scene == {**board, "prompt": f"A harbour town.\n{element_prompt_line(character)}"}

    gateway.calls.clear()
    for request, uses, code, message in [
        (board, [ElementUse(character, "first_frame")], "invalid_element", "description only"),
        ({"prompt": "", "mode": "storyboard"}, [ElementUse(character, "first_frame")], "invalid_element", "description only"),
        ({"prompt": ""}, [ElementUse(voice, "first_frame")], "invalid_element", "reference audio"),
        ({"prompt": ""}, [ElementUse(character, "source_video")], "invalid_element", "can't be used as source_video"),
        ({"prompt": ""}, [ElementUse(character, "prompt")], "invalid_element", "can't be used as prompt"),
        ({"prompt": ""}, [ElementUse(character, "first_frame", file=4)], "invalid_element", "no such file"),
        ({"prompt": ""}, [ElementUse(character, "first_frame", file="all")], "invalid_element", "for reference images"),
        ({"prompt": ""}, [ElementUse(character, "keyframe")], "invalid_element", "needs its time"),
        ({"prompt": "", "first_frame": PNG}, [ElementUse(character, "first_frame")], "invalid_element", "already has a first_frame"),
        ({"prompt": ""}, [ElementUse(character, "last_frame"), ElementUse(character, "last_frame", file=1)], "invalid_element", "already has a last_frame"),
        ({"plan": object()}, [character], "invalid_params", "add_element_lines"),
    ]:
        with pytest.raises(KunoError) as refusal:
            kuno.elements.attach(request, uses)
        assert (refusal.value.code, message in refusal.value.message) == (code, True), message
    assert gateway.calls == [], "refused uses download nothing"


def test_an_attached_element_is_sealed_to_the_enclave_or_uploaded_like_any_other_input():
    network = FakeNetwork()
    elements = ElementsGateway(blobs=network.blobs)
    key = keyed(elements)

    def route(request: httpx.Request) -> httpx.Response:
        return elements(request) if request.url.path.startswith("/v1/elements") else network(request)

    kuno = KunoClient(API_KEY, API_URL, transport=httpx.MockTransport(route))
    kuno._pick_enclave = lambda route: network.enclave  # type: ignore[method-assign]
    mara = kuno.elements.create(key, **MARA, affirm_rules=True)

    private = kuno.generate(**kuno.elements.attach({"prompt": "She walks along the pier.", "model": "ltx-2.5-fast"}, [ElementUse(mara, "first_frame")]), wait=False)
    payload = network.jobs[private.job_id].payload
    assert payload.prompt == f"She walks along the pier.\n{element_prompt_line(mara)}"
    assert [(ref.role, ref.sha256) for ref in payload.inputs] == [(InputRole.FIRST_FRAME, sha256_hex(PNG))]
    job = network.calls[-1]
    assert b"raincoat" not in job.content and PNG not in b"".join(r.content for r in network.calls), "sealed to the enclave, not readable"

    standard = kuno.generate(**kuno.elements.attach({"prompt": "A pier.", "model": "ltx-2.5-fast", "privacy": "standard"}, [ElementUse(mara, "first_frame")]), wait=False)
    uploaded = [r for r in network.calls if r.url.path == "/v1/standard/uploads"]
    assert [r.content for r in uploaded] == [PNG], "a Standard job uploads the file readable, like any input"
    assert network.jobs[standard.job_id].body["prompt"] == f"A pier.\n{element_prompt_line(mara)}"
