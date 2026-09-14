"""Share links against a fake gateway (httpx.MockTransport): owner calls carry the API key, public calls never do,
and `shares.open` checks and decrypts a really sealed video with the key from the link's fragment."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest

from kuno_protocol.blobs import encrypt_blob
from kuno_protocol.canonical import b64e, sha256_hex
from kuno_protocol.crypto import generate_signing_key, public_key_bytes
from kuno_protocol.receipts import ReceiptBody, VideoInfo, sign_receipt
from kuno_protocol.schemas import output_label
from kunoworld import (
    ERROR_CODES,
    GenerationResult,
    KunoClient,
    KunoError,
    StandardVideoJob,
    VideoJob,
    parse_share_link,
    share_url_with_key,
)

SITE = "https://kunoworld.test"
VIDEO = b"\x00\x00\x00\x18ftypisom a film worth sharing"
TOKEN = b64e(bytes([7]) * 32)
OTHER_TOKEN = b64e(bytes([9]) * 32)
PROFILE_ID = "ltx-2.5-fast"
API_KEY = "kw_live_test"


def detail(status: int, **fields) -> httpx.Response:
    return httpx.Response(status, json={"detail": fields})


class FakeGateway:
    """Answers from `routes` ("METHOD /path" -> handler) and records every request."""

    def __init__(self, routes):
        self.routes = routes
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        handler = self.routes.get(f"{request.method} {request.url.path}")
        if handler is None:
            return detail(404, code="not_found", message=request.url.path)
        return handler(request)

    def client(self) -> KunoClient:
        return KunoClient(API_KEY, "https://gw.test", transport=httpx.MockTransport(self))

    def paths(self) -> list[str]:
        return [f"{r.method} {r.url.path}" for r in self.calls]


def row(job_id: str, privacy: str, **extra) -> dict:
    body = {
        "share_id": "sh-1",
        "job_id": job_id,
        "privacy": privacy,
        "profile_id": PROFILE_ID,
        "created_at": 1_800_000_000.0,
        "expires_at": None,
        "revoked_at": None,
        "status": "active",
        "view_count": 0,
    }
    body.update(extra)
    return body


def made(job_id: str, privacy: str) -> dict:
    return {**row(job_id, privacy), "token": TOKEN, "url_path": f"/s/{TOKEN}", "url": f"{SITE}/s/{TOKEN}"}


def private_video(job_id: str = "job-priv", sealed_for: str | None = None) -> tuple[bytes, bytes, dict]:
    """(output key, sealed blob, public details) for a private video, with a receipt a real Ed25519 key signed.
    `sealed_for` seals the blob under another job's label."""
    output_key = bytes(range(32))
    sealed = encrypt_blob(output_key, output_label(sealed_for or job_id), VIDEO)
    signing_key = generate_signing_key()
    body = ReceiptBody(
        job_id=job_id,
        enclave_id="enc-1",
        profile_id=PROFILE_ID,
        image_digest="a" * 64,
        params_digest="b" * 64,
        input_digest="c" * 64,
        output_digest=sha256_hex(sealed),
        output_bytes=len(sealed),
        content_digest=sha256_hex(VIDEO),
        attestation_digest="d" * 64,
        started_at=1_800_000_000.0,
        finished_at=1_800_000_042.5,
        gpu_seconds=40.25,
        video=VideoInfo(duration_s=5.0, width=1920, height=1080, fps=24.0, frames=120, audio=True),
    )
    details = {
        "privacy": "private",
        "profile_id": PROFILE_ID,
        "created_at": 1_800_000_000.0,
        "shared_at": 1_800_000_100.0,
        "expires_at": None,
        "content_digest": sha256_hex(VIDEO),
        "receipt": sign_receipt(signing_key, body).model_dump(mode="json"),
        "signing_public_key": b64e(public_key_bytes(signing_key)),
    }
    return output_key, sealed, details


def public_routes(details: dict, video: bytes) -> dict:
    return {
        f"GET /v1/shares/{TOKEN}": lambda r: httpx.Response(200, json=details),
        f"GET /v1/shares/{TOKEN}/video": lambda r: httpx.Response(200, content=video),
    }


def test_create_adds_the_key_only_to_a_private_video_jobs_link():
    bodies: list[dict] = []

    def create(job_id: str, privacy: str):
        def handler(request: httpx.Request) -> httpx.Response:
            bodies.append(json.loads(request.content))
            return httpx.Response(201, json=made(job_id, privacy))

        return handler

    gateway = FakeGateway(
        {
            "POST /v1/videos/job-priv/shares": create("job-priv", "private"),
            "POST /v1/videos/job-std/shares": create("job-std", "standard"),
        }
    )
    client = gateway.client()
    output_key, _, _ = private_video()
    key_text = b64e(output_key)
    job = VideoJob(client, "job-priv", output_key, b"\0" * 32, PROFILE_ID)

    link = client.shares.create(job, expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc))
    assert link["url"] == f"{SITE}/s/{TOKEN}#k={key_text}"
    assert link["key_included"] is True
    assert link["url_path"] == f"/s/{TOKEN}", "the path never carries the key"
    assert (link["share_id"], link["job_id"], link["privacy"], link["status"], link["token"]) == ("sh-1", "job-priv", "private", "active", TOKEN)
    assert bodies.pop(0) == {"expires_at": 1893456000.0}, "a datetime goes up as Unix seconds"

    by_id = client.shares.create("job-priv", expires_at=1_900_000_000)
    assert by_id["url"] == f"{SITE}/s/{TOKEN}" and by_id["key_included"] is False
    assert share_url_with_key(by_id["url"], output_key) == link["url"] == share_url_with_key(by_id["url"], key_text)
    assert bodies.pop(0) == {"expires_at": 1_900_000_000.0}

    standard = client.shares.create(StandardVideoJob(client, "job-std", PROFILE_ID))
    assert standard["url"] == f"{SITE}/s/{TOKEN}" and standard["key_included"] is False
    assert bodies.pop(0) == {"expires_at": None}

    # A job that holds a key still gets no fragment when the gateway says the video is Standard.
    mismatched = client.shares.create(VideoJob(client, "job-std", output_key, b"\0" * 32, PROFILE_ID))
    assert "#" not in mismatched["url"] and mismatched["key_included"] is False

    for request in gateway.calls:
        assert request.headers["authorization"] == f"Bearer {API_KEY}"
        assert key_text not in str(request.url) and key_text.encode() not in request.content, "the key never leaves this process"


def test_a_bad_expiry_or_key_is_refused_before_a_link_is_made():
    gateway = FakeGateway({})
    client = gateway.client()
    for bad in (float("nan"), float("inf"), "tomorrow", True):
        with pytest.raises(KunoError) as exc:
            client.shares.create("job-priv", expires_at=bad)  # type: ignore[arg-type]
        assert exc.value.code == "invalid_expiry"
    with pytest.raises(KunoError) as short_key:
        client.shares.create(VideoJob(client, "job-priv", b"\0" * 16, b"\0" * 32, PROFILE_ID))
    assert short_key.value.code == "invalid_key"
    assert gateway.calls == []

    with pytest.raises(KunoError) as bad_text:
        share_url_with_key(f"{SITE}/s/{TOKEN}", "not-a-key")
    assert bad_text.value.code == "invalid_key"
    assert share_url_with_key(f"{SITE}/s/{TOKEN}#k=old", b"\0" * 32) == f"{SITE}/s/{TOKEN}#k={'A' * 43}"


def test_list_and_revoke_use_the_account_routes_with_the_api_key():
    gateway = FakeGateway(
        {
            "GET /v1/account/shares": lambda r: httpx.Response(
                200,
                json=[
                    row("job-priv", "private", view_count=3),
                    row("job-std", "standard", share_id="sh-0", status="expired", expires_at=1_800_000_060.0),
                ],
            ),
            "DELETE /v1/account/shares/sh-1": lambda r: httpx.Response(
                200, json=row("job-priv", "private", status="revoked", revoked_at=1_800_000_500.0)
            ),
        }
    )
    client = gateway.client()

    rows = client.shares.list(job_id="job-priv", limit=10)
    assert [(r["share_id"], r["status"], r["view_count"]) for r in rows] == [("sh-1", "active", 3), ("sh-0", "expired", 0)]
    assert dict(gateway.calls[0].url.params) == {"job_id": "job-priv", "limit": "10"}
    client.shares.list()
    assert dict(gateway.calls[1].url.params) == {"limit": "100"}

    revoked = client.shares.revoke("sh-1")
    assert (revoked["status"], revoked["revoked_at"]) == ("revoked", 1_800_000_500.0)
    assert gateway.paths() == ["GET /v1/account/shares", "GET /v1/account/shares", "DELETE /v1/account/shares/sh-1"]
    assert all(r.headers["authorization"] == f"Bearer {API_KEY}" for r in gateway.calls)


def test_public_calls_send_no_api_key_and_get_reads_the_key_from_the_fragment():
    output_key, sealed, details = private_video()
    key_text = b64e(output_key)
    gateway = FakeGateway(public_routes(details, sealed))
    client = gateway.client()

    got = client.shares.get(f"{SITE}/s/{TOKEN}#k={key_text}")
    assert (got["token"], got["key"], got["privacy"], got["content_digest"]) == (TOKEN, key_text, "private", sha256_hex(VIDEO))
    assert got["signing_public_key"] == details["signing_public_key"] and got["receipt"]["body"]["job_id"] == "job-priv"
    assert client.shares.get(TOKEN)["key"] is None
    assert client.shares.get(f"/s/{TOKEN}")["token"] == TOKEN
    for request in gateway.calls:
        assert "authorization" not in request.headers, "public routes never get the API key"
        assert str(request.url) == f"https://gw.test/v1/shares/{TOKEN}", "only the token is sent"

    assert parse_share_link(f"{SITE}/s/{TOKEN}/?utm_source=x#k={key_text}") == (TOKEN, key_text)
    assert parse_share_link(f"{TOKEN}#k={key_text}") == (TOKEN, key_text)
    assert parse_share_link(f"  {TOKEN}\n") == (TOKEN, None), "pasted whitespace is trimmed"
    for bad in (f"{SITE}/s/not-a-token", f"{SITE}/s/{TOKEN}/../../v1/account/shares", f"{TOKEN}x"):
        with pytest.raises(KunoError) as exc:
            client.shares.get(bad)
        assert (exc.value.status, exc.value.code) == (0, "not_found")
    assert len(gateway.calls) == 3, "a malformed link is refused before anything is sent"


def test_open_checks_the_receipt_and_decrypts_a_private_video():
    output_key, sealed, details = private_video()
    key_text = b64e(output_key)
    gateway = FakeGateway(public_routes(details, sealed))
    client = gateway.client()

    opened = client.shares.open(f"{SITE}/s/{TOKEN}#k={key_text}")
    assert isinstance(opened, GenerationResult)
    assert opened.video == VIDEO and opened.privacy == "private"
    assert (opened.job_id, opened.profile_id, opened.content_digest) == ("job-priv", PROFILE_ID, sha256_hex(VIDEO))

    assert client.shares.open(f"{SITE}/s/{TOKEN}", key=key_text).video == VIDEO, "the key can be passed separately"
    assert client.shares.open(TOKEN, key=output_key).video == VIDEO, "as text or raw bytes"

    assert gateway.paths() == [f"GET /v1/shares/{TOKEN}", f"GET /v1/shares/{TOKEN}/video"] * 3
    for request in gateway.calls:
        assert "authorization" not in request.headers
        assert key_text not in str(request.url), "the key is never sent"


def test_a_private_link_without_its_key_or_with_the_wrong_one_does_not_open():
    _, sealed, details = private_video()
    gateway = FakeGateway(public_routes(details, sealed))
    client = gateway.client()

    with pytest.raises(KunoError) as missing:
        client.shares.open(f"{SITE}/s/{TOKEN}")
    assert missing.value.code == "missing_key" and missing.value.explanation == ERROR_CODES["missing_key"]
    assert not any(p.endswith("/video") for p in gateway.paths()), "nothing is downloaded without a key"

    for wrong in (b64e(bytes([1]) * 32), "not-a-key"):
        with pytest.raises(KunoError) as exc:
            client.shares.open(f"{SITE}/s/{TOKEN}#k={wrong}")
        assert exc.value.code == "decrypt_failed"


def test_a_tampered_video_a_receipt_from_another_key_or_a_mismatched_digest_is_refused():
    output_key, sealed, details = private_video()
    link = f"{SITE}/s/{TOKEN}#k={b64e(output_key)}"

    def open_with(details: dict, video: bytes, url: str = link):
        return FakeGateway(public_routes(details, video)).client().shares.open(url)

    tampered = bytearray(sealed)
    tampered[-5] ^= 1
    other_signer = {**details, "signing_public_key": b64e(public_key_bytes(generate_signing_key()))}
    relabelled = {**details, "content_digest": "0" * 64}
    forged_body = {**details, "receipt": {**details["receipt"], "body": {**details["receipt"]["body"], "profile_id": "h3-turbo"}}}
    no_receipt = {**details, "receipt": None}
    for bad_details, video in ((details, bytes(tampered)), (other_signer, sealed), (relabelled, sealed), (forged_body, sealed), (no_receipt, sealed)):
        with pytest.raises(KunoError) as exc:
            open_with(bad_details, video)
        assert exc.value.code == "integrity"

    # A blob sealed for another job doesn't open under this receipt's job id, even with the right key.
    swapped_key, swapped_sealed, swapped = private_video(sealed_for="job-other")
    with pytest.raises(KunoError) as swapped_exc:
        open_with(swapped, swapped_sealed, f"{SITE}/s/{TOKEN}#k={b64e(swapped_key)}")
    assert swapped_exc.value.code == "decrypt_failed"


def test_a_standard_link_plays_as_it_is_checked_against_its_digest():
    _, _, details = private_video()
    standard = {**details, "privacy": "standard"}
    opened = FakeGateway(public_routes(standard, VIDEO)).client().shares.open(f"{SITE}/s/{TOKEN}")
    assert opened.video == VIDEO and opened.privacy == "standard"

    with pytest.raises(KunoError) as exc:
        FakeGateway(public_routes(standard, b"\x00\x00\x00\x18ftypisom another film")).client().shares.open(TOKEN)
    assert exc.value.code == "integrity"


def test_links_that_stopped_working_and_refusals_surface_the_gateway_codes():
    gateway = FakeGateway(
        {
            f"GET /v1/shares/{TOKEN}": lambda r: detail(410, code="share_unavailable", message="This link no longer works."),
            f"GET /v1/shares/{OTHER_TOKEN}": lambda r: detail(429, code="rate_limited", message="Too many requests from this network."),
            "POST /v1/videos/full/shares": lambda r: detail(409, code="too_many_shares", message="A video can have 20 working links."),
            "POST /v1/videos/soon/shares": lambda r: detail(422, code="invalid_expiry", message="expires_at must be between a minute and ten years."),
            "POST /v1/videos/held/shares": lambda r: detail(403, code="account_restricted", message="Restricted.", restricted_until=1_900_000_000),
            "DELETE /v1/account/shares/nope": lambda r: detail(404, code="not_found", message="No such share link."),
        }
    )
    client = gateway.client()

    with pytest.raises(KunoError) as gone:
        client.shares.open(f"{SITE}/s/{TOKEN}#k={'A' * 43}")
    assert (gone.value.status, gone.value.code, gone.value.message) == (410, "share_unavailable", "This link no longer works.")
    assert "revoked" in (gone.value.explanation or "")
    assert len(gateway.calls) == 1, "no video is fetched for a dead link"

    expected = [
        (lambda: client.shares.get(OTHER_TOKEN), 429, "rate_limited"),
        (lambda: client.shares.create("full"), 409, "too_many_shares"),
        (lambda: client.shares.create("soon", expires_at=1.0), 422, "invalid_expiry"),
        (lambda: client.shares.create("held"), 403, "account_restricted"),
        (lambda: client.shares.revoke("nope"), 404, "not_found"),
    ]
    for call, status, code in expected:
        with pytest.raises(KunoError) as exc:
            call()
        assert (exc.value.status, exc.value.code) == (status, code)
        if code == "account_restricted":
            assert exc.value.restricted_until == 1_900_000_000

    for code in ("share_unavailable", "missing_key", "too_many_shares", "invalid_expiry", "decrypt_failed"):
        assert code in ERROR_CODES
