"""Standard mode and the account-safety errors, against a fake gateway (httpx.MockTransport)."""

from __future__ import annotations

import json

import httpx
import pytest

from kuno_protocol.canonical import sha256_hex
from kuno_protocol.profiles import InputRole, load_profiles
from kuno_protocol.schemas import JobStatus
from kunoworld import KunoClient, KunoError, StandardVideoJob

PROFILE = load_profiles()["ltx-2.5-fast"]
PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 32
VIDEO = b"\x00\x00\x00\x18ftypisom a standard film"


def status_json(job_id: str, state: str, **extra) -> dict:
    body = {
        "job_id": job_id,
        "status": state,
        "stage": None,
        "progress": 1.0 if state == "succeeded" else 0.0,
        "params": {
            "profile_id": PROFILE.id,
            "mode": "image_to_video",
            "duration_s": 5.0,
            "resolution": "1080p",
            "aspect_ratio": "16:9",
            "fps": 24,
            "audio": True,
            "input_roles": ["first_frame"],
        },
        "enclave_id": "enc-open-1",
        "price_usd": 0.2,
        "created_at": 1_700_000_000.0,
        "updated_at": 1_700_000_001.0,
        "output_blob_id": None,
        "receipt": None,
        "error_code": None,
        "error": None,
        "privacy": "standard",
    }
    if state == "succeeded":
        body["receipt"] = {
            "body": {
                "v": 1,
                "job_id": job_id,
                "enclave_id": "enc-open-1",
                "profile_id": PROFILE.id,
                "image_digest": "0" * 64,
                "params_digest": "0" * 64,
                "input_digest": "0" * 64,
                "output_digest": "0" * 64,
                "output_bytes": len(VIDEO),
                "content_digest": sha256_hex(VIDEO),
                "attestation_digest": "0" * 64,
                "started_at": 1.0,
                "finished_at": 2.0,
                "gpu_seconds": 1.0,
                "video": {"duration_s": 5.0, "width": 1920, "height": 1080, "fps": 24, "frames": 120, "audio": True},
                "miner_hotkey": None,
            },
            "signature": "c2ln",
        }
    body.update(extra)
    return body


def detail(status: int, **fields) -> httpx.Response:
    return httpx.Response(status, json={"detail": fields})


class FakeGateway:
    """Answers from `routes` ("METHOD /path" → handler) and records every request."""

    def __init__(self, routes):
        self.routes = routes
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        handler = self.routes.get(f"{request.method} {request.url.path}")
        if handler is None:
            # "METHOD /prefix/*" matches any path under the prefix.
            handler = next(
                (h for k, h in self.routes.items() if k.endswith("*") and f"{request.method} {request.url.path}".startswith(k[:-1])),
                None,
            )
        if handler is None:
            return detail(404, code="not_found", message=request.url.path)
        return handler(request)

    def client(self) -> KunoClient:
        return KunoClient("kw_test", "https://gw.test", transport=httpx.MockTransport(self))

    def paths(self) -> list[str]:
        return [f"{r.method} {r.url.path}" for r in self.calls]


def test_standard_generate_uploads_plaintext_and_downloads_the_video():
    created: dict = {}

    def create(request):
        created.update(json.loads(request.content))
        return httpx.Response(201, json=status_json(created["job_id"], "queued"))

    gateway = FakeGateway(
        {
            "GET /v1/route": lambda r: httpx.Response(
                200, json={"profile_id": PROFILE.id, "requested_profile_id": PROFILE.id, "fallback_reason": None, "enclaves": []}
            ),
            "GET /v1/models": lambda r: httpx.Response(200, json={"models": [PROFILE.model_dump(mode="json")]}),
            "POST /v1/standard/uploads": lambda r: httpx.Response(
                201, json={"upload_id": "up-1", "sha256": sha256_hex(PNG), "size": len(PNG), "mime": "image/png"}
            ),
            "POST /v1/standard/videos": create,
            "GET /v1/videos/*": lambda r: httpx.Response(200, json=status_json(created["job_id"], "succeeded")),
            "GET /v1/standard/videos/*": lambda r: httpx.Response(200, content=VIDEO, headers={"content-type": "video/mp4"}),
        }
    )
    client = gateway.client()
    seen: list[JobStatus] = []
    result = client.generate("A lantern in the rain", model=PROFILE.id, first_frame=PNG, privacy="standard", on_progress=seen.append)

    assert result.privacy == "standard" and result.video == VIDEO
    assert result.content_digest == sha256_hex(VIDEO)
    assert seen[-1].privacy == "standard"

    route = next(r for r in gateway.calls if r.url.path == "/v1/route")
    assert route.url.params["privacy"] == "standard"
    upload = next(r for r in gateway.calls if r.url.path == "/v1/standard/uploads")
    assert upload.url.params["role"] == "first_frame"
    assert upload.headers["content-type"] == "image/png"
    assert upload.content == PNG, "inputs go up as they are"

    assert created["prompt"] == "A lantern in the rain"
    assert created["inputs"] == [{"upload_id": "up-1", "index": 0, "role": "first_frame"}]
    assert created["params"]["profile_id"] == PROFILE.id
    assert "ciphertext" not in created and "enc" not in created
    paths = gateway.paths()
    for path in ("GET /v1/manifest", "POST /v1/blobs", "POST /v1/videos"):
        assert path not in paths, f"{path} should not be called on the standard path"


def test_wait_false_returns_a_standard_job_that_exports_no_secrets():
    gateway = FakeGateway(
        {
            "GET /v1/route": lambda r: httpx.Response(
                200, json={"profile_id": PROFILE.id, "requested_profile_id": None, "fallback_reason": "capacity", "enclaves": []}
            ),
            "GET /v1/models": lambda r: httpx.Response(200, json={"models": [PROFILE.model_dump(mode="json")]}),
            "POST /v1/standard/videos": lambda r: httpx.Response(201, json=status_json(json.loads(r.content)["job_id"], "queued")),
        }
    )
    job = gateway.client().generate("x", privacy="standard", wait=False)
    assert isinstance(job, StandardVideoJob)
    assert job.export() == {"privacy": "standard", "job_id": job.job_id, "profile_id": PROFILE.id, "fallback_reason": "capacity"}


def test_a_standard_video_that_does_not_match_its_receipt_is_refused():
    gateway = FakeGateway(
        {
            "GET /v1/videos/job-x": lambda r: httpx.Response(200, json=status_json("job-x", "succeeded")),
            "GET /v1/standard/videos/job-x/video": lambda r: httpx.Response(200, content=b"something else"),
        }
    )
    with pytest.raises(KunoError) as exc:
        gateway.client().standard_job("job-x").wait(poll_s=0)
    assert exc.value.code == "integrity"


def test_account_safety_errors_keep_their_details():
    gateway = FakeGateway(
        {
            "GET /v1/route": lambda r: detail(
                403, code="private_mode_not_eligible", message="Needs a verified payment.", reasons=["no_verified_payment"]
            ),
            "POST /v1/standard/uploads": lambda r: detail(422, code="upload_blocked", message="This file can't be used."),
            "GET /v1/account/eligibility": lambda r: detail(403, code="account_restricted", message="Restricted.", restricted_until=1_900_000_000),
        }
    )
    client = gateway.client()

    with pytest.raises(KunoError) as denied:
        client.generate("x")
    assert (denied.value.status, denied.value.code) == (403, "private_mode_not_eligible")
    assert denied.value.reasons == ["no_verified_payment"]
    assert denied.value.restricted_until is None
    assert gateway.calls[0].headers["authorization"] == "Bearer kw_test"

    with pytest.raises(KunoError) as blocked_upload:
        client.upload_standard(InputRole.FIRST_FRAME, PNG, "image/png")
    assert blocked_upload.value.code == "upload_blocked"

    with pytest.raises(KunoError) as restricted:
        client.eligibility()
    assert restricted.value.code == "account_restricted"
    assert restricted.value.restricted_until == 1_900_000_000


def test_reports_are_sent_without_a_credential_and_library_calls_with_one():
    gateway = FakeGateway(
        {
            "POST /v1/reports": lambda r: httpx.Response(202, json={"report_id": "rep-1"}),
            "GET /v1/standard/videos": lambda r: httpx.Response(200, json=[{"job_id": "a", "status": "succeeded"}]),
            "GET /v1/standard/videos/a/thumbnail": lambda r: httpx.Response(200, content=b"\xff\xd8\xff"),
            "DELETE /v1/standard/videos/a": lambda r: httpx.Response(204),
            "GET /v1/account/eligibility": lambda r: httpx.Response(
                200, json={"private_mode": {"eligible": True, "reasons": []}, "restricted_until": None, "strikes_24h": 0, "strikes_7d": 1}
            ),
        }
    )
    client = gateway.client()

    assert client.report("copyright", job_id="a", details="my film") == "rep-1"
    report = gateway.calls[0]
    assert "authorization" not in report.headers
    assert json.loads(report.content) == {"job_id": "a", "reason": "copyright", "details": "my film"}

    assert client.standard_videos(limit=10)[0]["job_id"] == "a"
    assert gateway.calls[-1].url.params["limit"] == "10"
    job = client.standard_job("a")
    assert job.thumbnail() == b"\xff\xd8\xff"
    job.delete()
    assert client.eligibility()["strikes_7d"] == 1
    assert all(r.headers["authorization"] == "Bearer kw_test" for r in gateway.calls[1:])


def test_report_requires_a_known_reason_and_something_to_identify_the_video():
    client = FakeGateway({}).client()
    with pytest.raises(KunoError) as bad_reason:
        client.report("spam", job_id="a")
    assert bad_reason.value.code == "invalid_reason"
    with pytest.raises(KunoError) as nothing:
        client.report("other")
    assert nothing.value.code == "invalid_report"


def test_privacy_must_be_a_known_mode_and_job_status_defaults_to_private():
    with pytest.raises(KunoError) as exc:
        FakeGateway({}).client().generate("x", privacy="public")  # type: ignore[arg-type]
    assert exc.value.code == "invalid_privacy"

    legacy = status_json("old", "queued")
    del legacy["privacy"]
    assert JobStatus.model_validate(legacy).privacy == "private"
