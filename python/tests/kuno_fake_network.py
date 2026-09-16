"""A fake gateway with a fake enclave behind it (httpx.MockTransport), for the quote, budget and MCP tests.

It answers the routes those tests use the way the gateway does: `/v1/quote` prices with `ModelProfile.price_usd` on the
params the SDK would fill in; a private job is really opened with the enclave's HPKE key (so a test can read what was
sealed), rendered as a few bytes, sealed to the job's output key and receipted with the enclave's signing key; each
status poll moves a job one stage on, through `shot i/N` for a storyboard. The client it makes skips attestation, which
has its own tests: `_pick_enclave` returns this enclave.
"""

from __future__ import annotations

import json
import os
import uuid
from types import SimpleNamespace

import httpx

from kuno_protocol.attestation import enclave_id_for
from kuno_protocol.blobs import encrypt_blob
from kuno_protocol.canonical import b64d, b64e, sha256_hex
from kuno_protocol.crypto import RecipientSession, generate_hpke_keypair, generate_signing_key, public_key_bytes
from kuno_protocol.profiles import InputRole, Mode, example_roles, load_profiles
from kuno_protocol.receipts import ReceiptBody, VideoInfo, sign_receipt
from kuno_protocol.schemas import GenerationParams, JobCreate, job_aad, output_label
from kuno_protocol.sealed_payload import open_payload
from kunoworld import Input, KunoClient, Shot, infer_mode
from kunoworld.client import _fit_params

PROFILES = load_profiles()
API_URL = "https://gw.test"
API_KEY = "kw_live_test"


def detail(status: int, code: str, message: str = "", **extra) -> httpx.Response:
    return httpx.Response(status, json={"detail": {"code": code, "message": message or code, **extra}})


class FakeNetwork:
    def __init__(self) -> None:
        self.hpke_private, hpke_public = generate_hpke_keypair()
        self.signing_key = generate_signing_key()
        signing_public = public_key_bytes(self.signing_key)
        self.enclave = {
            "enclave_id": enclave_id_for(hpke_public, signing_public), "hpke_public_key": b64e(hpke_public),
            "signing_public_key": b64e(signing_public), "evidence": {}, "envelope": None,
        }
        self.calls: list[httpx.Request] = []
        self.quotes: list[dict] = []
        self.jobs: dict[str, SimpleNamespace] = {}
        self.blobs: dict[str, bytes] = {}
        # A test sets these to make the gateway answer differently.
        self.price_usd: float | None = None
        self.balance_usd = 25.0
        self.refuse: dict[str, httpx.Response] = {}

    # ------------------------------------------------------------ client

    def client(self, config=None) -> KunoClient:
        client = KunoClient(API_KEY, API_URL, transport=httpx.MockTransport(self))
        client._pick_enclave = lambda route: self.enclave  # type: ignore[method-assign]
        return client

    def paths(self) -> list[str]:
        return [f"{r.method} {r.url.path}" for r in self.calls]

    def sent(self) -> bytes:
        """Every request body, for checking what never left the client."""
        return b"".join(r.content for r in self.calls) + b"".join(str(r.url).encode() for r in self.calls)

    # ------------------------------------------------------------ routing

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        key = f"{request.method} {request.url.path}"
        if key in self.refuse:
            return self.refuse[key]
        parts = request.url.path.strip("/").split("/")
        if key == "GET /v1/models":
            return httpx.Response(200, json=self.models())
        if key == "GET /v1/route":
            profile_id = request.url.params.get("profile_id") or "ltx-2.5-fast"
            return httpx.Response(200, json={"profile_id": profile_id, "requested_profile_id": profile_id, "fallback_reason": None,
                                             "enclaves": [self.enclave]})
        if key == "POST /v1/quote":
            return self.quote(json.loads(request.content))
        if key == "POST /v1/blobs":
            blob_id = uuid.uuid4().hex
            self.blobs[blob_id] = request.content
            return httpx.Response(201, json={"blob_id": blob_id, "sha256": sha256_hex(request.content), "size": len(request.content)})
        if key == "POST /v1/standard/uploads":
            return httpx.Response(201, json={"upload_id": uuid.uuid4().hex, "sha256": sha256_hex(request.content), "size": len(request.content), "mime": "image/png"})
        if key == "POST /v1/videos":
            return self.create_private(JobCreate.model_validate_json(request.content))
        if key == "POST /v1/standard/videos":
            return self.create_standard(json.loads(request.content))
        if parts[:2] == ["v1", "videos"] and len(parts) == 3 and request.method == "GET":
            return self.poll(parts[2])
        if parts[:2] == ["v1", "videos"] and len(parts) == 4 and parts[3] == "cancel":
            return self.cancel(parts[2])
        if parts[:2] == ["v1", "blobs"] and len(parts) == 3 and parts[2] in self.blobs:
            return httpx.Response(200, content=self.blobs[parts[2]])
        if parts[:3] == ["v1", "standard", "videos"] and len(parts) == 5 and parts[4] == "video" and parts[3] in self.jobs:
            return httpx.Response(200, content=self.jobs[parts[3]].video)
        return detail(404, "not_found", request.url.path)

    def models(self) -> dict:
        rows = []
        for profile in PROFILES.values():
            rows.append({**profile.model_dump(mode="json"), "privacy_modes": profile.privacy_modes, "enabled": True,
                         "available_in_region": profile.family != "minimax-h3", "workers": 1 if profile.id == "ltx-2.5-fast" else 0})
        return {"country": None, "workers_online": 1, "switch": {}, "pricing_placeholder": True, "models": rows}

    def quote(self, body: dict) -> httpx.Response:
        self.quotes.append(body)
        profile = PROFILES[body.get("profile_id") or "ltx-2.5-fast"]
        shots = body.get("shots")
        if shots is not None:
            mode = Mode.STORYBOARD
        else:
            roles = [InputRole(r) for r in body["input_roles"]] if body.get("input_roles") is not None else None
            mode = Mode(body["mode"]) if body.get("mode") else infer_mode(roles or [])
        roles = [] if shots is not None else (roles if roles is not None else example_roles(mode))
        params = _fit_params(
            profile, mode, [Input(role, b"", "") for role in roles], body.get("duration_s"), body.get("resolution"),
            body.get("aspect_ratio"), body.get("fps"), body.get("audio", True), None,
            shots=None if shots is None else [Shot("-", s.get("duration_s"), s.get("join")) for s in shots],
        )
        privacy = body.get("privacy", "private")
        price = self.price_usd if self.price_usd is not None else profile.price_usd(params, privacy)
        rate = (profile.pricing.usd_per_second if privacy == "private" else profile.pricing.standard_usd_per_second)[params.resolution]
        return httpx.Response(200, json={
            "price_usd": price, "currency": "USD", "privacy": privacy, "profile_id": profile.id, "profile_name": profile.name,
            "requested_profile_id": body.get("profile_id"), "fallback_reason": None, "params": params.model_dump(mode="json"),
            "breakdown": {"usd_per_second": rate, "billable_seconds": params.duration_s, "fps_multiplier": 1.0,
                          "long_clip_over_s": None, "long_clip_multiplier": 1.0, "subtotal_usd": price, "min_job_usd": 0.1,
                          "minimum_applied": False},
            "placeholder": True, "balance_usd": self.balance_usd, "balance_covers": self.balance_usd >= price,
        })

    # ------------------------------------------------------------ jobs

    def _job(self, job_id: str, params: GenerationParams, privacy: str, **extra) -> SimpleNamespace:
        count = len(params.shots or [])
        stages = [("queued", None, 0.0)]
        stages += [("running", f"shot {i}/{count}", (i - 1) / count) for i in range(1, count + 1)] if count else [("running", "rendering", 0.5)]
        stages += [("succeeded", "done", 1.0)]
        job = SimpleNamespace(job_id=job_id, params=params, privacy=privacy, stages=stages, step=0, video=b"", receipt=None,
                              output_blob_id=None, price=PROFILES[params.profile_id].price_usd(params, privacy), **extra)
        self.jobs[job_id] = job
        return job

    def create_private(self, body: JobCreate) -> httpx.Response:
        session = RecipientSession(self.hpke_private, b64d(body.enc))
        aad = job_aad(body.job_id, body.enclave_id, body.params, body.input_blob_ids)
        payload = open_payload(session, b64d(body.ciphertext), aad)
        job = self._job(body.job_id, body.params, "private", payload=payload, output_key=session.output_key)
        return httpx.Response(201, json=self.status_json(job))

    def create_standard(self, body: dict) -> httpx.Response:
        job = self._job(body["job_id"], GenerationParams.model_validate(body["params"]), "standard", body=body)
        return httpx.Response(201, json=self.status_json(job))

    def poll(self, job_id: str) -> httpx.Response:
        job = self.jobs.get(job_id)
        if job is None:
            return detail(404, "not_found", "No such video job.")
        response = httpx.Response(200, json=self.status_json(job))
        if job.stages[job.step][0] not in ("succeeded", "canceled"):
            job.step += 1
            if job.stages[job.step][0] == "succeeded":
                self._render(job)
        return response

    def cancel(self, job_id: str) -> httpx.Response:
        job = self.jobs[job_id]
        if job.stages[job.step][0] not in ("succeeded", "canceled"):
            job.stages, job.step = [("canceled", "canceled", 0.0)], 0
        return httpx.Response(200, json=self.status_json(job))

    def _render(self, job: SimpleNamespace) -> None:
        job.video = b"\x00\x00\x00\x18ftypisom" + os.urandom(64)
        stored = job.video
        if job.privacy == "private":
            stored = encrypt_blob(job.output_key, output_label(job.job_id), job.video)
            job.output_blob_id = uuid.uuid4().hex
            self.blobs[job.output_blob_id] = stored
        params = job.params
        body = ReceiptBody(
            job_id=job.job_id, enclave_id=self.enclave["enclave_id"], profile_id=params.profile_id, image_digest="0" * 64,
            params_digest="0" * 64, input_digest="0" * 64, output_digest=sha256_hex(stored), output_bytes=len(stored),
            content_digest=sha256_hex(job.video), attestation_digest="0" * 64, started_at=1.0, finished_at=2.0, gpu_seconds=1.0,
            video=VideoInfo(duration_s=params.duration_s, width=1280, height=704, fps=params.fps, frames=int(params.duration_s * params.fps), audio=True),
        )
        job.receipt = sign_receipt(self.signing_key, body)

    def status_json(self, job: SimpleNamespace) -> dict:
        state, stage, progress = job.stages[job.step]
        succeeded = state == "succeeded" and job.receipt is not None
        return {
            "job_id": job.job_id, "status": state if state != "succeeded" or succeeded else "running", "stage": stage,
            "progress": progress, "params": job.params.model_dump(mode="json"), "enclave_id": self.enclave["enclave_id"],
            "price_usd": job.price, "created_at": 1.0, "updated_at": 2.0,
            "output_blob_id": job.output_blob_id if succeeded else None,
            "receipt": job.receipt.model_dump(mode="json") if succeeded else None,
            "error_code": None, "error": None, "privacy": job.privacy,
        }
