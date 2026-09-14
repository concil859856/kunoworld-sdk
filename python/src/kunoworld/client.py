from __future__ import annotations

import math
import re
import time
import uuid
import warnings
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, Union
from urllib.parse import parse_qs, quote

import httpx

from kuno_protocol.attestation import AttestationEvidence, GoldenManifest, verify_evidence
from kuno_protocol.blobs import decrypt_blob, encrypt_blob
from kuno_protocol.canonical import b64d, b64e, sha256_hex
from kuno_protocol.crypto import DecryptionError, SenderSession
from kuno_protocol.media import sniff_mime
from kuno_protocol.profiles import InputRole, Mode, ModelProfile
from kuno_protocol.receipts import Receipt, verify_receipt
from kuno_protocol.schemas import (
    GenerationParams,
    InputRef,
    JobCreate,
    JobState,
    JobStatus,
    RouteResponse,
    SealedPayload,
    input_label,
    job_aad,
    output_label,
)

Source = Union[str, Path, bytes]
ProgressFn = Callable[[JobStatus], None]
Privacy = Literal["private", "standard"]

REPORT_REASONS = ("csam", "sexual_minor", "nonconsensual_intimate", "violent_extremism", "harassment", "copyright", "other")
# The only report reasons for which the gateway accepts a private video's output key.
KEY_REPORT_REASONS = ("csam", "sexual_minor")

# Error codes callers commonly branch on, and what each means. The gateway may send others;
# `KunoError.code` is always the raw string.
ERROR_CODES: dict[str, str] = {
    "unauthorized": "The API key was missing, unknown or revoked.",
    "gone": "This endpoint or credential was retired. Studio tokens (kwt_...) no longer work: use an API key.",
    "content_policy": "The request breaks the content policy, so the job wasn't created. All NSFW content is banned in "
    "both modes. Nothing was charged.",
    "safety_blocked": "The content check inside the enclave blocked the request before rendering. It counts as a strike.",
    "content_not_reviewable": "Operators only: this item's content can't be opened, because it isn't a report of child "
    "sexual abuse material or sexual content involving a minor, and no matching legal hold covers it.",
    "key_not_accepted": "An output_key can be attached to a report only when the reason is csam or sexual_minor.",
    "private_mode_not_eligible": "This account can't make private jobs yet; see `reasons`.",
    "account_restricted": "The account is restricted; see `restricted_until`.",
    "upload_blocked": "A Standard upload was refused by the scan.",
    "insufficient_balance": "The balance doesn't cover the job's price.",
    "not_found": "No such job, blob or video on this account, or no such share link.",
    "deleted": "The owner deleted this video.",
    "removed": "The video was removed after a review under the content policy.",
    "not_ready": "The job hasn't finished yet.",
    "integrity": "What came back didn't match the enclave-signed receipt.",
    "decrypt_failed": "The video didn't open with this key.",
    "share_unavailable": "The share link no longer works (revoked, expired, video deleted or removed, or account closed; the "
    "public answer never says which), or, when making one, the video can't be shared right now.",
    "missing_key": "A private share link needs the video's key: the #k=... part of the link, or pass it separately.",
    "too_many_shares": "Too many working share links: 20 per video and 1000 per account. Revoke some first.",
    "invalid_expiry": "A share link's expiry must be between a minute and ten years from now, in Unix seconds, or None.",
    "rate_limited": "Too many requests from this network to public share links. Try again in a minute.",
}


class KunoError(Exception):
    """A failed request. `details` is the rest of the gateway's error body, such as `reasons` on
    `private_mode_not_eligible` or `restricted_until` on `account_restricted`."""

    def __init__(self, status: int, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(f"{code}: {message}")
        self.status, self.code, self.message = status, code, message
        self.details: dict[str, Any] = details or {}

    @property
    def is_content_policy(self) -> bool:
        """The request broke the content policy: `content_policy` (Standard) or `safety_blocked` (Private)."""
        return self.code in ("content_policy", "safety_blocked")

    @property
    def explanation(self) -> str | None:
        """What this code means, when it's one the gateway documents."""
        return ERROR_CODES.get(self.code)

    @property
    def reasons(self) -> list[str]:
        """Why private mode isn't available (`private_mode_not_eligible`)."""
        reasons = self.details.get("reasons")
        return [r for r in reasons if isinstance(r, str)] if isinstance(reasons, list) else []

    @property
    def restricted_until(self) -> float | None:
        """Unix seconds until which the account is restricted (`account_restricted`)."""
        until = self.details.get("restricted_until")
        return float(until) if isinstance(until, (int, float)) else None


@dataclass
class Input:
    role: InputRole
    data: bytes
    mime: str
    time_s: float | None = None
    strength: float | None = None
    hint: str | None = None
    start_s: float | None = None
    end_s: float | None = None

    @classmethod
    def load(cls, role: InputRole, source: Source, **extra: Any) -> Input:
        data = source if isinstance(source, bytes) else Path(source).read_bytes()
        mime = sniff_mime(data)
        if mime is None:
            raise KunoError(0, "unsupported_media", f"Could not recognize the {role.value} file type.")
        return cls(role=role, data=data, mime=mime, **extra)


def infer_mode(roles: Iterable[InputRole]) -> Mode:
    present = set(roles)
    if InputRole.SOURCE_AUDIO in present:
        return Mode.AUDIO_TO_VIDEO
    if InputRole.SOURCE_VIDEO in present:
        return Mode.VIDEO_EDIT
    if present & {InputRole.REFERENCE_IMAGE, InputRole.REFERENCE_VIDEO, InputRole.REFERENCE_AUDIO}:
        return Mode.REFERENCE_TO_VIDEO
    if InputRole.KEYFRAME in present:
        return Mode.KEYFRAMES
    if {InputRole.FIRST_FRAME, InputRole.LAST_FRAME} <= present:
        return Mode.FIRST_LAST_FRAME
    if InputRole.FIRST_FRAME in present:
        return Mode.IMAGE_TO_VIDEO
    if InputRole.LAST_FRAME in present:
        return Mode.LAST_FRAME
    return Mode.TEXT_TO_VIDEO


@dataclass
class GenerationResult:
    job_id: str
    video: bytes
    receipt: Receipt
    profile_id: str
    fallback_reason: str | None = None
    privacy: Privacy = "private"

    @property
    def content_digest(self) -> str:
        return self.receipt.body.content_digest

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.write_bytes(self.video)
        return path


@dataclass
class PreparedJob:
    """A sealed request ready to POST. Keep `output_key` private: it is the only way to open the video."""

    request: JobCreate
    output_key: bytes
    signing_public_key: bytes
    fallback_reason: str | None = None
    input_blob_bytes: list[bytes] = field(default_factory=list)


class KunoClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.kunoworld.com",
        *,
        manifest: GoldenManifest | None = None,
        country: str | None = None,
        timeout: float = 60.0,
        transport: httpx.BaseTransport | None = None,
    ):
        """`api_key` is a developer API key from your account page. The KunoWorld website itself uses
        email sign-in; API keys are for your own programs and must never be shipped to a browser."""
        if api_key.startswith("kwt_"):
            raise KunoError(410, "gone", ERROR_CODES["gone"])
        headers = {"authorization": f"Bearer {api_key}"}
        if country:
            headers["x-kuno-country"] = country
        self._http = httpx.Client(base_url=base_url.rstrip("/"), headers=headers, timeout=timeout, transport=transport)
        self._manifest = manifest
        self._pinned = manifest is not None

    # ------------------------------------------------------------ plumbing

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> KunoClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _request(self, method: str, path: str, *, auth: bool = True, **kwargs) -> httpx.Response:
        request = self._http.build_request(method, path, **kwargs)
        if not auth:
            request.headers.pop("authorization", None)
        response = self._http.send(request)
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", {})
            except (ValueError, AttributeError):
                detail = {}
            if not isinstance(detail, dict):
                detail = {"message": str(detail)}
            rest = {k: v for k, v in detail.items() if k not in ("code", "message")}
            raise KunoError(
                response.status_code, detail.get("code", "error"), detail.get("message", response.text[:200]), rest
            )
        return response

    # ------------------------------------------------------------ discovery

    def models(self) -> dict:
        return self._request("GET", "/v1/models").json()

    def profile(self, profile_id: str) -> ModelProfile:
        for model in self.models()["models"]:
            if model["id"] == profile_id:
                return ModelProfile.model_validate(model)
        raise KunoError(404, "unknown_model", f"Unknown model {profile_id!r}.")

    def manifest(self) -> GoldenManifest:
        if self._manifest is None:
            warnings.warn(
                "Using the gateway-served golden manifest. Pin the published manifest for zero-trust verification.",
                stacklevel=3,
            )
            self._manifest = GoldenManifest.model_validate(self._request("GET", "/v1/manifest").json())
        return self._manifest

    def provenance_by_digest(self, content_digest: str) -> dict:
        """Public certificate lookup by the SHA-256 of a finished video."""
        return self._request("GET", f"/v1/provenance/{content_digest.lower()}").json()

    def provenance(self, video: bytes | str | Path) -> dict:
        data = video if isinstance(video, bytes) else Path(video).read_bytes()
        return self.provenance_by_digest(sha256_hex(data))

    def route(
        self, mode: Mode, model: str | None = None, family: str | None = None, privacy: Privacy = "private"
    ) -> RouteResponse:
        params = {"mode": mode.value}
        if model:
            params["profile_id"] = model
        if family:
            params["family"] = family
        if privacy == "standard":
            params["privacy"] = "standard"
        return RouteResponse.model_validate(self._request("GET", "/v1/route", params=params).json())

    # ------------------------------------------------------------ account safety

    def eligibility(self) -> dict:
        """Whether this account may make private jobs: `{private_mode: {eligible, reasons},
        restricted_until, strikes_24h, strikes_7d}`."""
        return self._request("GET", "/v1/account/eligibility").json()

    def report(
        self,
        reason: str,
        *,
        content_digest: str | None = None,
        job_id: str | None = None,
        url: str | None = None,
        details: str | None = None,
        output_key: str | None = None,
        contact_email: str | None = None,
    ) -> str:
        """Reports a video, identified by at least one of `content_digest`, `job_id` or `url`.
        No credential is sent. Returns the report id.

        `output_key` (base64url) is the key of a private video you received. It is accepted only for
        `csam` and `sexual_minor` reports, so that a reviewer can open that one video; the gateway
        refuses it for other reasons with `key_not_accepted`, and so does this method, before sending."""
        if reason not in REPORT_REASONS:
            raise KunoError(0, "invalid_reason", f"reason must be one of {', '.join(REPORT_REASONS)}.")
        if not (content_digest or job_id or url):
            raise KunoError(0, "invalid_report", "Identify the video by content_digest, job_id or url.")
        if output_key and reason not in KEY_REPORT_REASONS:
            raise KunoError(0, "key_not_accepted", ERROR_CODES["key_not_accepted"])
        fields = {
            "content_digest": content_digest,
            "job_id": job_id,
            "url": url,
            "reason": reason,
            "details": details,
            "output_key": output_key,
            "contact_email": contact_email,
        }
        body = {k: v for k, v in fields.items() if v is not None}
        return self._request("POST", "/v1/reports", json=body, auth=False).json()["report_id"]

    # ------------------------------------------------------------ share links

    @property
    def shares(self) -> ShareLinks:
        """Share links: `create`, `list` and `revoke` use this client's API key; `get` and `open` are public and send
        no credential."""
        return ShareLinks(self)

    # ------------------------------------------------------------ standard library

    def standard_videos(self, limit: int = 50) -> list[dict]:
        """This account's standard jobs, newest first."""
        return self._request("GET", "/v1/standard/videos", params={"limit": limit}).json()

    def delete(self, job_id: str) -> None:
        """Deletes a job's stored content, in either mode: a private job's sealed files, or a standard
        job's video, prompt, inputs and preview. Videos are kept until their owner deletes them; the
        charge record and receipt stay. A private job's output key opens nothing afterwards."""
        self._request("DELETE", f"/v1/videos/{job_id}")

    def standard_job(self, job_id: str, profile_id: str = "") -> StandardVideoJob:
        """A handle on an existing standard job, to wait on, download or delete it."""
        return StandardVideoJob(self, job_id, profile_id)

    def upload_standard(self, role: InputRole, data: bytes, mime: str) -> dict:
        """Uploads one standard-mode input as it is. Uploads are scanned: a match is `upload_blocked`."""
        return self._request(
            "POST", "/v1/standard/uploads", params={"role": role.value}, content=data, headers={"content-type": mime}
        ).json()

    # ------------------------------------------------------------ generation

    def generate(
        self,
        prompt: str,
        *,
        model: str | None = None,
        family: str | None = None,
        mode: Mode | str | None = None,
        duration_s: float | None = None,
        resolution: str | None = None,
        aspect_ratio: str | None = None,
        fps: int | None = None,
        audio: bool = True,
        seed: int | None = None,
        negative_prompt: str | None = None,
        first_frame: Source | None = None,
        last_frame: Source | None = None,
        keyframes: Iterable[tuple[Source, float]] = (),
        reference_images: Iterable[Source] = (),
        reference_videos: Iterable[Source] = (),
        reference_audio: Iterable[Source] = (),
        source_video: Source | None = None,
        source_audio: Source | None = None,
        options: dict[str, Any] | None = None,
        privacy: Privacy = "private",
        wait: bool = True,
        timeout: float = 1800.0,
        on_progress: ProgressFn | None = None,
    ) -> GenerationResult | VideoJob | StandardVideoJob:
        """`privacy="private"` (default) encrypts on this machine to an attested confidential enclave.
        `privacy="standard"` sends the prompt and inputs to KunoWorld readable: KunoWorld and the
        GPU provider can see them and the video; there is no client-side encryption."""
        if privacy not in ("private", "standard"):
            raise KunoError(0, "invalid_privacy", 'privacy must be "private" or "standard".')
        inputs: list[Input] = []
        if first_frame is not None:
            inputs.append(Input.load(InputRole.FIRST_FRAME, first_frame))
        if last_frame is not None:
            inputs.append(Input.load(InputRole.LAST_FRAME, last_frame))
        inputs += [Input.load(InputRole.KEYFRAME, src, time_s=t) for src, t in keyframes]
        inputs += [Input.load(InputRole.REFERENCE_IMAGE, src) for src in reference_images]
        inputs += [Input.load(InputRole.REFERENCE_VIDEO, src) for src in reference_videos]
        inputs += [Input.load(InputRole.REFERENCE_AUDIO, src) for src in reference_audio]
        if source_video is not None:
            inputs.append(Input.load(InputRole.SOURCE_VIDEO, source_video))
        if source_audio is not None:
            inputs.append(Input.load(InputRole.SOURCE_AUDIO, source_audio))

        if privacy == "standard":
            standard = self.submit_standard(
                prompt,
                inputs=inputs,
                model=model,
                family=family,
                mode=Mode(mode) if mode else None,
                duration_s=duration_s,
                resolution=resolution,
                aspect_ratio=aspect_ratio,
                fps=fps,
                audio=audio,
                seed=seed,
                negative_prompt=negative_prompt,
                options=options,
            )
            return standard.wait(timeout=timeout, on_progress=on_progress) if wait else standard

        prepared = self.prepare(
            prompt,
            inputs=inputs,
            model=model,
            family=family,
            mode=Mode(mode) if mode else None,
            duration_s=duration_s,
            resolution=resolution,
            aspect_ratio=aspect_ratio,
            fps=fps,
            audio=audio,
            seed=seed,
            negative_prompt=negative_prompt,
            options=options,
        )
        job = self.submit(prepared)
        return job.wait(timeout=timeout, on_progress=on_progress) if wait else job

    def prepare(
        self,
        prompt: str,
        *,
        inputs: list[Input] | None = None,
        model: str | None = None,
        family: str | None = None,
        mode: Mode | None = None,
        duration_s: float | None = None,
        resolution: str | None = None,
        aspect_ratio: str | None = None,
        fps: int | None = None,
        audio: bool = True,
        seed: int | None = None,
        negative_prompt: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> PreparedJob:
        """Routes, verifies the enclave, encrypts and uploads inputs, and seals the request."""
        inputs = inputs or []
        mode = mode or infer_mode(i.role for i in inputs)
        route = self.route(mode, model, family)
        profile = self.profile(route.profile_id)
        params = _fit_params(profile, mode, inputs, duration_s, resolution, aspect_ratio, fps, audio, route.fallback_reason)
        enclave = self._pick_enclave(route)

        job_id = str(uuid.uuid4())
        session = SenderSession(b64d(enclave["hpke_public_key"]))
        refs, blob_ids, blob_bytes = [], [], []
        for index, item in enumerate(inputs):
            sealed = encrypt_blob(session.input_key, input_label(job_id, index), item.data)
            blob_ids.append(self._request("POST", "/v1/blobs", content=sealed).json()["blob_id"])
            blob_bytes.append(sealed)
            refs.append(
                InputRef(
                    index=index,
                    role=item.role,
                    mime=item.mime,
                    sha256=sha256_hex(item.data),
                    size=len(item.data),
                    time_s=item.time_s,
                    strength=item.strength,
                    hint=item.hint,
                    start_s=item.start_s,
                    end_s=item.end_s,
                )
            )
        payload = SealedPayload(prompt=prompt, negative_prompt=negative_prompt, seed=seed, inputs=refs, options=options or {})
        ciphertext = session.seal(
            payload.model_dump_json().encode(), job_aad(job_id, enclave["enclave_id"], params, blob_ids)
        )
        request = JobCreate(
            job_id=job_id,
            params=params,
            enclave_id=enclave["enclave_id"],
            enc=b64e(session.enc),
            ciphertext=b64e(ciphertext),
            input_blob_ids=blob_ids,
        )
        return PreparedJob(
            request=request,
            output_key=session.output_key,
            signing_public_key=b64d(enclave["signing_public_key"]),
            fallback_reason=route.fallback_reason,
            input_blob_bytes=blob_bytes,
        )

    def submit_standard(
        self,
        prompt: str,
        *,
        inputs: list[Input] | None = None,
        model: str | None = None,
        family: str | None = None,
        mode: Mode | None = None,
        duration_s: float | None = None,
        resolution: str | None = None,
        aspect_ratio: str | None = None,
        fps: int | None = None,
        audio: bool = True,
        seed: int | None = None,
        negative_prompt: str | None = None,
        options: dict[str, Any] | None = None,
        webhook_url: str | None = None,
    ) -> StandardVideoJob:
        """Standard mode: uploads the inputs as they are and lets the gateway seal the job to a miner."""
        inputs = inputs or []
        mode = mode or infer_mode(i.role for i in inputs)
        route = self.route(mode, model, family, privacy="standard")
        profile = self.profile(route.profile_id)
        params = _fit_params(profile, mode, inputs, duration_s, resolution, aspect_ratio, fps, audio, route.fallback_reason)
        refs = []
        for index, item in enumerate(inputs):
            upload = self.upload_standard(item.role, item.data, item.mime)
            ref: dict[str, Any] = {"upload_id": upload["upload_id"], "index": index, "role": item.role.value}
            for key in ("time_s", "strength", "hint", "start_s", "end_s"):
                if getattr(item, key) is not None:
                    ref[key] = getattr(item, key)
            refs.append(ref)
        body: dict[str, Any] = {
            "job_id": str(uuid.uuid4()),
            "params": params.model_dump(mode="json"),
            "prompt": prompt,
            "negative_prompt": negative_prompt,
            "seed": seed,
            "options": options or {},
            "inputs": refs,
        }
        if webhook_url:
            body["webhook_url"] = webhook_url
        status = JobStatus.model_validate(self._request("POST", "/v1/standard/videos", json=body).json())
        return StandardVideoJob(self, status.job_id, status.params.profile_id, route.fallback_reason)

    def submit(self, prepared: PreparedJob) -> VideoJob:
        self._request("POST", "/v1/videos", json=prepared.request.model_dump(mode="json"))
        return VideoJob(
            self,
            prepared.request.job_id,
            prepared.output_key,
            prepared.signing_public_key,
            prepared.request.params.profile_id,
            prepared.fallback_reason,
        )

    def _pick_enclave(self, route: RouteResponse) -> dict:
        manifest = self.manifest()
        for enclave in route.enclaves:
            evidence = AttestationEvidence.model_validate(enclave["evidence"])
            verdict = verify_evidence(evidence, manifest)
            if (
                verdict.ok
                and verdict.enclave_id == enclave["enclave_id"]
                and evidence.hpke_public_key == enclave["hpke_public_key"]
                and evidence.signing_public_key == enclave["signing_public_key"]
                and route.profile_id in evidence.profiles
            ):
                return enclave
        raise KunoError(503, "no_attested_worker", "No worker with valid attestation is available for this model right now.")


class VideoJob:
    def __init__(
        self,
        client: KunoClient,
        job_id: str,
        output_key: bytes,
        signing_public_key: bytes,
        profile_id: str,
        fallback_reason: str | None = None,
    ):
        self.client = client
        self.job_id = job_id
        self.output_key = output_key
        self.signing_public_key = signing_public_key
        self.profile_id = profile_id
        self.fallback_reason = fallback_reason

    def export(self) -> dict[str, str | None]:
        """Everything needed to fetch and open the video later. Treat it as a secret."""
        return {
            "job_id": self.job_id,
            "output_key": b64e(self.output_key),
            "signing_public_key": b64e(self.signing_public_key),
            "profile_id": self.profile_id,
            "fallback_reason": self.fallback_reason,
        }

    @classmethod
    def restore(cls, client: KunoClient, data: dict) -> VideoJob:
        return cls(
            client,
            data["job_id"],
            b64d(data["output_key"]),
            b64d(data["signing_public_key"]),
            data["profile_id"],
            data.get("fallback_reason"),
        )

    def status(self) -> JobStatus:
        return JobStatus.model_validate(self.client._request("GET", f"/v1/videos/{self.job_id}").json())

    def cancel(self) -> JobStatus:
        return JobStatus.model_validate(self.client._request("POST", f"/v1/videos/{self.job_id}/cancel").json())

    def delete(self) -> None:
        """Deletes the sealed video and inputs stored for this job. Discard the exported handle too."""
        self.client.delete(self.job_id)

    def wait(self, timeout: float = 1800.0, poll_s: float = 1.0, on_progress: ProgressFn | None = None) -> GenerationResult:
        return _wait(self, timeout, poll_s, on_progress)

    def result(self, status: JobStatus | None = None) -> GenerationResult:
        status = status or self.status()
        if status.status is not JobState.SUCCEEDED or status.receipt is None or status.output_blob_id is None:
            raise KunoError(0, "not_ready", f"Job {self.job_id} is {status.status.value}.")
        receipt = status.receipt
        sealed = self.client._request("GET", f"/v1/blobs/{status.output_blob_id}").content
        if sha256_hex(sealed) != receipt.body.output_digest:
            raise KunoError(0, "integrity", "The downloaded video does not match the enclave's receipt.")
        if not verify_receipt(receipt, self.signing_public_key) or receipt.body.job_id != self.job_id:
            raise KunoError(0, "integrity", "The receipt was not signed by the attested enclave for this job.")
        video = decrypt_blob(self.output_key, output_label(self.job_id), sealed)
        if sha256_hex(video) != receipt.body.content_digest:
            raise KunoError(0, "integrity", "The decrypted video does not match the receipt.")
        return GenerationResult(self.job_id, video, receipt, self.profile_id, self.fallback_reason)


class StandardVideoJob:
    """A standard job. It holds no secrets: the account's credentials fetch the video."""

    privacy: Privacy = "standard"

    def __init__(self, client: KunoClient, job_id: str, profile_id: str, fallback_reason: str | None = None):
        self.client = client
        self.job_id = job_id
        self.profile_id = profile_id
        self.fallback_reason = fallback_reason

    def export(self) -> dict[str, str | None]:
        return {
            "privacy": "standard",
            "job_id": self.job_id,
            "profile_id": self.profile_id,
            "fallback_reason": self.fallback_reason,
        }

    @classmethod
    def restore(cls, client: KunoClient, data: dict) -> StandardVideoJob:
        return cls(client, data["job_id"], data.get("profile_id", ""), data.get("fallback_reason"))

    def status(self) -> JobStatus:
        return JobStatus.model_validate(self.client._request("GET", f"/v1/videos/{self.job_id}").json())

    def cancel(self) -> JobStatus:
        return JobStatus.model_validate(self.client._request("POST", f"/v1/videos/{self.job_id}/cancel").json())

    def wait(self, timeout: float = 1800.0, poll_s: float = 1.0, on_progress: ProgressFn | None = None) -> GenerationResult:
        return _wait(self, timeout, poll_s, on_progress)

    def result(self, status: JobStatus | None = None) -> GenerationResult:
        """Downloads the stored video and checks it against the receipt's content digest."""
        status = status or self.status()
        if status.status is not JobState.SUCCEEDED or status.receipt is None:
            raise KunoError(0, "not_ready", f"Job {self.job_id} is {status.status.value}.")
        video = self.client._request("GET", f"/v1/standard/videos/{self.job_id}/video").content
        if sha256_hex(video) != status.receipt.body.content_digest:
            raise KunoError(0, "integrity", "The downloaded video does not match the enclave's receipt.")
        profile_id = self.profile_id or status.params.profile_id
        return GenerationResult(self.job_id, video, status.receipt, profile_id, self.fallback_reason, privacy="standard")

    def thumbnail(self) -> bytes:
        """A JPEG frame of the finished video."""
        return self.client._request("GET", f"/v1/standard/videos/{self.job_id}/thumbnail").content

    def delete(self) -> None:
        """Deletes the stored video, prompt, inputs and preview. The billing record stays."""
        self.client.delete(self.job_id)


# A share token and an output key are both 32 bytes written as base64url: 43 characters.
_BASE64URL_32 = re.compile(r"[A-Za-z0-9_-]{43}")


def parse_share_link(link: str) -> tuple[str, str | None]:
    """A share link's token, and the key from its `#k=` fragment when it has one. Accepts a full link
    (`https://kunoworld.com/s/<token>#k=<key>`), a path (`/s/<token>`) or a bare token. Anything else raises
    `not_found` before a request is made."""
    before, _, fragment = link.strip().partition("#")
    token = before.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    if not _BASE64URL_32.fullmatch(token):
        raise KunoError(0, "not_found", "That isn't a valid share link.")
    key = parse_qs(fragment).get("k", [""])[0] if fragment else ""
    return token, key or None


def share_url_with_key(url: str, output_key: str | bytes) -> str:
    """A private video's share link with its key as the fragment, `#k=...`. Browsers never send a fragment, so the key
    doesn't reach KunoWorld, but anyone given the whole link can open the video. `output_key` is the 32 raw bytes
    (`VideoJob.output_key`) or their base64url text (`export()["output_key"]`). Replaces any fragment."""
    return f"{url.partition('#')[0]}#k={_output_key_text(output_key)}"


def _output_key_text(output_key: str | bytes) -> str:
    text = b64e(output_key) if isinstance(output_key, bytes) and len(output_key) == 32 else output_key
    if not isinstance(text, str) or not _BASE64URL_32.fullmatch(text):
        raise KunoError(0, "invalid_key", "An output key is 32 bytes, written as base64url (43 characters).")
    return text


def _output_key_bytes(output_key: str | bytes) -> bytes:
    raw = output_key if isinstance(output_key, bytes) else b64d(output_key)
    if len(raw) != 32:
        raise ValueError("an output key is 32 bytes")
    return raw


def _signed_by(receipt: Receipt, signing_public_key: Any) -> bool:
    if not isinstance(signing_public_key, str) or not signing_public_key:
        return False
    try:
        return verify_receipt(receipt, b64d(signing_public_key))
    except ValueError:
        return False


class ShareLinks:
    """`client.shares`: links that let anyone holding them watch one video.

    `create`, `list` and `revoke` use the client's API key. `get` and `open` are public and send no credential."""

    def __init__(self, client: KunoClient):
        self._client = client

    def create(self, job: str | VideoJob | StandardVideoJob, expires_at: float | datetime | None = None) -> dict:
        """Makes a link to one of this account's finished videos. Returns the owner's row plus `token`, `url_path` and
        `url`, shown only now, and `key_included`. Given a private `VideoJob`, `url` carries its key as `#k=...`;
        given a job id it can't, so add it with `share_url_with_key`.

        `expires_at` is Unix seconds or a datetime (a naive one is local time), from a minute to ten years ahead;
        None means until revoked."""
        job_id = job if isinstance(job, str) else job.job_id
        # Check the key before the link exists, so a bad key can't leave a link behind.
        key = _output_key_text(job.output_key) if isinstance(job, VideoJob) else None
        if isinstance(expires_at, datetime):
            expires_at = expires_at.timestamp()
        if expires_at is not None and (
            isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)) or not math.isfinite(expires_at)
        ):
            raise KunoError(0, "invalid_expiry", ERROR_CODES["invalid_expiry"])
        body = {"expires_at": None if expires_at is None else float(expires_at)}
        link = self._client._request("POST", f"/v1/videos/{quote(job_id, safe='')}/shares", json=body).json()
        link["key_included"] = False
        if key is not None and link.get("privacy") == "private":
            link["url"] = share_url_with_key(link["url"], key)
            link["key_included"] = True
        return link

    def revoke(self, share_id: str) -> dict:
        """Stops a link for good and returns its row, now `revoked`. Revoking twice is harmless."""
        return self._client._request("DELETE", f"/v1/account/shares/{quote(share_id, safe='')}").json()

    def get(self, token_or_url: str) -> dict:
        """Public, no credential sent: what a link shows (`privacy`, `profile_id`, `created_at`, `shared_at`,
        `expires_at`, `content_digest`, `receipt`, `signing_public_key`), plus its `token` and the fragment's `key`."""
        token, key = parse_share_link(token_or_url)
        details = self._client._request("GET", f"/v1/shares/{token}", auth=False).json()
        return {**details, "token": token, "key": key}

    def open(self, url: str, key: str | bytes | None = None) -> GenerationResult:
        """Public, no credential sent: downloads a shared video and checks it against the enclave-signed receipt. A
        private link needs its key, from the link's fragment or `key`; the video is decrypted here."""
        details = self.get(url)
        output_key = key if key is not None else details["key"]
        private = details.get("privacy") == "private"
        if private and not output_key:
            raise KunoError(0, "missing_key", ERROR_CODES["missing_key"])
        digest = details.get("content_digest")
        try:
            receipt = Receipt.model_validate(details.get("receipt"))
        except ValueError:  # pydantic's ValidationError is a ValueError
            raise KunoError(0, "integrity", "The link has no valid receipt to check the video against.") from None
        if receipt.body.content_digest != digest:
            raise KunoError(0, "integrity", "The link's receipt doesn't describe this video.")
        data = self._client._request("GET", f"/v1/shares/{details['token']}/video", auth=False).content
        profile_id = details.get("profile_id") or receipt.body.profile_id
        if not private:
            if sha256_hex(data) != digest:
                raise KunoError(0, "integrity", "The shared video does not match its receipt.")
            return GenerationResult(receipt.body.job_id, data, receipt, profile_id, privacy="standard")
        if sha256_hex(data) != receipt.body.output_digest:
            raise KunoError(0, "integrity", "The shared video does not match the enclave's receipt.")
        if not _signed_by(receipt, details.get("signing_public_key")):
            raise KunoError(0, "integrity", "The receipt was not signed by the enclave that made this video.")
        try:
            # The label binds the blob to the signed receipt's job: a blob sealed for another job doesn't open.
            video = decrypt_blob(_output_key_bytes(output_key), output_label(receipt.body.job_id), data)
        except (DecryptionError, ValueError):
            raise KunoError(0, "decrypt_failed", "This video didn't open with the link's key.") from None
        if sha256_hex(video) != digest:
            raise KunoError(0, "integrity", "The decrypted video does not match the receipt.")
        return GenerationResult(receipt.body.job_id, video, receipt, profile_id, privacy="private")

    def list(self, job_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """This account's links, newest first, each with `status` (`active`, `revoked`, `expired`, `video_deleted`,
        `video_removed`, `account_closed` or `unavailable`) and `view_count`. Tokens aren't kept, so they aren't here."""
        params: dict[str, Any] = {"limit": limit}
        if job_id:
            params["job_id"] = job_id
        return self._client._request("GET", "/v1/account/shares", params=params).json()


def _wait(
    job: VideoJob | StandardVideoJob, timeout: float, poll_s: float, on_progress: ProgressFn | None
) -> GenerationResult:
    deadline = time.time() + timeout
    while True:
        status = job.status()
        if on_progress:
            on_progress(status)
        if status.status is JobState.SUCCEEDED:
            return job.result(status)
        if status.status.terminal:
            code = status.error_code or f"job_{status.status.value}"
            raise KunoError(0, code, status.error or "The job did not complete.")
        if time.time() > deadline:
            raise KunoError(0, "timeout", f"Job {job.job_id} is still {status.status.value}.")
        time.sleep(poll_s)


def _fit_params(
    profile: ModelProfile,
    mode: Mode,
    inputs: list[Input],
    duration_s: float | None,
    resolution: str | None,
    aspect_ratio: str | None,
    fps: int | None,
    audio: bool,
    fallback_reason: str | None,
) -> GenerationParams:
    """Fills defaults from the profile. After a fallback, adapts requested values to the new model."""
    lim = profile.limits
    lenient = fallback_reason is not None
    if resolution is None or (lenient and resolution not in lim.sizes):
        resolution = next(iter(lim.sizes))
    sizes = lim.sizes.get(resolution, {})
    if aspect_ratio is None or (lenient and aspect_ratio not in sizes):
        aspect_ratio = "16:9" if "16:9" in sizes else next(iter(sizes), "16:9")
    if fps is None or (lenient and fps not in lim.fps):
        fps = lim.default_fps
    if duration_s is None:
        duration_s = min(max(5.0, lim.min_duration_s), lim.max_duration_s)
    elif lenient:
        duration_s = min(max(duration_s, lim.min_duration_s), lim.max_duration_s)
    return GenerationParams(
        profile_id=profile.id,
        mode=mode,
        duration_s=float(duration_s),
        resolution=resolution,
        aspect_ratio=aspect_ratio,
        fps=fps,
        audio=audio and lim.audio,
        input_roles=[i.role for i in inputs],
    )
