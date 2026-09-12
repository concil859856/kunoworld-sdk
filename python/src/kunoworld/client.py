from __future__ import annotations

import time
import uuid
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Union

import httpx

from kuno_protocol.attestation import AttestationEvidence, GoldenManifest, verify_evidence
from kuno_protocol.blobs import decrypt_blob, encrypt_blob
from kuno_protocol.canonical import b64d, b64e, sha256_hex
from kuno_protocol.crypto import SenderSession
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


class KunoError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.status, self.code, self.message = status, code, message


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

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        response = self._http.request(method, path, **kwargs)
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", {})
            except ValueError:
                detail = {}
            if not isinstance(detail, dict):
                detail = {"message": str(detail)}
            raise KunoError(response.status_code, detail.get("code", "error"), detail.get("message", response.text[:200]))
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

    def route(self, mode: Mode, model: str | None = None, family: str | None = None) -> RouteResponse:
        params = {"mode": mode.value}
        if model:
            params["profile_id"] = model
        if family:
            params["family"] = family
        return RouteResponse.model_validate(self._request("GET", "/v1/route", params=params).json())

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
        wait: bool = True,
        timeout: float = 1800.0,
        on_progress: ProgressFn | None = None,
    ) -> GenerationResult | VideoJob:
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

    def wait(self, timeout: float = 1800.0, poll_s: float = 1.0, on_progress: ProgressFn | None = None) -> GenerationResult:
        deadline = time.time() + timeout
        while True:
            status = self.status()
            if on_progress:
                on_progress(status)
            if status.status is JobState.SUCCEEDED:
                return self.result(status)
            if status.status.terminal:
                code = status.error_code or f"job_{status.status.value}"
                raise KunoError(0, code, status.error or "The job did not complete.")
            if time.time() > deadline:
                raise KunoError(0, "timeout", f"Job {self.job_id} is still {status.status.value}.")
            time.sleep(poll_s)

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
