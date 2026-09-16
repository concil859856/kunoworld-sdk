"""What the KunoWorld MCP server's tools do, without MCP: plain methods over the Python SDK that return JSON-ready dicts.
`server.py` wraps each one for FastMCP.

Everything a Private job needs to stay private happens here, on this machine: the SDK checks the worker's attestation,
encrypts the prompt, shots and images to it, verifies the enclave-signed receipt and decrypts the video. The job handle
with the output key goes only to the local job store (`jobs.py`). No prompt is logged or stored.
"""

from __future__ import annotations

import math
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from kuno_protocol.attestation import GoldenManifest
from kuno_protocol.canonical import sha256_hex
from kuno_protocol.profiles import InputRole, Mode
from kuno_protocol.schemas import JOB_ID_RE, GenerationParams, JobState, JobStatus

from ..client import ERROR_CODES, GenerationResult, Input, KunoClient, KunoError, Quote, Shot, StandardVideoJob, VideoJob
from .jobs import FILE_MODE, JobStore, default_directory

# The production gateway, as `KunoClient`'s default.
PRODUCTION_API_URL = "https://api.kunoworld.com"
PRIVACY_MODES = ("private", "standard")
FINISHED = tuple(state.value for state in JobState if state.terminal)


class ConfigError(ValueError):
    """The server's environment is unusable; it says which variable."""


@dataclass(frozen=True)
class Config:
    """The server's settings, from `KUNOWORLD_*` environment variables (`from_env`)."""

    api_key: str | None = None
    api_url: str = PRODUCTION_API_URL
    # The mode a job gets when the agent doesn't pick one.
    privacy: str = "private"
    # A hard cap on every job's price, in USD. An agent's max_price_usd can lower it, never raise it.
    max_job_usd: float | None = None
    output_dir: Path = field(default_factory=lambda: Path.home() / "KunoWorld")
    jobs_dir: Path = field(default_factory=default_directory)
    # Zero-trust attestation: a pinned golden manifest, or the subnet owner's key that signs it (KunoClient's own options).
    manifest_path: Path | None = None
    owner_public_key: str | None = None
    # Development gateways only (KUNO_ALLOW_COUNTRY_OVERRIDE): the country routing assumes.
    country: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        env = os.environ if env is None else env

        def text(name: str) -> str | None:
            value = (env.get(name) or "").strip()
            return value or None

        privacy = (text("KUNOWORLD_PRIVACY") or "private").lower()
        if privacy not in PRIVACY_MODES:
            raise ConfigError('KUNOWORLD_PRIVACY must be "private" or "standard".')
        cap = None
        if (raw := text("KUNOWORLD_MAX_JOB_USD")) is not None:
            try:
                cap = float(raw)
            except ValueError:
                cap = math.nan
            if not math.isfinite(cap) or cap < 0:
                raise ConfigError("KUNOWORLD_MAX_JOB_USD must be an amount in US dollars, zero or more.")
        defaults = cls()
        manifest = text("KUNOWORLD_MANIFEST")
        return cls(
            api_key=text("KUNOWORLD_API_KEY"),
            api_url=(text("KUNOWORLD_API_URL") or PRODUCTION_API_URL).rstrip("/"),
            privacy=privacy,
            max_job_usd=cap,
            output_dir=Path(text("KUNOWORLD_OUTPUT_DIR") or defaults.output_dir).expanduser(),
            jobs_dir=Path(text("KUNOWORLD_JOBS_DIR") or defaults.jobs_dir).expanduser(),
            manifest_path=Path(manifest).expanduser() if manifest else None,
            owner_public_key=text("KUNOWORLD_OWNER_PUBLIC_KEY"),
            country=text("KUNOWORLD_COUNTRY"),
        )

    @property
    def attestation_trust(self) -> str:
        """What a Private job's worker was checked against, in words an agent can pass on."""
        if self.manifest_path is not None:
            return "the pinned golden manifest in KUNOWORLD_MANIFEST"
        if self.owner_public_key:
            return "the golden manifest, checked against the subnet owner's signature (KUNOWORLD_OWNER_PUBLIC_KEY)"
        return ("the golden manifest as the gateway serves it, not pinned: set KUNOWORLD_MANIFEST or KUNOWORLD_OWNER_PUBLIC_KEY "
                "so the check doesn't rely on KunoWorld's gateway")


def make_client(config: Config) -> KunoClient:
    manifest = GoldenManifest.model_validate_json(config.manifest_path.read_text()) if config.manifest_path else None
    return KunoClient(
        config.api_key or "", config.api_url, manifest=manifest, owner_public_key=config.owner_public_key, country=config.country
    )


class ToolFailure(Exception):
    """A refusal made here rather than by the gateway, shown to the agent as `code: message`."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.details = code, message, details or {}


def describe_error(exc: BaseException) -> str:
    """One readable line for the agent, starting with the error code. Gateway messages never carry prompts or keys."""
    if isinstance(exc, ToolFailure):
        return str(exc)
    if isinstance(exc, KunoError):
        extra = []
        if exc.reasons:
            extra.append("reasons: " + ", ".join(exc.reasons))
        if exc.restricted_until is not None:
            # 253402300799 (9999-12-31) is how an indefinite restriction is written.
            until = time.gmtime(min(exc.restricted_until, 253402300799))
            extra.append(f"restricted until {time.strftime('%Y-%m-%d %H:%M UTC', until)}")
        if exc.details.get("max_duration_s") is not None:
            extra.append(f"longest available: {exc.details['max_duration_s']:g} s")
        if exc.explanation and exc.explanation not in exc.message:
            extra.append(exc.explanation)
        return f"{exc.code}: {exc.message}" + (f" ({'; '.join(extra)})" if extra else "")
    return f"error: {exc}"


def _shots(items: list[Mapping[str, Any]] | None, *, require_prompts: bool) -> list[Shot] | None:
    if items is None:
        return None
    shots = []
    for number, item in enumerate(items, start=1):
        prompt = item.get("prompt") or ""
        if require_prompts and not prompt.strip():
            raise ToolFailure("invalid_shots", f"Shot {number} needs a prompt.")
        shots.append(Shot(prompt, item.get("duration_s"), item.get("join")))
    return shots


def _existing(path: str) -> Path:
    found = Path(path).expanduser()
    if not found.is_file():
        raise ToolFailure("input_not_found", f"There is no file at {path}.")
    return found


def _check_job_id(job_id: str) -> None:
    if not isinstance(job_id, str) or not JOB_ID_RE.match(job_id):
        raise ToolFailure("invalid_job_id", "A job id is a lowercase UUID, as generate_video or list_jobs returned it.")


_UNSAFE = re.compile(r"[^A-Za-z0-9._ -]+")


def _safe_stem(filename: str | None) -> str | None:
    """A file name an agent chose, reduced to a plain name in the output directory: no directories, no hidden files."""
    if not filename:
        return None
    stem = Path(filename).name
    if stem.lower().endswith(".mp4"):
        stem = stem[:-4]
    stem = _UNSAFE.sub("-", stem).strip(" .-")[:100]
    return stem or None


def _settings(params: GenerationParams) -> dict[str, Any]:
    settings: dict[str, Any] = {
        "mode": params.mode.value,
        "duration_s": round(params.duration_s, 3),
        "resolution": params.resolution,
        "aspect_ratio": params.aspect_ratio,
        "fps": params.fps,
        "audio": params.audio,
        "input_roles": [role.value for role in params.input_roles],
    }
    if params.shots is not None:
        settings["shots"] = [{"duration_s": shot.duration_s, "join": shot.join} for shot in params.shots]
    return settings


def _model_row(model: Mapping[str, Any]) -> dict[str, Any]:
    limits, pricing = model["limits"], model["pricing"]
    durations: dict[str, Any] = {"min": limits["min_duration_s"], "max": limits["max_duration_s"], "step": limits.get("duration_step_s", 1.0)}
    if limits.get("max_duration_s_by_fps"):
        durations["max_at_fps"] = limits["max_duration_s_by_fps"]
    board = limits.get("storyboard")
    row: dict[str, Any] = {
        "id": model["id"],
        "name": model["name"],
        "family": model["family"],
        "available": bool(model.get("enabled", True) and model.get("available_in_region", True) and model.get("workers", 0) > 0),
        "workers": model.get("workers", 0),
        "modes": model["modes"],
        "privacy_modes": model.get("privacy_modes", ["private"]),
        "duration_s": durations,
        "sizes": {resolution: list(ratios) for resolution, ratios in limits["sizes"].items()},
        "fps": limits["fps"],
        "default_fps": limits["default_fps"],
        "audio": limits["audio"],
        "max_prompt_chars": limits.get("max_prompt_chars"),
        "negative_prompt": limits.get("negative_prompt", False),
        "inputs": limits.get("max_inputs", {}),
        "storyboard": None if not board else {
            "max_shots": board["max_shots"],
            "max_total_s": board["max_total_s"],
            "joins": ["fresh", "continue", "cut"],
            # Frames a continue or cut shot repeats from the shot before, trimmed from the video (LTX-2.5: 1 + 8 × (n − 1)).
            "overlap_frames": 1 + 8 * (board.get("overlap_latent_frames", 3) - 1),
        },
        "usd_per_second": {"private": pricing["usd_per_second"], "standard": pricing.get("standard_usd_per_second")},
        "min_job_usd": pricing.get("min_job_usd", 0.0),
    }
    if pricing.get("fps_multipliers"):
        row["fps_multipliers"] = pricing["fps_multipliers"]
    if pricing.get("long_clip"):
        row["private_long_clip"] = pricing["long_clip"]
    if not model.get("available_in_region", True):
        row["unavailable_reason"] = "not licensed in this region"
    elif not model.get("enabled", True):
        row["unavailable_reason"] = "switched off"
    elif not model.get("workers", 0):
        row["unavailable_reason"] = "no workers online"
    return row


class KunoTools:
    """The tools, as plain methods. `client_factory` makes a KunoClient per call (tests pass fakes); every call closes it."""

    poll_s = 2.0

    def __init__(
        self,
        config: Config,
        client_factory: Callable[[Config], KunoClient] = make_client,
        store: JobStore | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.config = config
        self._factory = client_factory
        self.store = store or JobStore(config.jobs_dir)
        self._clock, self._sleep = clock, sleep

    # ------------------------------------------------------------ plumbing

    def _client(self, *, key_required: bool = True) -> KunoClient:
        if key_required and not self.config.api_key:
            raise ToolFailure(
                "missing_api_key",
                "This KunoWorld server has no API key. The user needs to create one on their KunoWorld account page and set "
                "KUNOWORLD_API_KEY in this MCP server's configuration.",
            )
        return self._factory(self.config)

    def _privacy(self, privacy: str | None) -> str:
        chosen = privacy or self.config.privacy
        if chosen not in PRIVACY_MODES:
            raise ToolFailure("invalid_privacy", 'privacy is "private" or "standard".')
        return chosen

    def _budget(self, max_price_usd: float | None) -> float:
        """The cap for one job: the agent's max_price_usd, never above KUNOWORLD_MAX_JOB_USD; one of them is required."""
        if max_price_usd is not None and (isinstance(max_price_usd, bool) or not math.isfinite(max_price_usd) or max_price_usd < 0):
            raise ToolFailure("invalid_budget", "max_price_usd is an amount in US dollars, zero or more.")
        caps = [cap for cap in (max_price_usd, self.config.max_job_usd) if cap is not None]
        if not caps:
            raise ToolFailure(
                "budget_required",
                "Pass max_price_usd, the most this video may cost in US dollars. Call quote_price first and agree the price "
                "with the user.",
            )
        return min(caps)

    def _inputs(
        self, first_frame_path: str | None, last_frame_path: str | None, reference_image_paths: list[str] | None
    ) -> list[tuple[InputRole, Path]]:
        found = []
        if first_frame_path:
            found.append((InputRole.FIRST_FRAME, _existing(first_frame_path)))
        if last_frame_path:
            found.append((InputRole.LAST_FRAME, _existing(last_frame_path)))
        for path in reference_image_paths or ():
            found.append((InputRole.REFERENCE_IMAGE, _existing(path)))
        return found

    def _quote_json(self, quote: Quote) -> dict[str, Any]:
        cap = self.config.max_job_usd
        return {
            "price_usd": quote.price_usd,
            "currency": quote.currency,
            "privacy": quote.privacy,
            "model": quote.profile_id,
            "model_name": quote.profile_name,
            "requested_model": quote.requested_profile_id,
            "fallback_reason": quote.fallback_reason,
            "settings": _settings(quote.params),
            "breakdown": asdict(quote.breakdown),
            "prices_are_placeholders": quote.placeholder,
            "balance_usd": quote.balance_usd,
            "balance_covers": quote.balance_covers,
            "max_job_usd": cap,
            "within_max_job_usd": None if cap is None else quote.price_usd <= cap,
        }

    def _status_json(self, status: JobStatus, record: Mapping[str, Any] | None = None) -> dict[str, Any]:
        params = status.params
        succeeded = status.status is JobState.SUCCEEDED
        result: dict[str, Any] = {
            "job_id": status.job_id,
            "status": status.status.value,
            "stage": status.stage,
            "progress": round(status.progress, 3),
            "privacy": status.privacy,
            "model": params.profile_id,
            "mode": params.mode.value,
            "duration_s": round(params.duration_s, 3),
            "shots": len(params.shots) if params.shots else None,
            "price_usd": status.price_usd,
            "error_code": status.error_code,
            "error": status.error,
            "created_at": status.created_at,
            "updated_at": status.updated_at,
            "can_download": succeeded and (status.privacy == "standard" or bool(record and record.get("output_key"))),
        }
        if status.status in (JobState.FAILED, JobState.CANCELED):
            result["refunded"] = True
            if status.error_code in ERROR_CODES:
                result["error_explanation"] = ERROR_CODES[status.error_code]
        if record and record.get("saved_path"):
            result["saved_path"] = record["saved_path"]
        return result

    def _remember(self, status: JobStatus) -> dict[str, Any] | None:
        record = self.store.load(status.job_id)
        if record is not None and (record.get("status"), record.get("stage")) != (status.status.value, status.stage):
            record = self.store.update(status.job_id, status=status.status.value, stage=status.stage)
        return record

    # ------------------------------------------------------------ tools

    def list_models(self) -> dict[str, Any]:
        with self._client(key_required=False) as client:
            data = client.models()
        return {
            "prices_are_placeholders": bool(data.get("pricing_placeholder", False)),
            "country": data.get("country"),
            "workers_online": data.get("workers_online"),
            "models": [_model_row(model) for model in data.get("models", [])],
            "pricing": "usd_per_second is per output second, by resolution. Multipliers apply to the whole job; no job costs "
            "less than min_job_usd. A storyboard costs its stitched seconds. quote_price gives the exact price.",
        }

    def quote_price(
        self,
        *,
        model: str | None = None,
        family: str | None = None,
        mode: str | None = None,
        duration_s: float | None = None,
        resolution: str | None = None,
        aspect_ratio: str | None = None,
        fps: int | None = None,
        audio: bool = True,
        privacy: str | None = None,
        first_frame_path: str | None = None,
        last_frame_path: str | None = None,
        reference_image_paths: list[str] | None = None,
        shots: list[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        privacy = self._privacy(privacy)
        shot_list = _shots(shots, require_prompts=False)
        roles = [role for role, _ in self._inputs(first_frame_path, last_frame_path, reference_image_paths)]
        with self._client() as client:
            quote = client.quote(
                model, family=family, mode=mode, duration_s=duration_s, shots=shot_list, resolution=resolution,
                aspect_ratio=aspect_ratio, fps=fps, audio=audio, privacy=privacy,
                # Without files, the gateway assumes what the mode needs, so an image-to-video job can be priced first.
                input_roles=roles or None,
            )
        return self._quote_json(quote)

    def generate_video(
        self,
        prompt: str,
        *,
        model: str | None = None,
        family: str | None = None,
        mode: str | None = None,
        duration_s: float | None = None,
        resolution: str | None = None,
        aspect_ratio: str | None = None,
        fps: int | None = None,
        audio: bool = True,
        seed: int | None = None,
        privacy: str | None = None,
        first_frame_path: str | None = None,
        last_frame_path: str | None = None,
        reference_image_paths: list[str] | None = None,
        shots: list[Mapping[str, Any]] | None = None,
        max_price_usd: float | None = None,
        wait: bool = False,
        timeout_s: float = 1800.0,
        on_status: Callable[[JobStatus], None] | None = None,
    ) -> dict[str, Any]:
        privacy = self._privacy(privacy)
        cap = self._budget(max_price_usd)
        shot_list = _shots(shots, require_prompts=True)
        files = self._inputs(first_frame_path, last_frame_path, reference_image_paths)
        roles = [role for role, _ in files]
        chosen_mode = Mode(mode) if mode else None
        with self._client() as client:
            quote = client.quote(
                model, family=family, mode=chosen_mode, duration_s=duration_s, shots=shot_list, resolution=resolution,
                aspect_ratio=aspect_ratio, fps=fps, audio=audio, privacy=privacy, input_roles=roles,
            )
            if quote.price_usd > cap:
                server_cap = self.config.max_job_usd
                agents = max_price_usd is not None and (server_cap is None or max_price_usd <= server_cap)
                binding = "max_price_usd" if agents else "KUNOWORLD_MAX_JOB_USD"
                advice = (
                    "Only the user can raise KUNOWORLD_MAX_JOB_USD, in this server's configuration."
                    if binding == "KUNOWORLD_MAX_JOB_USD"
                    else f"Ask the user to approve ${quote.price_usd:g}, then call again with max_price_usd of at least that."
                )
                raise ToolFailure(
                    "over_budget",
                    f"This video would cost ${quote.price_usd:g} ({quote.profile_name or quote.profile_id}, {privacy}), over the "
                    f"${cap:g} limit set by {binding}. Nothing was created or charged. {advice}",
                )
            loaded = [Input.load(role, path) for role, path in files]
            common = dict(
                model=model, family=family, mode=chosen_mode, duration_s=duration_s, resolution=resolution, aspect_ratio=aspect_ratio,
                fps=fps, audio=audio, seed=seed, inputs=loaded, shots=shot_list, max_price_usd=cap,
            )
            if privacy == "private":
                # The handle is written before the job is sent: if the answer to the submission were lost, the job could
                # exist with its output key nowhere.
                prepared = client.prepare(prompt, **common)
                job = VideoJob(
                    client, prepared.request.job_id, prepared.output_key, prepared.signing_public_key,
                    prepared.request.params.profile_id, prepared.fallback_reason,
                )
                handle_path = self.store.save(self._record(job.export(), "private", prepared.request.params, prepared.quote or quote, cap))
                try:
                    client.submit(prepared)
                except KunoError as exc:
                    if exc.status >= 400:  # refused: no job exists, so no key to keep
                        self.store.delete(job.job_id)
                    raise
                self.store.update(job.job_id, status="queued")
                job_id = job.job_id
            else:
                standard = client.submit_standard(prompt, **common)
                job_id = standard.job_id
                handle_path = self.store.save(self._record(standard.export(), "standard", quote.params, quote, cap, status="queued"))
            status = client.status(job_id)
            record = self._remember(status)
            result: dict[str, Any] = {
                **self._status_json(status, record),
                "fallback_reason": quote.fallback_reason,
                "max_price_usd": cap,
                "prices_are_placeholders": quote.placeholder,
                "settings": _settings(status.params),
                "handle_file": str(handle_path),
            }
            if privacy == "private":
                result["attestation_checked_against"] = self.config.attestation_trust
                result["handle_note"] = "The output key that opens this video is only in handle_file, on this computer."
            if not wait:
                result["next"] = ("Call get_job with this job_id to follow it (a storyboard's stage reads 'shot i/N'), then "
                                  "download_video once it has succeeded.")
                return result
            final = self._wait(client, job_id, timeout_s, on_status)
            result.update(self._status_json(final, self.store.load(job_id)))
            if final.status is JobState.SUCCEEDED:
                result["download"] = self._download(client, job_id, None)
            elif not final.status.terminal:
                result["next"] = f"Still {final.status.value} after {timeout_s:g} s. Call get_job later; the job goes on."
            return result

    def _record(
        self, export: Mapping[str, Any], privacy: str, params: GenerationParams, quote: Quote, cap: float, status: str = "submitting"
    ) -> dict[str, Any]:
        now = self._clock()
        record: dict[str, Any] = {
            "v": 1,
            "job_id": export["job_id"],
            "api_url": self.config.api_url,
            "privacy": privacy,
            "profile_id": export.get("profile_id") or params.profile_id,
            "fallback_reason": export.get("fallback_reason"),
            "created_at": now,
            "updated_at": now,
            "status": status,
            "mode": params.mode.value,
            "duration_s": params.duration_s,
            "resolution": params.resolution,
            "shots": len(params.shots) if params.shots else None,
            "quoted_price_usd": quote.price_usd,
            "max_price_usd": cap,
        }
        if privacy == "private":
            record["output_key"] = export["output_key"]
            record["signing_public_key"] = export["signing_public_key"]
        return record

    def _wait(self, client: KunoClient, job_id: str, timeout_s: float, on_status: Callable[[JobStatus], None] | None) -> JobStatus:
        deadline = self._clock() + timeout_s
        while True:
            status = client.status(job_id)
            self._remember(status)
            if on_status is not None:
                on_status(status)
            if status.status.terminal or self._clock() >= deadline:
                return status
            self._sleep(self.poll_s)

    def get_job(self, job_id: str) -> dict[str, Any]:
        _check_job_id(job_id)
        with self._client() as client:
            status = client.status(job_id)
        return self._status_json(status, self._remember(status))

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        _check_job_id(job_id)
        with self._client() as client:
            status = client.cancel(job_id)
        result = self._status_json(status, self._remember(status))
        if status.status is JobState.CANCELED:
            result["note"] = "Canceled; its price was refunded automatically."
        else:
            result["note"] = f"The job had already {status.status.value}, so nothing changed."
        return result

    def download_video(self, job_id: str, filename: str | None = None) -> dict[str, Any]:
        _check_job_id(job_id)
        with self._client() as client:
            return self._download(client, job_id, filename)

    def _download(self, client: KunoClient, job_id: str, filename: str | None) -> dict[str, Any]:
        record = self.store.load(job_id)
        status = client.status(job_id)
        if status.privacy == "private":
            if not record or not record.get("output_key"):
                raise ToolFailure(
                    "missing_key",
                    f"This Private job's output key isn't in this server's job store ({self.store.directory}), so its video "
                    "can't be opened here. Only the key made with the job opens it; KunoWorld doesn't have it.",
                )
            job: VideoJob | StandardVideoJob = VideoJob.restore(client, record)
        else:
            job = StandardVideoJob(client, job_id, status.params.profile_id)
        if status.status is not JobState.SUCCEEDED:
            stage = f" ({status.stage})" if status.stage else ""
            raise ToolFailure("not_ready", f"The job is {status.status.value}{stage}. Download it once it has succeeded.")
        result = job.result(status)
        return self._save(result, filename, record)

    def _save(self, result: GenerationResult, filename: str | None, record: Mapping[str, Any] | None) -> dict[str, Any]:
        directory = self.config.output_dir
        directory.mkdir(parents=True, exist_ok=True)
        digest = sha256_hex(result.video)
        stem = _safe_stem(filename) or f"kunoworld-{result.job_id}"
        # Never write over a different file: a name an agent picks must not replace something of the user's.
        candidate, number = stem, 1
        while (path := directory / f"{candidate}.mp4").exists() and sha256_hex(path.read_bytes()) != digest:
            number += 1
            candidate = f"{stem}-{number}"
        receipt_path = directory / f"{candidate}.receipt.json"
        for target, data in ((path, result.video), (receipt_path, result.receipt.model_dump_json(indent=2).encode())):
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
            with os.fdopen(descriptor, "wb") as file:
                file.write(data)
        if record is not None:
            self.store.update(result.job_id, status="succeeded", saved_path=str(path), sha256=digest)
        body = result.receipt.body
        if result.privacy == "private":
            checks = [
                "the sealed file matched the receipt's output digest",
                "the receipt is signed by the enclave whose attestation this server checked when it sent the job",
                "the video was decrypted on this computer and matched the receipt's content digest",
            ]
        else:
            checks = ["the video matched the receipt's content digest (a Standard video is stored readable by KunoWorld)"]
        return {
            "path": str(path),
            "size_bytes": len(result.video),
            "sha256": digest,
            "receipt_path": str(receipt_path),
            "privacy": result.privacy,
            "checks": checks,
            "receipt": {
                "job_id": body.job_id,
                "model": body.profile_id,
                "enclave_id": body.enclave_id,
                "image_digest": body.image_digest,
                "miner_hotkey": body.miner_hotkey,
                "content_digest": body.content_digest,
                "duration_s": body.video.duration_s,
                "width": body.video.width,
                "height": body.video.height,
                "fps": body.video.fps,
                "frames": body.video.frames,
                "audio": body.video.audio,
                "gpu_seconds": body.gpu_seconds,
                "finished_at": body.finished_at,
                "step_commitment": body.step_commitment is not None,
            },
        }

    def list_jobs(self, limit: int = 10, refresh: bool = True) -> dict[str, Any]:
        records = self.store.records(self.config.api_url)[: max(1, min(int(limit), 100))]
        # Only unfinished jobs are asked about: a finished job's status doesn't change.
        pending = [index for index, record in enumerate(records) if record.get("status") not in FINISHED]
        if refresh and pending and self.config.api_key:
            with self._client() as client:
                for index in pending:
                    try:
                        records[index] = self._remember(client.status(records[index]["job_id"])) or records[index]
                    except KunoError:
                        continue
        jobs = [
            {
                "job_id": r["job_id"],
                "privacy": r.get("privacy"),
                "model": r.get("profile_id"),
                "mode": r.get("mode"),
                "duration_s": round(r["duration_s"], 3) if isinstance(r.get("duration_s"), (int, float)) else None,
                "shots": r.get("shots"),
                "status": r.get("status"),
                "stage": r.get("stage"),
                "quoted_price_usd": r.get("quoted_price_usd"),
                "created_at": r.get("created_at"),
                "saved_path": r.get("saved_path"),
            }
            for r in records
        ]
        return {"jobs": jobs, "job_store": str(self.store.directory)}
