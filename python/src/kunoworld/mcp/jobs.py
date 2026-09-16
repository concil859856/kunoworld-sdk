"""The MCP server's job handles, kept on this machine only.

A Private job's handle holds its output key, the only thing that opens the video: lose it and the video is lost, leak it
and whoever has the sealed file can watch. So handles live in one file per job under a directory only this user can
enter (0700), each file readable only by this user (0600), written to a temporary file and renamed so a crash never
leaves half a key. Nothing here is sent anywhere, and no prompt is ever stored.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import time
from pathlib import Path
from typing import Any

from kuno_protocol.schemas import JOB_ID_RE

DIRECTORY_MODE = 0o700
FILE_MODE = 0o600


def default_directory() -> Path:
    return Path.home() / ".kunoworld" / "jobs"


class JobStore:
    """`<directory>/<job_id>.json`, one record per job this server started."""

    def __init__(self, directory: Path):
        self.directory = Path(directory).expanduser()

    def _ready(self) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True, mode=DIRECTORY_MODE)
        # mkdir's mode is filtered by the umask and ignored for a directory that already exists: set it outright.
        if stat.S_IMODE(self.directory.stat().st_mode) != DIRECTORY_MODE:
            os.chmod(self.directory, DIRECTORY_MODE)
        return self.directory

    def _path(self, job_id: str) -> Path:
        # Job ids come from agents: only a UUIDv4 names a file, so no id can point outside the directory.
        if not isinstance(job_id, str) or not JOB_ID_RE.match(job_id):
            raise ValueError("not a job id")
        return self.directory / f"{job_id}.json"

    def save(self, record: dict[str, Any]) -> Path:
        path = self._path(record["job_id"])
        self._ready()
        temporary = self.directory / f".{record['job_id']}.{secrets.token_hex(4)}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as file:
                json.dump(record, file, indent=2, sort_keys=True)
                file.flush()
                os.fsync(file.fileno())
            os.chmod(temporary, FILE_MODE)
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return path

    def load(self, job_id: str) -> dict[str, Any] | None:
        try:
            path = self._path(job_id)
        except ValueError:
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None

    def delete(self, job_id: str) -> None:
        """Forgets a job, for one the gateway refused: no job exists, so there is no key worth keeping."""
        try:
            self._path(job_id).unlink(missing_ok=True)
        except ValueError:
            return

    def update(self, job_id: str, **changes: Any) -> dict[str, Any] | None:
        record = self.load(job_id)
        if record is None:
            return None
        record.update(changes, updated_at=time.time())
        self.save(record)
        return record

    def records(self, api_url: str | None = None) -> list[dict[str, Any]]:
        """Every record, newest first; with `api_url`, only jobs made through that gateway."""
        if not self.directory.is_dir():
            return []
        found = []
        for path in self.directory.glob("*.json"):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if api_url is None or record.get("api_url") == api_url:
                found.append(record)
        return sorted(found, key=lambda r: r.get("created_at") or 0, reverse=True)
