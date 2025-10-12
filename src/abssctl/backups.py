"""Helpers for managing backup archives and metadata."""
from __future__ import annotations

import json
import os
import secrets
import shutil
import tempfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class BackupError(RuntimeError):
    """Raised when backup operations fail."""


class BackupRegistryError(BackupError):
    """Raised when backup index interactions fail."""


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _normalise_identifier(value: str, *, label: str) -> str:
    normalised = value.strip()
    if not normalised:
        raise BackupRegistryError(f"{label} must be a non-empty string.")
    return normalised


@dataclass(slots=True)
class BackupsRegistry:
    """Manage the JSON backup index under the backups directory."""

    root: Path
    index: Path

    def __post_init__(self) -> None:
        """Normalise root/index paths after initialisation."""
        self.root = self.root.expanduser()
        self.index = self.index.expanduser()

    # Basic helpers -------------------------------------------------
    def ensure_root(self) -> None:
        """Ensure the backup root directory exists with safe permissions."""
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            os.chmod(self.root, 0o750)
        except OSError as exc:  # pragma: no cover - permissions env-specific
            raise BackupRegistryError(f"Failed to prepare backup root {self.root}: {exc}") from exc

    def read(self) -> dict[str, object]:
        """Return the parsed backups index (empty structure when missing)."""
        if not self.index.exists():
            return {"backups": []}
        try:
            text = self.index.read_text(encoding="utf-8")
            data = json.loads(text)
        except FileNotFoundError:
            return {"backups": []}
        except json.JSONDecodeError as exc:
            raise BackupRegistryError(f"Backup index corrupted ({self.index}): {exc}") from exc
        if not isinstance(data, Mapping):
            raise BackupRegistryError(f"Backup index must be a JSON object ({self.index}).")
        return dict(data)

    def write(self, payload: Mapping[str, object]) -> None:
        """Atomically persist *payload* to the backups index."""
        self.ensure_root()
        tmp_fd, tmp_name = tempfile.mkstemp(
            dir=str(self.index.parent),
            prefix=f".{self.index.name}.",
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=False)
                handle.write("\n")
            os.replace(tmp_path, self.index)
            os.chmod(self.index, 0o640)
        except OSError as exc:
            raise BackupRegistryError(f"Failed to write backup index: {exc}") from exc
        finally:
            tmp_path.unlink(missing_ok=True)

    def append(self, entry: Mapping[str, object]) -> None:
        """Append *entry* to the backups index."""
        data = self.read()
        backups = data.get("backups")
        if isinstance(backups, list):
            updated: list[object] = list(backups)
        else:
            updated = []
        updated.append(dict(entry))
        self.write({"backups": updated})

    def list_entries(self) -> list[dict[str, object]]:
        """Return a list of backup entries."""
        data = self.read()
        backups = data.get("backups", [])
        entries: list[dict[str, object]] = []
        if isinstance(backups, list):
            for item in backups:
                if isinstance(item, Mapping):
                    entries.append(dict(item))
        return entries

    def find_by_id(self, backup_id: str) -> dict[str, object] | None:
        """Return the entry for *backup_id* if present."""
        normalized = _normalise_identifier(backup_id, label="Backup identifier")
        for entry in self.list_entries():
            if str(entry.get("id", "")).strip() == normalized:
                return entry
        return None

    def entries_for_instance(self, instance: str) -> list[dict[str, object]]:
        """Return entries associated with *instance*."""
        normalized = _normalise_identifier(instance, label="Instance name")
        return [
            entry
            for entry in self.list_entries()
            if str(entry.get("instance", "")).strip() == normalized
        ]

    def update_entry(
        self,
        backup_id: str,
        mutator: Callable[[dict[str, object]], None],
    ) -> dict[str, object]:
        """Apply *mutator* to the entry for *backup_id* and persist changes."""
        normalized = _normalise_identifier(backup_id, label="Backup identifier")
        entries = self.list_entries()
        updated_entry: dict[str, object] | None = None
        for index, entry in enumerate(entries):
            if str(entry.get("id", "")).strip() == normalized:
                mutable = dict(entry)
                mutator(mutable)
                entries[index] = mutable
                updated_entry = mutable
                break
        if updated_entry is None:
            raise BackupRegistryError(f"Backup '{normalized}' not found in index.")
        self.write({"backups": entries})
        return updated_entry

    # Utility helpers -----------------------------------------------
    def generate_identifier(self, instance: str) -> str:
        """Return a unique backup identifier for *instance*."""
        timestamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
        token = secrets.token_hex(3)
        safe_instance = "".join(
            char if char.isalnum() or char in {"-", "_"} else "-" for char in instance
        )
        return f"{timestamp}-{safe_instance}-{token}"

    def archive_directory(self, instance: str) -> Path:
        """Return the directory that should contain archives for *instance*."""
        return self.root / instance


@dataclass(slots=True)
class BackupEntryBuilder:
    """Helper for constructing backup index entries."""

    instance: str
    archive_path: Path
    algorithm: str
    checksum: str
    size_bytes: int
    message: str | None = None
    labels: Iterable[str] | None = None
    compression_level: int | None = None
    data_only: bool = False
    actor: Mapping[str, object] | None = None

    def build(self, *, backup_id: str) -> dict[str, object]:
        """Return the JSON-serialisable entry for the backup index."""
        entry: dict[str, object] = {
            "id": backup_id,
            "instance": self.instance,
            "created_at": _now_iso(),
            "path": str(self.archive_path),
            "algorithm": self.algorithm,
            "size_bytes": self.size_bytes,
            "checksum": {"algorithm": "sha256", "value": self.checksum},
            "status": "available",
            "metadata": {
                "data_only": self.data_only,
                "labels": list(self.labels or []),
            },
        }
        if self.compression_level is not None:
            entry["compression_level"] = self.compression_level
        if self.message:
            entry["message"] = self.message
        if self.actor:
            entry["created_by"] = dict(self.actor)
        return entry


def copy_into(source: Path, destination: Path) -> None:
    """Copy or mirror *source* into *destination*."""
    if not source.exists():
        destination.mkdir(parents=True, exist_ok=True)
        return
    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
