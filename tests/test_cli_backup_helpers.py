"""Unit tests for backup helper utilities in the CLI."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from abssctl.cli import _compute_checksum, _verify_backup_entry
from abssctl.logging import OperationScope, StructuredLogger


class DummyBackupsRegistry:
    """In-memory stand-in for the backups registry."""

    def __init__(self, entry: dict[str, object]) -> None:
        """Store a mutable copy of the backup entry."""
        self.entry = dict(entry)
        self.mutations: list[dict[str, object]] = []

    def update_entry(
        self,
        backup_id: str,
        mutator: Callable[[dict[str, object]], None],
    ) -> dict[str, object]:
        """Apply *mutator* to the stored entry."""
        if backup_id != str(self.entry.get("id", "")):
            raise AssertionError("Unexpected backup identifier")
        payload = dict(self.entry)
        mutator(payload)
        self.entry = payload
        self.mutations.append(payload)
        return payload


class DummyRuntime:
    """Runtime context carrying only a backups registry."""

    def __init__(self, backups: DummyBackupsRegistry) -> None:
        """Attach a backups registry stub."""
        self.backups = backups


def _operation_scope(tmp_path: Path) -> OperationScope:
    """Return an OperationScope bound to a StructuredLogger in *tmp_path*."""
    logger = StructuredLogger(tmp_path / "logs")
    return logger.operation("backup-test")


def test_verify_backup_entry_missing_path(tmp_path: Path) -> None:
    """Entries without archive paths should remain untouched."""
    registry = DummyBackupsRegistry({"id": "backup-1"})
    runtime = DummyRuntime(registry)
    with _operation_scope(tmp_path) as op:
        result = _verify_backup_entry(runtime, {"id": "backup-1"}, op=op)
    assert result["status"] == "unknown"
    assert result["message"] == "Backup entry is missing an archive path."
    assert registry.mutations == []


def test_verify_backup_entry_missing_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing archives should mark the entry as missing."""
    archive = tmp_path / "missing.tar.gz"
    entry = {
        "id": "backup-2",
        "path": str(archive),
        "status": "available",
        "checksum": {"value": "deadbeef"},
        "metadata": {"verification_error": "stale"},
    }
    registry = DummyBackupsRegistry(entry)
    runtime = DummyRuntime(registry)
    monkeypatch.setattr("abssctl.cli._iso_now", lambda: "2025-01-01T00:00:00Z")

    with _operation_scope(tmp_path) as op:
        result = _verify_backup_entry(runtime, entry, op=op)

    assert result["status"] == "missing"
    assert registry.entry["checksum"]["last_verified"] == "2025-01-01T00:00:00Z"
    assert registry.entry["metadata"]["verification_error"] == "Archive not found on disk."


def test_verify_backup_entry_checksum_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checksum mismatches should mark entries as corrupt."""
    archive = tmp_path / "archive.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(b"payload")
    entry = {
        "id": "backup-3",
        "path": str(archive),
        "status": "unknown",
        "checksum": {"value": "expected"},
        "metadata": {},
    }
    registry = DummyBackupsRegistry(entry)
    runtime = DummyRuntime(registry)
    monkeypatch.setattr("abssctl.cli._iso_now", lambda: "2025-01-02T00:00:00Z")
    monkeypatch.setattr("abssctl.cli._compute_checksum", lambda path: "observed")

    with _operation_scope(tmp_path) as op:
        result = _verify_backup_entry(runtime, entry, op=op)

    assert result["status"] == "corrupt"
    checksum_info = registry.entry["checksum"]
    assert checksum_info["observed"] == "observed"
    assert checksum_info["last_verified"] == "2025-01-02T00:00:00Z"
    assert registry.entry["metadata"]["verification_error"] == "Checksum mismatch."


def test_verify_backup_entry_checksum_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I/O errors during checksum should surface as error status."""
    archive = tmp_path / "broken.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(b"payload")
    entry = {
        "id": "backup-4",
        "path": str(archive),
        "status": "unknown",
        "checksum": {"value": ""},
        "metadata": {},
    }
    registry = DummyBackupsRegistry(entry)
    runtime = DummyRuntime(registry)
    monkeypatch.setattr("abssctl.cli._iso_now", lambda: "2025-01-03T00:00:00Z")

    def _raise(_path: Path) -> str:
        raise OSError("disk failure")

    monkeypatch.setattr("abssctl.cli._compute_checksum", _raise)

    with _operation_scope(tmp_path) as op:
        result = _verify_backup_entry(runtime, entry, op=op)

    assert result["status"] == "error"
    assert "disk failure" in result["message"]
    assert registry.entry["metadata"]["verification_error"].startswith("Failed to read archive")


def test_verify_backup_entry_available(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful checksum verification should clear error metadata."""
    archive = tmp_path / "valid.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(b"payload")
    expected = _compute_checksum(archive)
    entry = {
        "id": "backup-5",
        "path": str(archive),
        "status": "missing",
        "checksum": {"value": expected, "last_verified": "stale"},
        "metadata": {"verification_error": "old error"},
    }
    registry = DummyBackupsRegistry(entry)
    runtime = DummyRuntime(registry)
    monkeypatch.setattr("abssctl.cli._iso_now", lambda: "2025-01-04T00:00:00Z")

    with _operation_scope(tmp_path) as op:
        result = _verify_backup_entry(runtime, entry, op=op)

    assert result["status"] == "available"
    checksum_info = registry.entry["checksum"]
    assert checksum_info["observed"] == expected
    assert checksum_info["last_verified"] == "2025-01-04T00:00:00Z"
    assert "verification_error" not in registry.entry["metadata"]
