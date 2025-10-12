"""Tests for the BackupsRegistry helpers."""
from __future__ import annotations

from pathlib import Path

from abssctl.backups import BackupEntryBuilder, BackupsRegistry


def test_backups_registry_append_and_read(tmp_path: Path) -> None:
    """Append persists entries in backups.json."""
    registry = BackupsRegistry(tmp_path / "backups", tmp_path / "backups" / "backups.json")
    registry.ensure_root()

    entry = BackupEntryBuilder(
        instance="alpha",
        archive_path=tmp_path / "backups" / "alpha" / "demo.tar.gz",
        algorithm="gzip",
        checksum="deadbeef",
        size_bytes=1234,
        message="pre-flight",
        labels=["pre-version-install"],
        data_only=False,
    ).build(backup_id="alpha-demo")

    registry.append(entry)

    data = registry.read()
    assert "backups" in data
    assert data["backups"][0]["id"] == "alpha-demo"
    assert data["backups"][0]["message"] == "pre-flight"


def test_backups_registry_generates_identifier(tmp_path: Path) -> None:
    """Generated backup identifiers include timestamp and instance slug."""
    registry = BackupsRegistry(tmp_path / "backups", tmp_path / "backups" / "backups.json")
    backup_id = registry.generate_identifier("alpha")
    assert backup_id.startswith("20")  # timestamp prefix
    assert "alpha" in backup_id


def test_backups_registry_update_entry(tmp_path: Path) -> None:
    """`update_entry` applies mutators and persists changes."""
    registry = BackupsRegistry(tmp_path / "backups", tmp_path / "backups" / "backups.json")
    registry.ensure_root()
    entry = BackupEntryBuilder(
        instance="alpha",
        archive_path=tmp_path / "backups" / "alpha" / "demo.tar.gz",
        algorithm="gzip",
        checksum="deadbeef",
        size_bytes=100,
    ).build(backup_id="demo")
    registry.append(entry)

    updated = registry.update_entry("demo", lambda payload: payload.update({"status": "removed"}))
    assert updated["status"] == "removed"
    assert registry.find_by_id("demo")["status"] == "removed"
