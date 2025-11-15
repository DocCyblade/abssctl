"""Tests for the BackupsRegistry helpers."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from abssctl import backups as backups_module
from abssctl.backups import (
    BackupEntryBuilder,
    BackupRegistryError,
    BackupsRegistry,
    _normalise_identifier,
    _now_iso,
    copy_into,
)


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


def test_now_iso_returns_utc_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """_now_iso should request UTC timestamps and emit whole-second precision."""

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz: object | None = None) -> datetime:
            assert tz is backups_module.UTC
            return cls(2024, 7, 8, 9, 10, 11, 987_654, tzinfo=tz)

    monkeypatch.setattr(backups_module, "datetime", FixedDatetime)

    assert _now_iso() == "2024-07-08T09:10:11Z"


def test_normalise_identifier_strips_and_validates() -> None:
    """Identifiers should be trimmed and validated."""
    assert _normalise_identifier("  demo-id \n", label="Identifier") == "demo-id"
    with pytest.raises(BackupRegistryError, match="Identifier must be a non-empty string."):
        _normalise_identifier(" \t ", label="Identifier")


def test_copy_into_creates_directory_when_source_missing(tmp_path: Path) -> None:
    """Missing sources should still yield a destination directory."""
    destination = tmp_path / "payload" / "data"
    copy_into(tmp_path / "missing", destination)
    assert destination.is_dir()
    assert not any(destination.iterdir())


def test_copy_into_mirrors_directory_tree(tmp_path: Path) -> None:
    """Directory sources should be mirrored recursively."""
    source = tmp_path / "src"
    nested = source / "nested"
    nested.mkdir(parents=True)
    (nested / "file.txt").write_text("hello", encoding="utf-8")
    (source / "root.txt").write_text("root", encoding="utf-8")

    destination = tmp_path / "dest"
    copy_into(source, destination)

    assert (destination / "nested" / "file.txt").read_text(encoding="utf-8") == "hello"
    assert (destination / "root.txt").read_text(encoding="utf-8") == "root"


def test_copy_into_copies_file_and_creates_parent(tmp_path: Path) -> None:
    """Regular files should be copied and ensure parent directories exist."""
    source = tmp_path / "source.txt"
    source.write_text("payload", encoding="utf-8")
    destination = tmp_path / "target" / "copied.txt"

    copy_into(source, destination)

    assert destination.read_text(encoding="utf-8") == "payload"
    assert destination.parent.is_dir()


def test_copy_into_directory_uses_copytree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Directory copies should invoke shutil.copytree with dirs_exist_ok."""
    source = tmp_path / "src"
    source.mkdir()
    destination = tmp_path / "dest"
    called: dict[str, tuple[Path, Path, bool]] = {}

    def fake_copytree(src: Path, dst: Path, *, dirs_exist_ok: bool) -> None:
        called["args"] = (src, dst, dirs_exist_ok)
        dst.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr("abssctl.backups.shutil.copytree", fake_copytree)

    copy_into(source, destination)

    assert called["args"] == (source, destination, True)
    assert destination.exists()


def test_copy_into_file_uses_copy2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """File copies should call shutil.copy2 after preparing parent directories."""
    source = tmp_path / "file.txt"
    source.write_text("payload", encoding="utf-8")
    destination = tmp_path / "out" / "file.txt"
    called: dict[str, tuple[Path, Path]] = {}

    def fake_copy2(src: Path, dst: Path) -> None:
        called["args"] = (src, dst)
        dst.write_text("copied", encoding="utf-8")

    monkeypatch.setattr("abssctl.backups.shutil.copy2", fake_copy2)

    copy_into(source, destination)

    assert called["args"] == (source, destination)
    assert destination.read_text(encoding="utf-8") == "copied"


def test_copy_into_missing_source_is_idempotent(tmp_path: Path) -> None:
    """Creating placeholder directories for missing sources should be idempotent."""
    destination = tmp_path / "payload" / "data"
    copy_into(tmp_path / "missing", destination)
    copy_into(tmp_path / "missing", destination)
    assert destination.is_dir()


def test_copy_into_directory_allows_existing_destination(tmp_path: Path) -> None:
    """Directory copies should tolerate pre-existing destinations (dirs_exist_ok)."""
    source = tmp_path / "src"
    nested = source / "nested"
    nested.mkdir(parents=True)
    (nested / "file.txt").write_text("v1", encoding="utf-8")
    destination = tmp_path / "dest"

    copy_into(source, destination)

    (nested / "file.txt").write_text("v2", encoding="utf-8")
    copy_into(source, destination)

    assert (destination / "nested" / "file.txt").read_text(encoding="utf-8") == "v2"


def test_copy_into_file_parent_exists(tmp_path: Path) -> None:
    """File copies should not fail when parent directories already exist."""
    source = tmp_path / "file.txt"
    source.write_text("one", encoding="utf-8")
    destination = tmp_path / "out" / "file.txt"
    destination.parent.mkdir(parents=True, exist_ok=True)

    copy_into(source, destination)

    source.write_text("two", encoding="utf-8")
    copy_into(source, destination)

    assert destination.read_text(encoding="utf-8") == "two"


def test_copy_into_missing_source_skips_copy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Missing sources must not trigger copytree/copy2 calls."""
    source = tmp_path / "missing"
    destination = tmp_path / "payload" / "data"

    def boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("copy helper should not be called for missing source")

    monkeypatch.setattr("abssctl.backups.shutil.copytree", boom)
    monkeypatch.setattr("abssctl.backups.shutil.copy2", boom)

    copy_into(source, destination)
    assert destination.is_dir()


def test_copy_into_creates_nested_parents(tmp_path: Path) -> None:
    """Missing multi-level parent directories should be created automatically."""
    source = tmp_path / "payload.txt"
    source.write_text("payload", encoding="utf-8")
    destination = tmp_path / "deep" / "nested" / "path" / "copied.txt"

    copy_into(source, destination)

    assert destination.read_text(encoding="utf-8") == "payload"
