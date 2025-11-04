"""Tests for the VersionInstaller abstraction."""
from __future__ import annotations

import base64
import json
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from abssctl.providers import VersionInstaller, VersionInstallError

FAKE_SHASUM = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
_FAKE_DIGEST_BYTES = bytes(range(64))
FAKE_INTEGRITY = f"sha512-{base64.b64encode(_FAKE_DIGEST_BYTES).decode('ascii')}"
FAKE_DIGEST_HEX = _FAKE_DIGEST_BYTES.hex()


def _fake_successful_install(staging_dir: Path, package_name: str) -> None:
    """Create a fake npm installation layout for testing."""
    node_modules = staging_dir / "node_modules"
    node_modules.mkdir(parents=True, exist_ok=True)
    package_path = node_modules
    for part in package_name.split("/"):
        package_path /= part
    package_path.mkdir(parents=True, exist_ok=True)
    metadata = {
        "name": "fake",
        "_shasum": FAKE_SHASUM,
        "_integrity": FAKE_INTEGRITY,
        "dist": {"tarball": "https://example.invalid/fake.tgz"},
    }
    (package_path / "package.json").write_text(json.dumps(metadata), encoding="utf-8")


def test_install_success_creates_target_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installer stages npm output then moves it to the version directory."""
    install_root = tmp_path / "srv" / "app"
    installer = VersionInstaller(install_root=install_root, package_name="@actual-app/sync-server")

    def fake_run(
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        _fake_successful_install(staging_dir, "@actual-app/sync-server")
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(installer, "_run_install_command", fake_run)

    result = installer.install("25.9.0")

    assert result.version == "25.9.0"
    assert result.path == install_root / "v25.9.0"
    package_dir = result.path / "node_modules" / "@actual-app" / "sync-server"
    assert package_dir.exists()
    assert result.metadata["package"] == "@actual-app/sync-server"
    assert "package_json" in result.metadata
    assert result.integrity["npm"]["shasum"] == FAKE_SHASUM
    assert result.integrity["npm"]["integrity"] == FAKE_INTEGRITY
    assert result.integrity["tarball"]["algorithm"] == "sha512"
    assert result.integrity["tarball"]["digest"] == FAKE_DIGEST_HEX


def test_install_failure_cleans_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failed installs raise an error and clean temporary directories."""
    install_root = tmp_path / "srv" / "app"
    installer = VersionInstaller(install_root=install_root, package_name="@actual-app/sync-server")

    def fake_run(
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")

    monkeypatch.setattr(installer, "_run_install_command", fake_run)

    with pytest.raises(VersionInstallError):
        installer.install("25.9.1")

    staging_dirs = list(install_root.glob("abssctl-install-25.9.1-*"))
    assert staging_dirs == []


def test_dry_run_returns_metadata_without_files(tmp_path: Path) -> None:
    """Dry-run installations do not touch the filesystem."""
    install_root = tmp_path / "srv" / "app"
    installer = VersionInstaller(install_root=install_root, package_name="@actual-app/sync-server")

    result = installer.install("25.9.2", dry_run=True)

    assert result.metadata["dry_run"] is True
    assert not result.path.exists()


def test_install_rejects_blank_version(tmp_path: Path) -> None:
    """Blank or whitespace-only versions raise an error."""
    install_root = tmp_path / "srv" / "app"
    installer = VersionInstaller(install_root=install_root, package_name="@actual-app/sync-server")

    with pytest.raises(VersionInstallError):
        installer.install("   ")


def test_install_rejects_existing_directory(tmp_path: Path) -> None:
    """Existing version directory raises VersionInstallError."""
    install_root = tmp_path / "srv" / "app"
    target = install_root / "v1.2.3"
    target.mkdir(parents=True, exist_ok=True)
    installer = VersionInstaller(install_root=install_root, package_name="@actual-app/sync-server")

    with pytest.raises(VersionInstallError):
        installer.install("1.2.3")


def test_install_missing_package_directory_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installer errors when npm succeeds but package directory is absent."""
    install_root = tmp_path / "srv" / "app"
    installer = VersionInstaller(install_root=install_root, package_name="@actual-app/sync-server")

    def fake_run(
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        (staging_dir / "node_modules").mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(installer, "_run_install_command", fake_run)

    with pytest.raises(VersionInstallError):
        installer.install("30.0.0")

    staging_dirs = list(install_root.glob("abssctl-install-30.0.0-*"))
    assert staging_dirs == []


def test_install_propagates_custom_npm_args(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Custom npm arguments are recorded in metadata."""
    install_root = tmp_path / "srv" / "app"
    args = ["--registry", "https://registry.example.invalid"]
    installer = VersionInstaller(
        install_root=install_root,
        package_name="@actual-app/sync-server",
        npm_args=args,
    )

    def fake_run(
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        _fake_successful_install(staging_dir, "@actual-app/sync-server")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(installer, "_run_install_command", fake_run)

    result = installer.install("31.0.0")

    assert result.metadata["npm_args"] == args


def test_integrity_parsing_handles_malformed_strings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed integrity values omit tarball digest from metadata."""
    install_root = tmp_path / "srv" / "app"
    installer = VersionInstaller(install_root=install_root, package_name="@actual-app/sync-server")
    invalid_integrity = "sha512-not-base64"

    def fake_run(
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        node_modules = staging_dir / "node_modules" / "@actual-app"
        package_dir = node_modules / "sync-server"
        package_dir.mkdir(parents=True, exist_ok=True)
        metadata = {
            "_integrity": invalid_integrity,
            "_shasum": FAKE_SHASUM,
        }
        (package_dir / "package.json").write_text(json.dumps(metadata), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(installer, "_run_install_command", fake_run)

    result = installer.install("32.0.0")

    assert result.integrity["npm"]["integrity"] == invalid_integrity
    assert "tarball" not in result.integrity
