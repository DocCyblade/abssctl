"""Tests for the VersionInstaller abstraction."""
from __future__ import annotations

import base64
import io
import json
import subprocess
import tarfile
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from abssctl.providers import VersionInstaller, VersionInstallError

FAKE_SHASUM = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
_FAKE_DIGEST_BYTES = bytes(range(64))
FAKE_INTEGRITY = f"sha512-{base64.b64encode(_FAKE_DIGEST_BYTES).decode('ascii')}"
FAKE_DIGEST_HEX = _FAKE_DIGEST_BYTES.hex()
FAKE_TARBALL_NAME = "actual-app-sync-server-25.9.0.tgz"


def _pack_stdout(
    filename: str,
    *,
    shasum: str | None = FAKE_SHASUM,
    integrity: str | None = FAKE_INTEGRITY,
) -> str:
    """Return ``npm pack --json`` output for one packed tarball."""
    payload: dict[str, object] = {"filename": filename}
    if shasum is not None:
        payload["shasum"] = shasum
    if integrity is not None:
        payload["integrity"] = integrity
    return json.dumps([payload])


def _add_tar_bytes(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    """Add *payload* to *archive* as *name*."""
    info = tarfile.TarInfo(name=name)
    info.size = len(payload)
    archive.addfile(info, io.BytesIO(payload))


def _write_pack_tarball(
    staging_dir: Path,
    filename: str,
    *,
    package_json: Mapping[str, object] | None,
    entrypoint: bytes | None = b"console.log('stub');\n",
    extra: dict[str, bytes] | None = None,
) -> None:
    """Write an npm pack tarball whose members live under ``package/``."""
    with tarfile.open(staging_dir / filename, "w:gz") as archive:
        if package_json is not None:
            _add_tar_bytes(
                archive,
                "package/package.json",
                json.dumps(package_json).encode("utf-8"),
            )
        if entrypoint is not None:
            _add_tar_bytes(archive, "package/build/bin/actual-server.js", entrypoint)
        for name, payload in (extra or {}).items():
            _add_tar_bytes(archive, name, payload)


def test_install_success_creates_target_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pack extracts package.json and the server entrypoint at the version root."""
    install_root = tmp_path / "srv" / "app"
    installer = VersionInstaller(install_root=install_root, package_name="@actual-app/sync-server")
    seen: dict[str, list[str]] = {}

    def fake_run(
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = list(cmd)
        _write_pack_tarball(
            staging_dir,
            FAKE_TARBALL_NAME,
            package_json={"name": "@actual-app/sync-server", "version": "25.9.0"},
        )
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=_pack_stdout(FAKE_TARBALL_NAME),
            stderr="",
        )

    monkeypatch.setattr(installer, "_run_install_command", fake_run)

    result = installer.install("25.9.0")

    assert seen["cmd"][:3] == ["npm", "pack", "@actual-app/sync-server@25.9.0"]
    assert "--json" in seen["cmd"]
    assert "--pack-destination" in seen["cmd"]
    assert "--prefix" not in seen["cmd"]
    assert result.version == "25.9.0"
    assert result.path == install_root / "v25.9.0"
    package_json = result.path / "package.json"
    entrypoint = result.path / "build" / "bin" / "actual-server.js"
    assert package_json.is_file()
    assert json.loads(package_json.read_text(encoding="utf-8"))["name"] == "@actual-app/sync-server"
    assert entrypoint.is_file()
    assert entrypoint.read_text(encoding="utf-8") == "console.log('stub');\n"
    assert not (result.path / "package").exists()
    assert result.metadata["package"] == "@actual-app/sync-server"
    assert result.metadata["package_json"] == str(package_json)
    assert result.integrity["npm"]["shasum"] == FAKE_SHASUM
    assert result.integrity["npm"]["integrity"] == FAKE_INTEGRITY
    assert result.integrity["tarball"]["algorithm"] == "sha512"
    assert result.integrity["tarball"]["digest"] == FAKE_DIGEST_HEX
    assert list(install_root.glob("abssctl-install-25.9.0-*")) == []


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


def test_install_missing_tarball_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installer errors when npm pack reports success but writes no tarball."""
    install_root = tmp_path / "srv" / "app"
    installer = VersionInstaller(install_root=install_root, package_name="@actual-app/sync-server")

    def fake_run(
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=_pack_stdout("missing.tgz"),
            stderr="",
        )

    monkeypatch.setattr(installer, "_run_install_command", fake_run)

    with pytest.raises(VersionInstallError, match="tarball missing"):
        installer.install("30.0.0")

    assert list(install_root.glob("abssctl-install-30.0.0-*")) == []
    assert not (install_root / "v30.0.0").exists()


def test_install_missing_package_json_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installer errors when the extracted tarball has no package.json."""
    install_root = tmp_path / "srv" / "app"
    installer = VersionInstaller(install_root=install_root, package_name="@actual-app/sync-server")

    def fake_run(
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        _write_pack_tarball(staging_dir, "pkg.tgz", package_json=None, entrypoint=None)
        return subprocess.CompletedProcess(cmd, 0, stdout=_pack_stdout("pkg.tgz"), stderr="")

    monkeypatch.setattr(installer, "_run_install_command", fake_run)

    with pytest.raises(VersionInstallError, match="package.json missing"):
        installer.install("30.1.0")

    assert list(install_root.glob("abssctl-install-30.1.0-*")) == []
    assert not (install_root / "v30.1.0").exists()


def test_install_rejects_tarball_path_traversal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Archive members that climb out of the version directory are refused."""
    install_root = tmp_path / "srv" / "app"
    installer = VersionInstaller(install_root=install_root, package_name="@actual-app/sync-server")

    def fake_run(
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        _write_pack_tarball(
            staging_dir,
            "pkg.tgz",
            package_json={"name": "@actual-app/sync-server"},
            extra={"package/../../outside.txt": b"nope"},
        )
        return subprocess.CompletedProcess(cmd, 0, stdout=_pack_stdout("pkg.tgz"), stderr="")

    monkeypatch.setattr(installer, "_run_install_command", fake_run)

    with pytest.raises(VersionInstallError, match="Refusing to extract"):
        installer.install("30.2.0")

    assert not (install_root / "outside.txt").exists()
    assert not (tmp_path / "outside.txt").exists()
    assert not (install_root / "v30.2.0").exists()


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

    seen: dict[str, list[str]] = {}

    def fake_run(
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = list(cmd)
        _write_pack_tarball(
            staging_dir,
            "pkg.tgz",
            package_json={"name": "@actual-app/sync-server"},
        )
        return subprocess.CompletedProcess(cmd, 0, stdout=_pack_stdout("pkg.tgz"), stderr="")

    monkeypatch.setattr(installer, "_run_install_command", fake_run)

    result = installer.install("31.0.0")

    assert result.metadata["npm_args"] == args
    assert seen["cmd"][-2:] == args


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
        _write_pack_tarball(
            staging_dir,
            "pkg.tgz",
            package_json={"name": "@actual-app/sync-server"},
        )
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=_pack_stdout("pkg.tgz", integrity=invalid_integrity),
            stderr="",
        )

    monkeypatch.setattr(installer, "_run_install_command", fake_run)

    result = installer.install("32.0.0")

    assert result.integrity["npm"]["integrity"] == invalid_integrity
    assert "tarball" not in result.integrity


def test_integrity_falls_back_to_package_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """package.json integrity is recorded when npm pack JSON omits it."""
    install_root = tmp_path / "srv" / "app"
    installer = VersionInstaller(install_root=install_root, package_name="@actual-app/sync-server")

    def fake_run(
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        _write_pack_tarball(
            staging_dir,
            "pkg.tgz",
            package_json={
                "name": "@actual-app/sync-server",
                "_shasum": FAKE_SHASUM,
                "_integrity": FAKE_INTEGRITY,
            },
        )
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=_pack_stdout("pkg.tgz", shasum=None, integrity=None),
            stderr="",
        )

    monkeypatch.setattr(installer, "_run_install_command", fake_run)

    result = installer.install("32.1.0")

    assert result.integrity["npm"]["shasum"] == FAKE_SHASUM
    assert result.integrity["tarball"]["digest"] == FAKE_DIGEST_HEX


def test_install_locates_single_tarball_without_filename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lone packed tarball is used when npm pack JSON has no filename."""
    install_root = tmp_path / "srv" / "app"
    installer = VersionInstaller(install_root=install_root, package_name="@actual-app/sync-server")

    def fake_run(
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        _write_pack_tarball(
            staging_dir,
            "only.tgz",
            package_json={"name": "@actual-app/sync-server"},
        )
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([{}]), stderr="")

    monkeypatch.setattr(installer, "_run_install_command", fake_run)

    result = installer.install("33.0.0")

    assert (result.path / "package.json").is_file()
    assert (result.path / "build" / "bin" / "actual-server.js").is_file()
