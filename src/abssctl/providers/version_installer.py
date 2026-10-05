"""Installer utilities for Actual Sync Server versions."""
from __future__ import annotations

import base64
import binascii
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, cast


class VersionInstallError(RuntimeError):
    """Raised when installing an Actual version fails."""


@dataclass(frozen=True, slots=True)
class VersionInstallResult:
    """Metadata describing a completed installation."""

    version: str
    path: Path
    installed_at: str
    metadata: dict[str, object]
    integrity: dict[str, object]


class VersionInstaller:
    """Install Actual Sync Server releases via npm."""

    def __init__(
        self,
        *,
        install_root: Path,
        package_name: str,
        npm_bin: str = "npm",
        npm_args: Sequence[str] | None = None,
    ) -> None:
        """Initialise the installer with target directory and npm configuration."""
        self.install_root = install_root.expanduser()
        self.package_name = package_name
        self.npm_bin = npm_bin
        self.npm_args = list(npm_args or [])

    def install(
        self,
        version: str,
        *,
        env: Mapping[str, str] | None = None,
        dry_run: bool = False,
    ) -> VersionInstallResult:
        """Install *version* by packing the npm tarball into the version directory.

        Matches ``000-manual-install.sh``: ``npm pack``, extract into
        ``<install_root>/v<version>`` with the leading ``package/`` directory
        removed, then leave dependency installation to the caller
        (``npm install --omit=dev --no-save`` in that directory).
        """
        normalized_version = version.strip()
        if not normalized_version:
            raise VersionInstallError("Version identifier must be a non-empty string.")

        target_dir = self.install_root / f"v{normalized_version}"
        if target_dir.exists():
            raise VersionInstallError(f"Version directory already exists: {target_dir}")

        if dry_run:
            installed_at = datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
            return VersionInstallResult(
                version=normalized_version,
                path=target_dir,
                installed_at=installed_at,
                metadata={
                    "package": self.package_name,
                    "dry_run": True,
                    "npm_args": list(self.npm_args),
                },
                integrity={},
            )

        self.install_root.mkdir(parents=True, exist_ok=True)

        staging_dir = Path(
            tempfile.mkdtemp(
                prefix=f"abssctl-install-{normalized_version}-",
                dir=str(self.install_root),
            )
        )
        cmd = [
            self.npm_bin,
            "pack",
            f"{self.package_name}@{normalized_version}",
            "--json",
            "--pack-destination",
            str(staging_dir),
        ]
        cmd.extend(self.npm_args)

        env_vars = os.environ.copy()
        if env:
            env_vars.update(env)

        moved = False
        success = False
        try:
            result = self._run_install_command(staging_dir, cmd, env=env_vars)
            if result.returncode != 0:
                raise VersionInstallError("npm pack failed")

            packed = _parse_pack_metadata(result.stdout)
            tarball = _locate_packed_tarball(staging_dir, packed)
            extract_dir = staging_dir / "unpack"
            _extract_npm_tarball(tarball, extract_dir)
            staged_package_json = extract_dir / "package.json"
            if not staged_package_json.is_file():
                raise VersionInstallError(
                    f"npm pack completed but package.json missing: {target_dir / 'package.json'}"
                )

            shutil.move(str(extract_dir), str(target_dir))
            moved = True
            package_json = target_dir / "package.json"
            integrity = _integrity_from_mapping(
                {
                    "_shasum": packed.get("shasum"),
                    "_integrity": packed.get("integrity"),
                }
            )
            if not integrity:
                integrity = self._collect_integrity(package_json)

            metadata = cast(
                dict[str, object],
                {
                    "package": self.package_name,
                    "npm_args": list(self.npm_args),
                    "package_json": str(package_json),
                },
            )
            installed_at = datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
            install_result = VersionInstallResult(
                version=normalized_version,
                path=target_dir,
                installed_at=installed_at,
                metadata=metadata,
                integrity=integrity,
            )
            success = True
            return install_result
        finally:
            if moved and not success and target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)
            if staging_dir.exists():
                shutil.rmtree(staging_dir, ignore_errors=True)

    def _run_install_command(
        self,
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        """Execute the npm pack command (isolated for testing)."""
        return subprocess.run(  # noqa: S603,S607
            cmd,
            check=False,
            capture_output=True,
            text=True,
            cwd=str(staging_dir),
            env=dict(env),
        )

    def _collect_integrity(self, package_json_path: Path) -> dict[str, object]:
        """Extract integrity details from a package.json if available."""
        try:
            payload = json.loads(package_json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, Mapping):
            return {}
        return _integrity_from_mapping(payload)


def _integrity_from_mapping(data: Mapping[str, Any]) -> dict[str, object]:
    """Extract npm shasum and tarball integrity from *data*."""
    integrity: dict[str, object] = {}

    npm_details: dict[str, object] = {}
    shasum = _extract_shasum(data)
    if shasum:
        npm_details["shasum"] = shasum

    integrity_string = _extract_integrity_string(data)
    if integrity_string:
        npm_details["integrity"] = integrity_string
        parsed = _parse_integrity(integrity_string)
        if parsed:
            algorithm, digest_hex = parsed
            integrity["tarball"] = {"algorithm": algorithm, "digest": digest_hex}

    if npm_details:
        integrity["npm"] = npm_details

    return integrity


def _parse_pack_metadata(stdout: str) -> dict[str, object]:
    """Return the first object from ``npm pack --json`` output."""
    text = stdout.strip()
    starts = [index for index in (text.find("["), text.find("{")) if index != -1]
    if not starts:
        raise VersionInstallError("npm pack returned unreadable metadata")
    payload_text = text[min(starts) :]
    try:
        data = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        raise VersionInstallError("npm pack returned unreadable metadata") from exc
    if isinstance(data, list):
        first = data[0] if data else None
        if not isinstance(first, Mapping):
            raise VersionInstallError("npm pack returned unreadable metadata")
        return {str(key): value for key, value in first.items()}
    if isinstance(data, Mapping):
        return {str(key): value for key, value in data.items()}
    raise VersionInstallError("npm pack returned unreadable metadata")


def _locate_packed_tarball(staging_dir: Path, packed: Mapping[str, object]) -> Path:
    """Return the tarball ``npm pack`` wrote into *staging_dir*."""
    filename = packed.get("filename")
    if isinstance(filename, str) and filename.strip():
        candidate = staging_dir / Path(filename).name
        if candidate.is_file():
            return candidate
    matches = sorted(path for path in staging_dir.glob("*.tgz") if path.is_file())
    if len(matches) == 1:
        return matches[0]
    raise VersionInstallError("npm pack completed but tarball missing")


def _stripped_member_path(name: str) -> Path | None:
    """Drop the leading ``package/`` component from an npm pack member name."""
    normalized = name.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    while normalized.startswith("/"):
        normalized = normalized[1:]
    if not normalized:
        return None
    parts = PurePosixPath(normalized).parts
    if any(part == ".." for part in parts):
        raise VersionInstallError(f"Refusing to extract tarball member: {name}")
    if len(parts) <= 1:
        return None
    return Path(*parts[1:])


def _extract_npm_tarball(tarball: Path, destination: Path) -> None:
    """Extract *tarball* into *destination*, stripping the top-level directory."""
    destination.mkdir(parents=True, exist_ok=True)
    dest_root = destination.resolve()
    try:
        with tarfile.open(tarball, "r:*") as archive:
            for member in archive.getmembers():
                relative = _stripped_member_path(member.name)
                if relative is None:
                    continue
                target = (dest_root / relative).resolve()
                if dest_root != target and dest_root not in target.parents:
                    raise VersionInstallError(
                        f"Refusing to extract tarball member outside destination: {member.name}"
                    )
                if member.islnk():
                    raise VersionInstallError(
                        f"Refusing to extract tarball hard link: {member.name}"
                    )
                if member.issym():
                    _extract_link(member, target)
                    continue
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    continue
                source = archive.extractfile(member)
                if source is None:
                    raise VersionInstallError(f"Unable to read tarball member: {member.name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as handle:
                    shutil.copyfileobj(source, handle)
    except tarfile.TarError as exc:
        raise VersionInstallError(f"Unable to extract npm pack tarball: {exc}") from exc


def _extract_link(member: tarfile.TarInfo, target: Path) -> None:
    """Recreate a relative archive link that stays inside the extract tree."""
    linkname = member.linkname
    link_path = PurePosixPath(linkname)
    if link_path.is_absolute() or ".." in link_path.parts:
        raise VersionInstallError(f"Refusing to extract tarball link: {member.name}")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        target.unlink()
    target.symlink_to(linkname)


def _extract_shasum(data: Mapping[str, Any]) -> str | None:
    """Return the npm shasum value if present."""
    candidates = [
        data.get("_shasum"),
        data.get("shasum"),
    ]
    dist = data.get("dist")
    if isinstance(dist, Mapping):
        candidates.append(dist.get("shasum"))

    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def _extract_integrity_string(data: Mapping[str, Any]) -> str | None:
    """Return the integrity string (sha512-...) if present."""
    candidates = [
        data.get("_integrity"),
    ]
    dist = data.get("dist")
    if isinstance(dist, Mapping):
        candidates.append(dist.get("integrity"))

    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def _parse_integrity(value: str) -> tuple[str, str] | None:
    """Parse npm integrity strings as (algorithm, hex digest)."""
    if "-" not in value:
        return None
    algorithm, digest_part = value.split("-", 1)
    algorithm = algorithm.strip().lower()
    digest_part = digest_part.strip()
    if not algorithm or not digest_part:
        return None
    try:
        digest_bytes = base64.b64decode(digest_part, validate=True)
    except (binascii.Error, ValueError):
        return None
    return algorithm, digest_bytes.hex()


__all__ = ["VersionInstallError", "VersionInstallResult", "VersionInstaller"]
