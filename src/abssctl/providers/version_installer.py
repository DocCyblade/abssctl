"""Installer utilities for Actual Sync Server versions."""
from __future__ import annotations

import base64
import binascii
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
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
        """Install *version* of the configured npm package."""
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
            "install",
            f"{self.package_name}@{normalized_version}",
            "--prefix",
            str(staging_dir),
        ]
        cmd.extend(self.npm_args)
        cmd.extend(["--no-save", "--omit=dev"])

        env_vars = os.environ.copy()
        if env:
            env_vars.update(env)

        staging_to_cleanup: Path | None = staging_dir
        try:
            result = self._run_install_command(staging_dir, cmd, env=env_vars)
            if result.returncode != 0:
                raise VersionInstallError(
                    "npm install failed",
                )

            package_dir = _resolve_package_directory(staging_dir, self.package_name)
            if not package_dir.exists():
                raise VersionInstallError(
                    f"npm install completed but package directory missing: {package_dir}"
                )

            shutil.move(str(staging_dir), str(target_dir))
            staging_to_cleanup = None
            package_dir = _resolve_package_directory(target_dir, self.package_name)
        finally:
            if staging_to_cleanup and staging_to_cleanup.exists():
                shutil.rmtree(staging_to_cleanup, ignore_errors=True)

        metadata = cast(
            dict[str, object],
            {
                "package": self.package_name,
                "npm_args": list(self.npm_args),
            },
        )
        pkg_json = package_dir / "package.json"
        integrity: dict[str, object] = {}
        if pkg_json.exists():
            metadata["package_json"] = str(pkg_json)
            integrity = self._collect_integrity(pkg_json)

        installed_at = datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        return VersionInstallResult(
            version=normalized_version,
            path=target_dir,
            installed_at=installed_at,
            metadata=metadata,
            integrity=integrity,
        )

    def _run_install_command(
        self,
        staging_dir: Path,
        cmd: Sequence[str],
        *,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        """Execute npm install command (isolated for testing)."""
        return subprocess.run(  # noqa: S603,S607
            cmd,
            check=False,
            capture_output=True,
            text=True,
            env=dict(env),
        )

    def _collect_integrity(self, package_json_path: Path) -> dict[str, object]:
        """Extract integrity details from a package.json if available."""
        try:
            payload = json.loads(package_json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

        integrity: dict[str, object] = {}

        npm_details: dict[str, object] = {}
        shasum = _extract_shasum(payload)
        if shasum:
            npm_details["shasum"] = shasum

        integrity_string = _extract_integrity_string(payload)
        if integrity_string:
            npm_details["integrity"] = integrity_string
            parsed = _parse_integrity(integrity_string)
            if parsed:
                algorithm, digest_hex = parsed
                integrity["tarball"] = {"algorithm": algorithm, "digest": digest_hex}

        if npm_details:
            integrity["npm"] = npm_details

        return integrity


def _resolve_package_directory(staging_dir: Path, package_name: str) -> Path:
    """Return the expected package directory under an npm prefix."""
    parts = package_name.split("/")
    package_path = staging_dir / "node_modules"
    for part in parts:
        package_path /= part
    return package_path


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
