"""Version provider that fetches metadata from npm when available."""
from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterable
from pathlib import Path


class VersionProvider:
    """Return available versions for the configured npm package."""

    def __init__(
        self,
        *,
        cache_env: str = "ABSSCTL_VERSIONS_CACHE",
        skip_env: str = "ABSSCTL_SKIP_NPM",
        cache_path: Path | None = None,
    ) -> None:
        """Initialise the provider with optional environment overrides."""
        self.cache_env = cache_env
        self.skip_env = skip_env
        self.cache_path = cache_path

    def list_remote_versions(self, package: str) -> list[str]:
        """Return versions published to npm for *package*.

        Falls back to cached data when the environment variable specified by
        ``cache_env`` is set, or returns an empty list when npm execution is
        skipped (``skip_env=1``) or fails.
        """
        if os.getenv(self.skip_env) == "1":
            return []

        if self.cache_path and self.cache_path.exists():
            cached = self._from_cache(self.cache_path)
            if cached:
                return cached

        cache_path = os.getenv(self.cache_env)
        if cache_path:
            return self._from_cache(Path(cache_path))

        versions = self._from_npm(package)
        if versions and self.cache_path:
            self._write_cache(self.cache_path, versions)
        return versions

    def refresh_cache(self, package: str) -> list[str]:
        """Fetch versions from npm and write them to the configured cache path."""
        versions = self._from_npm(package)
        if versions and self.cache_path:
            self._write_cache(self.cache_path, versions)
        return versions

    def _from_cache(self, path: Path) -> list[str]:
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        return _normalise_versions(data)

    def _write_cache(self, path: Path, versions: list[str]) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(versions, indent=2), encoding="utf-8")
        except OSError:
            # Non-fatal; cache updates are opportunistic.
            pass

    def _from_npm(self, package: str) -> list[str]:
        try:
            result = subprocess.run(  # noqa: S603, S607 - controlled command
                ["npm", "view", package, "versions", "--json"],
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return []

        if result.returncode != 0:
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        return _normalise_versions(data)


def _normalise_versions(data: object) -> list[str]:
    if isinstance(data, list):
        return [str(item) for item in data]
    if isinstance(data, str):
        return [data]
    if isinstance(data, Iterable):
        return [str(item) for item in data]
    return []


__all__ = ["VersionProvider"]
