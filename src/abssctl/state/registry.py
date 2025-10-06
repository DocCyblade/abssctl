"""Helpers for interacting with the abssctl state registry.

The registry directory (``/var/lib/abssctl/registry`` by default) stores YAML
artifacts such as ``instances.yml`` and ``ports.yml``. This module provides
lightweight helpers to read and write those files using atomic operations so
future mutating commands can safely extend the logic.
"""
from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

try:  # PyYAML is a runtime dependency declared in pyproject.toml
    import yaml
except Exception as exc:  # pragma: no cover - import failure handled in tests
    raise RuntimeError(
        "PyYAML is required to manage abssctl state. Install with `pip install abssctl`."
    ) from exc


class StateRegistryError(RuntimeError):
    """Raised when state registry operations fail."""


@dataclass(frozen=True)
class StateRegistry:
    """High-level interface to the YAML registry."""

    root: Path

    def __post_init__(self) -> None:
        """Normalise the root path after initialisation."""
        object.__setattr__(self, "root", self.root.expanduser())

    def ensure_root(self) -> None:
        """Create the registry directory if it does not yet exist."""
        self.root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
    def path_for(self, name: str) -> Path:
        """Return the filesystem path for a named registry file."""
        return self.root / name

    def read(self, name: str, *, default: object | None = None) -> object | None:
        """Read a registry file, returning *default* when missing."""
        path = self.path_for(name)
        if not path.exists():
            return deepcopy(default)
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:  # pragma: no cover - delegated to PyYAML
            raise StateRegistryError(f"Failed to parse registry file {path}: {exc}") from exc
        return data if data is not None else deepcopy(default)

    def write(self, name: str, payload: Mapping[str, object]) -> None:
        """Atomically write *payload* to the given registry file."""
        self.ensure_root()
        path = self.path_for(name)

        tmp_fd, tmp_name = tempfile.mkstemp(dir=str(self.root), prefix=f".{path.name}.")
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
                yaml.safe_dump(payload, handle, sort_keys=False)
            os.replace(tmp_path, path)
            os.chmod(path, 0o640)
        finally:
            tmp_path.unlink(missing_ok=True)

    # Convenience wrappers -------------------------------------------------
    def read_instances(self) -> Mapping[str, object]:
        """Return the contents of ``instances.yml`` (empty mapping if missing)."""
        value = self.read("instances.yml", default={"instances": []})
        return value if isinstance(value, Mapping) else {"instances": []}

    def read_ports(self) -> Mapping[str, object]:
        """Return the contents of ``ports.yml`` (empty mapping if missing)."""
        value = self.read("ports.yml", default={"ports": []})
        return value if isinstance(value, Mapping) else {"ports": []}

    def read_versions(self) -> Mapping[str, object]:
        """Return the contents of ``versions.yml`` (empty mapping if missing)."""
        value = self.read("versions.yml", default={"versions": []})
        return value if isinstance(value, Mapping) else {"versions": []}


__all__ = ["StateRegistry", "StateRegistryError"]
