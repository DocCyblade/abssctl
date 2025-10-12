"""Helpers for interacting with the abssctl state registry.

The registry directory (``/var/lib/abssctl/registry`` by default) stores YAML
artifacts such as ``instances.yml`` and ``ports.yml``. This module provides
lightweight helpers to read and write those files using atomic operations so
future mutating commands can safely extend the logic.
"""
from __future__ import annotations

import os
import tempfile
from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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

    def write_instances(self, instances: Iterable[object]) -> None:
        """Persist instance entries to ``instances.yml``."""
        self.write("instances.yml", {"instances": list(instances)})

    def write_versions(self, versions: Iterable[object]) -> None:
        """Persist version entries to ``versions.yml``."""
        self.write("versions.yml", {"versions": list(versions)})

    # Version helpers -------------------------------------------------
    def get_version(self, version: str) -> dict[str, Any] | None:
        """Return the registry entry for *version* if present."""
        normalized_version = version.strip()
        if not normalized_version:
            raise StateRegistryError("Version identifier must be a non-empty string.")

        entries = _load_version_entries(self.read_versions())
        for entry in entries:
            if entry.get("version") == normalized_version:
                return deepcopy(entry)
        return None

    def upsert_version(self, entry: Mapping[str, object]) -> None:
        """Add or update a version registry entry."""
        normalized_entry = _normalize_version_entry(entry)
        versions = _load_version_entries(self.read_versions())
        metadata_to_store: list[dict[str, Any]] = []
        replaced = False

        for existing in versions:
            if existing.get("version") == normalized_entry["version"]:
                merged = _merge_version_entries(existing, normalized_entry)
                metadata_to_store.append(merged)
                replaced = True
            else:
                metadata_to_store.append(existing)

        if not replaced:
            metadata_to_store.append(normalized_entry)

        self.write_versions(metadata_to_store)

    def remove_version(self, version: str) -> None:
        """Remove *version* from the registry."""
        normalized_version = version.strip()
        if not normalized_version:
            raise StateRegistryError("Version identifier must be a non-empty string.")

        versions = _load_version_entries(self.read_versions())
        filtered = [entry for entry in versions if entry.get("version") != normalized_version]

        if len(filtered) == len(versions):
            raise StateRegistryError(f"Version '{normalized_version}' not found in registry")

        self.write_versions(filtered)

    # Instance helpers -------------------------------------------------
    def get_instance(self, name: str) -> dict[str, Any] | None:
        """Return the instance mapping for *name* if registered."""
        data = self.read_instances()
        raw_instances = data.get("instances", [])
        if not isinstance(raw_instances, list):
            return None
        for entry in raw_instances:
            if isinstance(entry, Mapping) and entry.get("name") == name:
                return dict(entry)
        return None

    def update_instance(self, name: str, updates: Mapping[str, object]) -> None:
        """Apply *updates* to the registered instance named *name*."""
        data = self.read_instances()
        raw_instances = data.get("instances", [])
        instances: list[object] = []
        found = False
        if isinstance(raw_instances, list):
            for entry in raw_instances:
                if isinstance(entry, Mapping) and entry.get("name") == name:
                    merged = dict(entry)
                    merged.update(updates)
                    instances.append(merged)
                    found = True
                else:
                    instances.append(entry)
        if not found:
            raise StateRegistryError(f"Instance '{name}' not found in registry")
        self.write_instances(instances)

    def remove_instance(self, name: str) -> None:
        """Remove the instance named *name* from the registry."""
        data = self.read_instances()
        raw_instances = data.get("instances", [])
        instances: list[object] = []
        removed = False
        if isinstance(raw_instances, list):
            for entry in raw_instances:
                if isinstance(entry, Mapping) and entry.get("name") == name:
                    removed = True
                    continue
                instances.append(entry)
        if not removed:
            raise StateRegistryError(f"Instance '{name}' not found in registry")
        self.write_instances(instances)


def _load_version_entries(raw: Mapping[str, object]) -> list[dict[str, Any]]:
    """Return a normalised list of version entries from the registry mapping."""
    entries: list[dict[str, Any]] = []
    raw_entries = raw.get("versions", [])

    if isinstance(raw_entries, list):
        for item in raw_entries:
            if isinstance(item, Mapping):
                entries.append(_normalize_version_entry(item))
            elif isinstance(item, str):
                entries.append({"version": item.strip()})
            else:
                entries.append({"version": str(item)})
    return entries


def _normalize_version_entry(entry: Mapping[str, object]) -> dict[str, Any]:
    """Validate and normalise a version registry entry."""
    if not isinstance(entry, Mapping):
        raise StateRegistryError("Version entry must be a mapping.")

    version_raw = entry.get("version")
    version = str(version_raw).strip() if version_raw is not None else ""
    if not version:
        raise StateRegistryError("Version entry missing 'version'.")

    normalized: dict[str, Any] = {"version": version}

    if "path" in entry and entry["path"] is not None:
        normalized["path"] = str(entry["path"])

    if "installed_at" in entry and entry["installed_at"] is not None:
        normalized["installed_at"] = str(entry["installed_at"])

    if "source" in entry and entry["source"] is not None:
        normalized["source"] = str(entry["source"])

    if "metadata" in entry and entry["metadata"] is not None:
        metadata = entry["metadata"]
        if not isinstance(metadata, Mapping):
            raise StateRegistryError("Version entry 'metadata' must be a mapping.")
        normalized["metadata"] = dict(metadata)

    if "integrity" in entry and entry["integrity"] is not None:
        integrity = entry["integrity"]
        if not isinstance(integrity, Mapping):
            raise StateRegistryError("Version entry 'integrity' must be a mapping.")
        normalized["integrity"] = dict(integrity)

    if "notes" in entry and entry["notes"] is not None:
        normalized["notes"] = str(entry["notes"])

    return normalized


def _merge_version_entries(
    existing: Mapping[str, Any],
    new: Mapping[str, Any],
) -> dict[str, Any]:
    """Merge two version entries, preferring values from *new*."""
    merged: dict[str, Any] = dict(existing)
    for key, value in new.items():
        if key in {"metadata", "integrity"} and key in merged:
            if isinstance(merged[key], Mapping):
                combined = dict(merged[key])
                if isinstance(value, Mapping):
                    combined.update(dict(value))
                    merged[key] = combined
                    continue
        merged[key] = value
    return merged


__all__ = ["StateRegistry", "StateRegistryError"]
