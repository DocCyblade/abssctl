"""Helpers for loading the Node compatibility matrix."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import yaml


class NodeCompatibilityError(RuntimeError):
    """Raised when the compatibility matrix cannot be loaded."""


@dataclass(frozen=True)
class NodeVersionSpec:
    """Supported Node major/minimum patch tuple."""

    major: int
    min_patch: str
    status: str = "supported"
    adr: str | None = None
    notes: str | None = None

    def min_tuple(self) -> tuple[int, int, int]:
        """Return ``(major, minor, patch)`` tuple for comparisons."""
        return _coerce_semver(self.min_patch)


@dataclass(frozen=True)
class ActualVersionSpec:
    """Recorded Actual release metadata."""

    version: str
    release_date: str | None
    node_constraint: str | None
    node_major: int | None
    status: str
    tested_at: str | None
    notes: str | None
    npm_dist_tags: tuple[str, ...]


@dataclass(frozen=True)
class NodeCompatibilityMatrix:
    """Complete compatibility dataset."""

    schema_version: int
    generated_at: str | None
    package: str | None
    source: str | None
    limit: int | None
    node_versions: tuple[NodeVersionSpec, ...]
    actual_versions: tuple[ActualVersionSpec, ...]
    path: Path | None = None

    def preferred_node_version(self) -> NodeVersionSpec | None:
        """Return the recommended Node version entry."""
        if not self.node_versions:
            return None
        ranked = sorted(
            self.node_versions,
            key=lambda entry: (
                _status_rank(entry.status),
                -entry.major,
                entry.min_tuple(),
            ),
        )
        return ranked[0]

    def find_actual(self, version: str) -> ActualVersionSpec | None:
        """Return metadata for the requested Actual release, if present."""
        normalized = version.strip().lstrip("v")
        for entry in self.actual_versions:
            candidate = entry.version.strip().lstrip("v")
            if candidate == normalized:
                return entry
        return None


def load_node_compatibility(path: str | Path | None = None) -> NodeCompatibilityMatrix:
    """Load Node compatibility data from *path* or the packaged default."""
    resolved_path: Path | None = None
    if path is None:
        resource = resources.files("abssctl.data").joinpath("node-compat.yaml")
        try:
            raw_text = resource.read_text(encoding="utf-8")
        except FileNotFoundError as exc:  # pragma: no cover - packaged resource missing
            raise NodeCompatibilityError("Packaged node-compat.yaml is missing.") from exc
    else:
        resolved_path = Path(path)
        try:
            raw_text = resolved_path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise NodeCompatibilityError(f"Compatibility file not found: {resolved_path}") from exc

    try:
        payload = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError as exc:
        raise NodeCompatibilityError(f"Failed to parse compatibility YAML: {exc}") from exc
    if not isinstance(payload, dict):
        raise NodeCompatibilityError("Compatibility YAML must contain a mapping at the root.")

    node_versions = _load_node_versions(payload.get("node_versions"))
    actual_versions = _load_actual_versions(payload.get("actual_versions"))
    schema_version = int(payload.get("schema_version") or 1)
    generated_at = payload.get("generated_at")
    package = payload.get("package")
    source = payload.get("source")
    limit = payload.get("limit")

    return NodeCompatibilityMatrix(
        schema_version=schema_version,
        generated_at=str(generated_at) if generated_at is not None else None,
        package=str(package) if package is not None else None,
        source=str(source) if source is not None else None,
        limit=int(limit) if isinstance(limit, int) else None,
        node_versions=node_versions,
        actual_versions=actual_versions,
        path=resolved_path,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_node_versions(raw: object) -> tuple[NodeVersionSpec, ...]:
    entries: list[NodeVersionSpec] = []
    for entry in _iter_dicts(raw):
        major = _parse_required_int(entry.get("major"), "node_versions.major")
        min_patch = str(entry.get("min_patch") or "").strip()
        if not min_patch:
            raise NodeCompatibilityError(f"Node major {major} missing min_patch.")
        spec = NodeVersionSpec(
            major=major,
            min_patch=min_patch,
            status=str(entry.get("status") or "supported"),
            adr=str(entry.get("adr")) if entry.get("adr") is not None else None,
            notes=str(entry.get("notes")) if entry.get("notes") is not None else None,
        )
        entries.append(spec)
    return tuple(entries)


def _load_actual_versions(raw: object) -> tuple[ActualVersionSpec, ...]:
    entries: list[ActualVersionSpec] = []
    for entry in _iter_dicts(raw):
        tags = entry.get("npm_dist_tags") or ()
        tag_tuple = tuple(str(tag) for tag in tags) if isinstance(tags, Iterable) else ()
        spec = ActualVersionSpec(
            version=str(entry.get("version") or ""),
            release_date=(
                str(entry.get("release_date")) if entry.get("release_date") else None
            ),
            node_constraint=(
                str(entry.get("node_constraint")) if entry.get("node_constraint") else None
            ),
            node_major=_parse_optional_int(entry.get("node_major")),
            status=str(entry.get("status") or "unknown"),
            tested_at=str(entry.get("tested_at")) if entry.get("tested_at") else None,
            notes=str(entry.get("notes")) if entry.get("notes") else None,
            npm_dist_tags=tag_tuple,
        )
        entries.append(spec)
    return tuple(entries)


def _iter_dicts(raw: object) -> Iterable[dict[str, object]]:
    if not isinstance(raw, Iterable):
        return ()
    result: list[dict[str, object]] = []
    for item in raw:
        if isinstance(item, dict):
            result.append(item)
    return result


def _parse_required_int(value: object, field: str) -> int:
    parsed = _parse_optional_int(value)
    if parsed is None:
        raise NodeCompatibilityError(f"{field} must be an integer.")
    return parsed


def _parse_optional_int(value: object) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            return int(stripped)
        except ValueError as exc:
            raise NodeCompatibilityError(f"Invalid integer value '{value}'.") from exc
    raise NodeCompatibilityError(f"Unsupported integer value type: {type(value)!r}")


def _status_rank(value: str) -> int:
    normalized = (value or "").strip().lower()
    priority: dict[str, int] = {
        "recommended": 0,
        "supported": 1,
        "preview": 2,
        "beta": 2,
        "experimental": 3,
        "deprecated": 4,
    }
    return priority.get(normalized, 5)


def _coerce_semver(value: str) -> tuple[int, int, int]:
    parts = [part for part in value.strip().lstrip("v").split(".") if part]
    numbers: list[int] = []
    for part in parts[:3]:
        try:
            numbers.append(int(part))
        except ValueError:
            numbers.append(0)
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers)  # type: ignore[return-value]


__all__ = [
    "ActualVersionSpec",
    "NodeCompatibilityError",
    "NodeCompatibilityMatrix",
    "NodeVersionSpec",
    "load_node_compatibility",
]
