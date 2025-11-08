"""Tests for the Node compatibility loader."""
from __future__ import annotations

from pathlib import Path

import yaml

from abssctl.node_compat import (
    NodeCompatibilityError,
    NodeCompatibilityMatrix,
    load_node_compatibility,
)


def test_load_node_compatibility_from_package() -> None:
    """The packaged compatibility data should load successfully."""
    matrix = load_node_compatibility()
    assert isinstance(matrix, NodeCompatibilityMatrix)
    entry = matrix.preferred_node_version()
    assert entry is not None
    assert entry.major >= 18


def test_preferred_node_version_selects_supported_entry(tmp_path: Path) -> None:
    """Preferred version should honour status priority and highest major."""
    payload = {
        "schema_version": 1,
        "node_versions": [
            {"major": 16, "min_patch": "16.20.0", "status": "deprecated"},
            {"major": 18, "min_patch": "18.17.0", "status": "supported"},
            {"major": 20, "min_patch": "20.10.0", "status": "preview"},
        ],
        "actual_versions": [],
    }
    compat_file = tmp_path / "node-compat.yaml"
    compat_file.write_text(yaml.safe_dump(payload), encoding="utf-8")
    matrix = load_node_compatibility(compat_file)
    preferred = matrix.preferred_node_version()
    assert preferred is not None
    assert preferred.major == 18
    assert preferred.min_patch == "18.17.0"


def test_load_node_compatibility_errors_on_missing_file(tmp_path: Path) -> None:
    """Missing compatibility files should raise a descriptive error."""
    missing = tmp_path / "absent.yaml"
    try:
        load_node_compatibility(missing)
    except NodeCompatibilityError as exc:
        assert str(missing) in str(exc)
    else:  # pragma: no cover - ensure failure surfaces during tests
        raise AssertionError("Expected NodeCompatibilityError for missing file")
