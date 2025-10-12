"""State registry helpers tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from abssctl.state import StateRegistry, StateRegistryError


def test_read_missing_files_returns_default(tmp_path: Path) -> None:
    """Missing files return the provided default structure."""
    registry = StateRegistry(tmp_path)

    result = registry.read("instances.yml", default={"instances": []})

    assert result == {"instances": []}


def test_write_and_read_roundtrip(tmp_path: Path) -> None:
    """Writing a registry file and reading it back succeeds."""
    registry = StateRegistry(tmp_path)
    payload = {"instances": [{"name": "primary"}]}

    registry.write("instances.yml", payload)

    path = tmp_path / "instances.yml"
    assert path.exists()
    assert (path.stat().st_mode & 0o777) == 0o640

    loaded = registry.read("instances.yml")
    assert loaded == payload


def test_read_helpers(tmp_path: Path) -> None:
    """Helper methods normalise return values."""
    registry = StateRegistry(tmp_path)

    assert registry.read_instances() == {"instances": []}
    assert registry.read_versions() == {"versions": []}

    registry.write("ports.yml", {"ports": [{"port": 5000}]})
    ports = registry.read_ports()

    assert ports["ports"][0]["port"] == 5000


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    """Invalid YAML raises a StateRegistryError."""
    registry = StateRegistry(tmp_path)
    path = tmp_path / "instances.yml"
    path.write_text("::: not yaml :::\n")

    with pytest.raises(StateRegistryError):
        registry.read("instances.yml")


def test_version_upsert_and_get(tmp_path: Path) -> None:
    """Version registry helpers normalise and persist entries."""
    registry = StateRegistry(tmp_path)

    registry.upsert_version(
        {
            "version": "1.2.3",
            "path": tmp_path / "v1.2.3",
            "metadata": {"npm": "@actual-app/sync-server"},
            "integrity": {"shasum": "deadbeef"},
        }
    )

    entry = registry.get_version("1.2.3")
    assert entry is not None
    assert entry["version"] == "1.2.3"
    assert entry["path"].endswith("v1.2.3")
    assert entry["metadata"]["npm"] == "@actual-app/sync-server"
    assert entry["integrity"]["shasum"] == "deadbeef"

    # Update entry with partial data (merge metadata)
    registry.upsert_version({"version": "1.2.3", "metadata": {"channel": "stable"}})
    updated = registry.get_version("1.2.3")
    assert updated is not None
    assert updated["metadata"]["npm"] == "@actual-app/sync-server"
    assert updated["metadata"]["channel"] == "stable"


def test_remove_version(tmp_path: Path) -> None:
    """Removing a version deletes it from the registry."""
    registry = StateRegistry(tmp_path)
    registry.upsert_version({"version": "2.0.0"})

    registry.remove_version("2.0.0")
    assert registry.get_version("2.0.0") is None

    with pytest.raises(StateRegistryError):
        registry.remove_version("2.0.0")


def test_invalid_version_entry_raises(tmp_path: Path) -> None:
    """Invalid version metadata types raise errors."""
    registry = StateRegistry(tmp_path)

    with pytest.raises(StateRegistryError):
        registry.upsert_version({"version": ""})

    with pytest.raises(StateRegistryError):
        registry.upsert_version({"version": "1.0.0", "metadata": "not-a-mapping"})

    with pytest.raises(StateRegistryError):
        registry.remove_version("")
