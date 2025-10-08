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
