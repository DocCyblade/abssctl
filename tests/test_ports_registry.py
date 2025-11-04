"""Tests for the ports registry helper."""
from __future__ import annotations

from pathlib import Path

import pytest

from abssctl.ports import PortsRegistry, PortsRegistryError
from abssctl.state import StateRegistry


@pytest.fixture
def ports(tmp_path: Path) -> PortsRegistry:
    """Return a ports registry rooted at a temporary path."""
    registry = StateRegistry(tmp_path / "registry")
    return PortsRegistry(registry=registry, base_port=5000)


def test_reserve_assigns_sequential_ports(ports: PortsRegistry) -> None:
    """Reserve allocates ports sequentially starting at the base port."""
    first = ports.reserve("alpha")
    second = ports.reserve("beta")
    assert first == 5000
    assert second == 5001
    assert ports.get_port("alpha") == 5000
    assert ports.get_port("beta") == 5001


def test_release_frees_port_for_reuse(ports: PortsRegistry) -> None:
    """Releasing a port makes it available for future reservations."""
    first = ports.reserve("alpha")
    second = ports.reserve("beta")
    assert (first, second) == (5000, 5001)

    ports.release("alpha")
    recycled = ports.reserve("gamma")
    assert recycled == 5000


def test_duplicate_reserve_raises(ports: PortsRegistry) -> None:
    """Attempting to reserve a port for an existing instance raises an error."""
    ports.reserve("alpha")
    with pytest.raises(PortsRegistryError):
        ports.reserve("alpha")


def test_request_specific_port_and_collision(ports: PortsRegistry) -> None:
    """Specific port requests succeed when free and fail when in use."""
    assigned = ports.reserve("alpha", requested_port=5005)
    assert assigned == 5005
    ports.reserve("beta")

    with pytest.raises(PortsRegistryError):
        ports.reserve("gamma", requested_port=5005)


def test_release_missing_port_raises(ports: PortsRegistry) -> None:
    """Releasing a port that does not exist raises an error."""
    ports.reserve("alpha")
    with pytest.raises(PortsRegistryError):
        ports.release("beta")


def test_reserve_rejects_blank_name(ports: PortsRegistry) -> None:
    """Blank instance names are rejected."""
    with pytest.raises(PortsRegistryError):
        ports.reserve("   ")


def test_ports_registry_persist_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Write failures bubble up as errors to callers."""
    registry = StateRegistry(tmp_path / "registry")
    ports = PortsRegistry(registry=registry, base_port=5000)

    def fail_write(entries: list[dict[str, int]]) -> None:  # noqa: ARG001 - signature matches
        raise OSError("disk full")

    monkeypatch.setattr(StateRegistry, "write_ports", fail_write)

    with pytest.raises(OSError):
        ports.reserve("alpha")
