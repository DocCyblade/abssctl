"""Port allocation helpers for abssctl."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .state import StateRegistry


class PortsRegistryError(RuntimeError):
    """Raised when port allocation or release fails."""


@dataclass(slots=True)
class PortsRegistry:
    """Manage the ports registry stored under ``ports.yml``."""

    registry: StateRegistry
    base_port: int
    strategy: str = "sequential"

    def __post_init__(self) -> None:
        """Validate initialiser parameters."""
        if self.base_port < 1:
            raise PortsRegistryError("Base port must be a positive integer.")
        if self.strategy != "sequential":
            raise PortsRegistryError(f"Unsupported port allocation strategy '{self.strategy}'.")
        self.registry.ensure_root()

    # ------------------------------------------------------------------
    def list_entries(self) -> list[dict[str, Any]]:
        """Return the current port reservations sorted by port."""
        raw = self.registry.read_ports()
        ports = raw.get("ports", [])
        entries: list[dict[str, Any]] = []
        if isinstance(ports, Iterable):
            for item in ports:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "")).strip()
                port_value = item.get("port")
                if not name:
                    continue
                if not isinstance(port_value, (int, str)):
                    continue
                try:
                    port = int(port_value)
                except ValueError:
                    continue
                entries.append({"name": name, "port": port})
        entries.sort(key=lambda entry: entry["port"])
        return entries

    def get_port(self, name: str) -> int | None:
        """Return the reserved port for *name*, if present."""
        normalized = _normalize_name(name)
        for entry in self.list_entries():
            if entry["name"] == normalized:
                return entry["port"]
        return None

    def reserve(self, name: str, *, requested_port: int | None = None) -> int:
        """Reserve a port for *name* and return the assigned value."""
        normalized = _normalize_name(name)
        entries = self.list_entries()
        if any(entry["name"] == normalized for entry in entries):
            raise PortsRegistryError(f"Port already reserved for instance '{normalized}'.")

        used_ports = {entry["port"] for entry in entries}
        if requested_port is not None:
            if requested_port < self.base_port:
                raise PortsRegistryError(
                    f"Requested port {requested_port} is below the configured base "
                    f"{self.base_port}."
                )
            if requested_port in used_ports:
                raise PortsRegistryError(f"Port {requested_port} is already in use.")
            port = requested_port
        else:
            port = self._next_available_port(used_ports)

        entries.append({"name": normalized, "port": port})
        self.registry.write_ports(entries)
        return port

    def release(self, name: str) -> None:
        """Release the port reserved for *name*."""
        normalized = _normalize_name(name)
        entries = self.list_entries()
        filtered = [entry for entry in entries if entry["name"] != normalized]
        if len(filtered) == len(entries):
            raise PortsRegistryError(f"No port reservation found for instance '{normalized}'.")
        self.registry.write_ports(filtered)

    # Internal helpers -------------------------------------------------
    def _next_available_port(self, used: set[int]) -> int:
        """Return the next free port using the configured strategy."""
        if self.strategy != "sequential":
            raise PortsRegistryError(f"Unsupported strategy '{self.strategy}'.")

        candidate = self.base_port
        while candidate in used:
            candidate += 1
        return candidate


def _normalize_name(name: str) -> str:
    """Return a normalised instance name."""
    normalized = name.strip()
    if not normalized:
        raise PortsRegistryError("Instance name must be a non-empty string.")
    return normalized


__all__ = ["PortsRegistry", "PortsRegistryError"]
