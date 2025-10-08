"""Placeholder instance status provider."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class InstanceStatus:
    """Represents the status of an Actual Sync Server instance."""

    state: str
    detail: str = ""


class InstanceStatusProvider:
    """Return status information for instances.

    This Alpha stub always returns ``unknown`` to confirm wiring. Future
    implementations will consult systemd/nginx and other probes.
    """

    def status(self, name: str, entry: Mapping[str, object]) -> InstanceStatus:
        """Return the status for *name* based on registry metadata."""
        detail = entry.get("status_detail") if isinstance(entry, Mapping) else ""
        text = str(detail or "Status checks not implemented yet.")
        return InstanceStatus(state="unknown", detail=text)


__all__ = ["InstanceStatus", "InstanceStatusProvider"]
