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
        state = "unknown"
        detail_text = ""
        if isinstance(entry, Mapping):
            status_value = entry.get("status")
            if isinstance(status_value, str) and status_value.strip():
                state = status_value.strip()
            detail_candidate = entry.get("status_detail")
            if isinstance(detail_candidate, str):
                detail_text = detail_candidate
            metadata = entry.get("metadata")
            if isinstance(metadata, Mapping):
                diagnostics = metadata.get("diagnostics")
                if isinstance(diagnostics, Mapping):
                    systemd_diag = diagnostics.get("systemd")
                    if isinstance(systemd_diag, Mapping):
                        diag_state = systemd_diag.get("state")
                        if isinstance(diag_state, str) and diag_state.strip():
                            state = diag_state.strip()
                        detail_candidate = systemd_diag.get("detail")
                        if isinstance(detail_candidate, str) and detail_candidate.strip():
                            detail_text = detail_candidate.strip()
                meta_detail = metadata.get("status_detail")
                if isinstance(meta_detail, str) and meta_detail.strip():
                    detail_text = meta_detail.strip()

        if not detail_text:
            detail_text = "Status checks not implemented yet."
        return InstanceStatus(state=state, detail=detail_text)


__all__ = ["InstanceStatus", "InstanceStatusProvider"]
