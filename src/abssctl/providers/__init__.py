"""Provider interfaces for abssctl."""
from __future__ import annotations

from .instance_status_provider import InstanceStatus, InstanceStatusProvider
from .version_provider import VersionProvider

__all__ = ["InstanceStatus", "InstanceStatusProvider", "VersionProvider"]
