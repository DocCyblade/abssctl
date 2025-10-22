"""Provider interfaces for abssctl."""
from __future__ import annotations

from .instance_status_provider import InstanceStatus, InstanceStatusProvider
from .nginx import NginxError, NginxProvider, NginxRenderResult
from .systemd import SystemdError, SystemdProvider
from .version_installer import VersionInstaller, VersionInstallError, VersionInstallResult
from .version_provider import VersionProvider

__all__ = [
    "InstanceStatus",
    "InstanceStatusProvider",
    "NginxError",
    "NginxProvider",
    "NginxRenderResult",
    "NginxError",
    "SystemdError",
    "SystemdProvider",
    "VersionInstallError",
    "VersionInstallResult",
    "VersionInstaller",
    "VersionProvider",
]
