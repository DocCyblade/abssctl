"""Systemd provider for managing instance service units."""
from __future__ import annotations

import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ..locking import LockManager
from ..logging import StructuredLogger
from ..templates import TemplateEngine


class SystemdError(RuntimeError):
    """Raised when systemd operations fail."""


@dataclass(slots=True)
class SystemdProvider:
    """Render and manage systemd service units for abssctl instances."""

    templates: TemplateEngine
    logger: StructuredLogger
    locks: LockManager
    systemd_dir: Path = Path("/etc/systemd/system")
    systemctl_bin: str = "systemctl"

    def unit_path(self, instance: str) -> Path:
        """Return the full path for the instance unit file."""
        safe = instance.replace("/", "-")
        return self.systemd_dir / f"abssctl-{safe}.service"

    def render_unit(self, instance: str, context: Mapping[str, object]) -> bool:
        """Render the unit file for *instance* using *context*."""
        template_name = "systemd/service.j2"
        path = self.unit_path(instance)
        changed = self.templates.render_to_path(template_name, path, context, mode=0o644)
        if changed:
            self._reload_daemon()
        return changed

    def enable(self, instance: str) -> None:
        """Enable the instance unit."""
        self._systemctl("enable", self.unit_path(instance))

    def disable(self, instance: str) -> None:
        """Disable the instance unit."""
        self._systemctl("disable", self.unit_path(instance))

    def start(self, instance: str) -> None:
        """Start the instance unit."""
        self._systemctl("start", self.unit_path(instance))

    def stop(self, instance: str) -> None:
        """Stop the instance unit."""
        self._systemctl("stop", self.unit_path(instance))

    def status(self, instance: str) -> subprocess.CompletedProcess[str]:
        """Return the status output for the unit."""
        return self._systemctl("status", self.unit_path(instance), check=False)

    def remove(self, instance: str) -> None:
        """Remove the unit file for *instance*."""
        path = self.unit_path(instance)
        try:
            path.unlink()
        except FileNotFoundError:
            return
        self._reload_daemon()

    # ------------------------------------------------------------------
    def _reload_daemon(self) -> None:
        self._systemctl("daemon-reload")

    def _systemctl(
        self,
        command: str,
        unit_or_path: Path | None = None,
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        args = [self.systemctl_bin, command]
        if unit_or_path is not None:
            args.append(str(unit_or_path))
        result = subprocess.run(  # noqa: S603, S607
            args,
            capture_output=True,
            text=True,
            check=False,
        )
        if check and result.returncode != 0:
            raise SystemdError(result.stderr or result.stdout)
        return result


__all__ = ["SystemdProvider", "SystemdError"]
