"""Systemd provider for managing instance service units."""
from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
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
    journalctl_bin: str = "journalctl"

    def unit_name(self, instance: str) -> str:
        """Return the systemd unit name for *instance*."""
        safe = instance.replace("/", "-")
        return f"abssctl-{safe}.service"

    def unit_path(self, instance: str) -> Path:
        """Return the full path for the instance unit file."""
        return self.systemd_dir / self.unit_name(instance)

    def render_unit(self, instance: str, context: Mapping[str, object]) -> bool:
        """Render the unit file for *instance* using *context*."""
        template_name = "systemd/service.j2"
        path = self.unit_path(instance)
        changed = self.templates.render_to_path(template_name, path, context, mode=0o644)
        if changed:
            self._reload_daemon()
        return changed

    def enable(self, instance: str, *, dry_run: bool = False) -> subprocess.CompletedProcess[str]:
        """Enable the instance unit."""
        return self._systemctl("enable", self.unit_name(instance), dry_run=dry_run)

    def disable(self, instance: str, *, dry_run: bool = False) -> subprocess.CompletedProcess[str]:
        """Disable the instance unit."""
        return self._systemctl("disable", self.unit_name(instance), dry_run=dry_run)

    def start(self, instance: str, *, dry_run: bool = False) -> subprocess.CompletedProcess[str]:
        """Start the instance unit."""
        return self._systemctl("start", self.unit_name(instance), dry_run=dry_run)

    def stop(self, instance: str, *, dry_run: bool = False) -> subprocess.CompletedProcess[str]:
        """Stop the instance unit."""
        return self._systemctl("stop", self.unit_name(instance), dry_run=dry_run)

    def restart(self, instance: str, *, dry_run: bool = False) -> subprocess.CompletedProcess[str]:
        """Restart the instance unit."""
        return self._systemctl("restart", self.unit_name(instance), dry_run=dry_run)

    def status(self, instance: str) -> subprocess.CompletedProcess[str]:
        """Return the status output for the unit."""
        return self._systemctl("status", self.unit_name(instance), check=False, dry_run=False)

    def logs(
        self,
        instance: str,
        *,
        lines: int | None = None,
        since: str | None = None,
        follow: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        """Return journalctl output for the unit."""
        args: list[str] = ["--unit", self.unit_name(instance), "--no-pager"]
        if lines is not None:
            args.extend(["--lines", str(lines)])
        if since is not None:
            args.extend(["--since", since])
        if follow:
            args.append("--follow")
        return self._journalctl(args, capture_output=not follow)

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
        try:
            self._systemctl("daemon-reload")
        except SystemdError as exc:
            if "not found" in str(exc).lower():
                return
            raise
        except FileNotFoundError:
            # Allow tests and non-systemd environments to proceed without error.
            return

    def _systemctl(
        self,
        command: str,
        unit_or_path: str | Path | None = None,
        *,
        check: bool = True,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        args: list[str] = [self.systemctl_bin, command]
        if unit_or_path is not None:
            args.append(str(unit_or_path))
        return self._run_command(
            args,
            check=check,
            error_prefix=f"{self.systemctl_bin} {command}",
            capture_output=True,
            dry_run=dry_run,
        )

    def _journalctl(
        self,
        args: Sequence[str],
        *,
        check: bool = True,
        capture_output: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        command = [self.journalctl_bin, *args]
        joined = " ".join(args)
        return self._run_command(
            command,
            check=check,
            error_prefix=f"{self.journalctl_bin} {joined}".rstrip(),
            capture_output=capture_output,
            dry_run=False,
        )

    def _run_command(
        self,
        args: Sequence[str],
        *,
        check: bool,
        error_prefix: str,
        capture_output: bool,
        dry_run: bool,
    ) -> subprocess.CompletedProcess[str]:
        if dry_run:
            return subprocess.CompletedProcess(
                list(args),
                returncode=0,
                stdout="",
                stderr="",
            )
        try:
            if capture_output:
                result = subprocess.run(  # noqa: S603, S607
                    list(args),
                    capture_output=True,
                    text=True,
                    check=False,
                )
            else:
                result = subprocess.run(  # noqa: S603, S607
                    list(args),
                    text=True,
                    check=False,
                )
        except FileNotFoundError as exc:
            raise SystemdError(f"{args[0]} not found: {exc}") from exc
        if check and result.returncode != 0:
            stdout = getattr(result, "stdout", "") or ""
            stderr = getattr(result, "stderr", "") or ""
            message = stderr.strip() or stdout.strip() or "no output"
            raise SystemdError(f"{error_prefix} failed (exit {result.returncode}): {message}")
        return result


__all__ = ["SystemdProvider", "SystemdError"]
