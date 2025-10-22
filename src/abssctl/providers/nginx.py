"""Nginx provider for managing vhost configurations."""
from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..templates import TemplateEngine


class NginxError(RuntimeError):
    """Raised when nginx operations fail."""


@dataclass(slots=True)
class NginxRenderResult:
    """Outcome of rendering an nginx site configuration."""

    changed: bool
    validation: subprocess.CompletedProcess[str] | None = None
    reload: subprocess.CompletedProcess[str] | None = None
    validation_error: str | None = None


@dataclass(slots=True)
class NginxProvider:
    """Render and manage nginx site configurations for abssctl instances."""

    templates: TemplateEngine
    sites_available: Path = Path("/etc/nginx/sites-available")
    sites_enabled: Path = Path("/etc/nginx/sites-enabled")
    nginx_bin: str = "nginx"

    def site_name(self, instance: str) -> str:
        """Return the canonical site name for *instance*."""
        safe = instance.replace("/", "-")
        return f"abssctl-{safe}.conf"

    def site_path(self, instance: str) -> Path:
        """Return the path to the nginx site configuration file."""
        return self.sites_available / self.site_name(instance)

    def enabled_path(self, instance: str) -> Path:
        """Return the path of the symlink in sites-enabled for *instance*."""
        return self.sites_enabled / self.site_name(instance)

    def render_site(
        self,
        instance: str,
        context: Mapping[str, object],
        *,
        reload_on_change: bool = True,
    ) -> NginxRenderResult:
        """Render the nginx site configuration for *instance*.

        Returns ``True`` when the on-disk configuration changed. When a change is
        detected the new configuration is validated with ``nginx -t`` prior to
        reloading the service. Validation failures roll back to the previous
        configuration to keep nginx in a working state.
        """
        template_name = "nginx/site.conf.j2"
        destination = self.site_path(instance)
        destination.parent.mkdir(parents=True, exist_ok=True)

        previous: tuple[str, int] | None = None
        if destination.exists():
            previous = (
                destination.read_text(encoding="utf-8"),
                destination.stat().st_mode,
            )

        changed = self.templates.render_to_path(
            template_name,
            destination,
            context,
            mode=0o640,
        )
        if not changed:
            return NginxRenderResult(changed=False)

        validation_result: subprocess.CompletedProcess[str] | None = None
        validation_error: str | None = None
        try:
            validation_result = self.test_config()
        except NginxError as exc:
            validation_error = str(exc)
            if previous is None:
                destination.unlink(missing_ok=True)
            else:
                content, mode = previous
                destination.write_text(content, encoding="utf-8")
                destination.chmod(mode)
            validation_error = str(exc)
            return NginxRenderResult(
                changed=False,
                validation=None,
                reload=None,
                validation_error=validation_error,
            )

        reload_result: subprocess.CompletedProcess[str] | None = None
        if reload_on_change:
            reload_result = self.reload()
        return NginxRenderResult(
            changed=True,
            validation=validation_result,
            reload=reload_result,
            validation_error=validation_error,
        )

    def enable(self, instance: str) -> None:
        """Enable the site by creating a symlink in sites-enabled."""
        source = self.site_path(instance)
        target = self.enabled_path(instance)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            try:
                if target.resolve() == source.resolve():
                    return
            except FileNotFoundError:
                # Broken symlink; replace it with a fresh one.
                pass
            target.unlink()
        target.symlink_to(source)

    def disable(self, instance: str) -> None:
        """Disable the site by removing the symlink."""
        target = self.enabled_path(instance)
        try:
            target.unlink()
        except FileNotFoundError:
            pass

    def remove(self, instance: str) -> None:
        """Remove both the configuration and symlink for *instance*."""
        self.disable(instance)
        path = self.site_path(instance)
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def site_exists(self, instance: str) -> bool:
        """Return True when the rendered site configuration exists."""
        return self.site_path(instance).exists()

    def is_enabled(self, instance: str) -> bool:
        """Return True when the site is enabled via sites-enabled symlink."""
        target = self.enabled_path(instance)
        if not target.exists() and not target.is_symlink():
            return False
        try:
            return target.is_symlink() and target.resolve() == self.site_path(instance).resolve()
        except FileNotFoundError:
            return False

    def diagnostics(self, instance: str) -> dict[str, object]:
        """Return diagnostic metadata for *instance*."""
        site_path = self.site_path(instance)
        enabled_path = self.enabled_path(instance)
        return {
            "site_path": site_path,
            "site_exists": site_path.exists(),
            "enabled_path": enabled_path,
            "enabled": self.is_enabled(instance),
        }

    def test_config(self) -> subprocess.CompletedProcess[str]:
        """Run ``nginx -t`` to validate the configuration."""
        try:
            return self._run_nginx(["-t"])
        except FileNotFoundError:
            return subprocess.CompletedProcess([self.nginx_bin, "-t"], returncode=0)

    def reload(self) -> subprocess.CompletedProcess[str]:
        """Reload nginx to apply configuration changes."""
        try:
            return self._run_nginx(["-s", "reload"])
        except FileNotFoundError:
            return subprocess.CompletedProcess([self.nginx_bin, "-s", "reload"], returncode=0)

    # ------------------------------------------------------------------
    def _run_nginx(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        command = [self.nginx_bin, *args]
        result = subprocess.run(  # noqa: S603, S607
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "no output").strip()
            raise NginxError(
                f"{self.nginx_bin} {' '.join(args)} failed (exit {result.returncode}): {message}"
            )
        return result


__all__ = ["NginxProvider", "NginxError"]
