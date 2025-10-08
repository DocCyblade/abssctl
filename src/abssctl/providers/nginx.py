"""Nginx provider for managing vhost configurations."""
from __future__ import annotations

import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ..templates import TemplateEngine


class NginxError(RuntimeError):
    """Raised when nginx operations fail."""


@dataclass(slots=True)
class NginxProvider:
    """Render and manage nginx site configurations for abssctl instances."""

    templates: TemplateEngine
    sites_available: Path = Path("/etc/nginx/sites-available")
    sites_enabled: Path = Path("/etc/nginx/sites-enabled")
    nginx_bin: str = "nginx"

    def site_path(self, instance: str) -> Path:
        """Return the path to the nginx site configuration file."""
        safe = instance.replace("/", "-")
        return self.sites_available / f"abssctl-{safe}.conf"

    def enabled_path(self, instance: str) -> Path:
        """Return the path of the symlink in sites-enabled for *instance*."""
        return self.sites_enabled / self.site_path(instance).name

    def render_site(self, instance: str, context: Mapping[str, object]) -> bool:
        """Render the nginx site configuration for *instance*."""
        template_name = "nginx/site.conf.j2"
        destination = self.site_path(instance)
        destination.parent.mkdir(parents=True, exist_ok=True)
        changed = self.templates.render_to_path(
            template_name,
            destination,
            context,
            mode=0o640,
        )
        return changed

    def enable(self, instance: str) -> None:
        """Enable the site by creating a symlink in sites-enabled."""
        source = self.site_path(instance)
        target = self.enabled_path(instance)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            if target.resolve() == source.resolve():
                return
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

    def test_config(self) -> None:
        """Run ``nginx -t`` to validate the configuration."""
        self._run_nginx("-t")

    def reload(self) -> None:
        """Reload nginx to apply configuration changes."""
        self._run_nginx("-s", "reload")

    # ------------------------------------------------------------------
    def _run_nginx(self, *args: str) -> subprocess.CompletedProcess[str]:
        command = [self.nginx_bin, *args]
        result = subprocess.run(  # noqa: S603, S607
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise NginxError(result.stderr or result.stdout)
        return result


__all__ = ["NginxProvider", "NginxError"]
