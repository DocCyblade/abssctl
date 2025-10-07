"""Tests for the nginx provider."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from abssctl.providers.nginx import NginxProvider
from abssctl.templates import TemplateEngine


class DummyResult:
    """Stand-in for ``subprocess.CompletedProcess``."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        """Initialise the dummy result."""
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _make_provider(tmp_path: Path) -> NginxProvider:
    templates = TemplateEngine.with_overrides(None)
    sites_available = tmp_path / "sites-available"
    sites_enabled = tmp_path / "sites-enabled"
    return NginxProvider(
        templates=templates,
        sites_available=sites_available,
        sites_enabled=sites_enabled,
        nginx_bin="nginx",
    )


@pytest.fixture
def provider(tmp_path: Path) -> NginxProvider:
    """Return an nginx provider bound to temporary directories."""
    return _make_provider(tmp_path)


def _context() -> dict[str, Any]:
    """Provide a minimal render context for nginx templates."""
    return {
        "listen_port": 8080,
        "server_name": "example.test",
        "access_log": "/var/log/nginx/example_access.log",
        "error_log": "/var/log/nginx/example_error.log",
        "upstream": "127.0.0.1:5000",
    }


def test_render_site_writes_file(provider: NginxProvider) -> None:
    """Rendering writes the site configuration using the template."""
    changed = provider.render_site("alpha", _context())

    path = provider.site_path("alpha")
    assert changed is True
    assert path.exists()
    contents = path.read_text(encoding="utf-8")
    assert "server_name example.test;" in contents
    assert "proxy_pass http://127.0.0.1:5000;" in contents


def test_enable_creates_symlink(provider: NginxProvider) -> None:
    """Enable creates a symlink in sites-enabled pointing to the rendered file."""
    provider.render_site("alpha", _context())

    provider.enable("alpha")
    link = provider.enabled_path("alpha")
    assert link.is_symlink()
    assert link.resolve() == provider.site_path("alpha").resolve()


def test_disable_removes_symlink(provider: NginxProvider) -> None:
    """Disable removes the symlink if present."""
    provider.render_site("alpha", _context())
    provider.enable("alpha")
    link = provider.enabled_path("alpha")
    assert link.exists()

    provider.disable("alpha")
    assert not link.exists()


def test_remove_deletes_site_and_symlink(provider: NginxProvider) -> None:
    """Remove deletes both the configuration file and symlink."""
    provider.render_site("alpha", _context())
    provider.enable("alpha")

    provider.remove("alpha")
    assert not provider.site_path("alpha").exists()
    assert not provider.enabled_path("alpha").exists()


def test_test_config_invokes_nginx(
    monkeypatch: pytest.MonkeyPatch,
    provider: NginxProvider,
) -> None:
    """Nginx -t is invoked through the provider."""
    calls: list[tuple[str, ...]] = []

    def fake_run(self: NginxProvider, *args: str) -> DummyResult:
        calls.append(args)
        return DummyResult()

    monkeypatch.setattr(NginxProvider, "_run_nginx", fake_run)

    provider.test_config()
    assert calls == [("-t",)]


def test_reload_invokes_nginx(
    monkeypatch: pytest.MonkeyPatch,
    provider: NginxProvider,
) -> None:
    """Reload triggers ``nginx -s reload``."""
    calls: list[tuple[str, ...]] = []

    def fake_run(self: NginxProvider, *args: str) -> DummyResult:
        calls.append(args)
        return DummyResult()

    monkeypatch.setattr(NginxProvider, "_run_nginx", fake_run)

    provider.reload()
    assert calls == [("-s", "reload")]
