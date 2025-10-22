"""Tests for the nginx provider."""
from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from abssctl.providers.nginx import NginxError, NginxProvider
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
        "http_listen_port": 80,
        "https_listen_port": 443,
        "server_name": "example.test",
        "access_log": "/var/log/nginx/example_access.log",
        "error_log": "/var/log/nginx/example_error.log",
        "upstream_host": "127.0.0.1",
        "upstream_port": 5000,
        "upstream_url": "127.0.0.1:5000",
        "tls": {
            "enabled": True,
            "mode": "system",
            "domain": "example.test",
            "certificate": "/etc/ssl/cert.pem",
            "certificate_key": "/etc/ssl/key.pem",
            "system": {
                "cert": "/etc/ssl/cert.pem",
                "key": "/etc/ssl/key.pem",
            },
            "lets_encrypt": {"live_dir": "/etc/letsencrypt/live"},
        },
    }


def test_render_site_writes_file(
    monkeypatch: pytest.MonkeyPatch,
    provider: NginxProvider,
) -> None:
    """Rendering writes the site configuration using the template."""
    calls: list[tuple[str, ...]] = []

    def fake_run(self: NginxProvider, args: Sequence[str]) -> DummyResult:
        calls.append(tuple(args))
        return DummyResult()

    monkeypatch.setattr(NginxProvider, "_run_nginx", fake_run)

    result = provider.render_site("alpha", _context())
    assert result.changed is True
    assert result.validation is not None
    assert result.reload is not None

    path = provider.site_path("alpha")
    assert path.exists()
    contents = path.read_text(encoding="utf-8")
    assert "server_name example.test;" in contents
    assert "proxy_pass http://127.0.0.1:5000;" in contents
    assert "listen 443 ssl;" in contents
    assert "ssl_certificate /etc/ssl/cert.pem;" in contents
    assert "proxy_set_header X-Forwarded-Ssl on;" in contents
    assert calls == [("-t",), ("-s", "reload")]


def test_render_site_without_tls(
    monkeypatch: pytest.MonkeyPatch,
    provider: NginxProvider,
) -> None:
    """Rendering when TLS disabled omits SSL directives."""
    calls: list[tuple[str, ...]] = []

    def fake_run(self: NginxProvider, args: Sequence[str]) -> DummyResult:
        calls.append(tuple(args))
        return DummyResult()

    monkeypatch.setattr(NginxProvider, "_run_nginx", fake_run)

    context = _context()
    context["tls"] = {
        **context["tls"],
        "enabled": False,
        "mode": "disabled",
    }

    provider.render_site("beta", context)
    contents = provider.site_path("beta").read_text(encoding="utf-8")
    assert "listen 443 ssl;" not in contents
    assert "ssl_certificate " not in contents
    assert "proxy_set_header X-Forwarded-Ssl on;" not in contents
    assert calls == [("-t",), ("-s", "reload")]


def test_render_site_skip_reload(monkeypatch: pytest.MonkeyPatch, provider: NginxProvider) -> None:
    """Reload step can be skipped when requested."""
    calls: list[tuple[str, ...]] = []

    def fake_run(self: NginxProvider, args: Sequence[str]) -> DummyResult:
        calls.append(tuple(args))
        return DummyResult()

    monkeypatch.setattr(NginxProvider, "_run_nginx", fake_run)

    result = provider.render_site("alpha", _context(), reload_on_change=False)
    assert result.changed is True
    assert result.validation is not None
    assert result.reload is None
    assert calls == [("-t",)]


def test_enable_creates_symlink(
    monkeypatch: pytest.MonkeyPatch,
    provider: NginxProvider,
) -> None:
    """Enable creates a symlink in sites-enabled pointing to the rendered file."""
    monkeypatch.setattr(NginxProvider, "_run_nginx", lambda self, args: DummyResult())
    provider.render_site("alpha", _context())

    provider.enable("alpha")
    link = provider.enabled_path("alpha")
    assert link.is_symlink()
    assert link.resolve() == provider.site_path("alpha").resolve()


def test_disable_removes_symlink(
    monkeypatch: pytest.MonkeyPatch,
    provider: NginxProvider,
) -> None:
    """Disable removes the symlink if present."""
    monkeypatch.setattr(NginxProvider, "_run_nginx", lambda self, args: DummyResult())
    provider.render_site("alpha", _context())
    provider.enable("alpha")
    link = provider.enabled_path("alpha")
    assert link.exists()

    provider.disable("alpha")
    assert not link.exists()


def test_remove_deletes_site_and_symlink(
    monkeypatch: pytest.MonkeyPatch,
    provider: NginxProvider,
) -> None:
    """Remove deletes both the configuration file and symlink."""
    monkeypatch.setattr(NginxProvider, "_run_nginx", lambda self, args: DummyResult())
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

    def fake_run(self: NginxProvider, args: Sequence[str]) -> DummyResult:
        calls.append(tuple(args))
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

    def fake_run(self: NginxProvider, args: Sequence[str]) -> DummyResult:
        calls.append(tuple(args))
        return DummyResult()

    monkeypatch.setattr(NginxProvider, "_run_nginx", fake_run)

    provider.reload()
    assert calls == [("-s", "reload")]


def test_render_site_rolls_back_on_validation_failure(
    monkeypatch: pytest.MonkeyPatch,
    provider: NginxProvider,
) -> None:
    """A failed validation restores the previous configuration content."""
    monkeypatch.setattr(NginxProvider, "_run_nginx", lambda self, args: DummyResult())
    initial_result = provider.render_site("alpha", _context())
    assert initial_result.changed is True
    path = provider.site_path("alpha")
    initial_contents = path.read_text(encoding="utf-8")

    def fail_validation(self: NginxProvider, args: Sequence[str]) -> DummyResult:
        if args and args[0] == "-t":
            raise NginxError("bad config")
        return DummyResult()

    monkeypatch.setattr(NginxProvider, "_run_nginx", fail_validation)

    result = provider.render_site(
        "alpha",
        {
            **_context(),
            "upstream_port": 6000,
            "upstream_url": "127.0.0.1:6000",
        },
    )

    assert result.changed is False
    assert result.validation is None
    assert result.validation_error == "bad config"

    contents = provider.site_path("alpha").read_text(encoding="utf-8")
    assert contents == initial_contents


def test_render_site_cleans_up_on_initial_validation_failure(
    monkeypatch: pytest.MonkeyPatch,
    provider: NginxProvider,
) -> None:
    """Validation failure on first render removes the new configuration file."""

    def fail_validation(self: NginxProvider, args: Sequence[str]) -> DummyResult:
        if args and args[0] == "-t":
            raise NginxError("first render failure")
        return DummyResult()

    monkeypatch.setattr(NginxProvider, "_run_nginx", fail_validation)

    result = provider.render_site("alpha", _context())

    assert result.changed is False
    assert result.validation is None
    assert result.validation_error == "first render failure"

    assert not provider.site_path("alpha").exists()


def test_is_enabled_and_diagnostics(tmp_path: Path) -> None:
    """Helper methods expose filesystem status for doctor/log commands."""
    provider = _make_provider(tmp_path)
    provider.templates.render_to_path(
        "nginx/site.conf.j2",
        provider.site_path("alpha"),
        _context(),
        mode=0o640,
    )
    assert provider.site_exists("alpha") is True
    assert provider.is_enabled("alpha") is False

    provider.enable("alpha")
    assert provider.is_enabled("alpha") is True

    diag = provider.diagnostics("alpha")
    assert diag["site_exists"] is True
    assert diag["enabled"] is True
