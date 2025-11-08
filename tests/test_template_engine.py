"""Tests for the template rendering engine."""
from __future__ import annotations

from pathlib import Path

from abssctl.templates import TemplateEngine


def test_render_to_string_uses_builtin_templates(tmp_path: Path) -> None:
    """Built-in templates render with strict variables."""
    engine = TemplateEngine.with_overrides(None)

    output = engine.render_to_string(
        "systemd/service.j2",
        {
            "instance_name": "alpha",
            "service_user": "actual-sync",
            "working_directory": "/srv/app/alpha",
            "exec_start": "/usr/bin/node server.js",
            "environment_file": "/etc/default/abssctl-node",
            "environment": ["NODE_ENV=production"],
        },
    )

    assert "Actual Budget Sync Server (alpha)" in output
    assert "NODE_ENV=production" in output


def test_render_to_path_writes_with_mode(tmp_path: Path) -> None:
    """Rendering to a file writes content and respects the requested mode."""
    engine = TemplateEngine.with_overrides(None)
    destination = tmp_path / "service.service"

    changed = engine.render_to_path(
        "systemd/service.j2",
        destination,
        {
            "instance_name": "beta",
            "service_user": "actual-sync",
            "working_directory": "/srv/app/beta",
            "exec_start": "/usr/bin/node server.js",
            "environment_file": "/etc/default/abssctl-node",
            "environment": ["NODE_ENV=production"],
        },
        mode=0o600,
    )

    assert changed is True
    assert destination.exists()
    assert oct(destination.stat().st_mode & 0o777) == "0o600"

    # Second render with same content should be a no-op.
    changed_again = engine.render_to_path(
        "systemd/service.j2",
        destination,
        {
            "instance_name": "beta",
            "service_user": "actual-sync",
            "working_directory": "/srv/app/beta",
            "exec_start": "/usr/bin/node server.js",
            "environment_file": "/etc/default/abssctl-node",
            "environment": ["NODE_ENV=production"],
        },
        mode=0o600,
    )
    assert changed_again is False


def test_override_path_takes_precedence(tmp_path: Path) -> None:
    """Override templates shadow the built-in ones."""
    override_dir = tmp_path / "templates"
    override_dir.mkdir()
    override_template = override_dir / "systemd" / "service.j2"
    override_template.parent.mkdir(parents=True, exist_ok=True)
    override_template.write_text("override {{ instance_name }}", encoding="utf-8")

    engine = TemplateEngine.with_overrides(override_dir)

    rendered = engine.render_to_string(
        "systemd/service.j2",
        {
            "instance_name": "gamma",
            "service_user": "actual-sync",
            "working_directory": "/srv/app/gamma",
            "exec_start": "/usr/bin/node server.js",
            "environment_file": "/etc/default/abssctl-node",
            "environment": [],
        },
    )

    assert rendered == "override gamma"
