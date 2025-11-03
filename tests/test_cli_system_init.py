"""CLI integration tests for the `system init` command."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from abssctl.cli import app

runner = CliRunner()


def _bootstrap_args(tmp_path: Path) -> list[str]:
    """Return common bootstrap arguments anchored in the provided temp directory."""
    config_path = tmp_path / "etc" / "abssctl" / "config.yml"
    return [
        "system",
        "init",
        "--config-file",
        str(config_path),
        "--service-user",
        "abssctl-test",
        "--service-group",
        "abssctl-test",
        "--install-root",
        str(tmp_path / "srv" / "app"),
        "--instance-root",
        str(tmp_path / "srv"),
        "--state-dir",
        str(tmp_path / "var" / "lib" / "abssctl"),
        "--logs-dir",
        str(tmp_path / "var" / "log" / "abssctl"),
        "--runtime-dir",
        str(tmp_path / "run" / "abssctl"),
        "--templates-dir",
        str(tmp_path / "etc" / "abssctl" / "templates"),
        "--backups-root",
        str(tmp_path / "srv" / "backups"),
    ]


def test_system_init_requires_confirmation_when_non_interactive(tmp_path: Path) -> None:
    """Non-interactive execution without --yes or --defaults should fail fast."""
    result = runner.invoke(app, _bootstrap_args(tmp_path))
    assert result.exit_code == 2
    assert "system init requires" in result.stdout


def test_system_init_dry_run_outputs_plan(tmp_path: Path) -> None:
    """Dry-run mode should print a plan without applying changes."""
    args = _bootstrap_args(tmp_path) + ["--yes", "--dry-run", "--allow-create-user"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    assert "Service account" in result.stdout
    assert "Dry run only" in result.stdout


def test_system_init_json_plan(tmp_path: Path) -> None:
    """JSON output should include dry-run details and planned actions."""
    args = _bootstrap_args(tmp_path) + ["--yes", "--dry-run", "--json"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["dry_run"] is True
    assert payload["status"] == "dry-run"
    assert payload["service_account"]["actions"]
