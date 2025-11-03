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


def test_system_init_discover_dry_run(tmp_path: Path) -> None:
    """Discovery mode should emit a readable summary in dry-run."""
    args = _bootstrap_args(tmp_path) + ["--yes", "--dry-run", "--discover"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    assert "Discovery" in result.stdout
    assert "No instances discovered" in result.stdout


def _write_instance_config(root: Path, name: str, port: int) -> None:
    config_path = root / name / "data" / "config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": 1,
        "instance": {"name": name, "domain": f"{name}.example.com"},
        "server": {
            "upstream": {"host": "127.0.0.1", "port": port},
            "version": "v1.2.3",
        },
        "paths": {
            "root": str(root / name),
            "data": str(root / name / "data"),
            "config": str(config_path),
        },
    }
    config_path.write_text(json.dumps(payload), encoding="utf-8")


def test_system_init_rebuild_state_dry_run(tmp_path: Path) -> None:
    """Rebuild state dry-run should display planned registry files."""
    instance_root = tmp_path / "srv"
    _write_instance_config(instance_root, "alpha", 6000)

    args = _bootstrap_args(tmp_path) + ["--yes", "--dry-run", "--rebuild-state"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    assert "Rebuild state" in result.stdout
    assert "instances.yml" in result.stdout


def test_system_init_rebuild_state_json(tmp_path: Path) -> None:
    """JSON payload should include rebuild plan details when requested."""
    instance_root = tmp_path / "srv"
    _write_instance_config(instance_root, "beta", 7000)

    args = _bootstrap_args(tmp_path) + [
        "--yes",
        "--dry-run",
        "--rebuild-state",
        "--json",
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    rebuild = payload.get("rebuild")
    assert rebuild is not None
    assert rebuild["planned"]["registry"]
    assert rebuild["planned"]["config"]
