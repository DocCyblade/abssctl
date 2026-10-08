"""Tests for the packaged abssctl-node-run wrapper."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from abssctl.cli import NODE_WRAPPER_PATH, app
from abssctl.node_wrapper import (
    DEFAULT_WRAPPER_PATH,
    WRAPPER_PATH_ENV_VAR,
    install_node_wrapper,
    packaged_wrapper_path,
    resolve_wrapper_path,
    wrapper_needs_install,
)

runner = CliRunner()


def test_packaged_wrapper_is_shipped() -> None:
    """The wheel must include the systemd node wrapper script."""
    path = packaged_wrapper_path()
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash")
    assert "REQUIRED_NODE" in text
    assert "exec" in text


def test_packaged_wrapper_matches_tools_copy() -> None:
    """Keep tools/abssctl-node-run.sh aligned with the packaged script."""
    tools_copy = Path(__file__).resolve().parents[1] / "tools" / "abssctl-node-run.sh"
    assert tools_copy.is_file()
    assert tools_copy.read_bytes() == packaged_wrapper_path().read_bytes()


def test_install_node_wrapper_writes_executable(tmp_path: Path) -> None:
    """install_node_wrapper copies the packaged script and sets mode 0755."""
    destination = tmp_path / "usr" / "local" / "bin" / "abssctl-node-run"
    assert wrapper_needs_install(destination) is True
    assert install_node_wrapper(destination) is True
    assert destination.is_file()
    assert destination.read_bytes() == packaged_wrapper_path().read_bytes()
    assert destination.stat().st_mode & 0o111
    assert wrapper_needs_install(destination) is False
    assert install_node_wrapper(destination) is False


def test_install_node_wrapper_dry_run_skips_write(tmp_path: Path) -> None:
    """Dry-run reports a pending install without creating the destination."""
    destination = tmp_path / "abssctl-node-run"
    assert install_node_wrapper(destination, dry_run=True) is True
    assert not destination.exists()


def test_system_init_installs_node_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """System init must provide /usr/local/bin/abssctl-node-run (or the override)."""
    wrapper = tmp_path / "usr" / "local" / "bin" / "abssctl-node-run"
    monkeypatch.setenv(WRAPPER_PATH_ENV_VAR, str(wrapper))
    monkeypatch.setattr("abssctl.cli.apply_service_account_plan", lambda *_a, **_k: None)
    monkeypatch.setattr("abssctl.cli.apply_directory_plan", lambda *_a, **_k: None)

    config_path = tmp_path / "etc" / "abssctl" / "config.yml"
    args = [
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
        "--yes",
        "--allow-create-user",
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.stdout
    assert wrapper.is_file()
    assert wrapper.read_bytes() == packaged_wrapper_path().read_bytes()
    assert "Installed node wrapper" in result.stdout


def test_system_init_dry_run_plans_wrapper_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run should report the wrapper without writing it."""
    wrapper = tmp_path / "missing-wrapper"
    monkeypatch.setenv(WRAPPER_PATH_ENV_VAR, str(wrapper))
    config_path = tmp_path / "etc" / "abssctl" / "config.yml"
    args = [
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
        "--yes",
        "--dry-run",
        "--allow-create-user",
        "--json",
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.stdout
    assert not wrapper.exists()
    assert '"action": "install"' in result.stdout
    assert str(wrapper) in result.stdout


def test_default_wrapper_path_matches_systemd_exec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Units ExecStart the same path system init / node ensure install."""
    monkeypatch.delenv(WRAPPER_PATH_ENV_VAR, raising=False)
    assert NODE_WRAPPER_PATH == DEFAULT_WRAPPER_PATH
    assert resolve_wrapper_path() == Path("/usr/local/bin/abssctl-node-run")
