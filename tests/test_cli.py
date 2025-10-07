"""Tests for the abssctl CLI scaffold."""
from __future__ import annotations

import json
import os
from pathlib import Path

import yaml
from typer.testing import CliRunner

from abssctl import __version__
from abssctl.cli import app
from abssctl.state import StateRegistry

runner = CliRunner()


def _prepare_environment(
    tmp_path: Path,
    *,
    config_overrides: dict[str, object] | None = None,
    versions: list[object] | None = None,
    instances: list[object] | None = None,
    remote_versions: list[str] | None = None,
) -> tuple[dict[str, str], Path]:
    state_dir = tmp_path / "state"
    logs_dir = tmp_path / "logs"
    runtime_dir = tmp_path / "run"
    templates_dir = tmp_path / "templates"
    config = {
        "state_dir": str(state_dir),
        "logs_dir": str(logs_dir),
        "runtime_dir": str(runtime_dir),
        "templates_dir": str(templates_dir),
    }
    if config_overrides:
        config.update(config_overrides)

    config_file = tmp_path / "config.yml"
    config_file.write_text(yaml.safe_dump(config), encoding="utf-8")

    registry = StateRegistry(state_dir / "registry")

    if versions is not None:
        registry.write_versions(versions)

    if instances is not None:
        registry.write_instances(instances)

    env = {"ABSSCTL_CONFIG_FILE": str(config_file)}
    if remote_versions is not None:
        cache_file = tmp_path / "remote.json"
        cache_file.write_text(json.dumps(remote_versions), encoding="utf-8")
        env["ABSSCTL_VERSIONS_CACHE"] = str(cache_file)
        env.pop("ABSSCTL_SKIP_NPM", None)
    else:
        env["ABSSCTL_SKIP_NPM"] = "1"
    return env, state_dir


def test_version_option_outputs_package_version(tmp_path: Path) -> None:
    """CLI ``--version`` flag emits the package version."""
    env, _ = _prepare_environment(tmp_path)
    result = runner.invoke(app, ["--version"], env=env)

    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_invocation_without_subcommand_shows_help(tmp_path: Path) -> None:
    """Calling the CLI without a subcommand shows help output."""
    env, _ = _prepare_environment(tmp_path)
    result = runner.invoke(app, env=env)

    assert result.exit_code == 0
    assert "Actual Budget Multi-Instance Sync Server Admin CLI" in result.stdout


def test_config_show_renders_table(tmp_path: Path) -> None:
    """`config show` prints the merged configuration in a table."""
    env, state_dir = _prepare_environment(tmp_path)

    result = runner.invoke(app, ["config", "show"], env=env)

    assert result.exit_code == 0
    assert "state_dir" in result.stdout
    assert state_dir.name in result.stdout
    assert "lock_timeout" in result.stdout
    assert "templates_dir" in result.stdout


def test_config_show_json(tmp_path: Path) -> None:
    """`config show --json` emits JSON with the resolved configuration."""
    env, state_dir = _prepare_environment(
        tmp_path, config_overrides={"install_root": "/opt/abssctl"}
    )

    result = runner.invoke(app, ["config", "show", "--json"], env=env)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["install_root"] == "/opt/abssctl"
    assert payload["state_dir"] == str(state_dir)
    assert payload["lock_timeout"] == 30.0
    assert Path(payload["templates_dir"]).name == "templates"


def test_version_list_uses_registry(tmp_path: Path) -> None:
    """`version list` reports versions from the registry."""
    versions = ["25.8.0", {"version": "25.7.1", "source": "local"}]
    env, _ = _prepare_environment(tmp_path, versions=versions)

    result = runner.invoke(app, ["version", "list"], env=env)

    assert result.exit_code == 0
    assert "25.8.0" in result.stdout
    assert "yes" in result.stdout


def test_version_list_remote_merges(tmp_path: Path) -> None:
    """Remote flag merges npm responses with local installs."""
    versions = ["25.8.0"]
    remote = ["25.9.0", "25.8.0", "25.7.1"]
    env, _ = _prepare_environment(tmp_path, versions=versions, remote_versions=remote)

    result = runner.invoke(app, ["version", "list", "--remote"], env=env)

    assert result.exit_code == 0
    assert "25.9.0" in result.stdout
    assert "no" in result.stdout  # non-installed
    assert "yes" in result.stdout  # installed


def test_version_list_json(tmp_path: Path) -> None:
    """`version list --json` emits structured data."""
    versions = ["25.8.0", {"version": "25.7.1", "source": "local"}]
    env, _ = _prepare_environment(tmp_path, versions=versions)

    result = runner.invoke(app, ["version", "list", "--json"], env=env)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["versions"][0]["version"] == "25.8.0"
    assert payload["versions"][1]["metadata"]["source"] == "local"


def test_version_check_updates_placeholder(tmp_path: Path) -> None:
    """`version check-updates` references the configured package."""
    env, _ = _prepare_environment(tmp_path, config_overrides={"npm_package_name": "demo"})

    result = runner.invoke(app, ["version", "check-updates"], env=env)

    assert result.exit_code == 0
    assert "demo" in result.stdout


def test_version_check_updates_json(tmp_path: Path) -> None:
    """JSON form of `version check-updates`."""
    env, _ = _prepare_environment(tmp_path, config_overrides={"npm_package_name": "demo"})

    result = runner.invoke(app, ["version", "check-updates", "--json"], env=env)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["package"] == "demo"
    assert payload["status"] == "unimplemented"


def test_instance_list_reads_registry(tmp_path: Path) -> None:
    """`instance list` reports entries from instances.yml."""
    instances = [
        {"name": "alpha", "version": "v25.8.0", "domain": "alpha.local", "port": 5000},
        {"name": "beta", "status": "stopped"},
    ]
    env, _ = _prepare_environment(tmp_path, instances=instances)

    result = runner.invoke(app, ["instance", "list"], env=env)

    assert result.exit_code == 0
    assert "alpha" in result.stdout
    assert "beta" in result.stdout
    assert "5000" in result.stdout


def test_instance_list_json(tmp_path: Path) -> None:
    """`instance list --json` emits structured data."""
    instances = [{"name": "alpha", "version": "v25.8.0"}]
    env, _ = _prepare_environment(tmp_path, instances=instances)

    result = runner.invoke(app, ["instance", "list", "--json"], env=env)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["instances"][0]["name"] == "alpha"
    assert payload["instances"][0]["version"] == "v25.8.0"
    assert payload["instances"][0]["status"] in {"enabled", "disabled", "unknown"}


def test_instance_show_success(tmp_path: Path) -> None:
    """`instance show` renders details for the requested instance."""
    instances = [{"name": "alpha", "version": "v25.8.0", "domain": "alpha.local"}]
    env, _ = _prepare_environment(tmp_path, instances=instances)

    result = runner.invoke(app, ["instance", "show", "alpha"], env=env)

    assert result.exit_code == 0
    assert "alpha" in result.stdout
    assert "alpha.local" in result.stdout


def test_instance_show_json(tmp_path: Path) -> None:
    """JSON form of `instance show`."""
    instances = [{"name": "alpha", "version": "v25.8.0"}]
    env, _ = _prepare_environment(tmp_path, instances=instances)

    result = runner.invoke(app, ["instance", "show", "alpha", "--json"], env=env)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["name"] == "alpha"
    assert payload["version"] == "v25.8.0"


def test_instance_show_missing(tmp_path: Path) -> None:
    """Missing instances exit with a non-zero status."""
    env, _ = _prepare_environment(tmp_path, instances=[])

    result = runner.invoke(app, ["instance", "show", "alpha"], env=env)

    assert result.exit_code == 1
    assert "not found" in result.stdout


def test_instance_create_acquires_lock(tmp_path: Path) -> None:
    """`instance create` acquires the expected lock and logs wait duration."""
    env, state_dir = _prepare_environment(tmp_path)

    result = runner.invoke(app, ["instance", "create", "alpha"], env=env)

    assert result.exit_code == 0

    runtime_dir = tmp_path / "run"
    lock_path = runtime_dir / "alpha.lock"
    assert lock_path.exists()
    lock_metadata = json.loads(lock_path.read_text(encoding="utf-8"))
    assert lock_metadata["pid"] == os.getpid()

    systemd_unit = runtime_dir / "systemd" / "abssctl-alpha.service"
    assert systemd_unit.exists()
    assert "Actual Budget Sync Server" in systemd_unit.read_text(encoding="utf-8")

    nginx_site = runtime_dir / "nginx" / "sites-available" / "abssctl-alpha.conf"
    assert nginx_site.exists()
    assert "server_name alpha.local" in nginx_site.read_text(encoding="utf-8")

    logs_dir = state_dir.parent / "logs"
    operations_log = logs_dir / "operations.jsonl"
    log_lines = operations_log.read_text(encoding="utf-8").splitlines()
    record = json.loads(log_lines[-1])
    assert record["command"] == "instance create"
    assert record.get("lock_wait_ms") is not None
    assert record["result"]["status"] == "success"
    steps = record.get("steps", [])
    assert any(step.get("name") == "systemd.render_unit" for step in steps)
    assert any(step.get("name") == "nginx.render_site" for step in steps)
    assert any(step.get("name") == "registry.write_instances" for step in steps)

    registry_file = state_dir / "registry" / "instances.yml"
    registry_data = yaml.safe_load(registry_file.read_text(encoding="utf-8"))
    instances = registry_data.get("instances", [])
    assert any(item.get("name") == "alpha" for item in instances)


def test_operations_logging_creates_records(tmp_path: Path) -> None:
    """Commands emit structured logging records in the configured logs directory."""
    env, state_dir = _prepare_environment(tmp_path)

    result = runner.invoke(app, ["config", "show", "--json"], env=env)

    assert result.exit_code == 0

    logs_dir = state_dir.parent / "logs"
    operations_log = logs_dir / "operations.jsonl"
    human_log = logs_dir / "abssctl.log"

    assert operations_log.exists()
    assert human_log.exists()

    record = json.loads(operations_log.read_text(encoding="utf-8").splitlines()[-1])
    assert record["command"] == "config show"
    assert record["args"] == {"json": True}
    assert record["result"]["status"] == "success"
    assert record["context"]["abssctl_version"] == __version__

    human_content = human_log.read_text(encoding="utf-8")
    assert "config show" in human_content
