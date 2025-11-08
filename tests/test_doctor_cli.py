"""Tests for the ``abssctl doctor`` CLI command with real probes."""

from __future__ import annotations

import grp
import json
import os
import pwd
import time
from collections import namedtuple
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner, Result

from abssctl.cli import app
from abssctl.doctor import DoctorImpact
from abssctl.doctor import probes as doctor_probes
from abssctl.providers.nginx import NginxError
from tests.test_cli import _extract_json, _prepare_environment

runner = CliRunner()
_MockDiskUsage = namedtuple("DiskUsage", "total used free")


def _setup_instance_assets(tmp_path: Path, name: str) -> None:
    runtime_dir = tmp_path / "run"
    systemd_dir = runtime_dir / "systemd"
    systemd_dir.mkdir(parents=True, exist_ok=True)
    unit_path = systemd_dir / f"abssctl-{name}.service"
    unit_path.write_text("[Unit]\nDescription=Stub\n", encoding="utf-8")
    unit_path.chmod(0o644)

    sites_available = runtime_dir / "nginx" / "sites-available"
    sites_enabled = runtime_dir / "nginx" / "sites-enabled"
    sites_available.mkdir(parents=True, exist_ok=True)
    sites_enabled.mkdir(parents=True, exist_ok=True)
    site_path = sites_available / f"abssctl-{name}.conf"
    site_path.write_text("server { listen 5100; }\n", encoding="utf-8")
    enabled_path = sites_enabled / f"abssctl-{name}.conf"
    if not enabled_path.exists():
        enabled_path.symlink_to(site_path)


def _write_instance_config(root: Path, name: str, port: int) -> None:
    """Write a minimal config.json for discovery to consume."""
    config_path = root / name / "data" / "config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": 1,
        "instance": {
            "name": name,
            "domain": f"{name}.example.com",
        },
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


def _invoke_doctor(args: list[str], env: dict[str, str]) -> Result:
    return runner.invoke(app, ["doctor", *args], env=env)


def _patch_disk_usage(monkeypatch: pytest.MonkeyPatch, *, percent_free: float = 50.0) -> None:
    total = 100_000_000
    free = int(total * percent_free / 100)
    used = total - free
    monkeypatch.setattr(
        "abssctl.doctor.probes.shutil.disk_usage",
        lambda path: _MockDiskUsage(total, used, free),
    )


def _operations_log_lines(state_dir: Path) -> list[str]:
    log_path = state_dir.parent / "logs" / "operations.jsonl"
    if not log_path.exists():
        return []
    return log_path.read_text(encoding="utf-8").splitlines()


def _doctor_status_map(payload: dict[str, object]) -> dict[str, str]:
    return {
        str(item["id"]): str(item.get("status", ""))
        for item in payload.get("results", [])
        if isinstance(item, dict) and "id" in item
    }


def _doctor_entry(payload: dict[str, object], probe_id: str) -> dict[str, object]:
    for item in payload.get("results", []):
        if isinstance(item, dict) and item.get("id") == probe_id:
            return item
    raise AssertionError(f"Doctor payload missing probe '{probe_id}'")


def test_doctor_cli_reports_warning_for_missing_optional_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Running doctor in a healthy fixture should succeed with optional warnings."""
    instances = [
        {
            "name": "alpha",
            "status": "running",
            "metadata": {
                "diagnostics": {
                    "systemd": {"state": "running", "detail": "active"},
                }
            },
        }
    ]
    ports = [{"name": "alpha", "port": 5100}]
    env, _ = _prepare_environment(tmp_path, instances=instances, ports=ports)
    _patch_disk_usage(monkeypatch, percent_free=50.0)
    _setup_instance_assets(tmp_path, "alpha")
    _write_instance_config(tmp_path / "instances", "alpha", 5100)

    result = _invoke_doctor(["--json"], env)

    assert result.exit_code == 0, result.stdout
    payload = _extract_json(result.stdout)
    assert payload["summary"]["exit_code"] == 0
    assert payload["summary"]["status"] in {"green", "yellow"}
    result_ids = {item["id"] for item in payload["results"]}
    assert "env-python" in result_ids
    assert "env-zstd" in result_ids
    zstd_entry = next(item for item in payload["results"] if item["id"] == "env-zstd")
    assert zstd_entry["status"] in {"green", "yellow"}


def test_doctor_cli_missing_required_binary_triggers_environment_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Missing a required binary should set exit code 3."""
    instances = [{"name": "alpha", "status": "running"}]
    ports = [{"name": "alpha", "port": 5100}]
    env, _ = _prepare_environment(tmp_path, instances=instances, ports=ports)
    _patch_disk_usage(monkeypatch, percent_free=50.0)
    _setup_instance_assets(tmp_path, "alpha")
    _write_instance_config(tmp_path / "instances", "alpha", 5100)

    original_exists = doctor_probes._command_exists  # type: ignore[attr-defined]

    def fake_command_exists(command: str) -> bool:
        if command == "node":
            return False
        return original_exists(command)

    monkeypatch.setattr(doctor_probes, "_command_exists", fake_command_exists)

    result = _invoke_doctor(["--json"], env)

    assert result.exit_code == DoctorImpact.ENVIRONMENT.value
    payload = _extract_json(result.stdout)
    failing = {item["id"]: item for item in payload["results"]}
    assert failing["env-node"]["status"] == "red"
    assert payload["summary"]["exit_code"] == DoctorImpact.ENVIRONMENT.value


def test_doctor_cli_duplicate_ports_triggers_validation_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Duplicate port assignments should produce a validation failure."""
    instances = [
        {"name": "alpha", "status": "running"},
        {"name": "beta", "status": "running"},
    ]
    ports = [
        {"name": "alpha", "port": 5100},
        {"name": "beta", "port": 5100},
    ]
    env, _ = _prepare_environment(tmp_path, instances=instances, ports=ports)
    _patch_disk_usage(monkeypatch, percent_free=50.0)
    _setup_instance_assets(tmp_path, "alpha")
    _setup_instance_assets(tmp_path, "beta")
    _write_instance_config(tmp_path / "instances", "alpha", 5100)
    _write_instance_config(tmp_path / "instances", "beta", 5100)

    result = _invoke_doctor(["--json"], env)

    assert result.exit_code == DoctorImpact.VALIDATION.value
    payload = _extract_json(result.stdout)
    failing = {item["id"]: item for item in payload["results"]}
    assert failing["ports-registry"]["status"] == "red"


def test_doctor_cli_nginx_failure_triggers_provider_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nginx failures should produce a provider exit code."""
    instances = [{"name": "alpha", "status": "running"}]
    ports = [{"name": "alpha", "port": 5100}]
    env, _ = _prepare_environment(tmp_path, instances=instances, ports=ports)
    _patch_disk_usage(monkeypatch, percent_free=50.0)
    _setup_instance_assets(tmp_path, "alpha")
    _write_instance_config(tmp_path / "instances", "alpha", 5100)

    def boom(self: object) -> None:  # noqa: D401 - simple stub
        raise NginxError("nginx -t failed")

    monkeypatch.setattr(
        "abssctl.providers.nginx.NginxProvider.test_config",
        boom,
        raising=False,
    )

    result = _invoke_doctor(["--json"], env)

    assert result.exit_code == DoctorImpact.PROVIDER.value
    payload = _extract_json(result.stdout)
    failing = {item["id"]: item for item in payload["results"]}
    assert failing["nginx-config"]["status"] == "red"


def test_doctor_cli_only_filter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Category filters should limit the reported probes."""
    instances = [{"name": "alpha", "status": "running"}]
    ports = [{"name": "alpha", "port": 5100}]
    env, _ = _prepare_environment(tmp_path, instances=instances, ports=ports)
    _patch_disk_usage(monkeypatch, percent_free=50.0)
    _setup_instance_assets(tmp_path, "alpha")
    _write_instance_config(tmp_path / "instances", "alpha", 5100)

    result = _invoke_doctor(["--json", "--only", "env"], env)

    assert result.exit_code == 0
    payload = _extract_json(result.stdout)
    categories = {item["category"] for item in payload["results"]}
    assert categories <= {"env"}


def test_doctor_fix_dry_run_previews_repairs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Doctor --fix --dry-run should show the plan without mutating state."""
    instances = [{"name": "alpha", "status": "running"}]
    ports = [{"name": "alpha", "port": 5100}]
    env, state_dir = _prepare_environment(tmp_path, instances=instances, ports=ports)
    _patch_disk_usage(monkeypatch, percent_free=50.0)
    _setup_instance_assets(tmp_path, "alpha")
    _write_instance_config(tmp_path / "instances", "alpha", 5100)

    runtime_dir = tmp_path / "run"
    lock_path = runtime_dir / "abssctl.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps({"pid": 999_999}), encoding="utf-8")
    old = time.time() - 600
    os.utime(lock_path, (old, old))

    result = _invoke_doctor(["--fix", "--dry-run"], env)

    assert "doctor --fix plan" in result.stdout
    assert lock_path.exists()


def test_doctor_fix_applies_repairs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Doctor --fix --yes should repair registry files, perms, and stale locks."""
    instances = [{"name": "alpha", "status": "running"}]
    ports = [{"name": "alpha", "port": 5100}]
    env, state_dir = _prepare_environment(tmp_path, instances=instances, ports=ports)
    _patch_disk_usage(monkeypatch, percent_free=50.0)
    _setup_instance_assets(tmp_path, "alpha")
    _write_instance_config(tmp_path / "instances", "alpha", 5100)

    registry_dir = state_dir / "registry"
    instances_file = registry_dir / "instances.yml"
    instances_file.unlink()

    runtime_dir = tmp_path / "run"
    lock_path = runtime_dir / "abssctl.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps({"pid": 999_999}), encoding="utf-8")
    old = time.time() - 600
    os.utime(lock_path, (old, old))

    state_dir.chmod(0o777)

    _invoke_doctor(["--fix", "--yes", "--json"], env)
    assert instances_file.exists()
    assert yaml.safe_load(instances_file.read_text(encoding="utf-8")).get("instances") == []
    assert oct(state_dir.stat().st_mode & 0o777) == "0o750"
    assert not lock_path.exists()

    operations = _operations_log_lines(state_dir)
    assert operations, "operations log should record doctor --fix steps"
    payload = json.loads(operations[-1])
    step_names = [step["name"] for step in payload.get("steps", [])]
    assert "repair.registry.create" in step_names
    assert "repair.locks.cleanup" in step_names


def test_doctor_cli_repeat_runs_stable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Running doctor twice should yield consistent results and append logs."""
    instances = [
        {
            "name": "alpha",
            "status": "running",
            "metadata": {
                "diagnostics": {
                    "systemd": {"state": "running", "detail": "active"},
                }
            },
        }
    ]
    ports = [{"name": "alpha", "port": 5100}]
    env, state_dir = _prepare_environment(tmp_path, instances=instances, ports=ports)
    _patch_disk_usage(monkeypatch, percent_free=45.0)
    _setup_instance_assets(tmp_path, "alpha")
    _write_instance_config(tmp_path / "instances", "alpha", 5100)

    baseline_lines = _operations_log_lines(state_dir)

    first = _invoke_doctor(["--json"], env)
    assert first.exit_code == 0, first.stdout
    payload_first = _extract_json(first.stdout)
    summary_first = payload_first["summary"]
    statuses_first = _doctor_status_map(payload_first)
    lines_after_first = _operations_log_lines(state_dir)
    assert len(lines_after_first) >= len(baseline_lines) + 1

    second = _invoke_doctor(["--json"], env)
    assert second.exit_code == 0, second.stdout
    payload_second = _extract_json(second.stdout)
    summary_second = payload_second["summary"]
    statuses_second = _doctor_status_map(payload_second)
    lines_after_second = _operations_log_lines(state_dir)

    assert summary_second["status"] == summary_first["status"]
    assert summary_second["exit_code"] == summary_first["exit_code"]
    assert statuses_second == statuses_first
    assert len(lines_after_second) >= len(lines_after_first) + 1


@pytest.mark.mutation_timeout
def test_doctor_cli_rebuild_state_clears_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`system init --rebuild-state` should resolve doctor state-reconcile failures."""
    instances = [{"name": "alpha", "status": "running"}]
    ports = [{"name": "alpha", "port": 5100}]
    env, state_dir = _prepare_environment(tmp_path, instances=instances, ports=ports)
    _patch_disk_usage(monkeypatch, percent_free=40.0)
    _setup_instance_assets(tmp_path, "alpha")
    _setup_instance_assets(tmp_path, "beta")
    _write_instance_config(tmp_path / "instances", "alpha", 5100)
    _write_instance_config(tmp_path / "instances", "beta", 5200)

    failing = _invoke_doctor(["--json"], env)
    assert failing.exit_code == DoctorImpact.VALIDATION.value, failing.stdout
    payload_failing = _extract_json(failing.stdout)
    reconcile_failing = _doctor_entry(payload_failing, "state-reconcile")
    assert reconcile_failing["status"] == "red"
    discovered_only = reconcile_failing.get("data", {}).get("discovered_only", [])
    assert "beta" in discovered_only

    config_path = Path(env["ABSSCTL_CONFIG_FILE"])
    config_data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    owner = pwd.getpwuid(os.getuid()).pw_name
    group = grp.getgrgid(os.getgid()).gr_name
    install_root_path = Path(config_data.get("install_root") or (tmp_path / "install"))
    instance_root_path = Path(config_data.get("instance_root") or (tmp_path / "instances"))
    state_dir_path = Path(config_data["state_dir"])
    logs_dir_path = Path(config_data["logs_dir"])
    runtime_dir_path = Path(config_data["runtime_dir"])
    templates_dir_path = Path(config_data["templates_dir"])
    backups_root_path = Path(config_data["backups"]["root"])

    install_root_path.mkdir(parents=True, exist_ok=True)
    instance_root_path.mkdir(parents=True, exist_ok=True)
    state_dir_path.mkdir(parents=True, exist_ok=True)
    logs_dir_path.mkdir(parents=True, exist_ok=True)
    runtime_dir_path.mkdir(parents=True, exist_ok=True)
    templates_dir_path.mkdir(parents=True, exist_ok=True)
    backups_root_path.mkdir(parents=True, exist_ok=True)

    rebuild_args = [
        "system",
        "init",
        "--config-file",
        str(config_path),
        "--yes",
        "--rebuild-state",
        "--allow-create-user",
        "--service-user",
        owner,
        "--service-group",
        group,
        "--install-root",
        str(install_root_path),
        "--instance-root",
        str(instance_root_path),
        "--state-dir",
        str(state_dir_path),
        "--logs-dir",
        str(logs_dir_path),
        "--runtime-dir",
        str(runtime_dir_path),
        "--templates-dir",
        str(templates_dir_path),
        "--backups-root",
        str(backups_root_path),
    ]
    rebuild_result = runner.invoke(app, rebuild_args, env=env)
    assert rebuild_result.exit_code == 0, rebuild_result.stdout

    healed = _invoke_doctor(["--json"], env)
    assert healed.exit_code == 0, healed.stdout
    payload_healed = _extract_json(healed.stdout)
    reconcile_healed = _doctor_entry(payload_healed, "state-reconcile")
    assert reconcile_healed["status"] in {"green", "yellow"}
    assert not reconcile_healed.get("data", {}).get("discovered_only")
    assert not reconcile_healed.get("data", {}).get("registry_only")


def test_doctor_cli_detects_registry_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """State reconcile probe should report mismatches between disk and registry."""
    instances = [
        {
            "name": "alpha",
            "status": "running",
        }
    ]
    ports = [
        {"name": "alpha", "port": 5100},
    ]
    env, _ = _prepare_environment(tmp_path, instances=instances, ports=ports)
    _patch_disk_usage(monkeypatch, percent_free=50.0)
    _setup_instance_assets(tmp_path, "alpha")
    _setup_instance_assets(tmp_path, "beta")

    instance_root = tmp_path / "instances"
    _write_instance_config(instance_root, "alpha", 5100)
    _write_instance_config(instance_root, "beta", 5200)

    result = _invoke_doctor(["--json"], env)

    assert result.exit_code == DoctorImpact.VALIDATION.value
    payload = _extract_json(result.stdout)
    reconcile = next(item for item in payload["results"] if item["id"] == "state-reconcile")
    assert reconcile["status"] == "red"
    assert "beta" in reconcile.get("data", {}).get("discovered_only", [])


def test_doctor_cli_rejects_invalid_category(tmp_path: Path) -> None:
    """Unknown categories should raise a validation error."""
    env, _ = _prepare_environment(tmp_path)
    result = _invoke_doctor(["--only", "unknown"], env)

    assert result.exit_code == 2
    assert "Unknown probe categories" in result.stdout
