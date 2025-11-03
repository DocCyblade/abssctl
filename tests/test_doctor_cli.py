"""Tests for the ``abssctl doctor`` CLI command with real probes."""

from __future__ import annotations

import json
from collections import namedtuple
from pathlib import Path

import pytest
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


def test_doctor_cli_fix_flag_reports_placeholder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--fix should report that remediation is not yet implemented."""
    instances = [{"name": "alpha", "status": "running"}]
    ports = [{"name": "alpha", "port": 5100}]
    env, _ = _prepare_environment(tmp_path, instances=instances, ports=ports)
    _patch_disk_usage(monkeypatch, percent_free=50.0)
    _setup_instance_assets(tmp_path, "alpha")
    _write_instance_config(tmp_path / "instances", "alpha", 5100)

    result = _invoke_doctor(["--fix"], env)

    assert result.exit_code == 0
    assert "--fix is not implemented yet" in result.stdout


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
