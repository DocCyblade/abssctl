"""Unit tests for bootstrap discovery helpers."""
from __future__ import annotations

import json
from pathlib import Path

from abssctl.bootstrap.discovery import discover_instances


def _write_config(path: Path, domain: str, port: int, version: str) -> None:
    """Write a minimal config.json payload for discovery fixtures."""
    payload = {
        "schema": 1,
        "instance": {
            "name": path.parent.parent.name,
            "domain": domain,
        },
        "server": {
            "upstream": {"host": "127.0.0.1", "port": port},
            "version": version,
        },
        "paths": {
            "root": str(path.parent.parent),
            "data": str(path.parent),
            "config": str(path),
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_discovery_reports_instances(tmp_path: Path) -> None:
    """Discovery should populate metadata for existing instances."""
    instance_root = tmp_path / "srv"
    runtime_root = tmp_path / "run" / "abssctl"
    logs_root = tmp_path / "var" / "log" / "abssctl"
    state_root = tmp_path / "var" / "lib" / "abssctl"
    systemd_dir = tmp_path / "etc" / "systemd"
    nginx_sites = tmp_path / "etc" / "nginx" / "sites-available"

    config_path = instance_root / "alpha" / "data" / "config.json"
    _write_config(config_path, "alpha.example.com", 5555, "v1.2.3")

    report = discover_instances(
        instance_root,
        runtime_root=runtime_root,
        logs_root=logs_root,
        state_root=state_root,
        systemd_dir=systemd_dir,
        nginx_sites_available=nginx_sites,
    )

    assert not report.errors
    assert not report.warnings
    assert len(report.instances) == 1
    instance = report.instances[0]
    assert instance.name == "alpha"
    assert instance.domain == "alpha.example.com"
    assert instance.port == 5555
    assert instance.version == "v1.2.3"
    assert instance.systemd_unit == systemd_dir / "abssctl-alpha.service"
    assert instance.nginx_site == nginx_sites / "alpha.conf"


def test_discovery_handles_missing_config(tmp_path: Path) -> None:
    """Discovery should capture warnings when config.json is absent."""
    instance_root = tmp_path / "srv"
    (instance_root / "beta" / "data").mkdir(parents=True)

    report = discover_instances(instance_root)

    assert len(report.instances) == 1
    beta = report.instances[0]
    assert beta.name == "beta"
    assert beta.warnings == [f"config.json missing under {beta.data_dir}."]
