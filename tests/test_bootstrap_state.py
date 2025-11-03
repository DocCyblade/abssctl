"""Unit tests for bootstrap state rebuild helpers."""

from __future__ import annotations

from pathlib import Path

import yaml

from abssctl.bootstrap.discovery import DiscoveredInstance, DiscoveryReport
from abssctl.bootstrap.state import rebuild_registry_from_report
from abssctl.config import AppConfig, load_config
from abssctl.state.registry import StateRegistry


def _make_config(tmp_path: Path) -> AppConfig:
    config_path = tmp_path / "etc" / "abssctl" / "config.yml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("{}", encoding="utf-8")
    return load_config(config_file=config_path)


def test_rebuild_registry_from_discovery(tmp_path: Path) -> None:
    """Rebuilding the registry should reflect discovered instance metadata."""
    config = _make_config(tmp_path)
    registry = StateRegistry(tmp_path / "var" / "lib" / "abssctl" / "registry")
    registry.ensure_root()

    instance = DiscoveredInstance(
        name="alpha",
        root=tmp_path / "srv" / "alpha",
        data_dir=tmp_path / "srv" / "alpha" / "data",
        config_path=tmp_path / "srv" / "alpha" / "data" / "config.json",
        runtime_dir=tmp_path / "run" / "abssctl" / "instances" / "alpha",
        logs_dir=tmp_path / "var" / "log" / "abssctl" / "alpha",
        state_dir=tmp_path / "var" / "lib" / "abssctl" / "instances" / "alpha",
        systemd_unit=tmp_path / "etc" / "systemd" / "abssctl-alpha.service",
        nginx_site=tmp_path / "etc" / "nginx" / "sites-available" / "alpha.conf",
        port=5555,
        domain="alpha.example.com",
        version="v1.2.3",
    )
    report = DiscoveryReport(instances=[instance])

    artifacts = rebuild_registry_from_report(registry, config, report)

    instances_payload = yaml.safe_load(artifacts.instances.read_text(encoding="utf-8"))
    assert instances_payload["instances"][0]["name"] == "alpha"
    assert instances_payload["instances"][0]["domain"] == "alpha.example.com"
    assert instances_payload["instances"][0]["port"] == 5555

    ports_payload = yaml.safe_load(artifacts.ports.read_text(encoding="utf-8"))
    assert ports_payload["ports"][0]["port"] == 5555
    assert ports_payload["ports"][0]["name"] == "alpha"

    versions_payload = yaml.safe_load(artifacts.versions.read_text(encoding="utf-8"))
    assert versions_payload == {"versions": []}
