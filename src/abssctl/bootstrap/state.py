"""Helpers for rebuilding abssctl registry/config state from discovery data."""
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..config import AppConfig
from ..state.registry import StateRegistry
from .discovery import DiscoveredInstance, DiscoveryReport


@dataclass(slots=True)
class RegistryArtifacts:
    """Paths to registry artifacts created during rebuild."""

    instances: Path
    ports: Path
    versions: Path


def _timestamp() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _back_up(path: Path) -> None:
    if not path.exists():
        return
    timestamp = f"{datetime.now(tz=UTC).timestamp():.0f}"
    backup_path = path.with_suffix(f"{path.suffix or ''}.bak.{timestamp}")
    backup_path.write_bytes(path.read_bytes())
    backup_path.chmod(path.stat().st_mode)


def _describe_instance(instance: DiscoveredInstance, config: AppConfig) -> Mapping[str, object]:
    metadata = {
        "created_at": _timestamp(),
        "last_changed": _timestamp(),
        "domain": instance.domain,
        "port": instance.port,
    }
    paths = {
        "root": str(instance.root),
        "data": str(instance.data_dir),
        "config": str(instance.config_path),
        "runtime": str(
            instance.runtime_dir
            if instance.runtime_dir is not None
            else config.runtime_dir / "instances" / instance.name
        ),
        "logs": str(
            instance.logs_dir if instance.logs_dir is not None else config.logs_dir / instance.name
        ),
        "state": str(
            instance.state_dir
            if instance.state_dir is not None
            else config.state_dir / "instances" / instance.name
        ),
        "systemd_unit": str(
            instance.systemd_unit
            if instance.systemd_unit is not None
            else config.runtime_dir / "systemd" / f"abssctl-{instance.name}.service"
        ),
        "nginx_site": str(
            instance.nginx_site
            if instance.nginx_site is not None
            else config.runtime_dir / "nginx" / "sites-available" / f"{instance.name}.conf"
        ),
    }
    entry = {
        "name": instance.name,
        "domain": instance.domain,
        "port": instance.port,
        "version": instance.version or "current",
        "status": "unknown",
        "paths": paths,
        "metadata": metadata,
    }
    return entry


def _build_instances_payload(
    instances: Iterable[DiscoveredInstance],
    config: AppConfig,
) -> dict[str, object]:
    entries = [_describe_instance(instance, config) for instance in instances]
    return {"instances": entries}


def _build_ports_payload(instances: Iterable[DiscoveredInstance]) -> dict[str, object]:
    entries = []
    now = _timestamp()
    for instance in instances:
        if instance.port is None:
            continue
        entries.append(
            {
                "port": instance.port,
                "name": instance.name,
                "reserved_at": now,
            }
        )
    return {"ports": entries}


def rebuild_registry_from_report(
    root_registry: StateRegistry,
    config: AppConfig,
    report: DiscoveryReport,
) -> RegistryArtifacts:
    """Rewrite registry files using discovered instance data."""
    instances_path = root_registry.path_for("instances.yml")
    ports_path = root_registry.path_for("ports.yml")
    versions_path = root_registry.path_for("versions.yml")

    root_registry.ensure_root()
    _back_up(instances_path)
    _back_up(ports_path)
    _back_up(versions_path)

    serialisable_instances = _build_instances_payload(report.instances, config)
    root_registry.write("instances.yml", serialisable_instances)

    serialisable_ports = _build_ports_payload(report.instances)
    root_registry.write("ports.yml", serialisable_ports)

    versions_payload: dict[str, list[object]] = {"versions": []}
    root_registry.write("versions.yml", versions_payload)

    return RegistryArtifacts(
        instances=instances_path,
        ports=ports_path,
        versions=versions_path,
    )


def write_config_file(config: AppConfig) -> Path:
    """Write the resolved config to disk if missing, returning the path."""
    config_file = config.config_file
    config_file.parent.mkdir(parents=True, exist_ok=True)
    payload = config.to_dict()
    payload.pop("config_file", None)
    config_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    config_file.chmod(0o640)
    return config_file
