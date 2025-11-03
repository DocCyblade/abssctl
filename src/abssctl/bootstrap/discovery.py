"""Instance discovery helpers used by the bootstrap workflow."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class DiscoveredInstance:
    """Representation of an Actual instance detected on disk."""

    name: str
    root: Path
    data_dir: Path
    config_path: Path
    runtime_dir: Path | None = None
    logs_dir: Path | None = None
    state_dir: Path | None = None
    systemd_unit: Path | None = None
    nginx_site: Path | None = None
    port: int | None = None
    domain: str | None = None
    version: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DiscoveryReport:
    """Aggregated report describing discovery results."""

    instances: list[DiscoveredInstance] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def discover_instances(
    instance_root: Path,
    *,
    runtime_root: Path | None = None,
    logs_root: Path | None = None,
    state_root: Path | None = None,
    systemd_dir: Path | None = None,
    nginx_sites_available: Path | None = None,
) -> DiscoveryReport:
    """Inspect *instance_root* for existing instances shaped like abssctl expects."""
    report = DiscoveryReport()
    if not instance_root.exists():
        report.errors.append(f"Instance root {instance_root} does not exist.")
        return report

    for child in sorted(instance_root.iterdir()):
        if not child.is_dir():
            continue
        name = child.name
        data_dir = child / "data"
        config_path = data_dir / "config.json"
        instance = DiscoveredInstance(
            name=name,
            root=child,
            data_dir=data_dir,
            config_path=config_path,
        )
        if runtime_root is not None:
            instance.runtime_dir = runtime_root / "instances" / name
        if logs_root is not None:
            instance.logs_dir = logs_root / name
        if state_root is not None:
            instance.state_dir = state_root / "instances" / name
        if systemd_dir is not None:
            instance.systemd_unit = systemd_dir / f"abssctl-{name}.service"
        if nginx_sites_available is not None:
            instance.nginx_site = nginx_sites_available / f"{name}.conf"

        if not config_path.exists():
            instance.warnings.append(f"config.json missing under {data_dir}.")
            report.instances.append(instance)
            continue

        try:
            payload = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            instance.warnings.append(f"Failed to parse {config_path}: {exc}")
            report.instances.append(instance)
            continue

        if not isinstance(payload, dict):
            instance.warnings.append(f"Config payload at {config_path} is not a mapping.")
            report.instances.append(instance)
            continue

        instance.domain = _get_nested_str(payload, ["instance", "domain"])
        port_value = _get_nested_value(payload, ["server", "upstream", "port"])
        if isinstance(port_value, int):
            instance.port = port_value
        elif isinstance(port_value, str):
            try:
                instance.port = int(port_value)
            except ValueError:
                instance.warnings.append(f"Upstream port value '{port_value}' is not numeric.")
        instance.version = _get_nested_str(payload, ["server", "version"])

        report.instances.append(instance)

    if not report.instances:
        report.warnings.append(f"No instances discovered under {instance_root}.")
    return report


def _get_nested_value(payload: dict[str, object], path: list[str]) -> object | None:
    current: object = payload
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _get_nested_str(payload: dict[str, object], path: list[str]) -> str | None:
    value = _get_nested_value(payload, path)
    return value if isinstance(value, str) else None


__all__ = ["DiscoveredInstance", "DiscoveryReport", "discover_instances"]
