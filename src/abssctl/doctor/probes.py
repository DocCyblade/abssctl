"""Probe registration entry point for the doctor command."""

from __future__ import annotations

import os
import platform
import shutil
import stat
import sys
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import __version__
from ..bootstrap import discover_instances
from ..node_compat import NodeVersionSpec
from ..node_runtime import NodeVersionInfo
from ..ports import PortsRegistryError
from ..providers.nginx import NginxError
from ..providers.systemd import SystemdError
from ..tls import TLSConfigurationError, TLSValidationSeverity
from .models import (
    DoctorImpact,
    ProbeCategory,
    ProbeContext,
    ProbeDefinition,
    ProbeResult,
    ProbeStatus,
)


def collect_probes(context: ProbeContext) -> Sequence[ProbeDefinition]:
    """Return the set of probes that should run for the current context."""
    probes: list[ProbeDefinition] = []
    probes.extend(_env_probes())
    probes.extend(_config_probes())
    probes.extend(_filesystem_probes())
    probes.extend(_state_probes())
    probes.extend(_ports_probes())
    probes.extend(_systemd_probes())
    probes.extend(_nginx_probes())
    probes.extend(_tls_probes())
    probes.extend(_app_probes())
    probes.extend(_disk_probes())
    return tuple(probes)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_probe(
    probe_id: str,
    category: ProbeCategory,
    handler: Callable[[ProbeContext], ProbeResult],
) -> ProbeDefinition:
    def _runner(context: ProbeContext) -> ProbeResult:
        return handler(context)

    return ProbeDefinition(id=probe_id, category=category, run=_runner)


def _command_exists(command: str) -> bool:
    path = Path(command)
    if path.is_absolute() or (path.parent and str(path.parent) not in {"", "."}):
        return path.exists() and os.access(path, os.X_OK)
    resolved = shutil.which(command)
    return resolved is not None and os.access(resolved, os.X_OK)


def _format_directory_permissions(path: Path) -> str:
    try:
        info = path.stat()
    except FileNotFoundError:
        return "missing"
    mode = stat.S_IMODE(info.st_mode)
    return f"{mode:03o}"


def _iter_instance_entries(context: ProbeContext) -> list[Mapping[str, Any]]:
    data = context.registry.read_instances()
    raw_instances = data.get("instances", [])
    entries: list[Mapping[str, Any]] = []
    if isinstance(raw_instances, Iterable):
        for entry in raw_instances:
            if isinstance(entry, Mapping):
                entries.append(entry)
    return entries


def _instance_names(entries: Iterable[Mapping[str, Any]]) -> list[str]:
    names: list[str] = []
    for entry in entries:
        name_raw = entry.get("name")
        if isinstance(name_raw, str):
            name = name_raw.strip()
            if name:
                names.append(name)
    return names


# ---------------------------------------------------------------------------
# Environment probes
# ---------------------------------------------------------------------------


def _env_probes() -> Sequence[ProbeDefinition]:
    return (
        _make_probe("env-python", "env", _probe_env_python),
        _make_probe("env-abssctl", "env", _probe_env_abssctl),
        _make_probe("env-platform", "env", _probe_env_platform),
        _make_probe("env-node", "env", _probe_env_command("node", fatal=True)),
        _make_probe("env-node-compat", "env", _probe_env_node_compat),
        _make_probe("env-npm", "env", _probe_env_command("npm", fatal=True)),
        _make_probe("env-tar", "env", _probe_env_command("tar", fatal=True)),
        _make_probe("env-gzip", "env", _probe_env_command("gzip", fatal=True)),
        _make_probe("env-zstd", "env", _probe_env_command("zstd", fatal=False)),
        _make_probe("env-nginx", "env", _probe_env_nginx),
        _make_probe("env-systemctl", "env", _probe_env_systemctl),
    )


def _probe_env_python(context: ProbeContext) -> ProbeResult:
    version = platform.python_version()
    return ProbeResult(
        id="env-python",
        category="env",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message=f"Python {version} detected.",
        data={
            "executable": sys.executable,
            "version": version,
        },
    )


def _probe_env_abssctl(_context: ProbeContext) -> ProbeResult:
    return ProbeResult(
        id="env-abssctl",
        category="env",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message=f"abssctl {__version__} installed.",
    )


def _probe_env_platform(_context: ProbeContext) -> ProbeResult:
    platform_summary = platform.platform()
    return ProbeResult(
        id="env-platform",
        category="env",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message=f"Platform: {platform_summary}",
    )


def _probe_env_command(
    command: str,
    *,
    fatal: bool,
) -> Callable[[ProbeContext], ProbeResult]:
    def _run(_context: ProbeContext) -> ProbeResult:
        exists = _command_exists(command)
        if exists:
            return ProbeResult(
                id=f"env-{command}",
                category="env",
                status=ProbeStatus.GREEN,
                impact=DoctorImpact.OK,
                message=f"Binary '{command}' available.",
            )
        if fatal:
            return ProbeResult(
                id=f"env-{command}",
                category="env",
                status=ProbeStatus.RED,
                impact=DoctorImpact.ENVIRONMENT,
                message=f"Required binary '{command}' not found on PATH.",
            )
        return ProbeResult(
            id=f"env-{command}",
            category="env",
            status=ProbeStatus.YELLOW,
            impact=DoctorImpact.OK,
            message=f"Optional binary '{command}' not found; performance may be reduced.",
            warnings=(f"missing:{command}",),
        )

    return _run


def _node_satisfies(info: NodeVersionInfo, requirement: NodeVersionSpec) -> bool:
    """Return True when the detected Node version meets the requirement."""
    if info.major > requirement.major:
        return True
    if info.major < requirement.major:
        return False
    detected_tuple = (info.major, info.minor, info.patch)
    required_tuple = requirement.min_tuple()
    return detected_tuple >= required_tuple


def _probe_env_node_compat(context: ProbeContext) -> ProbeResult:
    runtime = context.node_runtime
    detected = runtime.detect_version()
    if detected is None:
        return ProbeResult(
            id="env-node-compat",
            category="env",
            status=ProbeStatus.YELLOW,
            impact=DoctorImpact.OK,
            message="Node binary not detected; compatibility check skipped.",
            warnings=("node-missing",),
        )

    if context.node_compat is None:
        return ProbeResult(
            id="env-node-compat",
            category="env",
            status=ProbeStatus.YELLOW,
            impact=DoctorImpact.OK,
            message=(
                "Node compatibility data unavailable. "
                "Refresh docs/requirements/node-compat.yaml."
            ),
            warnings=("node-compat-missing",),
            data={"detected": detected.version},
        )

    requirement = context.node_compat.preferred_node_version()
    if requirement is None:
        return ProbeResult(
            id="env-node-compat",
            category="env",
            status=ProbeStatus.YELLOW,
            impact=DoctorImpact.OK,
            message="Node compatibility matrix missing node_versions entries.",
            warnings=("node-compat-empty",),
            data={"detected": detected.version},
        )

    if _node_satisfies(detected, requirement):
        return ProbeResult(
            id="env-node-compat",
            category="env",
            status=ProbeStatus.GREEN,
            impact=DoctorImpact.OK,
            message=(
                f"Node {detected.version} satisfies required {requirement.major}.x"
                f" (>= {requirement.min_patch})."
            ),
            data={
                "detected": detected.version,
                "required_major": requirement.major,
                "required_min_patch": requirement.min_patch,
                "requirement_status": requirement.status,
            },
        )

    message = (
        f"Detected Node {detected.version} but the compatibility matrix requires "
        f"{requirement.major}.x (>= {requirement.min_patch})."
    )
    remediation = (
        "Install the required Node version via `abssctl node ensure` or update "
        "/etc/default/abssctl-node to match the compatibility matrix."
    )
    return ProbeResult(
        id="env-node-compat",
        category="env",
        status=ProbeStatus.YELLOW,
        impact=DoctorImpact.OK,
        message=message,
        remediation=remediation,
        warnings=("node-version-mismatch",),
        data={
            "detected": detected.version,
            "detected_major": detected.major,
            "required_major": requirement.major,
            "required_min_patch": requirement.min_patch,
            "requirement_status": requirement.status,
        },
    )


def _probe_env_nginx(context: ProbeContext) -> ProbeResult:
    binary = context.nginx_provider.nginx_bin
    exists = _command_exists(binary)
    if exists:
        return ProbeResult(
            id="env-nginx",
            category="env",
            status=ProbeStatus.GREEN,
            impact=DoctorImpact.OK,
            message=f"nginx binary '{binary}' available.",
        )
    return ProbeResult(
        id="env-nginx",
        category="env",
        status=ProbeStatus.RED,
        impact=DoctorImpact.ENVIRONMENT,
        message=f"nginx binary '{binary}' not found.",
    )


def _probe_env_systemctl(context: ProbeContext) -> ProbeResult:
    binary = context.systemd_provider.systemctl_bin
    exists = _command_exists(binary)
    if exists:
        return ProbeResult(
            id="env-systemctl",
            category="env",
            status=ProbeStatus.GREEN,
            impact=DoctorImpact.OK,
            message=f"systemctl binary '{binary}' available.",
        )
    return ProbeResult(
        id="env-systemctl",
        category="env",
        status=ProbeStatus.YELLOW,
        impact=DoctorImpact.OK,
        message="systemctl not found; commands falling back to dry-run.",
        warnings=("missing:systemctl",),
    )


# ---------------------------------------------------------------------------
# Config / filesystem probes
# ---------------------------------------------------------------------------


def _config_probes() -> Sequence[ProbeDefinition]:
    return (
        _make_probe("config-file", "config", _probe_config_file),
    )


def _probe_config_file(context: ProbeContext) -> ProbeResult:
    config_file = context.config.config_file
    if config_file.exists():
        return ProbeResult(
            id="config-file",
            category="config",
            status=ProbeStatus.GREEN,
            impact=DoctorImpact.OK,
            message=f"Config file {config_file} loaded successfully.",
        )
    return ProbeResult(
        id="config-file",
        category="config",
        status=ProbeStatus.RED,
        impact=DoctorImpact.VALIDATION,
        message=f"Config file {config_file} is missing.",
    )


def _filesystem_probes() -> Sequence[ProbeDefinition]:
    return (
        _make_probe("fs-directories", "fs", _probe_filesystem_directories),
    )


def _probe_filesystem_directories(context: ProbeContext) -> ProbeResult:
    config = context.config
    directories = {
        "config": config.config_file.parent,
        "state": config.state_dir,
        "registry": config.registry_dir,
        "logs": config.logs_dir,
        "runtime": config.runtime_dir,
        "templates": config.templates_dir,
        "backups": config.backups.root,
    }

    missing = [name for name, path in directories.items() if not Path(path).exists()]
    if missing:
        detail = ", ".join(sorted(missing))
        return ProbeResult(
            id="fs-directories",
            category="fs",
            status=ProbeStatus.RED,
            impact=DoctorImpact.VALIDATION,
            message=f"Required directories missing: {detail}.",
        )

    permissions = {
        name: _format_directory_permissions(Path(path)) for name, path in directories.items()
    }
    return ProbeResult(
        id="fs-directories",
        category="fs",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message="Required directories exist.",
        data={"permissions": permissions},
    )


# ---------------------------------------------------------------------------
# State / registry probes
# ---------------------------------------------------------------------------


def _state_probes() -> Sequence[ProbeDefinition]:
    return (
        _make_probe("state-instances", "state", _probe_state_instances),
        _make_probe("state-reconcile", "state", _probe_state_reconcile),
    )


def _probe_state_instances(context: ProbeContext) -> ProbeResult:
    entries = _iter_instance_entries(context)
    names = _instance_names(entries)
    counts = Counter(names)
    duplicates = [name for name, count in counts.items() if count > 1]
    if duplicates:
        joined = ", ".join(sorted(duplicates))
        return ProbeResult(
            id="state-instances",
            category="state",
            status=ProbeStatus.RED,
            impact=DoctorImpact.VALIDATION,
            message=f"Duplicate instance names detected: {joined}.",
        )
    message = "No instances registered." if not names else f"{len(names)} instance(s) registered."
    return ProbeResult(
        id="state-instances",
        category="state",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message=message,
    )


def _probe_state_reconcile(context: ProbeContext) -> ProbeResult:
    config = context.config
    report = discover_instances(
        config.instance_root,
        runtime_root=config.runtime_dir,
        logs_root=config.logs_dir,
        state_root=config.state_dir,
        systemd_dir=config.runtime_dir / "systemd",
        nginx_sites_available=config.runtime_dir / "nginx" / "sites-available",
    )

    registry_entries = _iter_instance_entries(context)
    registry_names = set(_instance_names(registry_entries))
    discovered_names = {instance.name for instance in report.instances}

    missing_in_registry = sorted(discovered_names - registry_names)
    missing_on_disk = sorted(registry_names - discovered_names)

    instance_warnings = {
        instance.name: list(instance.warnings)
        for instance in report.instances
        if instance.warnings
    }

    data: dict[str, object] = {}
    if missing_in_registry:
        data["discovered_only"] = missing_in_registry
    if missing_on_disk:
        data["registry_only"] = missing_on_disk
    if instance_warnings:
        data["instance_warnings"] = instance_warnings

    if report.errors:
        return ProbeResult(
            id="state-reconcile",
            category="state",
            status=ProbeStatus.RED,
            impact=DoctorImpact.VALIDATION,
            message="Discovery encountered errors; unable to reconcile registry state.",
            warnings=tuple(report.errors),
            data=data or None,
            remediation=(
                "Resolve discovery issues, then run `abssctl system init --rebuild-state` to "
                "repopulate registry files."
            ),
        )

    if missing_in_registry or missing_on_disk:
        message_parts: list[str] = []
        if missing_in_registry:
            entries = ", ".join(missing_in_registry)
            message_parts.append(f"filesystem instances not registered: {entries}")
        if missing_on_disk:
            entries = ", ".join(missing_on_disk)
            message_parts.append(f"registry entries missing on disk: {entries}")
        message = "; ".join(message_parts)
        return ProbeResult(
            id="state-reconcile",
            category="state",
            status=ProbeStatus.RED,
            impact=DoctorImpact.VALIDATION,
            message=message,
            data=data or None,
            remediation=(
                "Review the discrepancies and run `abssctl system init --rebuild-state` once the "
                "filesystem matches the desired state."
            ),
        )

    if report.warnings or instance_warnings:
        combined_warnings = tuple(report.warnings)
        message = "Discovery completed with warnings; see details."
        return ProbeResult(
            id="state-reconcile",
            category="state",
            status=ProbeStatus.YELLOW,
            impact=DoctorImpact.OK,
            message=message,
            warnings=combined_warnings,
            data=data or None,
        )

    message = (
        "Registry matches discovery"
        if discovered_names
        else "No instances discovered; registry is empty"
    )
    return ProbeResult(
        id="state-reconcile",
        category="state",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message=message,
        data=data or None,
    )


# ---------------------------------------------------------------------------
# Ports probes
# ---------------------------------------------------------------------------


def _ports_probes() -> Sequence[ProbeDefinition]:
    return (
        _make_probe("ports-registry", "ports", _probe_ports_registry),
    )


def _probe_ports_registry(context: ProbeContext) -> ProbeResult:
    try:
        entries = context.ports.list_entries()
    except PortsRegistryError as exc:
        return ProbeResult(
            id="ports-registry",
            category="ports",
            status=ProbeStatus.RED,
            impact=DoctorImpact.VALIDATION,
            message=f"Failed to read ports registry: {exc}",
        )

    ports = [entry["port"] for entry in entries]
    port_counts = Counter(ports)
    duplicates = [str(port) for port, count in port_counts.items() if count > 1]
    if duplicates:
        detail = ", ".join(sorted(duplicates))
        return ProbeResult(
            id="ports-registry",
            category="ports",
            status=ProbeStatus.RED,
            impact=DoctorImpact.VALIDATION,
            message=f"Duplicate ports detected: {detail}.",
        )

    names = [entry["name"] for entry in entries]
    name_counts = Counter(names)
    duplicate_names = [name for name, count in name_counts.items() if count > 1]
    if duplicate_names:
        detail = ", ".join(sorted(duplicate_names))
        return ProbeResult(
            id="ports-registry",
            category="ports",
            status=ProbeStatus.RED,
            impact=DoctorImpact.VALIDATION,
            message=f"Duplicate port reservations detected: {detail}.",
        )

    instance_names = set(_instance_names(_iter_instance_entries(context)))
    missing = sorted(instance_names - set(names))
    if missing:
        detail = ", ".join(missing)
        return ProbeResult(
            id="ports-registry",
            category="ports",
            status=ProbeStatus.YELLOW,
            impact=DoctorImpact.OK,
            message=f"Instances without reserved ports: {detail}.",
            warnings=("ports:missing",),
        )

    return ProbeResult(
        id="ports-registry",
        category="ports",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message=f"{len(entries)} port reservation(s) recorded.",
    )


# ---------------------------------------------------------------------------
# Systemd probes
# ---------------------------------------------------------------------------


def _systemd_probes() -> Sequence[ProbeDefinition]:
    return (
        _make_probe("systemd-units", "systemd", _probe_systemd_units),
        _make_probe("systemd-status", "systemd", _probe_systemd_status),
    )


def _probe_systemd_units(context: ProbeContext) -> ProbeResult:
    provider = context.systemd_provider
    entries = _iter_instance_entries(context)
    missing = []
    for entry in entries:
        name_raw = entry.get("name")
        if not isinstance(name_raw, str):
            continue
        name = name_raw.strip()
        if not name:
            continue
        unit_path = provider.unit_path(name)
        if not unit_path.exists():
            missing.append(name)

    if missing:
        detail = ", ".join(sorted(missing))
        return ProbeResult(
            id="systemd-units",
            category="systemd",
            status=ProbeStatus.RED,
            impact=DoctorImpact.VALIDATION,
            message=f"Missing systemd unit files for: {detail}.",
        )

    return ProbeResult(
        id="systemd-units",
        category="systemd",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message="All systemd unit files are present.",
    )


def _probe_systemd_status(context: ProbeContext) -> ProbeResult:
    provider = context.systemd_provider
    entries = _iter_instance_entries(context)
    failures: dict[str, str] = {}
    warnings: dict[str, str] = {}
    for entry in entries:
        name_raw = entry.get("name")
        if not isinstance(name_raw, str):
            continue
        name = name_raw.strip()
        if not name:
            continue
        try:
            result = provider.status(name)
        except SystemdError as exc:
            message = str(exc)
            if "not found" in message.lower():
                warnings[name] = message
                continue
            failures[name] = message
            continue
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "no output").strip()
            failures[name] = message or "status command failed"

    if failures:
        detail = {name: reason for name, reason in failures.items()}
        return ProbeResult(
            id="systemd-status",
            category="systemd",
            status=ProbeStatus.RED,
            impact=DoctorImpact.PROVIDER,
            message="Systemd status checks failed.",
            data={"failures": detail},
        )

    if warnings:
        return ProbeResult(
            id="systemd-status",
            category="systemd",
            status=ProbeStatus.YELLOW,
            impact=DoctorImpact.OK,
            message="Systemd status unavailable (binary missing).",
            data={"warnings": warnings},
            warnings=("systemd:missing",),
        )

    return ProbeResult(
        id="systemd-status",
        category="systemd",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message="systemctl status reports healthy services.",
    )


# ---------------------------------------------------------------------------
# Nginx probes
# ---------------------------------------------------------------------------


def _nginx_probes() -> Sequence[ProbeDefinition]:
    return (
        _make_probe("nginx-config", "nginx", _probe_nginx_config),
        _make_probe("nginx-sites", "nginx", _probe_nginx_sites),
    )


def _probe_nginx_config(context: ProbeContext) -> ProbeResult:
    provider = context.nginx_provider
    try:
        result = provider.test_config()
    except NginxError as exc:
        return ProbeResult(
            id="nginx-config",
            category="nginx",
            status=ProbeStatus.RED,
            impact=DoctorImpact.PROVIDER,
            message=f"nginx -t failed: {exc}",
        )

    if result.returncode != 0:
        message = (result.stderr or result.stdout or "no output").strip()
        return ProbeResult(
            id="nginx-config",
            category="nginx",
            status=ProbeStatus.RED,
            impact=DoctorImpact.PROVIDER,
            message=f"nginx -t exited with {result.returncode}: {message}",
        )

    return ProbeResult(
        id="nginx-config",
        category="nginx",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message="nginx -t validation succeeded.",
    )


def _probe_nginx_sites(context: ProbeContext) -> ProbeResult:
    provider = context.nginx_provider
    entries = _iter_instance_entries(context)
    missing = []
    disabled = []
    for entry in entries:
        name_raw = entry.get("name")
        if not isinstance(name_raw, str):
            continue
        name = name_raw.strip()
        if not name:
            continue
        if not provider.site_path(name).exists():
            missing.append(name)
            continue
        if not provider.is_enabled(name):
            disabled.append(name)

    if missing:
        detail = ", ".join(sorted(missing))
        return ProbeResult(
            id="nginx-sites",
            category="nginx",
            status=ProbeStatus.RED,
            impact=DoctorImpact.VALIDATION,
            message=f"Missing nginx site configuration(s): {detail}.",
        )
    if disabled:
        detail = ", ".join(sorted(disabled))
        return ProbeResult(
            id="nginx-sites",
            category="nginx",
            status=ProbeStatus.YELLOW,
            impact=DoctorImpact.OK,
            message=f"Sites present but not enabled: {detail}.",
            warnings=("nginx:disabled",),
        )

    return ProbeResult(
        id="nginx-sites",
        category="nginx",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message="All nginx sites present and enabled.",
    )


# ---------------------------------------------------------------------------
# TLS probes
# ---------------------------------------------------------------------------


def _tls_probes() -> Sequence[ProbeDefinition]:
    return (
        _make_probe("tls-system-cert", "tls", _probe_tls_system_certificate),
    )


def _probe_tls_system_certificate(context: ProbeContext) -> ProbeResult:
    inspector = context.tls_inspector
    validator = context.tls_validator
    config = context.config
    try:
        selection = inspector.resolve_manual(
            certificate=config.tls.system.cert,
            key=config.tls.system.key,
            chain=None,
            source="system",
        )
        report = validator.validate(selection, now=datetime.now(UTC))
    except TLSConfigurationError as exc:
        return ProbeResult(
            id="tls-system-cert",
            category="tls",
            status=ProbeStatus.RED,
            impact=DoctorImpact.VALIDATION,
            message=f"Failed to resolve system TLS assets: {exc}",
        )

    status_map = {
        TLSValidationSeverity.OK: ProbeStatus.GREEN,
        TLSValidationSeverity.WARNING: ProbeStatus.YELLOW,
        TLSValidationSeverity.ERROR: ProbeStatus.RED,
    }
    status = status_map[report.status]
    impact = (
        DoctorImpact.OK
        if report.status is not TLSValidationSeverity.ERROR
        else DoctorImpact.PROVIDER
    )
    message = "System TLS assets validated successfully."
    if report.status is TLSValidationSeverity.WARNING:
        message = "System TLS assets validated with warnings."
    elif report.status is TLSValidationSeverity.ERROR:
        message = "System TLS assets failed validation."

    data = report.to_dict()
    findings = ", ".join(
        f"{finding.scope}:{finding.check}:{finding.severity.value}"
        for finding in report.findings
    )
    warnings: tuple[str, ...] = ()
    if report.status is TLSValidationSeverity.WARNING:
        warnings = ("tls:warning",)

    return ProbeResult(
        id="tls-system-cert",
        category="tls",
        status=status,
        impact=impact,
        message=message,
        data={
            "not_valid_after": data.get("not_valid_after"),
            "findings": data.get("findings"),
            "summary": findings,
        },
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Application probes
# ---------------------------------------------------------------------------


def _app_probes() -> Sequence[ProbeDefinition]:
    return (
        _make_probe("app-instance-status", "app", _probe_app_instance_status),
    )


def _probe_app_instance_status(context: ProbeContext) -> ProbeResult:
    provider = context.instance_status_provider
    entries = _iter_instance_entries(context)
    states: dict[str, str] = {}
    warnings: dict[str, str] = {}
    failures: dict[str, str] = {}
    good_states = {"running", "active", "enabled"}
    failure_states = {"failed", "error", "inactive", "degraded"}

    for entry in entries:
        name_raw = entry.get("name")
        if not isinstance(name_raw, str):
            continue
        name = name_raw.strip()
        if not name:
            continue
        status = provider.status(name, entry)
        state_lower = status.state.lower()
        states[name] = state_lower
        detail = status.detail
        if state_lower in failure_states:
            failures[name] = detail
        elif state_lower not in good_states:
            warnings[name] = detail

    if failures:
        return ProbeResult(
            id="app-instance-status",
            category="app",
            status=ProbeStatus.RED,
            impact=DoctorImpact.PROVIDER,
            message="One or more instances report failure state.",
            data={"states": states, "failures": failures},
        )

    if warnings:
        return ProbeResult(
            id="app-instance-status",
            category="app",
            status=ProbeStatus.YELLOW,
            impact=DoctorImpact.OK,
            message="Instance status unavailable or degraded.",
            data={"states": states, "warnings": warnings},
            warnings=("app:status",),
        )

    return ProbeResult(
        id="app-instance-status",
        category="app",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message="Instances report healthy states.",
        data={"states": states},
    )


# ---------------------------------------------------------------------------
# Disk probes
# ---------------------------------------------------------------------------


def _disk_probes() -> Sequence[ProbeDefinition]:
    return (
        _make_probe("disk-usage", "disk", _probe_disk_usage),
    )


def _probe_disk_usage(context: ProbeContext) -> ProbeResult:
    path = context.config.state_dir
    try:
        usage = shutil.disk_usage(path)
    except FileNotFoundError:
        return ProbeResult(
            id="disk-usage",
            category="disk",
            status=ProbeStatus.RED,
            impact=DoctorImpact.VALIDATION,
            message=f"State directory {path} does not exist; cannot determine disk usage.",
        )

    total = usage.total or 1
    free = usage.free
    percent_free = (free / total) * 100

    data = {
        "total_bytes": total,
        "free_bytes": free,
        "percent_free": round(percent_free, 2),
        "path": str(path),
    }

    if percent_free < 5:
        return ProbeResult(
            id="disk-usage",
            category="disk",
            status=ProbeStatus.RED,
            impact=DoctorImpact.PROVIDER,
            message="Disk free space below 5%.",
            data=data,
        )
    if percent_free < 10:
        return ProbeResult(
            id="disk-usage",
            category="disk",
            status=ProbeStatus.YELLOW,
            impact=DoctorImpact.OK,
            message="Disk free space below 10%.",
            data=data,
            warnings=("disk:low-free",),
        )
    return ProbeResult(
        id="disk-usage",
        category="disk",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message="Disk free space within acceptable limits.",
        data=data,
    )
