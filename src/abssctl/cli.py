"""Typer-powered command line scaffold for ``abssctl``.

The Pre-Alpha milestone focuses on wiring foundational structure so later
phases can layer in real functionality without reworking entry points. Each
subcommand currently emits a friendly placeholder message and exits with a
success code to keep automated smoke tests green.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import textwrap
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn, cast

import typer
from packaging.version import InvalidVersion, Version
from rich.console import Console
from rich.table import Table

from . import __version__
from .backups import (
    BackupEntryBuilder,
    BackupError,
    BackupRegistryError,
    BackupsRegistry,
    copy_into,
)
from .config import ALLOWED_BACKUP_COMPRESSION, AppConfig, TLSPermissionSpec, load_config
from .doctor import (
    PROBE_CATEGORY_VALUES,
    DoctorEngine,
    DoctorImpact,
    DoctorReport,
    ProbeExecutorOptions,
    ProbeResult,
    ProbeStatus,
    collect_probes,
    create_probe_context,
)
from .locking import LockManager
from .logging import OperationScope, StructuredLogger
from .ports import PortsRegistry, PortsRegistryError
from .providers import (
    InstanceStatusProvider,
    NginxError,
    NginxProvider,
    SystemdError,
    SystemdProvider,
    VersionInstaller,
    VersionInstallError,
    VersionInstallResult,
    VersionProvider,
)
from .state import StateRegistry, StateRegistryError
from .templates import TemplateEngine
from .tls import (
    TLSConfigurationError,
    TLSInspector,
    TLSSourceSelection,
    TLSValidationReport,
    TLSValidationSeverity,
    TLSValidator,
)

console = Console()

CONFIG_FILE_OPTION = typer.Option(
    None,
    "--config-file",
    dir_okay=False,
    help="Override the path to abssctl's YAML config file.",
)

BACKUP_OUT_DIR_OPTION = typer.Option(
    None,
    "--out-dir",
    help="Override the backup root directory for this invocation.",
    dir_okay=True,
    file_okay=False,
    writable=True,
)

NO_PRE_BACKUP_OPTION = typer.Option(
    False,
    "--no-pre-backup",
    help="Skip the safety prompt to take a fresh backup before restoring.",
)

RESTORE_DEST_OPTION = typer.Option(
    None,
    "--dest",
    help="Restore into this directory instead of the instance data path.",
    dir_okay=True,
    file_okay=False,
)

DATA_DIR_OPTION = typer.Option(
    None,
    "--data-dir",
    dir_okay=True,
    file_okay=False,
    help="Custom data directory for Actual (defaults to /srv/<name>/data).",
)

NO_START_OPTION = typer.Option(
    False,
    "--no-start",
    help="Provision without starting the systemd service.",
)

TLS_VERIFY_INSTANCE_OPTION = typer.Option(
    None,
    "--instance",
    help="Instance name to verify (omit to supply --cert/--key manually).",
)
TLS_VERIFY_CERT_OPTION = typer.Option(
    None,
    "--cert",
    help="Path to the certificate (PEM). Required when --instance is omitted.",
)
TLS_VERIFY_KEY_OPTION = typer.Option(
    None,
    "--key",
    help="Path to the private key (PEM). Required when --instance is omitted.",
)
TLS_VERIFY_CHAIN_OPTION = typer.Option(
    None,
    "--chain",
    help="Optional chain bundle to verify.",
)
TLS_SOURCE_OPTION = typer.Option(
    "auto",
    "--source",
    help="TLS source to inspect (auto|system|custom|lets-encrypt).",
)
TLS_JSON_OPTION = typer.Option(
    False,
    "--json",
    help="Emit the validation report as JSON.",
)

TLS_INSTALL_CERT_OPTION = typer.Option(
    ...,
    "--cert",
    help="Source certificate (PEM).",
)
TLS_INSTALL_KEY_OPTION = typer.Option(
    ...,
    "--key",
    help="Source private key (PEM).",
)
TLS_INSTALL_CHAIN_OPTION = typer.Option(
    None,
    "--chain",
    help="Optional chain bundle (PEM).",
)

_PROBE_CATEGORY_NAMES = ", ".join(PROBE_CATEGORY_VALUES)

DOCTOR_JSON_OPTION = typer.Option(
    False,
    "--json",
    help="Emit a JSON doctor report.",
)
DOCTOR_ONLY_OPTION = typer.Option(
    None,
    "--only",
    metavar="CATEGORY[,CATEGORY...]",
    help=f"Comma-separated probe categories to include ({_PROBE_CATEGORY_NAMES}).",
)
DOCTOR_EXCLUDE_OPTION = typer.Option(
    None,
    "--exclude",
    metavar="CATEGORY[,CATEGORY...]",
    help=f"Comma-separated probe categories to exclude ({_PROBE_CATEGORY_NAMES}).",
)
DOCTOR_TIMEOUT_MS_OPTION = typer.Option(
    None,
    "--timeout-ms",
    min=0,
    help="Override probe timeout in milliseconds (applies to exec and request probes).",
)
DOCTOR_RETRIES_OPTION = typer.Option(
    None,
    "--retries",
    min=0,
    help="Override retry count for service probes.",
)
DOCTOR_MAX_CONCURRENCY_OPTION = typer.Option(
    None,
    "--max-concurrency",
    min=1,
    help="Limit the number of probes executed concurrently.",
)
DOCTOR_FIX_OPTION = typer.Option(
    False,
    "--fix",
    help="Attempt safe remediations (not yet implemented).",
)

_PROBE_CATEGORY_SET = frozenset(PROBE_CATEGORY_VALUES)
_PROBE_STATUS_STYLE = {
    ProbeStatus.GREEN: "[green]PASS[/green]",
    ProbeStatus.YELLOW: "[yellow]WARN[/yellow]",
    ProbeStatus.RED: "[red]FAIL[/red]",
}
_SUMMARY_STATUS_STYLE = {
    ProbeStatus.GREEN: "[green]GREEN[/green]",
    ProbeStatus.YELLOW: "[yellow]WARN[/yellow]",
    ProbeStatus.RED: "[red]RED[/red]",
}
_DOCTOR_IMPACT_MESSAGES = {
    DoctorImpact.OK: "Doctor run completed successfully.",
    DoctorImpact.VALIDATION: "Doctor detected configuration validation errors.",
    DoctorImpact.ENVIRONMENT: "Doctor detected environment dependency errors.",
    DoctorImpact.PROVIDER: "Doctor detected provider/service failures.",
}


def _parse_probe_categories(raw: str | None) -> set[str]:
    """Parse comma-separated probe categories into a normalised set."""
    if raw is None:
        return set()
    values = {part.strip().lower() for part in raw.split(",") if part.strip()}
    return values


def _sanitize_doctor_payload(value: object) -> object:
    """Sanitise doctor payload values for JSON/log contexts."""
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _sanitize_doctor_payload(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_sanitize_doctor_payload(item) for item in value]
    return str(value)


def _serialize_doctor_report(report: DoctorReport) -> dict[str, object]:
    """Convert a doctor report into a JSON-serialisable mapping."""
    totals = {
        status.value: int(report.summary.totals.get(status, 0))
        for status in ProbeStatus
    }
    summary_payload = {
        "status": report.summary.status.value,
        "impact": report.summary.impact.name.lower(),
        "impact_code": report.summary.impact.value,
        "exit_code": report.summary.exit_code,
        "totals": totals,
    }
    results_payload: list[dict[str, object]] = []
    for result in report.results:
        result_payload: dict[str, object] = {
            "id": result.id,
            "category": result.category,
            "status": result.status.value,
            "impact": result.impact.name.lower(),
            "impact_code": result.impact.value,
            "message": result.message,
        }
        if result.remediation:
            result_payload["remediation"] = result.remediation
        if result.duration_ms is not None:
            result_payload["duration_ms"] = result.duration_ms
        if result.data:
            result_payload["data"] = _sanitize_doctor_payload(result.data)
        if result.warnings:
            result_payload["warnings"] = list(result.warnings)
        results_payload.append(result_payload)

    metadata_payload = (
        _sanitize_doctor_payload(report.metadata) if report.metadata else {}
    )
    return {
        "summary": summary_payload,
        "results": results_payload,
        "metadata": metadata_payload,
    }


def _collect_status_identifiers(
    results: Sequence[ProbeResult],
    status: ProbeStatus,
) -> list[str]:
    """Return identifiers for results matching a particular status."""
    return [
        f"{result.category}:{result.id}"
        for result in results
        if result.status is status
    ]


def _render_doctor_report(report: DoctorReport) -> None:
    """Render a doctor report in a human-friendly format."""
    summary = report.summary
    summary_style = _SUMMARY_STATUS_STYLE[summary.status]
    totals = summary.totals
    totals_line = (
        f"green={totals.get(ProbeStatus.GREEN, 0)} "
        f"warn={totals.get(ProbeStatus.YELLOW, 0)} "
        f"red={totals.get(ProbeStatus.RED, 0)}"
    )
    impact_label = summary.impact.name.lower()
    console.print(
        f"Doctor summary: {summary_style} "
        f"(impact={impact_label}, exit={summary.exit_code})"
    )
    console.print(f"Totals: {totals_line}")
    if not report.results:
        console.print("No probes were executed.")
        return

    console.print()
    for result in report.results:
        status_label = _PROBE_STATUS_STYLE[result.status]
        console.print(
            f"{status_label} [{result.category}] {result.id}: {result.message}"
        )
        if result.remediation:
            console.print(f"  remediation: {result.remediation}")
        if result.warnings:
            console.print(f"  notes: {', '.join(result.warnings)}")
        if result.impact is not DoctorImpact.OK:
            console.print(
                f"  impact: {result.impact.name.lower()} (exit={result.impact.value})"
            )
        if result.duration_ms is not None:
            console.print(f"  duration: {result.duration_ms} ms")

app = typer.Typer(
    add_completion=False,
    help=textwrap.dedent(
        """
        Actual Budget Multi-Instance Sync Server Admin CLI.

        This Pre-Alpha build ships with structural scaffolding only. Subcommands
        communicate planned responsibilities and will be fully implemented
        during the Alpha and Beta phases once the underlying APIs are ready.
        """
    ).strip(),
)


@dataclass
class RuntimeContext:
    """Aggregated runtime objects shared by commands."""

    config: AppConfig
    registry: StateRegistry
    ports: PortsRegistry
    version_provider: VersionProvider
    version_installer: VersionInstaller
    instance_status_provider: InstanceStatusProvider
    locks: LockManager
    logger: StructuredLogger
    templates: TemplateEngine
    systemd_provider: SystemdProvider
    nginx_provider: NginxProvider
    backups: BackupsRegistry
    tls_inspector: TLSInspector
    tls_validator: TLSValidator


@dataclass(slots=True)
class InstancePaths:
    """Filesystem paths associated with an instance."""

    root: Path
    data: Path
    config_file: Path
    runtime: Path
    logs: Path
    state: Path


def _instance_paths_from_entry(
    config: AppConfig,
    name: str,
    entry: Mapping[str, object] | None,
) -> InstancePaths:
    """Derive instance paths from the registry entry with sensible fallbacks."""
    paths_raw = entry.get("paths") if isinstance(entry, Mapping) else None
    root = _coerce_path(paths_raw, "root") if isinstance(paths_raw, Mapping) else None
    data_dir = _coerce_path(paths_raw, "data") if isinstance(paths_raw, Mapping) else None
    config_path = _coerce_path(paths_raw, "config") if isinstance(paths_raw, Mapping) else None
    runtime_dir = _coerce_path(paths_raw, "runtime") if isinstance(paths_raw, Mapping) else None
    logs_dir = _coerce_path(paths_raw, "logs") if isinstance(paths_raw, Mapping) else None
    state_dir = _coerce_path(paths_raw, "state") if isinstance(paths_raw, Mapping) else None

    root = root or (config.instance_root / name)
    data_dir = data_dir or (root / "data")
    config_path = config_path or (root / "config.json")
    runtime_dir = runtime_dir or (config.runtime_dir / "instances" / name)
    logs_dir = logs_dir or (config.logs_dir / name)
    state_dir = state_dir or (config.state_dir / "instances" / name)
    return InstancePaths(
        root=root,
        data=data_dir,
        config_file=config_path,
        runtime=runtime_dir,
        logs=logs_dir,
        state=state_dir,
    )


def _coerce_path(value: Mapping[str, object], key: str) -> Path | None:
    raw = value.get(key)
    if raw is None:
        return None
    return Path(str(raw)).expanduser()


def _coerce_port(value: object, default: int) -> int:
    """Return an integer port from arbitrary registry/config values."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        candidate = value.strip()
        if candidate:
            try:
                return int(candidate)
            except ValueError:
                return default
    return default


def _collect_provider_diagnostics(
    runtime: RuntimeContext,
    name: str,
    paths: InstancePaths,
) -> dict[str, object]:
    """Return structured diagnostics for systemd and nginx providers."""
    systemd_unit = runtime.systemd_provider.unit_path(name)
    systemd_diag: dict[str, object] = {
        "unit_path": str(systemd_unit),
        "unit_exists": systemd_unit.exists(),
        "logs_dir": str(paths.logs),
        "state_dir": str(paths.state),
    }
    nginx_raw = runtime.nginx_provider.diagnostics(name)
    nginx_diag = {
        key: (str(value) if isinstance(value, Path) else value)
        for key, value in nginx_raw.items()
    }
    return {
        "systemd": systemd_diag,
        "nginx": nginx_diag,
    }


def _record_instance_state(
    runtime: RuntimeContext,
    name: str,
    *,
    status: str | None = None,
    paths: InstancePaths | None = None,
    port: int | None = None,
    domain: str | None = None,
    version: str | None = None,
    systemd_enabled: bool | None = None,
    systemd_state: str | None = None,
    nginx_enabled: bool | None = None,
    metadata: Mapping[str, object] | None = None,
    update_last_changed: bool = True,
) -> None:
    """Persist instance metadata/diagnostics back to the registry."""
    entry = runtime.registry.get_instance(name)
    if entry is None:
        return

    now = datetime.now(UTC).isoformat()
    if paths is None:
        paths = _instance_paths_from_entry(runtime.config, name, entry)

    diagnostics = _collect_provider_diagnostics(runtime, name, paths)
    systemd_entry = diagnostics.get("systemd")
    systemd_diag: dict[str, object]
    if isinstance(systemd_entry, dict):
        systemd_diag = dict(systemd_entry)
    else:
        systemd_diag = {}
    diagnostics["systemd"] = systemd_diag
    if systemd_enabled is not None:
        systemd_diag["enabled"] = systemd_enabled
    if systemd_state is not None:
        systemd_diag["state"] = systemd_state
    systemd_diag["last_checked"] = now

    nginx_entry = diagnostics.get("nginx")
    nginx_diag: dict[str, object]
    if isinstance(nginx_entry, dict):
        nginx_diag = dict(nginx_entry)
    else:
        nginx_diag = {}
    diagnostics["nginx"] = nginx_diag
    if nginx_enabled is not None:
        nginx_diag["enabled"] = nginx_enabled
    nginx_diag["last_checked"] = now

    metadata_updates: dict[str, object] = {
        "diagnostics": diagnostics,
        "domain": domain if domain is not None else entry.get("domain"),
        "port": port if port is not None else entry.get("port"),
        "last_checked_at": now,
    }
    if metadata:
        for key, value in metadata.items():
            if value is not None:
                metadata_updates[key] = value

    existing_metadata = entry.get("metadata")
    if isinstance(existing_metadata, Mapping):
        created_at = existing_metadata.get("created_at")
        if created_at:
            metadata_updates.setdefault("created_at", created_at)
        auto_start = existing_metadata.get("auto_start")
        if auto_start is not None:
            metadata_updates.setdefault("auto_start", auto_start)

        previous_port = entry.get("port")
        if port is not None and previous_port not in (None, port):
            history = (
                list(existing_metadata.get("port_history", []))
                if isinstance(existing_metadata.get("port_history"), list)
                else []
            )
            history.append({"port": previous_port, "changed_at": now})
            metadata_updates["port_history"] = history
        elif isinstance(existing_metadata.get("port_history"), list):
            metadata_updates.setdefault("port_history", existing_metadata["port_history"])

        previous_domain = entry.get("domain")
        if domain and previous_domain and domain != previous_domain:
            domain_history = (
                list(existing_metadata.get("domain_history", []))
                if isinstance(existing_metadata.get("domain_history"), list)
                else []
            )
            domain_history.append({"domain": previous_domain, "changed_at": now})
            metadata_updates["domain_history"] = domain_history
        elif isinstance(existing_metadata.get("domain_history"), list):
            metadata_updates.setdefault(
                "domain_history",
                existing_metadata["domain_history"],
            )

    if update_last_changed:
        metadata_updates.setdefault("last_changed", now)

    updates: dict[str, object] = {}
    if status is not None:
        updates["status"] = status
    if domain is not None:
        updates["domain"] = domain
    if port is not None:
        updates["port"] = port
    if version is not None:
        updates["version"] = version
    updates["paths"] = {
        "root": str(paths.root),
        "data": str(paths.data),
        "config": str(paths.config_file),
        "runtime": str(paths.runtime),
        "logs": str(paths.logs),
        "state": str(paths.state),
        "systemd_unit": str(runtime.systemd_provider.unit_path(name)),
        "nginx_site": str(runtime.nginx_provider.site_path(name)),
        "nginx_enabled": str(runtime.nginx_provider.enabled_path(name)),
    }

    _update_instance_registry(runtime, name, updates, metadata=metadata_updates)


def _ensure_runtime(
    ctx: typer.Context,
    config_file: Path | None,
    lock_timeout_override: float | None = None,
) -> RuntimeContext:
    runtime = ctx.obj
    if isinstance(runtime, RuntimeContext):
        return runtime

    overrides: dict[str, object] = {}
    if lock_timeout_override is not None:
        overrides["lock_timeout"] = lock_timeout_override

    config = load_config(config_file=config_file, overrides=overrides)
    registry = StateRegistry(config.registry_dir)
    registry.ensure_root()
    version_cache = registry.root / "remote-versions.json"
    version_provider = VersionProvider(cache_path=version_cache)
    instance_status_provider = InstanceStatusProvider()
    locks = LockManager(config.runtime_dir, config.lock_timeout)
    logger = StructuredLogger(config.logs_dir)
    templates = TemplateEngine.with_overrides(config.templates_dir)
    systemd_config = config.systemd
    systemd_unit_dir = systemd_config.unit_dir or (config.runtime_dir / "systemd")
    ports_registry = PortsRegistry(
        registry=registry,
        base_port=config.ports.base,
        strategy=config.ports.strategy,
    )
    installer = VersionInstaller(
        install_root=config.install_root,
        package_name=config.npm_package_name,
    )
    systemd_provider = SystemdProvider(
        templates=templates,
        logger=logger,
        locks=locks,
        systemd_dir=systemd_unit_dir,
        systemctl_bin=systemd_config.systemctl_bin,
        journalctl_bin=systemd_config.journalctl_bin,
    )
    nginx_provider = NginxProvider(
        templates=templates,
        sites_available=config.runtime_dir / "nginx" / "sites-available",
        sites_enabled=config.runtime_dir / "nginx" / "sites-enabled",
    )
    backups_registry = BackupsRegistry(config.backups.root, config.backups.index)
    backups_registry.ensure_root()
    tls_inspector = TLSInspector(config)
    tls_validator = TLSValidator(config.tls.validation)
    runtime = RuntimeContext(
        config=config,
        registry=registry,
        ports=ports_registry,
        version_provider=version_provider,
        version_installer=installer,
        instance_status_provider=instance_status_provider,
        locks=locks,
        logger=logger,
        templates=templates,
        systemd_provider=systemd_provider,
        nginx_provider=nginx_provider,
        backups=backups_registry,
        tls_inspector=tls_inspector,
        tls_validator=tls_validator,
    )
    ctx.obj = runtime
    return runtime


def _get_runtime(ctx: typer.Context) -> RuntimeContext:
    runtime = ctx.obj
    if isinstance(runtime, RuntimeContext):
        return runtime
    return _ensure_runtime(ctx, None, None)


@app.callback(invoke_without_command=True)
def _root(  # noqa: D401 - Typer displays help for us, docstring optional.
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show the abssctl version and exit.",
    ),
    config_file: Path | None = CONFIG_FILE_OPTION,
    lock_timeout: float | None = typer.Option(
        None,
        "--lock-timeout",
        help="Override lock acquisition timeout in seconds.",
    ),
) -> None:
    """Entry point callback invoked for every CLI execution."""
    if version:
        runtime = _ensure_runtime(ctx, config_file, lock_timeout)
        with runtime.logger.operation(
            "root --version",
            args={"version": True},
            target={"kind": "meta", "scope": "version"},
        ) as op:
            console.print(f"abssctl {__version__}")
            op.success("Reported CLI version.", changed=0)
        raise typer.Exit(code=0)

    _ensure_runtime(ctx, config_file, lock_timeout)

    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit(code=0)


def _placeholder(message: str) -> None:
    console.print(f"[bold yellow]Pre-Alpha placeholder:[/bold yellow] {message}")


def _normalize_versions(raw_entries: object) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    if not isinstance(raw_entries, list):
        return normalized

    for entry in raw_entries:
        if isinstance(entry, str):
            normalized.append(
                {
                    "version": entry,
                    "metadata": {"installed": True, "source": "registry"},
                }
            )
        elif isinstance(entry, Mapping):
            version = str(entry.get("version", ""))
            metadata: dict[str, Any] = {}
            raw_metadata = entry.get("metadata")
            if isinstance(raw_metadata, Mapping):
                metadata.update(raw_metadata)
            elif raw_metadata is not None:
                metadata["metadata"] = raw_metadata

            for key, value in entry.items():
                if key in {"version", "metadata", "integrity"}:
                    continue
                metadata[key] = value

            metadata.setdefault("installed", True)
            metadata.setdefault("source", "registry")

            normalized_entry: dict[str, Any] = {"version": version, "metadata": metadata}
            integrity = entry.get("integrity")
            if isinstance(integrity, Mapping):
                normalized_entry["integrity"] = dict(integrity)
            normalized.append(normalized_entry)
    return normalized


def _normalize_instances(raw_entries: object) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    if not isinstance(raw_entries, list):
        return normalized

    for entry in raw_entries:
        if isinstance(entry, str):
            normalized.append(
                {
                    "name": entry,
                    "version": "",
                    "domain": "",
                    "port": "",
                    "status": "unknown",
                    "path": "",
                    "notes": "",
                    "metadata": {"source": "registry"},
                }
            )
            continue

        if isinstance(entry, Mapping):
            name = str(entry.get("name", ""))
            version = entry.get("version") or entry.get("version_binding") or ""
            domain = entry.get("domain") or entry.get("fqdn") or ""
            port = entry.get("port", "")
            status = entry.get("status")
            if status is None and "enabled" in entry:
                status = "enabled" if entry.get("enabled") else "disabled"
            path = entry.get("path") or entry.get("data_dir") or ""
            notes = entry.get("notes", "")
            excluded_keys = {
                "name",
                "version",
                "version_binding",
                "domain",
                "fqdn",
                "port",
                "status",
                "enabled",
                "path",
                "data_dir",
                "notes",
            }
            metadata = {k: v for k, v in entry.items() if k not in excluded_keys}
            metadata.setdefault("source", "registry")
            derived_status = status or "unknown"
            normalized.append(
                {
                    "name": name,
                    "version": version,
                    "domain": domain,
                    "port": port,
                    "status": derived_status,
                    "path": path,
                    "notes": notes,
                    "metadata": metadata,
                }
            )

    return normalized


def _merge_versions(
    local_entries: list[dict[str, Any]],
    remote_versions: list[str],
) -> list[dict[str, Any]]:
    seen: set[str] = set()
    combined: list[dict[str, Any]] = []

    local_map = {entry["version"]: entry for entry in local_entries if entry["version"]}

    for version in remote_versions:
        seen.add(version)
        entry = local_map.get(version)
        if entry:
            entry = {
                "version": version,
                "metadata": {
                    **entry.get("metadata", {}),
                    "installed": True,
                    "source": entry.get("metadata", {}).get("source", "registry"),
                },
            }
        else:
            entry = {
                "version": version,
                "metadata": {"installed": False, "source": "npm"},
            }
        combined.append(entry)

    for version, entry in local_map.items():
        if version in seen:
            continue
        metadata = entry.get("metadata", {}).copy()
        metadata.setdefault("installed", True)
        metadata.setdefault("source", "registry")
        combined.append({"version": version, "metadata": metadata})

    if not remote_versions:
        return local_entries

    combined.sort(key=lambda item: item["version"], reverse=True)
    return combined


def _build_systemd_context(
    config: AppConfig,
    instance: str,
    *,
    port: int,
    domain: str,
    paths: InstancePaths,
    exec_path: Path,
    version: str,
) -> dict[str, object]:
    environment = [
        "NODE_ENV=production",
        f"ABSSCTL_INSTANCE={instance}",
        f"ABSSCTL_DOMAIN={domain}",
        f"PORT={port}",
        f"ABSSCTL_RUNTIME_DIR={config.runtime_dir}",
        f"ABSSCTL_STATE_DIR={config.state_dir}",
        f"ABSSCTL_LOGS_DIR={config.logs_dir}",
        f"ABSSCTL_INSTALL_ROOT={config.install_root}",
        f"ABSSCTL_INSTANCE_ROOT={config.instance_root}",
        f"ABSSCTL_CONFIG_FILE={config.config_file}",
        f"ABSSCTL_DATA_DIR={paths.data}",
        f"ABSSCTL_VERSION={version}",
    ]
    return {
        "instance_name": instance,
        "service_user": config.service_user,
        "working_directory": str(paths.root),
        "exec_start": str(exec_path),
        "environment": environment,
    }


def _format_systemd_detail(result: subprocess.CompletedProcess[str], *, dry_run: bool) -> str:
    """Format a human-readable detail string for systemd commands."""
    args = result.args
    if isinstance(args, (list, tuple)):
        command = " ".join(str(item) for item in args)
    else:
        command = str(args)
    return f"command={command} dry_run={dry_run} rc={result.returncode}"


def _format_nginx_detail(result: subprocess.CompletedProcess[str]) -> str:
    args = result.args
    if isinstance(args, (list, tuple)):
        command = " ".join(str(item) for item in args)
    else:
        command = str(args)
    stdout = (getattr(result, "stdout", "") or "").strip()
    stderr = (getattr(result, "stderr", "") or "").strip()
    detail = f"command={command} rc={result.returncode}"
    if stdout:
        detail += f" stdout={stdout}"
    if stderr:
        detail += f" stderr={stderr}"
    return detail


def _format_tls_status(severity: TLSValidationSeverity) -> str:
    if severity is TLSValidationSeverity.OK:
        return "[green]OK[/green]"
    if severity is TLSValidationSeverity.WARNING:
        return "[yellow]WARN[/yellow]"
    return "[red]ERROR[/red]"


def _command_error(
    op: OperationScope,
    message: str,
    *,
    rc: int = 2,
    errors: Sequence[str] | None = None,
) -> NoReturn:
    """Emit a structured error and terminate the command."""
    console.print(f"[red]{message}[/red]")
    op.error(message, errors=list(errors or [message]), rc=rc)
    raise typer.Exit(code=rc)


def _dry_run_complete(
    op: OperationScope,
    summary: str,
    *,
    context: Mapping[str, object] | None = None,
) -> None:
    """Standardise dry-run completion messaging."""
    console.print(f"[yellow]Dry run[/yellow]: {summary}")
    op.success("Dry run complete.", changed=0, context=dict(context or {}))


def _render_tls_report(report: TLSValidationReport, *, json_output: bool) -> None:
    if json_output:
        console.print(json.dumps(report.to_dict(), indent=2))
        return

    header = (
        f"TLS validation (requested={report.selection.requested}, "
        f"resolved={report.selection.resolved})"
    )
    console.print(f"[bold]{header}[/bold]")

    status_table = Table("Scope", "Check", "Status", "Details")
    for finding in report.findings:
        status_table.add_row(
            finding.scope,
            finding.check,
            _format_tls_status(finding.severity),
            finding.message,
        )
    console.print(status_table)

    material = report.selection.material
    console.print(
        f"Certificate: {material.certificate}\n"
        f"Key: {material.key}"
        + (
            f"\nChain: {material.chain}"
            if material.chain is not None
            else ""
        )
    )
    if report.not_valid_before is not None:
        console.print(f"Not valid before: {report.not_valid_before.isoformat()}")
    if report.not_valid_after is not None:
        console.print(f"Not valid after: {report.not_valid_after.isoformat()}")


def _build_tls_context(
    runtime: RuntimeContext,
    instance: str,
    *,
    domain: str,
    entry: Mapping[str, object] | None = None,
    selection: TLSSourceSelection | None = None,
) -> dict[str, object]:
    """Return the nginx TLS context for *instance* using resolved material."""
    config = runtime.config
    tls_config = config.tls
    entry_data = dict(entry or runtime.registry.get_instance(instance) or {})

    if not tls_config.enabled:
        certificate = selection.material.certificate if selection else tls_config.system.cert
        key = selection.material.key if selection else tls_config.system.key
        chain = selection.material.chain if selection else None
        return {
            "enabled": False,
            "mode": "disabled",
            "domain": domain,
            "source": "disabled",
            "requested": selection.requested if selection else "disabled",
            "certificate": str(certificate),
            "certificate_key": str(key),
            "certificate_chain": str(chain) if chain else None,
            "system": {
                "cert": str(tls_config.system.cert),
                "key": str(tls_config.system.key),
            },
            "lets_encrypt": {
                "live_dir": str(tls_config.lets_encrypt.live_dir),
            },
        }

    resolved = selection or runtime.tls_inspector.resolve_for_instance(instance, entry_data)
    material = resolved.material
    chain = material.chain
    return {
        "enabled": True,
        "mode": resolved.resolved,
        "source": resolved.resolved,
        "requested": resolved.requested,
        "domain": domain,
        "certificate": str(material.certificate),
        "certificate_key": str(material.key),
        "certificate_chain": str(chain) if chain else None,
        "system": {
            "cert": str(tls_config.system.cert),
            "key": str(tls_config.system.key),
        },
        "lets_encrypt": {
            "live_dir": str(tls_config.lets_encrypt.live_dir),
        },
    }


def _build_nginx_context(
    runtime: RuntimeContext,
    instance: str,
    *,
    domain: str,
    port: int,
    entry: Mapping[str, object] | None = None,
    selection: TLSSourceSelection | None = None,
) -> dict[str, object]:
    """Return render context for nginx including TLS selection."""
    config = runtime.config
    log_prefix = config.logs_dir / instance
    tls_context = _build_tls_context(
        runtime,
        instance,
        domain=domain,
        entry=entry,
        selection=selection,
    )
    return {
        "http_listen_port": 80,
        "https_listen_port": 443,
        "upstream_host": "127.0.0.1",
        "upstream_port": port,
        "server_name": domain,
        "access_log": str(log_prefix.with_suffix(".nginx.access.log")),
        "error_log": str(log_prefix.with_suffix(".nginx.error.log")),
        "upstream_url": f"127.0.0.1:{port}",
        "tls": tls_context,
    }


def _validate_instance_name(name: str) -> str:
    """Validate and normalise an instance name."""
    normalised = name.strip()
    if not normalised:
        raise ValueError("Instance name must be a non-empty string.")
    if not re.fullmatch(r"[a-z0-9-]+", normalised):
        raise ValueError("Instance name must match [a-z0-9-]+.")
    return normalised


def _validate_domain(value: str) -> str:
    """Validate and normalise a domain/FQDN."""
    normalised = value.strip().lower()
    if not normalised:
        raise ValueError("Domain must be a non-empty string.")
    if len(normalised) > 255:
        raise ValueError("Domain must be 255 characters or fewer.")
    if normalised.startswith("-") or normalised.endswith("-"):
        raise ValueError("Domain cannot start or end with a hyphen.")
    if not re.fullmatch(r"[a-z0-9.-]+", normalised):
        raise ValueError("Domain may contain letters, numbers, dots, and hyphens.")
    return normalised


def _determine_instance_paths(
    config: AppConfig,
    name: str,
    data_dir_override: Path | None,
) -> InstancePaths:
    """Return the filesystem paths required for an instance."""
    root = config.instance_root / name
    data_dir = Path(data_dir_override).expanduser() if data_dir_override else (root / "data")
    config_file = data_dir / "config.json"
    runtime_dir = config.runtime_dir / "instances" / name
    logs_dir = config.logs_dir / name
    state_dir = config.state_dir / "instances" / name
    return InstancePaths(
        root=root,
        data=data_dir,
        config_file=config_file,
        runtime=runtime_dir,
        logs=logs_dir,
        state=state_dir,
    )


def _build_instance_config(
    *,
    name: str,
    domain: str,
    port: int,
    version: str,
    paths: InstancePaths,
    created_at: datetime,
) -> dict[str, object]:
    """Construct the default config.json payload for a new instance."""
    return {
        "schema": 1,
        "instance": {
            "name": name,
            "domain": domain,
            "created_at": created_at.isoformat(),
        },
        "server": {
            "upstream": {
                "host": "127.0.0.1",
                "port": port,
            },
            "public_url": f"https://{domain}",
            "version": version,
        },
        "paths": {
            "root": str(paths.root),
            "data": str(paths.data),
            "config": str(paths.config_file),
        },
    }


def _default_instance_domain(config: AppConfig, instance: str) -> str:
    """Return the default domain for *instance* based on configuration."""
    # Placeholder logic until configurable domains land.
    return f"{instance}.local"


def _read_instance_config(paths: InstancePaths) -> dict[str, object]:
    """Return the instance config.json payload (empty mapping if missing)."""
    if not paths.config_file.exists():
        return {}
    try:
        payload = json.loads(paths.config_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse {paths.config_file}: {exc}") from exc
    return payload if isinstance(payload, dict) else {}


def _write_instance_config(paths: InstancePaths, payload: Mapping[str, object]) -> None:
    """Persist *payload* to config.json with strict permissions."""
    content = json.dumps(payload, indent=2, sort_keys=True)
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(content + "\n", encoding="utf-8")
    os.chmod(paths.config_file, 0o640)


def _update_instance_registry(
    runtime: RuntimeContext,
    name: str,
    updates: Mapping[str, object],
    *,
    metadata: Mapping[str, object] | None = None,
) -> None:
    """Update the registry entry for *name* merging metadata timestamps."""
    existing = runtime.registry.get_instance(name)
    if existing is None:
        raise StateRegistryError(f"Instance '{name}' not found in registry")
    merged_metadata = dict(existing.get("metadata", {}) if isinstance(existing, Mapping) else {})
    now = datetime.now(UTC).isoformat()
    merged_metadata.setdefault("created_at", now)
    merged_metadata["last_changed"] = now
    if metadata:
        merged_metadata.update(metadata)

    payload = dict(updates)
    if "metadata" in payload:
        inner = payload["metadata"]
        if isinstance(inner, Mapping):
            merged_metadata.update(inner)
        else:
            raise ValueError("metadata updates must be a mapping")
    payload["metadata"] = merged_metadata
    runtime.registry.update_instance(name, payload)


def _resolve_exec_path(runtime: RuntimeContext, version: str) -> Path:
    """Return the expected server.js path for *version*."""
    normalized = version.strip() or runtime.config.default_version
    if normalized == "current":
        base = runtime.config.install_root / "current"
    else:
        entry = runtime.registry.get_version(normalized)
        if entry and entry.get("path"):
            base = Path(str(entry["path"]))
        else:
            base = runtime.config.install_root / f"v{normalized}"
    return base / "server.js"


def _register_instance(
    runtime: RuntimeContext,
    entry: Mapping[str, object],
) -> None:
    name_raw = entry.get("name", "")
    name = str(name_raw).strip() if name_raw is not None else ""
    if not name:
        raise ValueError("Instance entry missing 'name'.")
    registry_data = runtime.registry.read_instances()
    raw_instances = registry_data.get("instances", [])
    if isinstance(raw_instances, list):
        existing: list[object] = list(raw_instances)
    else:
        existing = []
    for candidate in existing:
        if isinstance(candidate, Mapping) and candidate.get("name") == name:
            raise ValueError(f"Instance '{name}' already registered")

    existing.append(dict(entry))
    runtime.registry.write_instances(existing)


def _cleanup_instance_create(
    runtime: RuntimeContext,
    name: str,
    *,
    release_port: bool = False,
    paths: Sequence[Path] = (),
    remove_registry: bool = False,
) -> None:
    """Best-effort cleanup for partially provisioned instance scaffolding."""
    try:
        runtime.systemd_provider.remove(name)
    except SystemdError:
        pass
    try:
        runtime.nginx_provider.remove(name)
    except NginxError:
        pass
    if remove_registry:
        try:
            runtime.registry.remove_instance(name)
        except StateRegistryError:
            pass
    for path in paths:
        try:
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            else:
                path.unlink(missing_ok=True)
        except OSError:
            pass
    if release_port:
        try:
            runtime.ports.release(name)
        except PortsRegistryError:
            pass


def _require_instance(
    runtime: RuntimeContext,
    name: str,
    op: OperationScope,
) -> dict[str, object]:
    instance = runtime.registry.get_instance(name)
    if instance is None:
        _command_error(op, f"Instance '{name}' not found in registry.", rc=2)
    return instance


def _provider_error(op: OperationScope, message: str) -> None:
    _command_error(op, message, rc=4)




@app.command()
def doctor(
    ctx: typer.Context,
    json_output: bool = DOCTOR_JSON_OPTION,
    only: str | None = DOCTOR_ONLY_OPTION,
    exclude: str | None = DOCTOR_EXCLUDE_OPTION,
    timeout_ms: int | None = DOCTOR_TIMEOUT_MS_OPTION,
    retries: int | None = DOCTOR_RETRIES_OPTION,
    max_concurrency: int | None = DOCTOR_MAX_CONCURRENCY_OPTION,
    fix: bool = DOCTOR_FIX_OPTION,
) -> None:
    """Run environment and service health checks."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "doctor",
        args={
            "json": json_output,
            "only": only,
            "exclude": exclude,
            "timeout_ms": timeout_ms,
            "retries": retries,
            "max_concurrency": max_concurrency,
            "fix": fix,
        },
        target={"kind": "system", "scope": "health"},
    ) as op:
        include_categories = _parse_probe_categories(only)
        exclude_categories = _parse_probe_categories(exclude)

        invalid_categories = (include_categories | exclude_categories) - _PROBE_CATEGORY_SET
        if invalid_categories:
            _command_error(
                op,
                f"Unknown probe categories: {', '.join(sorted(invalid_categories))}",
                rc=2,
            )
        if only is not None and exclude is not None:
            _command_error(op, "Cannot combine --only and --exclude.", rc=2)

        timeout_seconds = (
            max(timeout_ms / 1000.0, 0.0) if timeout_ms is not None else None
        )
        if timeout_seconds is not None:
            timeout_seconds = max(timeout_seconds, 0.001)

        defaults = ProbeExecutorOptions()
        options = ProbeExecutorOptions(
            max_concurrency=(
                max_concurrency if max_concurrency is not None else defaults.max_concurrency
            ),
            exec_timeout=timeout_seconds if timeout_seconds is not None else defaults.exec_timeout,
            connect_timeout=(
                timeout_seconds if timeout_seconds is not None else defaults.connect_timeout
            ),
            request_timeout=(
                timeout_seconds if timeout_seconds is not None else defaults.request_timeout
            ),
            retries=retries if retries is not None else defaults.retries,
        )

        context = create_probe_context(runtime, options)
        discovered_probes = list(collect_probes(context))
        matched_probes = discovered_probes
        if include_categories:
            matched_probes = [
                probe
                for probe in matched_probes
                if probe.category in include_categories
            ]
        if exclude_categories:
            matched_probes = [
                probe
                for probe in matched_probes
                if probe.category not in exclude_categories
            ]

        if fix:
            op.add_step(
                "fix-mode",
                status="skipped",
                detail="--fix requested but remediation is not yet implemented.",
            )

        metadata = {
            "filters": {
                "only": sorted(include_categories) if only is not None else None,
                "exclude": sorted(exclude_categories) if exclude is not None else None,
            },
            "discovered_probes": len(discovered_probes),
            "matched_probes": len(matched_probes),
            "options": asdict(options),
            "fix": {"requested": fix, "supported": False, "applied": False},
        }

        engine = DoctorEngine(context)
        report = engine.run(matched_probes, metadata=metadata)
        report_payload = _serialize_doctor_report(report)

        if fix and not json_output:
            console.print(
                "[yellow]--fix is not implemented yet; no changes were made.[/yellow]"
            )

        if json_output:
            console.print(json.dumps(report_payload, indent=2))
        else:
            _render_doctor_report(report)
            if (
                not matched_probes
                and discovered_probes
                and (only is not None or exclude is not None)
            ):
                console.print(
                    "[yellow]No probes matched the provided filters.[/yellow]"
                )

        warning_ids = _collect_status_identifiers(report.results, ProbeStatus.YELLOW)
        error_ids = _collect_status_identifiers(report.results, ProbeStatus.RED)
        log_context = {"report": report_payload}

        summary = report.summary
        impact_message = _DOCTOR_IMPACT_MESSAGES.get(
            summary.impact, "Doctor detected issues."
        )

        if not json_output:
            if summary.exit_code == 0 and summary.status is ProbeStatus.YELLOW:
                console.print("[yellow]Doctor completed with warnings.[/yellow]")
            elif summary.exit_code != 0:
                console.print(f"[red]{impact_message}[/red]")

        if summary.exit_code == 0:
            if summary.status is ProbeStatus.YELLOW:
                op.warning(
                    "Doctor completed with warnings.",
                    warnings=warning_ids or None,
                    context=log_context,
                )
            else:
                op.success(
                    _DOCTOR_IMPACT_MESSAGES[DoctorImpact.OK],
                    context=log_context,
                )
            return

        op.error(
            impact_message,
            rc=summary.exit_code,
            errors=error_ids or None,
            warnings=warning_ids or None,
            context=log_context,
        )
        raise typer.Exit(code=summary.exit_code)


@app.command()
def support_bundle(ctx: typer.Context) -> None:
    """Create a diagnostic bundle for support cases (coming soon)."""
    runtime = _get_runtime(ctx)
    message = "Support bundle generation is planned for the Beta milestone."
    with runtime.logger.operation(
        "support-bundle",
        target={"kind": "system", "scope": "support-bundle"},
    ) as op:
        _placeholder(message)
        op.warning(
            "Support-bundle placeholder executed.",
            warnings=["unimplemented"],
        )


instances_app = typer.Typer(help="Manage Actual Budget Sync Server instances.")
ports_app = typer.Typer(help="Inspect and manage port reservations.")
versions_app = typer.Typer(help="Manage installed Sync Server versions.")
backups_app = typer.Typer(help="Create and reconcile instance backups.")
config_app = typer.Typer(help="Inspect and manage global configuration.")
tls_app = typer.Typer(help="Manage TLS certificates and validation.")

app.add_typer(instances_app, name="instance")
app.add_typer(ports_app, name="ports")
app.add_typer(versions_app, name="version")
app.add_typer(backups_app, name="backup")
app.add_typer(config_app, name="config")
app.add_typer(tls_app, name="tls")


@tls_app.command("verify")
def tls_verify(
    ctx: typer.Context,
    instance: str | None = TLS_VERIFY_INSTANCE_OPTION,
    cert: Path | None = TLS_VERIFY_CERT_OPTION,
    key: Path | None = TLS_VERIFY_KEY_OPTION,
    chain: Path | None = TLS_VERIFY_CHAIN_OPTION,
    source: str = TLS_SOURCE_OPTION,
    json_output: bool = TLS_JSON_OPTION,
) -> None:
    """Validate TLS assets for an instance or manual paths."""
    runtime = _get_runtime(ctx)
    normalized_source = (source or "auto").strip().lower()
    allowed_sources = {"auto", "system", "custom", "lets-encrypt", "manual"}
    if normalized_source not in allowed_sources:
        message = (
            f"Unsupported TLS source '{source}'. "
            "Allowed values: auto, system, custom, lets-encrypt."
        )
        console.print(f"[red]{message}[/red]")
        raise typer.Exit(code=2)

    args = {
        "instance": instance,
        "cert": str(cert) if cert else None,
        "key": str(key) if key else None,
        "chain": str(chain) if chain else None,
        "source": normalized_source,
        "json": json_output,
    }
    target = (
        {"kind": "instance", "name": instance}
        if instance
        else {"kind": "tls", "scope": "manual"}
    )

    with runtime.logger.operation("tls verify", args=args, target=target) as op:
        try:
            if instance:
                entry = _require_instance(runtime, instance, op)
                source_override = (
                    None
                    if normalized_source in {"auto", "lets-encrypt"}
                    else normalized_source
                )
                selection = runtime.tls_inspector.resolve_for_instance(
                    instance,
                    entry,
                    source_override=source_override,
                    certificate=cert,
                    key=key,
                    chain=chain,
                )
                if normalized_source == "lets-encrypt" and selection.resolved != "lets-encrypt":
                    message = (
                        "Let's Encrypt assets were not detected for the instance "
                        f"(resolved source: {selection.resolved})."
                    )
                    _command_error(op, message, rc=2)
            else:
                if cert is None or key is None:
                    message = "Provide --cert and --key when verifying without --instance."
                    _command_error(op, message, rc=2)
                selection = runtime.tls_inspector.resolve_manual(
                    certificate=cert,
                    key=key,
                    chain=chain,
                    source=normalized_source,
                )

            report = runtime.tls_validator.validate(selection)
            _render_tls_report(report, json_output=json_output)

            errors = [
                f"{finding.scope}:{finding.check} {finding.message}"
                for finding in report.findings
                if finding.severity is TLSValidationSeverity.ERROR
            ]
            warnings = [
                f"{finding.scope}:{finding.check} {finding.message}"
                for finding in report.findings
                if finding.severity is TLSValidationSeverity.WARNING
            ]
            context = {"report": report.to_dict()}
            if errors:
                op.error(
                    "TLS validation failed.",
                    errors=errors,
                    warnings=warnings,
                    rc=2,
                    context=context,
                )
                raise typer.Exit(code=2)
            if warnings:
                op.warning(
                    "TLS validation completed with warnings.",
                    warnings=warnings,
                    context=context,
                )
                return
            op.success("TLS validation successful.", context=context)
        except TLSConfigurationError as exc:
            _command_error(op, str(exc), rc=2)


@tls_app.command("install")
def tls_install(
    ctx: typer.Context,
    instance: str = typer.Argument(..., help="Instance to install TLS assets for."),
    cert: Path = TLS_INSTALL_CERT_OPTION,
    key: Path = TLS_INSTALL_KEY_OPTION,
    chain: Path | None = TLS_INSTALL_CHAIN_OPTION,
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show planned actions without copying files.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Skip confirmation prompt and proceed non-interactively.",
    ),
) -> None:
    """Install custom TLS assets for an instance."""
    runtime = _get_runtime(ctx)
    normalized_name = _validate_instance_name(instance)
    args = {
        "instance": normalized_name,
        "cert": str(cert),
        "key": str(key),
        "chain": str(chain) if chain else None,
        "dry_run": dry_run,
    }
    with runtime.logger.operation(
        "tls install",
        args=args,
        target={"kind": "instance", "name": normalized_name},
    ) as op:
        with runtime.locks.mutate_instances([normalized_name]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            _require_instance(runtime, normalized_name, op)

            selection = runtime.tls_inspector.resolve_manual(
                certificate=cert.expanduser(),
                key=key.expanduser(),
                chain=chain.expanduser() if chain else None,
                source="custom",
            )
            report = runtime.tls_validator.validate(selection)
            errors = [
                f"{finding.scope}:{finding.check} {finding.message}"
                for finding in report.findings
                if finding.severity is TLSValidationSeverity.ERROR
            ]
            if errors:
                _render_tls_report(report, json_output=False)
                op.error(
                    "TLS validation failed; aborting install.",
                    errors=errors,
                    rc=2,
                    context={"report": report.to_dict()},
                )
                raise typer.Exit(code=2)

            destination = runtime.tls_inspector.destination_for_instance(normalized_name)
            console.print(
                f"Installing TLS assets for [bold]{normalized_name}[/bold]:\n"
                f"  Source certificate: {selection.material.certificate}\n"
                f"  Source key: {selection.material.key}\n"
                + (
                    f"  Source chain: {selection.material.chain}\n"
                    if selection.material.chain is not None
                    else ""
                )
                + f"  Destination certificate: {destination.certificate}\n"
                f"  Destination key: {destination.key}"
                + (
                    f"\n  Destination chain: {destination.chain}"
                    if selection.material.chain is not None
                    else ""
                )
            )

            if dry_run:
                op.add_step("tls.copy.cert", status="skipped", detail="dry-run")
                op.add_step("tls.copy.key", status="skipped", detail="dry-run")
                if selection.material.chain is not None:
                    op.add_step("tls.copy.chain", status="skipped", detail="dry-run")
                console.print("[yellow]Dry run[/yellow]: no files were copied.")
                op.success(
                    "TLS install dry-run complete.",
                    changed=0,
                    context={"report": report.to_dict()},
                )
                return

            if not yes:
                confirmed = typer.confirm(
                    f"Proceed with installing TLS assets for '{normalized_name}'?",
                    default=True,
                )
                if not confirmed:
                    console.print("[yellow]TLS install cancelled.[/yellow]")
                    op.warning(
                        "TLS install cancelled by operator.",
                        warnings=["user-cancelled"],
                    )
                    return

            validation = runtime.config.tls.validation
            timestamp = datetime.now(UTC)
            change_count = 0
            copied_paths: list[str] = []

            def _copy_file(
                label: str,
                src: Path,
                dest: Path,
                perm: TLSPermissionSpec,
            ) -> None:
                nonlocal change_count
                dest.parent.mkdir(parents=True, exist_ok=True)
                backup_path: Path | None = None
                if dest.exists():
                    suffix = dest.suffix + f".bak-{timestamp:%Y%m%d%H%M%S}"
                    backup_path = dest.with_suffix(suffix)
                    shutil.copy2(dest, backup_path)
                    copied_paths.append(str(backup_path))
                    op.add_step(
                        f"tls.backup.{label}",
                        status="success",
                        detail=f"{dest} -> {backup_path}",
                    )
                shutil.copy2(src, dest)
                os.chmod(dest, perm.mode)
                try:
                    shutil.chown(dest, perm.owner, perm.group)
                except (LookupError, PermissionError) as exc:
                    message = f"Failed to adjust ownership for {dest}: {exc}"
                    _command_error(op, message, rc=3)
                change_count += 1
                detail = f"{src} -> {dest}"
                op.add_step(f"tls.copy.{label}", status="success", detail=detail)

            _copy_file(
                "key",
                selection.material.key,
                destination.key,
                validation.key_permissions[0],
            )
            _copy_file(
                "cert",
                selection.material.certificate,
                destination.certificate,
                validation.cert_permissions,
            )
            if selection.material.chain is not None and destination.chain is not None:
                _copy_file(
                    "chain",
                    selection.material.chain,
                    destination.chain,
                    validation.chain_permissions,
                )

            tls_payload: dict[str, object] = {
                "source": "custom",
                "cert": str(destination.certificate),
                "key": str(destination.key),
            }
            if selection.material.chain is not None and destination.chain is not None:
                tls_payload["chain"] = str(destination.chain)

            _update_instance_registry(
                runtime,
                normalized_name,
                {"tls": tls_payload},
                metadata={
                    "tls_source": "custom",
                    "tls_updated_at": timestamp.isoformat(),
                },
            )
            op.add_step("registry.update", status="success", detail="tls")

            _record_instance_state(
                runtime,
                normalized_name,
                update_last_changed=True,
                metadata={"tls_source": "custom"},
            )

            entry_after_raw = runtime.registry.get_instance(normalized_name)
            entry_for_nginx = (
                dict(entry_after_raw)
                if isinstance(entry_after_raw, Mapping)
                else {}
            )
            domain_value = str(
                entry_for_nginx.get("domain")
                or _default_instance_domain(runtime.config, normalized_name)
            )
            port_value_raw: object | None = entry_for_nginx.get("port")
            if port_value_raw in (None, "", 0):
                port_value_raw = runtime.ports.get_port(normalized_name)
            port_int = _coerce_port(port_value_raw, runtime.config.ports.base)
            entry_for_nginx["domain"] = domain_value
            entry_for_nginx["port"] = port_int
            try:
                nginx_context = _build_nginx_context(
                    runtime,
                    normalized_name,
                    domain=domain_value,
                    port=port_int,
                    entry=entry_for_nginx,
                )
            except TLSConfigurationError as exc:
                _command_error(op, str(exc), rc=2)

            nginx_result = runtime.nginx_provider.render_site(normalized_name, nginx_context)
            if nginx_result.validation_error is not None:
                _provider_error(
                    op,
                    (
                        f"nginx validation failed for '{normalized_name}': "
                        f"{nginx_result.validation_error}"
                    ),
                )
            op.add_step(
                "nginx.render_site",
                status="success" if nginx_result.changed else "noop",
                detail=str(runtime.nginx_provider.site_path(normalized_name)),
            )
            if nginx_result.validation is not None:
                op.add_step(
                    "nginx.validate",
                    status="success",
                    detail=_format_nginx_detail(nginx_result.validation),
                )
            if nginx_result.reload is not None:
                op.add_step(
                    "nginx.reload",
                    status="success",
                    detail=_format_nginx_detail(nginx_result.reload),
                )
            runtime.nginx_provider.enable(normalized_name)
            op.add_step(
                "nginx.enable",
                status="success",
                detail=str(runtime.nginx_provider.enabled_path(normalized_name)),
            )
            change_count += int(nginx_result.changed)

            op.success(
                "TLS assets installed.",
                changed=change_count,
                backups=copied_paths,
                context={"tls": tls_payload},
            )


@tls_app.command("use-system")
def tls_use_system(
    ctx: typer.Context,
    instance: str = typer.Argument(..., help="Instance to switch back to system TLS."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show the actions without updating the registry.",
    ),
) -> None:
    """Switch an instance back to the system TLS defaults."""
    runtime = _get_runtime(ctx)
    normalized_name = _validate_instance_name(instance)
    args = {"instance": normalized_name, "dry_run": dry_run}
    with runtime.logger.operation(
        "tls use-system",
        args=args,
        target={"kind": "instance", "name": normalized_name},
    ) as op:
        with runtime.locks.mutate_instances([normalized_name]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            entry = _require_instance(runtime, normalized_name, op)

            selection = runtime.tls_inspector.resolve_for_instance(
                normalized_name,
                entry,
                source_override="system",
            )
            report = runtime.tls_validator.validate(selection)
            errors = [
                f"{finding.scope}:{finding.check} {finding.message}"
                for finding in report.findings
                if finding.severity is TLSValidationSeverity.ERROR
            ]
            if errors:
                _render_tls_report(report, json_output=False)
                op.error(
                    "System TLS validation failed; refusing to switch.",
                    errors=errors,
                    rc=2,
                    context={"report": report.to_dict()},
                )
                raise typer.Exit(code=2)

            _render_tls_report(report, json_output=False)

            if dry_run:
                op.add_step("registry.update", status="skipped", detail="dry-run")
                console.print("[yellow]Dry run[/yellow]: registry unchanged.")
                op.success(
                    "TLS use-system dry-run complete.",
                    changed=0,
                    context={"report": report.to_dict()},
                )
                return

            timestamp = datetime.now(UTC)
            tls_payload = {
                "source": "system",
                "cert": str(runtime.config.tls.system.cert),
                "key": str(runtime.config.tls.system.key),
            }
            _update_instance_registry(
                runtime,
                normalized_name,
                {"tls": tls_payload},
                metadata={
                    "tls_source": "system",
                    "tls_updated_at": timestamp.isoformat(),
                },
            )
            op.add_step("registry.update", status="success", detail="tls")

            _record_instance_state(
                runtime,
                normalized_name,
                update_last_changed=True,
                metadata={"tls_source": "system"},
            )

            entry_after_raw = runtime.registry.get_instance(normalized_name)
            entry_for_nginx = (
                dict(entry_after_raw)
                if isinstance(entry_after_raw, Mapping)
                else {}
            )
            domain_value = str(
                entry_for_nginx.get("domain")
                or _default_instance_domain(runtime.config, normalized_name)
            )
            port_value_raw: object | None = entry_for_nginx.get("port")
            if port_value_raw in (None, "", 0):
                port_value_raw = runtime.ports.get_port(normalized_name)
            port_int = _coerce_port(port_value_raw, runtime.config.ports.base)
            entry_for_nginx["domain"] = domain_value
            entry_for_nginx["port"] = port_int
            try:
                nginx_context = _build_nginx_context(
                    runtime,
                    normalized_name,
                    domain=domain_value,
                    port=port_int,
                    entry=entry_for_nginx,
                    selection=selection,
                )
            except TLSConfigurationError as exc:
                _command_error(op, str(exc), rc=2)

            nginx_result = runtime.nginx_provider.render_site(normalized_name, nginx_context)
            if nginx_result.validation_error is not None:
                _provider_error(
                    op,
                    (
                        f"nginx validation failed for '{normalized_name}': "
                        f"{nginx_result.validation_error}"
                    ),
                )
            op.add_step(
                "nginx.render_site",
                status="success" if nginx_result.changed else "noop",
                detail=str(runtime.nginx_provider.site_path(normalized_name)),
            )
            if nginx_result.validation is not None:
                op.add_step(
                    "nginx.validate",
                    status="success",
                    detail=_format_nginx_detail(nginx_result.validation),
                )
            if nginx_result.reload is not None:
                op.add_step(
                    "nginx.reload",
                    status="success",
                    detail=_format_nginx_detail(nginx_result.reload),
                )
            runtime.nginx_provider.enable(normalized_name)
            op.add_step(
                "nginx.enable",
                status="success",
                detail=str(runtime.nginx_provider.enabled_path(normalized_name)),
            )

            op.success(
                "Instance configured to use system TLS defaults.",
                context={"tls": tls_payload},
            )


@ports_app.command("list")
def ports_list(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit port reservations as JSON instead of a table.",
    ),
) -> None:
    """List reserved instance ports."""
    runtime = _get_runtime(ctx)
    entries = runtime.ports.list_entries()

    with runtime.logger.operation(
        "ports list",
        args={"json": json_output},
        target={"kind": "ports"},
    ) as op:
        if json_output:
            console.print_json(data={"ports": entries})
            op.success("Reported port reservations as JSON.", changed=0)
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Instance", style="bold")
        table.add_column("Port")

        if not entries:
            table.add_row("(none)", "")
        else:
            for entry in entries:
                table.add_row(entry["name"], str(entry["port"]))

        console.print(table)
        op.success("Reported port reservations.", changed=0)


@versions_app.command("install")
def version_install(
    ctx: typer.Context,
    version: str = typer.Argument(..., help="Actual Sync Server version to install (X.Y.Z)."),
    set_current: bool = typer.Option(
        False,
        "--set-current",
        help="After installing, update the current symlink to point at the new version.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Report the actions that would be taken without installing files.",
    ),
    no_backup: bool = typer.Option(
        False,
        "--no-backup",
        help="Skip the safety prompt to run a backup before continuing.",
    ),
    backup_message: str | None = typer.Option(
        None,
        "--backup-message",
        help="Annotate the recommended backup with a custom message.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Auto-confirm backup prompts (non-interactive mode).",
    ),
) -> None:
    """Install a new Actual Sync Server version under the install root."""
    runtime = _get_runtime(ctx)
    args = {"version": version, "set_current": set_current, "dry_run": dry_run}
    with runtime.logger.operation(
        "version install",
        args=args,
        target={"kind": "version", "version": version},
    ) as op:
        with runtime.locks.mutate_versions([version]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)

            existing_entry = runtime.registry.get_version(version) if not dry_run else None
            if existing_entry and not dry_run:
                _command_error(op, f"Version '{version}' is already registered.", rc=2)

            impacted_instances = sorted(
                set(_instances_using_version(runtime.registry, "current"))
            )

            backup_ids: list[str] = []

            def _handle_install_backup(scope: OperationScope) -> None:
                nonlocal backup_ids
                backup_ids.extend(
                    _run_instance_backups(
                        runtime,
                        impacted_instances,
                        operation="version install",
                        backup_message=backup_message,
                        op=scope,
                    )
                )

            try:
                _maybe_prompt_backup(
                    operation="version install",
                    op=op,
                    skip_backup=dry_run or no_backup,
                    auto_confirm=yes,
                    backup_message=backup_message,
                    on_accept=_handle_install_backup,
                )
                install_result = runtime.version_installer.install(
                    version,
                    dry_run=dry_run,
                )
            except VersionInstallError as exc:
                _command_error(
                    op,
                    f"Failed to install version '{version}': {exc}",
                    rc=4,
                    errors=[str(exc)],
                )

            step_name = "installer.install" if not dry_run else "installer.dry-run"
            op.add_step(step_name, status="success", detail=str(install_result.path))

            if dry_run:
                console.print(
                    "[yellow]Dry run[/yellow]: "
                    f"version '{version}' would be installed at {install_result.path}"
                )
                op.success("Version install dry-run complete.", changed=0)
                if set_current:
                    op.add_step(
                        "switch.pending",
                        status="info",
                        detail="--set-current deferred during dry-run",
                    )
                return

            _record_installed_version(runtime, install_result, op)
            console.print(
                f"[green]Installed version '{version}' at {install_result.path}.[/green]"
            )

            if set_current:
                _switch_version(runtime, version, op)
                console.print(
                    f"[green]Updated current symlink to version '{version}'.[/green]"
                )

            op.success(
                "Version installation completed.",
                changed=2 if not set_current else 3,
                backups=backup_ids,
            )


@versions_app.command("switch")
def version_switch(
    ctx: typer.Context,
    version: str = typer.Argument(..., help="Installed version to activate as current."),
    restart: str = typer.Option(
        "rolling",
        "--restart",
        case_sensitive=False,
        help="Restart policy for instances bound to the current version "
        "(none | rolling | all).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview the symlink update and restart plan without changing state.",
    ),
    no_backup: bool = typer.Option(
        False,
        "--no-backup",
        help="Skip the safety prompt to run a backup before continuing.",
    ),
    backup_message: str | None = typer.Option(
        None,
        "--backup-message",
        help="Annotate the recommended backup with a custom message.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Auto-confirm backup prompts (non-interactive mode).",
    ),
) -> None:
    """Update the current symlink to point at the requested version."""
    runtime = _get_runtime(ctx)
    restart_mode = restart.lower()
    if restart_mode not in {"none", "rolling", "all"}:
        console.print(f"[red]Invalid restart mode '{restart}'.[/red]")
        raise typer.Exit(code=2)

    with runtime.logger.operation(
        "version switch",
        args={"version": version, "restart": restart_mode, "dry_run": dry_run},
        target={"kind": "version", "version": version},
    ) as op:
        with runtime.locks.mutate_versions([version]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            impacted_instances = sorted(
                set(_instances_using_version(runtime.registry, "current"))
                | set(_instances_using_version(runtime.registry, version))
            )
            backup_ids: list[str] = []

            if dry_run:
                plan = {
                    "version": version,
                    "restart": restart_mode,
                    "instances": impacted_instances,
                    "actions": [
                        "update-current-symlink",
                        f"restart:{restart_mode}",
                    ],
                }
                op.add_step("version.switch.plan", status="info", detail=str(plan))
                _dry_run_complete(
                    op,
                    f"version '{version}' would become current (restart={restart_mode}).",
                    context={"plan": plan},
                )
                return

            def _handle_switch_backup(scope: OperationScope) -> None:
                nonlocal backup_ids
                backup_ids.extend(
                    _run_instance_backups(
                        runtime,
                        impacted_instances,
                        operation="version switch",
                        backup_message=backup_message,
                        op=scope,
                    )
                )

            _maybe_prompt_backup(
                operation="version switch",
                op=op,
                skip_backup=no_backup,
                auto_confirm=yes,
                backup_message=backup_message,
                on_accept=_handle_switch_backup,
            )
            _switch_version(runtime, version, op)
            _handle_version_restart(runtime, version, restart_mode, op)
            console.print(f"[green]Current version switched to '{version}'.[/green]")
            op.success("Version switch completed.", changed=2, backups=backup_ids)


@versions_app.command("uninstall")
def version_uninstall(
    ctx: typer.Context,
    version: str = typer.Argument(..., help="Installed version to remove."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview the files and registry updates without deleting anything.",
    ),
    no_backup: bool = typer.Option(
        False,
        "--no-backup",
        help="Skip the safety prompt to run a backup before continuing.",
    ),
    backup_message: str | None = typer.Option(
        None,
        "--backup-message",
        help="Annotate the recommended backup with a custom message.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Auto-confirm backup prompts (non-interactive mode).",
    ),
) -> None:
    """Remove an installed Actual Sync Server version."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "version uninstall",
        args={"version": version, "dry_run": dry_run},
        target={"kind": "version", "version": version},
    ) as op:
        with runtime.locks.mutate_versions([version]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)

            entry = runtime.registry.get_version(version)
            if entry is None:
                _command_error(op, f"Version '{version}' is not registered.", rc=2)

            version_path = Path(entry.get("path", runtime.config.install_root / f"v{version}"))

            if _current_version_target(runtime.config.install_root) == version_path.resolve():
                _command_error(
                    op,
                    (
                        f"Version '{version}' is the active 'current' target. "
                        "Uninstalling the active version is not permitted."
                    ),
                    rc=2,
                )

            consumers = _instances_using_version(runtime.registry, version)
            if consumers:
                joined = ", ".join(sorted(consumers))
                _command_error(
                    op,
                    f"Cannot uninstall version '{version}' while in use by instances: {joined}",
                    rc=2,
                )

            impacted_instances = sorted(consumers)
            backup_ids: list[str] = []

            plan = {
                "version": version,
                "path": str(version_path),
                "will_remove_path": version_path.exists(),
            }

            if dry_run:
                op.add_step("version.uninstall.plan", status="info", detail=str(plan))
                _dry_run_complete(
                    op,
                    f"version '{version}' would be removed (path: {version_path}).",
                    context={"plan": plan},
                )
                return

            def _handle_uninstall_backup(scope: OperationScope) -> None:
                nonlocal backup_ids
                backup_ids.extend(
                    _run_instance_backups(
                        runtime,
                        impacted_instances,
                        operation="version uninstall",
                        backup_message=backup_message,
                        op=scope,
                    )
                )

            _maybe_prompt_backup(
                operation="version uninstall",
                op=op,
                skip_backup=no_backup,
                auto_confirm=yes,
                backup_message=backup_message,
                on_accept=_handle_uninstall_backup,
            )

            removed_files = 0
            if version_path.exists():
                shutil.rmtree(version_path)
                op.add_step(
                    "filesystem.remove",
                    status="success",
                    detail=str(version_path),
                )
                removed_files += 1

            runtime.registry.remove_version(version)
            op.add_step("registry.remove_version", status="success", detail=version)

            console.print(f"[yellow]Uninstalled version '{version}'.[/yellow]")
            op.success(
                "Version uninstall completed.",
                changed=removed_files + 1,
                backups=backup_ids,
            )


def _record_installed_version(
    runtime: RuntimeContext,
    result: VersionInstallResult,
    op: OperationScope,
) -> None:
    """Persist installation metadata to the registry."""
    metadata = dict(result.metadata)
    metadata["installed"] = True
    metadata.setdefault("source", "install")

    entry: dict[str, object] = {
        "version": result.version,
        "path": str(result.path),
        "installed_at": result.installed_at,
        "metadata": metadata,
    }
    if result.integrity:
        entry["integrity"] = dict(result.integrity)

    runtime.registry.upsert_version(entry)
    op.add_step("registry.upsert_version", status="success", detail=result.version)


def _switch_version(
    runtime: RuntimeContext,
    version: str,
    op: OperationScope,
) -> None:
    """Update the install_root/current symlink to point at *version*."""
    entry = runtime.registry.get_version(version)
    if entry is None:
        _command_error(op, f"Version '{version}' is not registered.", rc=2)

    version_path = Path(entry.get("path", runtime.config.install_root / f"v{version}"))
    if not version_path.exists():
        _command_error(
            op,
            f"Installed directory for version '{version}' is missing: {version_path}",
            rc=3,
        )

    install_root = runtime.config.install_root
    install_root.mkdir(parents=True, exist_ok=True)
    current_link = install_root / "current"
    temp_link = install_root / ".abssctl-current.tmp"

    if temp_link.exists() or temp_link.is_symlink():
        temp_link.unlink()
    temp_link.symlink_to(version_path)
    temp_link.replace(current_link)

    _mark_current_version(runtime, version)
    op.add_step("symlink.update", status="success", detail=str(current_link))


def _handle_version_restart(
    runtime: RuntimeContext,
    version: str,
    restart_mode: str,
    op: OperationScope,
) -> None:
    """Apply the configured restart policy after a version switch."""
    tracked_current = set(_instances_using_version(runtime.registry, "current"))
    bound_exact = set(_instances_using_version(runtime.registry, version))
    targets = sorted(tracked_current | bound_exact)

    if restart_mode == "none" or not targets:
        op.add_step(
            "restart.skip",
            status="success" if not targets else "info",
            detail="no-instances" if not targets else "--restart none",
        )
        return

    plan = _build_restart_plan(targets, restart_mode)
    op.add_step(
        "restart.plan",
        status="success",
        detail=f"mode={restart_mode} actions={len(plan)}",
    )

    with runtime.locks.mutate_instances(targets, include_global=False):
        op.add_step(
            "restart.acquire_locks",
            status="success",
            detail=f"{len(targets)} instance(s)",
        )

        _execute_restart_plan(runtime, plan, op)


def _build_restart_plan(instances: Sequence[str], mode: str) -> list[tuple[str, str]]:
    """Return an ordered list of (instance, action) tuples for restarts."""
    plan: list[tuple[str, str]] = []
    if mode == "rolling":
        for name in instances:
            plan.append((name, "stop"))
            plan.append((name, "start"))
    else:
        for name in instances:
            plan.append((name, "stop"))
        for name in instances:
            plan.append((name, "start"))
    return plan


def _execute_restart_plan(
    runtime: RuntimeContext,
    plan: Sequence[tuple[str, str]],
    op: OperationScope,
) -> None:
    """Execute the restart plan against the systemd provider."""
    for instance, action in plan:
        try:
            if action == "stop":
                result = runtime.systemd_provider.stop(instance)
            else:
                result = runtime.systemd_provider.start(instance)
            op.add_step(
                f"systemd.{action}",
                status="success",
                detail=_format_systemd_detail(result, dry_run=False),
            )
        except SystemdError as exc:
            _provider_error(op, f"systemd {action} failed for '{instance}': {exc}")


def _mark_current_version(runtime: RuntimeContext, version: str) -> None:
    """Mark *version* as the active current version in the registry metadata."""
    runtime.registry.upsert_version({"version": version, "metadata": {"current": True}})
    versions = runtime.registry.read_versions().get("versions", [])
    if not isinstance(versions, list):
        return
    for item in versions:
        if isinstance(item, Mapping):
            other_version = str(item.get("version", "")).strip()
            if other_version and other_version != version:
                runtime.registry.upsert_version(
                    {"version": other_version, "metadata": {"current": False}}
                )


def _current_version_target(install_root: Path) -> Path | None:
    """Return the resolved path the current symlink points to, if present."""
    current_link = install_root / "current"
    if not current_link.is_symlink():
        return None
    return current_link.resolve()


def _instances_using_version(registry: StateRegistry, version: str) -> list[str]:
    """Return instance names that depend on *version*."""
    data = registry.read_instances()
    raw_instances = data.get("instances", [])
    consumers: list[str] = []
    if isinstance(raw_instances, list):
        for entry in raw_instances:
            if not isinstance(entry, Mapping):
                continue
            name = str(entry.get("name", "")).strip()
            if not name:
                continue
            bound_version = str(
                entry.get("version")
                or entry.get("version_binding")
                or entry.get("current_version")
                or ""
            ).strip()
            if bound_version == version:
                consumers.append(name)
    return consumers


def _maybe_prompt_backup(
    *,
    operation: str,
    op: OperationScope,
    skip_backup: bool,
    auto_confirm: bool,
    backup_message: str | None,
    on_accept: Callable[[OperationScope], None] | None = None,
) -> None:
    """Prompt for a backup unless explicitly skipped."""
    if skip_backup:
        op.add_step("backup.skip", status="info", detail="--no-backup")
        return

    prompt = (
        f"Operation '{operation}' can be disruptive. Run 'abssctl backup create' "
        "before continuing?"
    )

    confirmed = auto_confirm or typer.confirm(prompt, default=True)

    if confirmed:
        detail = backup_message or ""
        op.add_step("backup.requested", status="success", detail=detail)
        console.print(
            "[yellow]Recommendation:[/yellow] run 'abssctl backup create' before proceeding."
        )
        if on_accept is not None:
            try:
                on_accept(op)
            except BackupError as exc:
                console.print(f"[red]Backup failed during {operation}: {exc}[/red]")
                op.error(
                    f"Backup failed during {operation}.",
                    errors=[str(exc)],
                    rc=4,
                )
                raise typer.Exit(code=4) from exc
    else:
        op.add_step("backup.deferred", status="warning", detail="user-declined")
        console.print(
            "[yellow]Backup skipped at your request. Proceed with caution.[/yellow]"
        )


def _detect_zstd_support() -> bool:
    """Return True when tar/zstd tooling is available."""
    return shutil.which("tar") is not None and shutil.which("zstd") is not None


def _resolve_backup_algorithm(preference: str | None, default: str) -> str:
    """Resolve the effective backup compression algorithm."""
    candidate = (preference or default).lower()
    if candidate not in ALLOWED_BACKUP_COMPRESSION:
        allowed = ", ".join(sorted(ALLOWED_BACKUP_COMPRESSION))
        raise BackupError(f"Unsupported compression '{candidate}'. Allowed: {allowed}.")
    if candidate == "auto":
        return "zstd" if _detect_zstd_support() else "gzip"
    return candidate


def _compression_extension(algorithm: str) -> str:
    """Return the archive file extension for *algorithm*."""
    if algorithm == "gzip":
        return "tar.gz"
    if algorithm == "zstd":
        return "tar.zst"
    return "tar"


def _collect_backup_sources(
    runtime: RuntimeContext,
    instance: str,
    *,
    include_services: bool,
) -> dict[str, dict[str, object]]:
    """Return mapping describing what will be captured in the backup."""
    data_dir = runtime.config.instance_root / instance
    sources: dict[str, dict[str, object]] = {
        "data": {"path": str(data_dir), "exists": data_dir.exists()},
    }

    if include_services:
        systemd_path = runtime.systemd_provider.unit_path(instance)
        nginx_site = runtime.nginx_provider.site_path(instance)
        nginx_enabled = runtime.nginx_provider.enabled_path(instance)
        sources["systemd"] = {"path": str(systemd_path), "exists": systemd_path.exists()}
        sources["nginx_site"] = {"path": str(nginx_site), "exists": nginx_site.exists()}
        sources["nginx_enabled"] = {
            "path": str(nginx_enabled),
            "exists": nginx_enabled.exists(),
        }

    registry_path = runtime.config.registry_dir / "instances.yml"
    sources["registry"] = {"path": str(registry_path), "exists": registry_path.exists()}
    sources["metadata_instance"] = {"path": "<generated>", "exists": True}
    return sources


def _materialise_backup_payload(
    payload_root: Path,
    sources: Mapping[str, Mapping[str, object]],
    instance_entry: Mapping[str, object],
) -> None:
    """Copy required files into *payload_root* prior to archiving."""
    data_info = sources.get("data")
    data_target = payload_root / "data"
    if data_info and data_info.get("exists"):
        copy_into(Path(str(data_info["path"])), data_target)
    else:
        data_target.mkdir(parents=True, exist_ok=True)

    if "systemd" in sources:
        systemd_info = sources["systemd"]
        if systemd_info.get("exists"):
            source = Path(str(systemd_info["path"]))
            copy_into(source, payload_root / "systemd" / source.name)

    if "nginx_site" in sources:
        nginx_info = sources["nginx_site"]
        if nginx_info.get("exists"):
            source = Path(str(nginx_info["path"]))
            copy_into(source, payload_root / "nginx" / source.name)

    if "nginx_enabled" in sources:
        enabled_info = sources["nginx_enabled"]
        if enabled_info.get("exists"):
            source = Path(str(enabled_info["path"]))
            copy_into(source, payload_root / "nginx-enabled" / source.name)

    if "registry" in sources:
        registry_info = sources["registry"]
        if registry_info.get("exists"):
            source = Path(str(registry_info["path"]))
            copy_into(source, payload_root / "metadata" / "instances.yml")

    metadata_dir = payload_root / "metadata"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    (metadata_dir / "instance.json").write_text(
        json.dumps(instance_entry, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _create_archive(
    source_dir: Path,
    archive_path: Path,
    algorithm: str,
    compression_level: int | None,
) -> None:
    """Create an archive from *source_dir* at *archive_path*."""
    tar_bin = shutil.which("tar")
    if tar_bin is None:
        raise BackupError("The 'tar' command is required to create backups.")

    env = os.environ.copy()
    cmd: list[str] = [tar_bin]

    if algorithm == "gzip":
        cmd.extend(["-czf", str(archive_path)])
        if compression_level is not None:
            env["GZIP"] = f"-{compression_level}"
    elif algorithm == "zstd":
        cmd.extend(["--zstd", "-cf", str(archive_path)])
        if compression_level is not None:
            env["ZSTD_CLEVEL"] = str(compression_level)
    else:
        cmd.extend(["-cf", str(archive_path)])

    cmd.extend(["-C", str(source_dir.parent), source_dir.name])

    result = subprocess.run(  # noqa: S603, S607 - controlled command
        cmd,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr or result.stdout or "tar command failed"
        raise BackupError(message.strip())

    try:
        os.chmod(archive_path, 0o640)
    except OSError:
        pass


def _compute_checksum(path: Path) -> str:
    """Return the SHA-256 checksum for *path*."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _write_checksum_file(archive_path: Path, checksum: str) -> Path:
    """Write ``<archive>.sha256`` and return the checksum path."""
    checksum_path = archive_path.with_name(f"{archive_path.name}.sha256")
    checksum_path.write_text(f"{checksum}  {archive_path.name}\n", encoding="utf-8")
    try:
        os.chmod(checksum_path, 0o640)
    except OSError:
        pass
    return checksum_path


def _build_backup_plan_context(
    backup_id: str,
    archive_path: Path,
    algorithm: str,
    compression_level: int | None,
    sources: Mapping[str, Mapping[str, object]],
    *,
    data_only: bool,
    message: str | None,
    labels: Sequence[str],
) -> dict[str, object]:
    """Return a context dictionary describing the backup outcome."""
    return {
        "id": backup_id,
        "archive": str(archive_path),
        "algorithm": algorithm,
        "compression_level": compression_level,
        "sources": {key: dict(value) for key, value in sources.items()},
        "data_only": data_only,
        "message": message,
        "labels": list(labels),
    }


def _iso_now() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_iso_datetime(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _latest_backups_by_instance(
    entries: Sequence[Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    latest: dict[str, dict[str, object]] = {}
    for entry in entries:
        instance = str(entry.get("instance", "")).strip()
        if not instance:
            continue
        created_at = _parse_iso_datetime(entry.get("created_at"))
        if created_at is None:
            continue
        existing = latest.get(instance)
        existing_ts = _parse_iso_datetime(existing["created_at"]) if existing else None
        if existing is None or (existing_ts and created_at > existing_ts):
            latest[instance] = {
                "id": entry.get("id"),
                "created_at": entry.get("created_at"),
                "status": entry.get("status"),
                "message": entry.get("message"),
            }
    return latest


def _verify_backup_entry(
    runtime: RuntimeContext,
    entry: Mapping[str, object],
    *,
    op: OperationScope,
) -> dict[str, object]:
    backup_id = str(entry.get("id", ""))
    path_value = entry.get("path")
    checksum_map = entry.get("checksum") if isinstance(entry.get("checksum"), Mapping) else {}
    if isinstance(checksum_map, Mapping):
        expected_checksum = str(checksum_map.get("value", ""))
    else:
        expected_checksum = ""

    previous_status = str(entry.get("status", ""))
    status: str = "unknown"
    message: str = ""
    result: dict[str, object] = {
        "id": backup_id,
        "status": status,
        "message": message,
        "previous_status": previous_status,
    }
    if not path_value:
        status = "unknown"
        message = "Backup entry is missing an archive path."
        result.update(status=status, message=message)
        op.add_step("backup.verify", status="warning", detail=f"{backup_id}:no-path")
        return result

    path = Path(str(path_value))
    checksum_value: str | None = None

    if not path.exists():
        status = "missing"
        message = "Archive not found on disk."
    else:
        try:
            checksum_value = _compute_checksum(path)
        except OSError as exc:
            status = "error"
            message = f"Failed to read archive: {exc}".strip()
        else:
            if expected_checksum and checksum_value != expected_checksum:
                status = "corrupt"
                message = "Checksum mismatch."
            else:
                status = "available"
                message = "Checksum verified."

    verified_at = _iso_now()

    def mutator(payload: dict[str, object]) -> None:
        payload["status"] = status
        payload["verified_at"] = verified_at
        if isinstance(payload.get("checksum"), Mapping):
            existing_checksum = cast(Mapping[str, object], payload["checksum"])
        else:
            existing_checksum = {}
        checksum_payload: dict[str, object] = dict(existing_checksum)
        checksum_payload["last_verified"] = verified_at
        if checksum_value is not None:
            checksum_payload["observed"] = checksum_value
        payload["checksum"] = checksum_payload
        if isinstance(payload.get("metadata"), Mapping):
            metadata_mapping = cast(Mapping[str, object], payload["metadata"])
        else:
            metadata_mapping = {}
        metadata_payload: dict[str, object] = dict(metadata_mapping)
        if status == "available":
            metadata_payload.pop("verification_error", None)
        else:
            metadata_payload["verification_error"] = message
        payload["metadata"] = metadata_payload

    updated_entry = runtime.backups.update_entry(backup_id, mutator)
    result.update(status=status, message=message, entry=updated_entry)

    step_status = "success" if status == "available" else "warning"
    if status == "error":
        step_status = "error"
    op.add_step("backup.verify", status=step_status, detail=f"{backup_id}:{status}")
    return result


def _infer_backup_algorithm(entry: Mapping[str, object], archive_path: Path) -> str:
    """Return the archive compression algorithm for *entry*/*archive_path*."""
    algorithm_value = str(entry.get("algorithm", "") or "").strip().lower()
    if algorithm_value in {"gzip", "zstd", "tar"}:
        return algorithm_value
    suffix = "".join(archive_path.suffixes).lower()
    if suffix.endswith(".tar.zst"):
        return "zstd"
    if suffix.endswith(".tar.gz"):
        return "gzip"
    return "tar"


def _is_data_only(entry: Mapping[str, object]) -> bool:
    """Return True when the backup entry was created with --data-only."""
    metadata = entry.get("metadata")
    if isinstance(metadata, Mapping):
        return bool(metadata.get("data_only"))
    return False


def _ensure_disk_space_available(target: Path, required_bytes: int) -> None:
    """Raise BackupError if *target* lacks *required_bytes* free space."""
    check_path = target
    if not check_path.exists():
        check_path.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(check_path)
    if usage.free < required_bytes:
        raise BackupError(
            f"Insufficient free space under {check_path} (need {required_bytes} bytes, "
            f"have {usage.free})."
        )


def _extract_backup_archive(
    archive_path: Path,
    *,
    algorithm: str,
    staging_root: Path,
    expected_root: str,
) -> Path:
    """Extract *archive_path* into *staging_root* and return the payload directory."""
    tar_bin = shutil.which("tar")
    if tar_bin is None:
        raise BackupError("The 'tar' command is required to restore backups.")

    extraction_dir = staging_root / "extracted"
    extraction_dir.mkdir(parents=True, exist_ok=True)

    cmd: list[str] = [tar_bin]
    if algorithm == "zstd":
        cmd.extend(["--zstd", "-xf", str(archive_path)])
    elif algorithm == "gzip":
        cmd.extend(["-xzf", str(archive_path)])
    else:
        cmd.extend(["-xf", str(archive_path)])
    cmd.extend(["-C", str(extraction_dir)])

    result = subprocess.run(  # noqa: S603, S607 - controlled command
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "tar extraction failed").strip()
        raise BackupError(f"Failed to extract backup archive: {message}")

    payload_root = extraction_dir / expected_root
    if not payload_root.exists():
        candidates = [item for item in extraction_dir.iterdir() if item.is_dir()]
        if len(candidates) == 1:
            payload_root = candidates[0]
        else:
            raise BackupError(
                "Backup archive did not contain the expected payload directory."
            )
    return payload_root


def _load_backup_instance_snapshot(payload_root: Path) -> dict[str, object]:
    """Return the instance snapshot stored in the payload (empty mapping if absent)."""
    snapshot_path = payload_root / "metadata" / "instance.json"
    if not snapshot_path.exists():
        return {}
    try:
        data = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return dict(data) if isinstance(data, Mapping) else {}


def _format_restore_suffix(timestamp: datetime) -> str:
    """Return a unique suffix for temporary restore artefacts."""
    return f"{timestamp:%Y%m%d%H%M%S}-{secrets.token_hex(2)}"


def _backup_and_copy_file(
    source: Path,
    destination: Path,
    *,
    timestamp: datetime,
    label: str,
    op: OperationScope,
    backups: list[tuple[Path, Path]],
) -> None:
    """Copy *source* to *destination*, keeping a backup for rollback."""
    if not source.exists():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    backup_path: Path | None = None
    if destination.exists():
        suffix = _format_restore_suffix(timestamp)
        backup_path = destination.with_suffix(destination.suffix + f".pre-restore-{suffix}")
        shutil.copy2(destination, backup_path)
        backups.append((destination, backup_path))
        op.add_step(
            f"backup.restore.backup.{label}",
            status="success",
            detail=f"{destination} -> {backup_path}",
        )
    shutil.copy2(source, destination)
    op.add_step(
        f"backup.restore.copy.{label}",
        status="success",
        detail=f"{source} -> {destination}",
    )


def _discover_backup_archives(root: Path, instance_filter: str | None = None) -> list[Path]:
    """Return a list of archive paths under *root* optionally filtered by instance."""
    archives: list[Path] = []
    if not root.exists():
        return archives
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        lowered = "".join(path.suffixes).lower()
        if lowered.endswith(".sha256"):
            continue
        if not (
            lowered.endswith(".tar")
            or lowered.endswith(".tar.gz")
            or lowered.endswith(".tar.zst")
        ):
            continue
        if instance_filter:
            try:
                relative = path.relative_to(root)
            except ValueError:
                continue
            if not relative.parts or relative.parts[0] != instance_filter:
                continue
        archives.append(path)
    return archives


def _run_instance_backups(
    runtime: RuntimeContext,
    instances: Sequence[str],
    *,
    operation: str,
    backup_message: str | None,
    op: OperationScope,
    acquire_locks: bool = True,
) -> list[str]:
    """Create backups for *instances*, returning created backup identifiers."""
    if not instances:
        op.add_step("backup.skip", status="info", detail="no-instances")
        return []

    derived_message, labels = _compose_backup_metadata(operation, backup_message)
    actor_value = op.actor
    actor_mapping = dict(actor_value) if isinstance(actor_value, Mapping) else None

    created: list[str] = []
    for name in instances:
        if acquire_locks:
            with runtime.locks.mutate_instances([name], include_global=False) as bundle:
                op.add_step(
                    "backup.lock",
                    status="success",
                    detail=f"{name}:{bundle.wait_ms}ms",
                )
                _, result_ctx = _create_backup(
                    runtime,
                    name,
                    message=derived_message,
                    labels=labels,
                    data_only=False,
                    out_dir=None,
                    compression=None,
                    compression_level=None,
                    dry_run=False,
                    actor=actor_mapping,
                    op=op,
                )
        else:
            _, result_ctx = _create_backup(
                runtime,
                name,
                message=derived_message,
                labels=labels,
                data_only=False,
                out_dir=None,
                compression=None,
                compression_level=None,
                dry_run=False,
                actor=actor_mapping,
                op=op,
            )

        if result_ctx:
            backup_id = str(result_ctx["id"])
            created.append(backup_id)
            console.print(
                f"[cyan]Created backup '{backup_id}' for instance '{name}'.[/cyan]"
            )
    return created


def _compose_backup_metadata(
    operation: str,
    message: str | None,
    *,
    default_prefix: str = "Pre",
) -> tuple[str | None, list[str]]:
    """Return (message, labels) for an automated backup."""
    slug = operation.replace(" ", "-")
    derived_message = message or f"{default_prefix} {operation}"
    label = f"pre-{slug}"
    return derived_message, [label]


def _create_backup(
    runtime: RuntimeContext,
    instance: str,
    *,
    message: str | None,
    labels: Sequence[str],
    data_only: bool,
    out_dir: Path | None,
    compression: str | None,
    compression_level: int | None,
    dry_run: bool,
    actor: Mapping[str, object] | None,
    op: OperationScope,
) -> tuple[dict[str, object], dict[str, object] | None]:
    """Execute a backup workflow, returning (plan_context, result_context)."""
    instance_entry = _require_instance(runtime, instance, op)

    effective_algorithm = _resolve_backup_algorithm(
        compression, runtime.config.backups.compression
    )
    level = (
        compression_level
        if compression_level is not None
        else runtime.config.backups.compression_level
    )

    backup_id = runtime.backups.generate_identifier(instance)
    archive_dir = out_dir if out_dir is not None else runtime.backups.archive_directory(instance)
    archive_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(archive_dir, 0o750)
    except OSError:
        pass

    extension = _compression_extension(effective_algorithm)
    archive_path = archive_dir / f"{backup_id}.{extension}"

    sources = _collect_backup_sources(runtime, instance, include_services=not data_only)
    plan_context = _build_backup_plan_context(
        backup_id,
        archive_path,
        effective_algorithm,
        level,
        sources,
        data_only=data_only,
        message=message,
        labels=labels,
    )

    if dry_run:
        plan_context["status"] = "planned"
        return plan_context, None

    staging_root = Path(
        tempfile.mkdtemp(prefix=f".abssctl-backup-{backup_id}-", dir=str(archive_dir))
    )
    payload_root = staging_root / backup_id
    payload_root.mkdir(parents=True, exist_ok=True)

    try:
        _materialise_backup_payload(payload_root, sources, instance_entry)
        op.add_step("backup.stage", status="success", detail=str(payload_root))

        _create_archive(payload_root, archive_path, effective_algorithm, level)
        op.add_step("backup.archive", status="success", detail=str(archive_path))

        checksum = _compute_checksum(archive_path)
        checksum_path = _write_checksum_file(archive_path, checksum)
        op.add_step("backup.checksum", status="success", detail=str(checksum_path))

        size_bytes = archive_path.stat().st_size
        entry = BackupEntryBuilder(
            instance=instance,
            archive_path=archive_path,
            algorithm=effective_algorithm,
            checksum=checksum,
            size_bytes=size_bytes,
            message=message,
            labels=labels,
            compression_level=level,
            data_only=data_only,
            actor=actor,
        ).build(backup_id=backup_id)
        runtime.backups.append(entry)
        op.add_step("backup.index", status="success", detail=backup_id)
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)

    result_context = {
        "id": backup_id,
        "archive": str(archive_path),
        "checksum": checksum,
        "size_bytes": size_bytes,
        "algorithm": effective_algorithm,
        "compression_level": level,
        "checksum_file": str(checksum_path),
        "message": message,
        "labels": list(labels),
        "data_only": data_only,
    }
    plan_context["status"] = "created"
    plan_context["checksum"] = checksum
    plan_context["size_bytes"] = size_bytes
    return plan_context, result_context


def _build_update_payload(
    package: str,
    installed_versions: set[str],
    remote_versions: list[str],
) -> dict[str, object]:
    """Construct the payload describing update status."""
    payload: dict[str, object] = {
        "package": package,
        "status": "unknown",
        "installed_versions": _sort_versions(installed_versions),
        "available_updates": [],
        "latest_installed": None,
        "latest_remote": None,
        "message": "",
    }

    remote_stable = _stable_version_tuples(remote_versions)
    installed_stable = _stable_version_tuples(installed_versions)

    latest_installed_version = installed_stable[-1][0] if installed_stable else None
    latest_installed = installed_stable[-1][1] if installed_stable else None
    payload["latest_installed"] = latest_installed

    if not remote_versions:
        payload["status"] = "remote-unavailable"
        payload["message"] = f"Unable to retrieve versions for {package} from npm."
        return payload

    if not remote_stable:
        payload["status"] = "remote-unavailable"
        payload["message"] = f"No stable versions reported by npm for {package}."
        return payload

    payload["latest_remote"] = remote_stable[-1][1]

    available = [
        version
        for parsed, version in remote_stable
        if version not in installed_versions
        and (
            latest_installed_version is None
            or parsed > latest_installed_version
        )
    ]

    if available:
        payload["status"] = "updates-available"
        payload["available_updates"] = available
        latest_installed_display = latest_installed or "none"
        payload["message"] = (
            f"{package}: New version(s) available: {', '.join(available)} "
            f"(latest installed: {latest_installed_display})."
        )
    else:
        payload["status"] = "up-to-date"
        payload["message"] = (
            f"{package}: Installed versions are up to date with npm "
            f"(latest: {payload['latest_remote']})."
        )

    return payload


def _sort_versions(versions: set[str]) -> list[str]:
    """Return versions sorted using packaging where possible."""
    parsed: list[tuple[Version, str]] = []
    invalid: list[str] = []
    for version in versions:
        try:
            parsed.append((Version(version), version))
        except InvalidVersion:
            invalid.append(version)
    parsed.sort()
    invalid.sort()
    return [item for _, item in parsed] + invalid


def _stable_version_tuples(versions: set[str] | list[str]) -> list[tuple[Version, str]]:
    """Return stable (non pre/post-release) versions sorted ascending."""
    tuples: list[tuple[Version, str]] = []
    for version in versions:
        try:
            parsed = Version(version)
        except InvalidVersion:
            continue
        if parsed.is_prerelease or parsed.is_postrelease:
            continue
        tuples.append((parsed, version))
    tuples.sort()
    return tuples


@config_app.command("show")
def config_show(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit configuration as JSON instead of a table.",
    ),
) -> None:
    """Display the effective configuration after merges."""
    runtime = _get_runtime(ctx)
    data = runtime.config.to_dict()

    with runtime.logger.operation(
        "config show",
        args={"json": json_output},
        target={"kind": "config"},
    ) as op:
        if json_output:
            console.print_json(data=data)
            op.success("Rendered configuration as JSON.", changed=0)
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Key", style="bold")
        table.add_column("Value")

        for key, value in data.items():
            if isinstance(value, dict):
                rendered = json.dumps(value, indent=2, sort_keys=True)
            else:
                rendered = str(value)
            table.add_row(key, rendered)

        console.print(table)
        op.success("Rendered configuration table.", changed=0)


@instances_app.command("list")
def instance_list(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit instances as JSON instead of a table.",
    ),
) -> None:
    """List registered instances and summary details."""
    runtime = _get_runtime(ctx)
    raw = runtime.registry.read_instances()
    entries = _normalize_instances(raw.get("instances", []))

    try:
        backup_map = _latest_backups_by_instance(runtime.backups.list_entries())
    except BackupRegistryError:
        backup_map = {}
    for entry in entries:
        summary = backup_map.get(entry.get("name", ""))
        if summary:
            entry.setdefault("metadata", {})["last_backup"] = summary

    with runtime.logger.operation(
        "instance list",
        args={"json": json_output},
        target={"kind": "instance", "scope": "registry"},
    ) as op:
        if json_output:
            console.print_json(data={"instances": entries})
            op.success("Reported instance list as JSON.", changed=0)
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Name", style="bold")
        table.add_column("Version")
        table.add_column("Domain")
        table.add_column("Port")
        table.add_column("Status")

        if not entries:
            table.add_row("(none)", "", "", "", "")
        else:
            for entry in entries:
                metadata = entry.setdefault("metadata", {})
                status_info = runtime.instance_status_provider.status(entry["name"], entry)
                if not entry.get("status") or entry.get("status") == "unknown":
                    entry["status"] = status_info.state
                metadata.setdefault("status_detail", status_info.detail)
                metadata.setdefault("source", "registry")
                port_val = entry.get("port", "")
                port_rendered = "" if port_val in ("", None) else str(port_val)
                table.add_row(
                    entry["name"],
                    str(entry.get("version", "") or ""),
                    str(entry.get("domain", "") or ""),
                    port_rendered,
                    str(entry.get("status", "") or ""),
                )

        console.print(table)
        op.success("Reported instance list.", changed=0)


@instances_app.command("show")
def instance_show(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Name of the instance to display."),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit details as JSON instead of a table.",
    ),
) -> None:
    """Show details for a single instance."""
    runtime = _get_runtime(ctx)
    raw = runtime.registry.read_instances()
    entries = _normalize_instances(raw.get("instances", []))

    with runtime.logger.operation(
        "instance show",
        args={"name": name, "json": json_output},
        target={"kind": "instance", "name": name},
    ) as op:
        target = next((entry for entry in entries if entry["name"] == name), None)

        if target is None:
            _command_error(op, f"Instance '{name}' not found.", rc=2)

        metadata = target.setdefault("metadata", {})
        status_info = runtime.instance_status_provider.status(target["name"], target)
        if not target.get("status") or target.get("status") == "unknown":
            target["status"] = status_info.state
        metadata.setdefault("status_detail", status_info.detail)
        metadata.setdefault("source", "registry")

        if json_output:
            console.print_json(data=target)
            op.success("Displayed instance details as JSON.", changed=0)
            return

        table = Table(show_header=False)
        for key, value in target.items():
            if key == "metadata":
                continue
            if value in (None, ""):
                continue
            table.add_row(key.title(), str(value))

        status_detail = metadata.get("status_detail")
        if status_detail:
            table.add_row("Status Detail", str(status_detail))

        console.print(table)
        op.success("Displayed instance details.", changed=0)


@instances_app.command("create")
def instance_create(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Name of the instance to create."),
    port: int | None = typer.Option(
        None,
        "--port",
        min=1,
        help="Reserve a specific port instead of auto-allocating.",
    ),
    domain: str | None = typer.Option(
        None,
        "--domain",
        help="Override the default domain (defaults to <name>.local).",
    ),
    version: str | None = typer.Option(
        None,
        "--version",
        help="Bind the instance to a specific installed version (default: current).",
    ),
    data_dir: Path | None = DATA_DIR_OPTION,
    no_start: bool = NO_START_OPTION,
) -> None:
    """Provision an Actual Budget instance with filesystem, registry, and provider scaffolding."""
    runtime = _get_runtime(ctx)

    try:
        normalised_name = _validate_instance_name(name)
    except ValueError as exc:
        with runtime.logger.operation(
            "instance create",
            args={"name": name},
            target={"kind": "instance", "name": name},
        ) as op:
            _command_error(op, str(exc), rc=2)

    resolved_domain = domain.strip() if domain and domain.strip() else None
    args = {
        "name": normalised_name,
        "port": port,
        "domain": resolved_domain,
        "version": version,
        "data_dir": str(data_dir) if data_dir else None,
        "no_start": no_start,
    }

    with runtime.logger.operation(
        "instance create",
        args=args,
        target={"kind": "instance", "name": normalised_name},
    ) as op:
        name = normalised_name
        with runtime.locks.mutate_instances([name]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)

            if runtime.registry.get_instance(name) is not None:
                _command_error(op, f"Instance '{name}' already exists in the registry.", rc=2)

            domain_value = resolved_domain or _default_instance_domain(runtime.config, name)
            version_value = (
                (version or runtime.config.default_version).strip()
                or runtime.config.default_version
            )

            if version_value != "current":
                version_entry = runtime.registry.get_version(version_value)
                if version_entry is None:
                    _command_error(op, f"Version '{version_value}' is not registered.", rc=2)

            exec_path = _resolve_exec_path(runtime, version_value)

            paths = _determine_instance_paths(runtime.config, name, data_dir)
            seen_paths: set[Path] = set()
            conflicts: list[str] = []
            for label, candidate in [
                ("root", paths.root),
                ("data", paths.data),
                ("runtime", paths.runtime),
                ("logs", paths.logs),
                ("state", paths.state),
            ]:
                if candidate in seen_paths:
                    continue
                seen_paths.add(candidate)
                if candidate.exists():
                    conflicts.append(f"{label}:{candidate}")
            if paths.config_file.exists():
                conflicts.append(f"config:{paths.config_file}")
            if conflicts:
                message = (
                    "Cannot create instance because the following paths already exist: "
                    + ", ".join(conflicts)
                )
                _command_error(op, message, rc=2)

            port_reserved = False

            try:
                port_value = runtime.ports.reserve(name, requested_port=port)
                op.add_step("ports.reserve", status="success", detail=str(port_value))
            except PortsRegistryError as exc:
                message = str(exc)
                _command_error(op, message, rc=2)

            port_reserved = True
            cleanup_files: list[Path] = []
            cleanup_dirs: list[Path] = []
            registry_registered = False
            registry_updated = False
            config_written = False
            systemd_changed = False
            systemd_enabled = False
            systemd_started = False
            nginx_changed = False
            nginx_enabled = False

            created_at = datetime.now(UTC)

            try:
                for label, path in [
                    ("filesystem.mkdir.root", paths.root),
                    ("filesystem.mkdir.data", paths.data),
                    ("filesystem.mkdir.runtime", paths.runtime),
                    ("filesystem.mkdir.logs", paths.logs),
                    ("filesystem.mkdir.state", paths.state),
                ]:
                    path.mkdir(parents=True, exist_ok=False)
                    os.chmod(path, 0o750)
                    op.add_step(label, status="success", detail=str(path))
                    cleanup_dirs.append(path)

                config_payload = _build_instance_config(
                    name=name,
                    domain=domain_value,
                    port=port_value,
                    version=version_value,
                    paths=paths,
                    created_at=created_at,
                )
                _write_instance_config(paths, config_payload)
                op.add_step("config.write", status="success", detail=str(paths.config_file))
                config_written = True
                cleanup_files.append(paths.config_file)

                registry_entry = {
                    "name": name,
                    "domain": domain_value,
                    "port": port_value,
                    "version": version_value,
                    "status": "provisioning",
                    "paths": {
                        "root": str(paths.root),
                        "data": str(paths.data),
                        "config": str(paths.config_file),
                        "runtime": str(paths.runtime),
                        "logs": str(paths.logs),
                        "state": str(paths.state),
                        "systemd_unit": str(runtime.systemd_provider.unit_path(name)),
                        "nginx_site": str(runtime.nginx_provider.site_path(name)),
                        "nginx_enabled": str(runtime.nginx_provider.enabled_path(name)),
                    },
                    "metadata": {
                        "created_at": created_at.isoformat(),
                        "auto_start": not no_start,
                        "domain": domain_value,
                        "port": port_value,
                    },
                }
                _register_instance(runtime, registry_entry)
                op.add_step(
                    "registry.write_instances",
                    status="success",
                    detail=f"registered:{name}",
                )
                registry_registered = True

                systemd_context = _build_systemd_context(
                    runtime.config,
                    name,
                    port=port_value,
                    domain=domain_value,
                    paths=paths,
                    exec_path=exec_path,
                    version=version_value,
                )
                systemd_changed = runtime.systemd_provider.render_unit(name, systemd_context)
                if systemd_changed:
                    op.add_step(
                        "systemd.render_unit",
                        status="success",
                        detail=str(runtime.systemd_provider.unit_path(name)),
                    )

                systemctl_missing = shutil.which(runtime.systemd_provider.systemctl_bin) is None
                enable_result = runtime.systemd_provider.enable(name, dry_run=systemctl_missing)
                enable_status = "success" if not systemctl_missing else "skipped"
                op.add_step(
                    "systemd.enable",
                    status=enable_status,
                    detail=_format_systemd_detail(enable_result, dry_run=systemctl_missing),
                )
                systemd_enabled = not systemctl_missing

                if no_start:
                    op.add_step("systemd.start", status="skipped", detail="--no-start requested")
                else:
                    start_result = runtime.systemd_provider.start(name, dry_run=systemctl_missing)
                    start_status = "success" if not systemctl_missing else "skipped"
                    op.add_step(
                        "systemd.start",
                        status=start_status,
                        detail=_format_systemd_detail(start_result, dry_run=systemctl_missing),
                    )
                    systemd_started = not systemctl_missing

                entry_for_nginx = runtime.registry.get_instance(name) or registry_entry
                nginx_context = _build_nginx_context(
                    runtime,
                    name,
                    domain=domain_value,
                    port=port_value,
                    entry=entry_for_nginx if isinstance(entry_for_nginx, Mapping) else None,
                )
                nginx_result = runtime.nginx_provider.render_site(name, nginx_context)
                if nginx_result.validation_error is not None:
                    _cleanup_instance_create(
                        runtime,
                        name,
                        release_port=True,
                        paths=cleanup_files + list(reversed(cleanup_dirs)),
                        remove_registry=registry_registered,
                    )
                    _provider_error(
                        op,
                        f"nginx validation failed for '{name}': {nginx_result.validation_error}",
                    )
                nginx_changed = nginx_result.changed
                if nginx_changed:
                    op.add_step(
                        "nginx.render_site",
                        status="success",
                        detail=str(runtime.nginx_provider.site_path(name)),
                    )
                    if nginx_result.validation is not None:
                        op.add_step(
                            "nginx.validate",
                            status="success",
                            detail=_format_nginx_detail(nginx_result.validation),
                        )
                    if nginx_result.reload is not None:
                        op.add_step(
                            "nginx.reload",
                            status="success",
                            detail=_format_nginx_detail(nginx_result.reload),
                        )
                runtime.nginx_provider.enable(name)
                op.add_step(
                    "nginx.enable",
                    status="success",
                    detail=str(runtime.nginx_provider.enabled_path(name)),
                )
                nginx_enabled = True

                activated_at = datetime.now(UTC)
                final_status = "running" if (not no_start and systemd_started) else "enabled"
                metadata_updates = {
                    "created_at": created_at.isoformat(),
                    "auto_start": not no_start,
                    "activated_at": activated_at.isoformat(),
                }
                if not no_start and systemd_started:
                    metadata_updates["last_started_at"] = activated_at.isoformat()
                _record_instance_state(
                    runtime,
                    name,
                    status=final_status,
                    paths=paths,
                    port=port_value,
                    domain=domain_value,
                    systemd_enabled=systemd_enabled,
                    systemd_state="running" if final_status == "running" else final_status,
                    nginx_enabled=nginx_enabled,
                    metadata=metadata_updates,
                )
                op.add_step("registry.update", status="success", detail=f"status={final_status}")
                registry_updated = True

                changed_count = (
                    1  # ports.reserve
                    + len(cleanup_dirs)
                    + int(config_written)
                    + int(systemd_changed)
                    + int(systemd_enabled)
                    + int(systemd_started and not no_start)
                    + int(nginx_changed)
                    + int(nginx_enabled)
                    + int(registry_registered)
                    + int(registry_updated)
                )

                console.print(
                    "[green]Provisioned instance "
                    f"'{name}' on port {port_value} ({domain_value}).[/green]"
                )
                if no_start:
                    console.print("[yellow]Instance start skipped (--no-start).[/yellow]")
                elif not systemd_started:
                    console.print(
                        "[yellow]systemctl not available; start recorded as dry-run.[/yellow]"
                    )

                op.success(
                    "Instance provisioned.",
                    changed=changed_count,
                    context={"status": final_status},
                )
            except ValueError as exc:
                _cleanup_instance_create(
                    runtime,
                    name,
                    release_port=port_reserved,
                    paths=cleanup_files + list(reversed(cleanup_dirs)),
                    remove_registry=registry_registered,
                )
                _command_error(op, str(exc), rc=2)
            except (SystemdError, NginxError, TLSConfigurationError) as exc:
                _cleanup_instance_create(
                    runtime,
                    name,
                    release_port=port_reserved,
                    paths=cleanup_files + list(reversed(cleanup_dirs)),
                    remove_registry=registry_registered,
                )
                _provider_error(op, f"Provisioning failed for '{name}': {exc}")
            except OSError as exc:
                _cleanup_instance_create(
                    runtime,
                    name,
                    release_port=port_reserved,
                    paths=cleanup_files + list(reversed(cleanup_dirs)),
                    remove_registry=registry_registered,
                )
                message = f"Filesystem error provisioning '{name}': {exc}"
                _command_error(op, message, rc=3)


@instances_app.command("enable")
def instance_enable(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Name of the instance to enable."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Report the actions that would be taken without applying changes.",
    ),
) -> None:
    """Enable an instance's systemd unit and nginx site."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "instance enable",
        args={"name": name, "dry_run": dry_run},
        target={"kind": "instance", "name": name},
    ) as op:
        with runtime.locks.mutate_instances([name]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            _require_instance(runtime, name, op)
            if dry_run:
                op.add_step("systemd.enable", status="skipped", detail="dry-run")
                op.add_step("nginx.enable", status="skipped", detail="dry-run")
                console.print(f"[yellow]Dry run[/yellow]: Instance '{name}' would be enabled.")
                op.success("Instance enable dry-run complete.", changed=0)
                return

            try:
                result = runtime.systemd_provider.enable(name, dry_run=False)
                op.add_step(
                    "systemd.enable",
                    status="success",
                    detail=_format_systemd_detail(result, dry_run=False),
                )
            except SystemdError as exc:
                _provider_error(op, f"systemd enable failed: {exc}")
            try:
                runtime.nginx_provider.enable(name)
                op.add_step("nginx.enable", status="success")
            except NginxError as exc:
                _provider_error(op, f"nginx enable failed: {exc}")
            metadata_updates = {"enabled_at": datetime.now(UTC).isoformat()}
            _record_instance_state(
                runtime,
                name,
                status="enabled",
                systemd_enabled=True,
                systemd_state="enabled",
                metadata=metadata_updates,
            )
            op.add_step("registry.update", status="success", detail="status=enabled")
            console.print(f"[green]Instance '{name}' enabled.[/green]")
            op.success("Instance enabled.", changed=3)


@instances_app.command("disable")
def instance_disable(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Name of the instance to disable."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Report the actions that would be taken without applying changes.",
    ),
) -> None:
    """Disable an instance's systemd unit and nginx site."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "instance disable",
        args={"name": name, "dry_run": dry_run},
        target={"kind": "instance", "name": name},
    ) as op:
        with runtime.locks.mutate_instances([name]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            _require_instance(runtime, name, op)

            if dry_run:
                op.add_step("systemd.disable", status="skipped", detail="dry-run")
                op.add_step("nginx.disable", status="skipped", detail="dry-run")
                console.print(f"[yellow]Dry run[/yellow]: Instance '{name}' would be disabled.")
                op.success("Instance disable dry-run complete.", changed=0)
                return

            try:
                result = runtime.systemd_provider.disable(name, dry_run=False)
                op.add_step(
                    "systemd.disable",
                    status="success",
                    detail=_format_systemd_detail(result, dry_run=False),
                )
            except SystemdError as exc:
                _provider_error(op, f"systemd disable failed: {exc}")
            try:
                runtime.nginx_provider.disable(name)
                op.add_step("nginx.disable", status="success")
            except NginxError as exc:
                _provider_error(op, f"nginx disable failed: {exc}")
            metadata_updates = {"disabled_at": datetime.now(UTC).isoformat()}
            _record_instance_state(
                runtime,
                name,
                status="disabled",
                systemd_enabled=False,
                systemd_state="disabled",
                metadata=metadata_updates,
            )
            op.add_step("registry.update", status="success", detail="status=disabled")
            console.print(f"[yellow]Instance '{name}' disabled.[/yellow]")
            op.success("Instance disabled.", changed=3)


@instances_app.command("start")
def instance_start(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Name of the instance to start."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Report the actions that would be taken without applying changes.",
    ),
) -> None:
    """Start the systemd unit for an instance."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "instance start",
        args={"name": name, "dry_run": dry_run},
        target={"kind": "instance", "name": name},
    ) as op:
        with runtime.locks.mutate_instances([name]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            _require_instance(runtime, name, op)

            if dry_run:
                op.add_step("systemd.start", status="skipped", detail="dry-run")
                console.print(f"[yellow]Dry run[/yellow]: Instance '{name}' would be started.")
                op.success("Instance start dry-run complete.", changed=0)
                return

            try:
                result = runtime.systemd_provider.start(name, dry_run=False)
                op.add_step(
                    "systemd.start",
                    status="success",
                    detail=_format_systemd_detail(result, dry_run=False),
                )
            except SystemdError as exc:
                _provider_error(op, f"systemd start failed: {exc}")
            metadata_updates = {"last_started_at": datetime.now(UTC).isoformat()}
            _record_instance_state(
                runtime,
                name,
                status="running",
                systemd_state="running",
                systemd_enabled=True,
                metadata=metadata_updates,
            )
            op.add_step("registry.update", status="success", detail="status=running")
            console.print(f"[green]Instance '{name}' started.[/green]")
            op.success("Instance started.", changed=2)


@instances_app.command("stop")
def instance_stop(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Name of the instance to stop."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Report the actions that would be taken without applying changes.",
    ),
) -> None:
    """Stop the systemd unit for an instance."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "instance stop",
        args={"name": name, "dry_run": dry_run},
        target={"kind": "instance", "name": name},
    ) as op:
        with runtime.locks.mutate_instances([name]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            _require_instance(runtime, name, op)

            if dry_run:
                op.add_step("systemd.stop", status="skipped", detail="dry-run")
                console.print(f"[yellow]Dry run[/yellow]: Instance '{name}' would be stopped.")
                op.success("Instance stop dry-run complete.", changed=0)
                return

            try:
                result = runtime.systemd_provider.stop(name)
                op.add_step(
                    "systemd.stop",
                    status="success",
                    detail=_format_systemd_detail(result, dry_run=False),
                )
            except SystemdError as exc:
                _provider_error(op, f"systemd stop failed: {exc}")
            metadata_updates = {"last_stopped_at": datetime.now(UTC).isoformat()}
            _record_instance_state(
                runtime,
                name,
                status="stopped",
                systemd_state="stopped",
                systemd_enabled=False,
                metadata=metadata_updates,
            )
            op.add_step("registry.update", status="success", detail="status=stopped")
            console.print(f"[yellow]Instance '{name}' stopped.[/yellow]")
            op.success("Instance stopped.", changed=2)


@instances_app.command("restart")
def instance_restart(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Name of the instance to restart."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Report the actions that would be taken without applying changes.",
    ),
) -> None:
    """Restart the systemd unit for an instance."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "instance restart",
        args={"name": name, "dry_run": dry_run},
        target={"kind": "instance", "name": name},
    ) as op:
        with runtime.locks.mutate_instances([name]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            _require_instance(runtime, name, op)

            if dry_run:
                op.add_step("systemd.stop", status="skipped", detail="dry-run")
                op.add_step("systemd.start", status="skipped", detail="dry-run")
                console.print(f"[yellow]Dry run[/yellow]: Instance '{name}' would be restarted.")
                op.success("Instance restart dry-run complete.", changed=0)
                return

            try:
                stop_result = runtime.systemd_provider.stop(name)
                op.add_step(
                    "systemd.stop",
                    status="success",
                    detail=_format_systemd_detail(stop_result, dry_run=False),
                )
                start_result = runtime.systemd_provider.start(name)
                op.add_step(
                    "systemd.start",
                    status="success",
                    detail=_format_systemd_detail(start_result, dry_run=False),
                )
            except SystemdError as exc:
                _provider_error(op, f"systemd restart failed: {exc}")
            metadata_updates = {"last_restarted_at": datetime.now(UTC).isoformat()}
            _record_instance_state(
                runtime,
                name,
                status="running",
                systemd_state="running",
                systemd_enabled=True,
                metadata=metadata_updates,
            )
            op.add_step("registry.update", status="success", detail="status=running")
            console.print(f"[green]Instance '{name}' restarted.[/green]")
            op.success("Instance restarted.", changed=3)


@instances_app.command("status")
def instance_status_command(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Name of the instance to query."),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit structured JSON instead of human-readable output.",
    ),
) -> None:
    """Report the registry/systemd state for an instance."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "instance status",
        args={"name": name, "json": json_output},
        target={"kind": "instance", "name": name},
    ) as op:
        entry = _require_instance(runtime, name, op)
        paths = _instance_paths_from_entry(runtime.config, name, entry)
        status_info = runtime.instance_status_provider.status(name, entry)
        registry_status = str(entry.get("status", "unknown") or "unknown")

        systemd_output = ""
        try:
            result = runtime.systemd_provider.status(name)
            op.add_step(
                "systemd.status",
                status="success",
                detail=_format_systemd_detail(result, dry_run=False),
            )
            systemd_output = (getattr(result, "stdout", "") or "").strip()
        except SystemdError as exc:
            op.add_step("systemd.status", status="warning", detail=str(exc))
            systemd_output = str(exc)

        metadata = entry.get("metadata") if isinstance(entry, Mapping) else {}
        diagnostics_meta = (
            dict(metadata.get("diagnostics", {}))
            if isinstance(metadata, Mapping)
            else {}
        )

        payload = {
            "name": name,
            "state": status_info.state,
            "detail": status_info.detail,
            "registry_status": registry_status,
            "systemd_output": systemd_output,
            "diagnostics": diagnostics_meta,
            "paths": entry.get("paths", {}),
        }

        if json_output:
            console.print_json(data=payload)
        else:
            table = Table(show_header=False)
            table.add_row("State", status_info.state)
            table.add_row("Registry", registry_status)
            if status_info.detail:
                table.add_row("Detail", status_info.detail)
            if systemd_output:
                table.add_row("systemd", systemd_output)
            systemd_diag = diagnostics_meta.get("systemd")
            if isinstance(systemd_diag, Mapping):
                enabled_flag = systemd_diag.get("enabled")
                if enabled_flag is not None:
                    table.add_row("systemd Enabled", str(enabled_flag))
                unit_exists = systemd_diag.get("unit_exists")
                if unit_exists is not None:
                    table.add_row("Unit Exists", str(unit_exists))
            nginx_diag = diagnostics_meta.get("nginx")
            if isinstance(nginx_diag, Mapping):
                enabled_flag = nginx_diag.get("enabled")
                if enabled_flag is not None:
                    table.add_row("nginx Enabled", str(enabled_flag))
            console.print(table)

        _record_instance_state(
            runtime,
            name,
            paths=paths,
            systemd_state=status_info.state,
            metadata={"last_status_check": datetime.now(UTC).isoformat()},
            update_last_changed=False,
        )

        op.success("Reported instance status.", changed=0)


@instances_app.command("delete")
def instance_delete(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Name of the instance to delete."),
    purge_data: bool = typer.Option(
        False,
        "--purge-data",
        help="Also remove the instance data directory (default: keep data).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Report the actions that would be taken without applying changes.",
    ),
    no_backup: bool = typer.Option(
        False,
        "--no-backup",
        help="Skip the safety prompt to run a backup before continuing.",
    ),
    backup_message: str | None = typer.Option(
        None,
        "--backup-message",
        help="Annotate the recommended backup with a custom message.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Auto-confirm backup prompts (non-interactive mode).",
    ),
) -> None:
    """Remove instance scaffolding and unregister it."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "instance delete",
        args={
            "name": name,
            "purge_data": purge_data,
            "dry_run": dry_run,
        },
        target={"kind": "instance", "name": name},
    ) as op:
        with runtime.locks.mutate_instances([name]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            entry = _require_instance(runtime, name, op)
            paths = _instance_paths_from_entry(runtime.config, name, entry)

            if dry_run:
                op.add_step("backup.prompt", status="skipped", detail="dry-run")
                op.add_step("systemd.stop", status="skipped", detail="dry-run")
                op.add_step("systemd.disable", status="skipped", detail="dry-run")
                op.add_step("nginx.disable", status="skipped", detail="dry-run")
                op.add_step("systemd.remove", status="skipped", detail="dry-run")
                op.add_step("nginx.remove", status="skipped", detail="dry-run")
                op.add_step("filesystem.cleanup", status="skipped", detail="dry-run")
                op.add_step("registry.remove", status="skipped", detail="dry-run")
                op.add_step("ports.release", status="skipped", detail="dry-run")
                message = (
                    f"[yellow]Dry run[/yellow]: Instance '{name}' would be deleted "
                    f"({'including data' if purge_data else 'preserving data'})."
                )
                console.print(message)
                op.success("Instance delete dry-run complete.", changed=0)
                return

            backup_ids: list[str] = []

            def _handle_instance_delete(scope: OperationScope) -> None:
                nonlocal backup_ids
                backup_ids.extend(
                    _run_instance_backups(
                        runtime,
                        [name],
                        operation="instance delete",
                        backup_message=backup_message,
                        op=scope,
                        acquire_locks=False,
                    )
                )

            _maybe_prompt_backup(
                operation="instance delete",
                op=op,
                skip_backup=no_backup,
                auto_confirm=yes,
                backup_message=backup_message,
                on_accept=_handle_instance_delete,
            )

            was_running = str(entry.get("status", "")).lower() == "running"
            try:
                if was_running:
                    stop_result = runtime.systemd_provider.stop(name)
                    op.add_step(
                        "systemd.stop",
                        status="success",
                        detail=_format_systemd_detail(stop_result, dry_run=False),
                    )
                else:
                    op.add_step("systemd.stop", status="skipped", detail="not-running")
            except SystemdError:
                # Non-fatal if service isn't running.
                op.add_step("systemd.stop", status="warning", detail="service-not-running")
            try:
                disable_result = runtime.systemd_provider.disable(name)
                op.add_step(
                    "systemd.disable",
                    status="success",
                    detail=_format_systemd_detail(disable_result, dry_run=False),
                )
            except SystemdError as exc:
                op.add_step("systemd.disable", status="warning", detail=str(exc))
            try:
                runtime.nginx_provider.disable(name)
                op.add_step("nginx.disable", status="success")
            except NginxError as exc:
                op.add_step("nginx.disable", status="warning", detail=str(exc))
            runtime.systemd_provider.remove(name)
            op.add_step("systemd.remove", status="success")
            runtime.nginx_provider.remove(name)
            op.add_step("nginx.remove", status="success")

            # Filesystem cleanup -------------------------------------------------
            removed_paths: list[str] = []
            for directory in [paths.runtime, paths.logs, paths.state]:
                if directory.exists():
                    shutil.rmtree(directory, ignore_errors=True)
                    removed_paths.append(str(directory))
            if purge_data:
                if paths.root.exists():
                    shutil.rmtree(paths.root, ignore_errors=True)
                    removed_paths.append(str(paths.root))
                else:
                    op.add_step("filesystem.purge", status="warning", detail="root-missing")
            else:
                op.add_step(
                    "filesystem.purge",
                    status="skipped",
                    detail="data-retained",
                )

            if removed_paths:
                op.add_step("filesystem.cleanup", status="success", detail=", ".join(removed_paths))

            runtime.registry.remove_instance(name)
            op.add_step("registry.remove", status="success")
            try:
                runtime.ports.release(name)
                op.add_step("ports.release", status="success")
            except PortsRegistryError:
                op.add_step("ports.release", status="warning", detail="not-found")
            console.print(
                f"[yellow]Instance '{name}' removed"
                f"{' and data purged' if purge_data else ''}.[/yellow]"
            )
            op.success("Instance deleted.", changed=8, backups=backup_ids)
@versions_app.command("list")
def version_list(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit versions as JSON instead of a table.",
    ),
    remote: bool = typer.Option(
        False,
        "--remote",
        help="Include versions reported by npm (requires npm CLI).",
    ),
) -> None:
    """List versions known to the registry and optionally npm."""
    runtime = _get_runtime(ctx)
    local_raw = runtime.registry.read_versions()
    local_entries = _normalize_versions(local_raw.get("versions", []))

    remote_versions: list[str] = []
    if remote:
        remote_versions = runtime.version_provider.list_remote_versions(
            runtime.config.npm_package_name
        )

    entries = _merge_versions(local_entries, remote_versions)

    try:
        backup_map = _latest_backups_by_instance(runtime.backups.list_entries())
    except BackupRegistryError:
        backup_map = {}

    version_backup_map: dict[str, dict[str, object]] = {}
    instances_raw = runtime.registry.read_instances().get("instances", [])
    if isinstance(instances_raw, list):
        for raw_entry in instances_raw:
            if not isinstance(raw_entry, Mapping):
                continue
            instance_name = str(raw_entry.get("name", "")).strip()
            if not instance_name:
                continue
            version_name = str(
                raw_entry.get("version")
                or raw_entry.get("version_binding")
                or runtime.config.default_version
            ).strip()
            if not version_name:
                continue
            summary = backup_map.get(instance_name)
            if not summary:
                continue
            summary_ts = _parse_iso_datetime(summary.get("created_at"))
            if summary_ts is None:
                continue
            existing = version_backup_map.get(version_name)
            existing_ts = (
                _parse_iso_datetime(existing.get("created_at"))
                if isinstance(existing, Mapping)
                else None
            )
            if existing is None or (existing_ts and summary_ts > existing_ts):
                version_backup_map[version_name] = dict(summary)

    for entry in entries:
        summary = version_backup_map.get(entry.get("version", ""))
        if summary:
            entry.setdefault("metadata", {})["last_backup"] = summary

    with runtime.logger.operation(
        "version list",
        args={"json": json_output, "remote": remote},
        target={"kind": "version", "scope": "registry"},
    ) as op:
        if json_output:
            console.print_json(data={"versions": entries})
            op.success("Reported version list as JSON.", changed=0)
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Version", style="bold")
        table.add_column("Installed")
        table.add_column("Source")

        if not entries:
            table.add_row("(none)", "", "")
        else:
            for entry in entries:
                metadata = entry.get("metadata", {})
                table.add_row(
                    entry["version"],
                    "yes" if metadata.get("installed") else "no",
                    str(metadata.get("source", "registry")),
                )

        console.print(table)
        op.success("Reported version list.", changed=0)


@versions_app.command("check-updates")
def version_check_updates(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit update information as JSON.",
    ),
) -> None:
    """Compare installed versions against npm metadata."""
    runtime = _get_runtime(ctx)
    package = runtime.config.npm_package_name
    installed_entries = _normalize_versions(runtime.registry.read_versions().get("versions", []))
    installed_versions = {
        entry["version"]
        for entry in installed_entries
        if entry.get("version")
    }
    remote_versions = runtime.version_provider.list_remote_versions(package)
    with runtime.logger.operation(
        "version check-updates",
        args={"json": json_output},
        target={"kind": "version", "scope": "update-check"},
    ) as op:
        payload = _build_update_payload(package, installed_versions, remote_versions)

        if json_output:
            console.print_json(data=payload)
            op.success("Reported update status (JSON).", changed=0)
            return

        console.print(payload["message"])
        if payload["status"] == "updates-available":
            available_updates = cast(list[str], payload.get("available_updates", []))
            updates = ", ".join(available_updates)
            console.print(f"[green]Updates available:[/green] {updates}")
        elif payload["status"] == "remote-unavailable":
            console.print("[yellow]Unable to fetch remote versions.[/yellow]")
        else:
            console.print("[green]Installed versions are up to date.[/green]")
        op.success("Reported update status.", changed=0)


@backups_app.command("create")
def backup_create(
    ctx: typer.Context,
    instance: str = typer.Argument(..., help="Instance name to back up."),
    message: str | None = typer.Option(
        None,
        "--message",
        "-m",
        help="Annotate the backup entry with a descriptive message.",
    ),
    labels: str | None = typer.Option(
        None,
        "--label",
        help="Apply one or more labels (comma-separated) to the backup metadata.",
        metavar="LABELS",
    ),
    data_only: bool = typer.Option(
        False,
        "--data-only",
        help="Skip systemd/nginx assets and capture only instance data.",
    ),
    out_dir: Path | None = BACKUP_OUT_DIR_OPTION,
    compression: str | None = typer.Option(
        None,
        "--compression",
        help="Compression algorithm to use (auto, zstd, gzip, none). Defaults to config setting.",
        metavar="ALGO",
    ),
    compression_level: int | None = typer.Option(
        None,
        "--compression-level",
        help="Compression level for gzip/zstd when supported (positive integer).",
        metavar="LEVEL",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit backup details as JSON.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview the backup plan without creating any files.",
    ),
) -> None:
    """Create a backup archive for an instance."""
    runtime = _get_runtime(ctx)

    compression_value = compression.lower() if compression else None
    if compression_value and compression_value not in ALLOWED_BACKUP_COMPRESSION:
        allowed = ", ".join(sorted(ALLOWED_BACKUP_COMPRESSION))
        console.print(f"[red]Unsupported compression '{compression}'. Allowed: {allowed}.[/red]")
        raise typer.Exit(code=2)

    if compression_level is not None and compression_level <= 0:
        console.print("[red]--compression-level must be greater than zero.[/red]")
        raise typer.Exit(code=2)

    label_list: list[str] = []
    if labels:
        label_list = [item.strip() for item in labels.split(",") if item.strip()]

    with runtime.logger.operation(
        "backup create",
        args={
            "instance": instance,
            "message": message,
            "labels": label_list,
            "data_only": data_only,
            "out_dir": str(out_dir) if out_dir else None,
            "compression": compression_value,
            "compression_level": compression_level,
            "dry_run": dry_run,
            "json": json_output,
        },
        target={"kind": "backup", "instance": instance},
    ) as op:
        with runtime.locks.mutate_instances([instance]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            plan_context: dict[str, object] | None = None
            result_context: dict[str, object] | None = None
            actor_value = op.actor
            actor_mapping: Mapping[str, object] | None = (
                dict(actor_value) if isinstance(actor_value, Mapping) else None
            )
            try:
                plan_context, result_context = _create_backup(
                    runtime,
                    instance,
                    message=message,
                    labels=label_list,
                    data_only=data_only,
                    out_dir=out_dir,
                    compression=compression_value,
                    compression_level=compression_level,
                    dry_run=dry_run,
                    actor=actor_mapping,
                    op=op,
                )
            except BackupError as exc:
                console.print(f"[red]Failed to create backup: {exc}[/red]")
                error_context = {"plan": plan_context} if plan_context is not None else {
                    "plan": {"instance": instance}
                }
                op.error(
                    "Backup creation failed.",
                    errors=[str(exc)],
                    rc=4,
                    context=error_context,
                )
                raise typer.Exit(code=4) from exc

            if plan_context is None:
                plan_context = {"id": None, "status": "unknown"}

            output_payload: dict[str, object] = {"plan": plan_context}
            if result_context:
                output_payload["result"] = result_context

            if json_output:
                console.print_json(data=output_payload)
            else:
                if result_context is None:
                    console.print(
                        "[yellow]Dry run[/yellow]: backup "
                        f"'{plan_context['id']}' would be created for instance '{instance}'."
                    )
                    sources = cast(dict[str, object], plan_context.get("sources", {}))
                    for name, info_obj in sources.items():
                        info_map = cast(dict[str, object], info_obj)
                        status = "present" if info_map.get("exists") else "missing"
                        console.print(
                            f"  - {name}: {info_map.get('path')} ({status})"
                        )
                else:
                    console.print(
                        "[green]Created backup "
                        f"'{result_context['id']}' for instance '{instance}'.[/green]"
                    )
                    console.print(f"Archive: {result_context['archive']}")
                    console.print(f"Checksum (sha256): {result_context['checksum']}")
                    console.print(f"Size: {result_context['size_bytes']} bytes")

            if result_context is None:
                op.success(
                    "Backup dry-run completed.",
                    changed=0,
                    context=output_payload,
                )
            else:
                op.success(
                    "Backup created.",
                    changed=3,
                    backups=[cast(str, result_context["id"])],
                    context=output_payload,
                )


def main() -> None:
    """Console script entry point."""
    app()

@backups_app.command("list")
def backup_list(
    ctx: typer.Context,
    instance: str | None = typer.Option(
        None,
        "--instance",
        "-i",
        help="Filter backups for a specific instance.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit backup details as JSON.",
    ),
) -> None:
    """List known backups from the registry."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "backup list",
        args={"instance": instance, "json": json_output},
        target={"kind": "backup", "scope": "registry"},
    ) as op:
        try:
            entries = runtime.backups.list_entries()
        except BackupRegistryError as exc:
            console.print(f"[red]Failed to read backup index: {exc}[/red]")
            op.error("Failed to read backup index.", errors=[str(exc)], rc=2)
            raise typer.Exit(code=2) from exc

        if instance:
            try:
                entries = runtime.backups.entries_for_instance(instance)
            except BackupRegistryError as exc:
                console.print(f"[red]{exc}[/red]")
                op.error(str(exc), errors=[str(exc)], rc=2)
                raise typer.Exit(code=2) from exc

        entries.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)

        if json_output:
            console.print_json(data={"backups": entries})
            op.success("Reported backup list (JSON).", changed=0)
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="bold")
        table.add_column("Instance")
        table.add_column("Created At")
        table.add_column("Status")
        table.add_column("Message")

        if not entries:
            table.add_row("(none)", "", "", "", "")
        else:
            for entry in entries:
                table.add_row(
                    str(entry.get("id", "")),
                    str(entry.get("instance", "")),
                    str(entry.get("created_at", "")),
                    str(entry.get("status", "")),
                    str(entry.get("message", "")),
                )

        console.print(table)
        op.success("Reported backup list.", changed=0)


@backups_app.command("show")
def backup_show(
    ctx: typer.Context,
    backup_id: str = typer.Argument(..., help="Backup identifier to inspect."),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit backup details as JSON.",
    ),
) -> None:
    """Show detailed information for a specific backup."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "backup show",
        args={"id": backup_id, "json": json_output},
        target={"kind": "backup", "id": backup_id},
    ) as op:
        try:
            entry = runtime.backups.find_by_id(backup_id)
        except BackupRegistryError as exc:
            console.print(f"[red]{exc}[/red]")
            op.error(str(exc), errors=[str(exc)], rc=2)
            raise typer.Exit(code=2) from exc

        if entry is None:
            _command_error(op, f"Backup '{backup_id}' not found.", rc=2)

        if json_output:
            console.print_json(data={"backup": entry})
            op.success("Reported backup details (JSON).", changed=0)
            return

        table = Table(show_header=False)
        for key in ["id", "instance", "created_at", "status", "algorithm", "message"]:
            value = entry.get(key)
            if value is not None:
                table.add_row(key.replace("_", " ").title(), str(value))

        checksum = entry.get("checksum")
        if isinstance(checksum, Mapping):
            table.add_row("Checksum Algorithm", str(checksum.get("algorithm", "")))
            table.add_row("Checksum Value", str(checksum.get("value", "")))

        metadata = entry.get("metadata")
        if isinstance(metadata, Mapping):
            labels = ", ".join(str(label) for label in metadata.get("labels", []))
            table.add_row("Data Only", str(metadata.get("data_only", False)))
            if labels:
                table.add_row("Labels", labels)

        console.print(table)
        op.success("Reported backup details.", changed=0)


@backups_app.command("verify")
def backup_verify(
    ctx: typer.Context,
    backup_id: str | None = typer.Argument(None, help="Backup identifier to verify."),
    all_backups: bool = typer.Option(
        False,
        "--all",
        help="Verify every backup in the registry.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit verification results as JSON.",
    ),
) -> None:
    """Re-run checksum validation for backups."""
    if not backup_id and not all_backups:
        console.print("[red]Specify a BACKUP_ID or pass --all.[/red]")
        raise typer.Exit(code=2)
    if backup_id and all_backups:
        console.print("[red]Provide a single BACKUP_ID or --all, not both.[/red]")
        raise typer.Exit(code=2)

    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "backup verify",
        args={"id": backup_id, "all": all_backups, "json": json_output},
        target={"kind": "backup", "scope": "verify", "id": backup_id},
    ) as op:
        try:
            entries = runtime.backups.list_entries()
        except BackupRegistryError as exc:
            console.print(f"[red]Failed to read backup index: {exc}[/red]")
            op.error("Failed to read backup index.", errors=[str(exc)], rc=2)
            raise typer.Exit(code=2) from exc

        targets: Sequence[Mapping[str, object]]
        if all_backups:
            targets = entries
        else:
            target_entry = runtime.backups.find_by_id(backup_id or "")
            if target_entry is None:
                _command_error(op, f"Backup '{backup_id}' not found.", rc=2)
            targets = [target_entry]

        results: list[dict[str, object]] = []
        for entry in targets:
            results.append(_verify_backup_entry(runtime, entry, op=op))

        if json_output:
            console.print_json(data={"results": results})
        else:
            for result in results:
                status = str(result["status"])
                message = str(result["message"])
                colour = "green" if status == "available" else "yellow"
                if status in {"corrupt", "error"}:
                    colour = "red"
                console.print(
                    f"[{colour}]backup {result['id']}: {status} - {message}[/{colour}]"
                )

        changed = sum(
            1
            for result in results
            if result.get("previous_status") != result.get("status")
        )
        summary_message = "Backup verification completed."
        if any(result["status"] in {"corrupt", "error"} for result in results):
            op.warning(
                summary_message,
                warnings=["verification issues detected"],
                changed=changed,
                context={"results": results},
            )
            raise typer.Exit(code=3)

        op.success(summary_message, changed=changed, context={"results": results})


@backups_app.command("reconcile")
def backup_reconcile(
    ctx: typer.Context,
    instance: str | None = typer.Option(
        None,
        "--instance",
        "-i",
        help="Limit reconciliation to a specific instance.",
    ),
    apply_changes: bool = typer.Option(
        False,
        "--apply",
        help="Update index metadata for missing archives.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit reconciliation results as JSON.",
    ),
) -> None:
    """Compare backup index entries with on-disk archives."""
    runtime = _get_runtime(ctx)
    instance_filter = instance.strip() if instance and instance.strip() else None
    with runtime.logger.operation(
        "backup reconcile",
        args={
            "instance": instance_filter,
            "apply": apply_changes,
            "json": json_output,
        },
        target={"kind": "backup", "scope": "reconcile"},
    ) as op:
        try:
            entries = runtime.backups.list_entries()
        except BackupRegistryError as exc:
            console.print(f"[red]{exc}[/red]")
            op.error("Failed to read backup index.", errors=[str(exc)], rc=2)
            raise typer.Exit(code=2) from exc

        filtered_entries = [
            entry
            for entry in entries
            if not instance_filter
            or str(entry.get("instance", "")).strip() == instance_filter
        ]

        existing_path_map: dict[str, dict[str, object]] = {}
        missing: list[dict[str, object]] = []
        mismatched: list[dict[str, object]] = []
        updates_applied = 0
        reconciled_at = _iso_now()

        for entry in filtered_entries:
            entry_id = str(entry.get("id", "")).strip()
            path_value = entry.get("path")
            entry_path = Path(str(path_value)).expanduser() if path_value else None
            status_value = str(entry.get("status", "") or "")
            if entry_path is None:
                missing.append({"id": entry_id, "reason": "no-path"})
                continue
            normalized_path = str(entry_path)
            existing_path_map[normalized_path] = entry
            if not entry_path.exists():
                missing.append({"id": entry_id, "path": normalized_path})
                if apply_changes:
                    def mutator(payload: dict[str, object]) -> None:
                        payload["status"] = "missing"
                        metadata = payload.get("metadata")
                        metadata_map = dict(metadata) if isinstance(metadata, Mapping) else {}
                        metadata_map["reconciled_at"] = reconciled_at
                        metadata_map["reconcile_reason"] = "archive-missing"
                        payload["metadata"] = metadata_map

                    runtime.backups.update_entry(entry_id, mutator)
                    updates_applied += 1
                continue
            if status_value in {"missing", "removed"}:
                mismatched.append(
                    {"id": entry_id, "path": normalized_path, "status": status_value}
                )

        archives_on_disk = _discover_backup_archives(runtime.backups.root, instance_filter)
        orphaned: list[dict[str, object]] = []
        for archive_path in archives_on_disk:
            normalized_path = str(archive_path)
            if normalized_path in existing_path_map:
                continue
            try:
                relative = archive_path.relative_to(runtime.backups.root)
                instance_name = relative.parts[0] if relative.parts else ""
            except ValueError:
                instance_name = ""
            orphaned.append(
                {
                    "path": normalized_path,
                    "instance": instance_name,
                    "size_bytes": archive_path.stat().st_size,
                }
            )

        result_payload = {
            "missing": missing,
            "mismatched": mismatched,
            "orphaned": orphaned,
            "updates_applied": updates_applied,
        }

        if json_output:
            console.print_json(data=result_payload)
        else:
            if not missing and not mismatched and not orphaned:
                console.print("[green]No backup discrepancies detected.[/green]")
            else:
                if missing:
                    console.print("[yellow]Missing archives:[/yellow]")
                    for item in missing:
                        path_or_reason = item.get("path") or item.get("reason")
                        console.print(f"  - {item.get('id')} ({path_or_reason})")
                if mismatched:
                    console.print("[yellow]Index status mismatches:[/yellow]")
                    for item in mismatched:
                        console.print(
                            f"  - {item['id']} ({item['path']}) recorded status={item['status']}"
                        )
                if orphaned:
                    console.print("[yellow]Orphaned archives (not in index):[/yellow]")
                    for item in orphaned:
                        console.print(
                            f"  - {item['path']} (instance={item.get('instance','') or 'unknown'})"
                        )
                if apply_changes and updates_applied:
                    console.print(
                        f"[green]Updated {updates_applied} index entr"
                        "ies with status=missing.[/green]"
                    )

        op.success(
            "Backup reconciliation completed.",
            changed=updates_applied,
            context=result_payload,
        )


@backups_app.command("prune")
def backup_prune(
    ctx: typer.Context,
    instance: str | None = typer.Option(
        None,
        "--instance",
        "-i",
        help="Limit pruning to a specific instance.",
    ),
    keep: int | None = typer.Option(
        None,
        "--keep",
        "-k",
        help="Retain the most recent N backups per instance.",
    ),
    older_than: int | None = typer.Option(
        None,
        "--older-than",
        help="Prune backups older than the specified number of days.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview the prune actions without deleting archives.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit prune results as JSON.",
    ),
) -> None:
    """Remove old backups based on retention policies."""
    if keep is None and older_than is None:
        console.print("[red]Provide --keep and/or --older-than criteria for pruning.[/red]")
        raise typer.Exit(code=2)
    if keep is not None and keep < 0:
        console.print("[red]--keep must be zero or a positive integer.[/red]")
        raise typer.Exit(code=2)

    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "backup prune",
        args={
            "instance": instance,
            "keep": keep,
            "older_than": older_than,
            "dry_run": dry_run,
            "json": json_output,
        },
        target={"kind": "backup", "scope": "prune", "instance": instance},
    ) as op:
        try:
            if instance:
                raw_entries: Sequence[Mapping[str, object]] = runtime.backups.entries_for_instance(
                    instance
                )
            else:
                raw_entries = runtime.backups.list_entries()
        except BackupRegistryError as exc:
            console.print(f"[red]{exc}[/red]")
            op.error(str(exc), errors=[str(exc)], rc=2)
            raise typer.Exit(code=2) from exc

        entries = [dict(entry) for entry in raw_entries]

        groups: dict[str, list[dict[str, object]]] = defaultdict(list)
        for entry in entries:
            groups[str(entry.get("instance", ""))].append(dict(entry))

        threshold = None
        if older_than is not None:
            threshold = datetime.now(tz=UTC) - timedelta(days=older_than)

        candidates: dict[str, dict[str, object]] = {}
        for _, inst_entries in groups.items():
            inst_entries.sort(
                key=lambda e: _parse_iso_datetime(e.get("created_at"))
                or datetime.min.replace(tzinfo=UTC),
                reverse=True,
            )
            if keep is not None:
                for index, entry in enumerate(inst_entries):
                    if index >= keep:
                        candidates[str(entry.get("id"))] = entry
            if threshold is not None:
                for entry in inst_entries:
                    created_at = _parse_iso_datetime(entry.get("created_at"))
                    if created_at and created_at < threshold:
                        candidates[str(entry.get("id"))] = entry

        if not candidates:
            message = "No backups matched prune criteria."
            console.print(f"[yellow]{message}[/yellow]")
            op.success(message, changed=0, context={"results": []})
            return

        ordered_candidates = sorted(
            candidates.values(),
            key=lambda e: _parse_iso_datetime(e.get("created_at"))
            or datetime.min.replace(tzinfo=UTC),
        )

        results: list[dict[str, object]] = []
        removed_ids: list[str] = []
        failures: list[str] = []

        for entry in ordered_candidates:
            backup_id = str(entry.get("id", ""))
            archive_value = entry.get("path")
            archive_path = Path(str(archive_value)) if archive_value else None
            checksum_path = (
                archive_path.with_name(f"{archive_path.name}.sha256")
                if archive_path is not None
                else None
            )
            result: dict[str, object] = {
                "id": backup_id,
                "instance": entry.get("instance"),
            }

            if dry_run:
                result["status"] = "planned"
                results.append(result)
                op.add_step("backup.prune.plan", status="info", detail=f"{backup_id}")
                continue

            deletion_errors: list[str] = []
            removed_artifacts: list[str] = []

            if archive_path is not None and archive_path.exists():
                try:
                    archive_path.unlink()
                    removed_artifacts.append(str(archive_path))
                except OSError as exc:
                    deletion_errors.append(f"archive: {exc}")
            else:
                removed_artifacts.append("archive-missing")

            if checksum_path is not None and checksum_path.exists():
                try:
                    checksum_path.unlink()
                    removed_artifacts.append(str(checksum_path))
                except OSError as exc:
                    deletion_errors.append(f"checksum: {exc}")
            elif checksum_path is not None:
                removed_artifacts.append("checksum-missing")

            if deletion_errors:
                failures.append(backup_id)
                result.update({"status": "error", "errors": deletion_errors})
                error_detail = f"{backup_id}:{'; '.join(deletion_errors)}"
                op.add_step("backup.prune", status="error", detail=error_detail)
                results.append(result)
                continue

            removed_at_value = _iso_now()

            def mutator(
                payload: dict[str, object], *, timestamp: str = removed_at_value
            ) -> None:
                payload["status"] = "removed"
                payload["removed_at"] = timestamp

            runtime.backups.update_entry(backup_id, mutator)
            op.add_step("backup.prune", status="success", detail=f"{backup_id}:removed")

            result.update({
                "status": "removed",
                "removed_at": removed_at_value,
                "artifacts": removed_artifacts,
            })
            removed_ids.append(backup_id)
            results.append(result)

        if json_output:
            console.print_json(data={"results": results})
        else:
            for result in results:
                status = result["status"]
                colour = "green" if status == "removed" else "yellow"
                if status == "error":
                    colour = "red"
                console.print(f"[{colour}]backup {result['id']}: {status}[/{colour}]")

        if failures:
            op.error(
                "Backup prune completed with errors.",
                errors=[f"failed: {', '.join(failures)}"],
                rc=3,
                context={"results": results},
            )
            raise typer.Exit(code=3)

        message = "Backup prune dry-run completed." if dry_run else "Backup prune completed."
        op.success(
            message,
            changed=0 if dry_run else len(removed_ids),
            context={"results": results},
        )


@backups_app.command("restore")
def backup_restore(
    ctx: typer.Context,
    backup_id: str = typer.Argument(..., help="Backup identifier to restore."),
    instance: str | None = typer.Option(
        None,
        "--instance",
        "-i",
        help="Assert the backup belongs to this instance before restoring.",
    ),
    destination: Path | None = RESTORE_DEST_OPTION,
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview the restore actions without touching the filesystem.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit the restore plan/result as JSON.",
    ),
    no_pre_backup: bool = NO_PRE_BACKUP_OPTION,
    backup_message: str | None = typer.Option(
        None,
        "--backup-message",
        help="Annotate the optional pre-restore backup with a custom message.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Auto-confirm prompts (non-interactive mode).",
    ),
) -> None:
    """Restore the specified backup archive (skeleton implementation)."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "backup restore",
        args={
            "id": backup_id,
            "instance": instance,
            "dest": str(destination) if destination else None,
            "dry_run": dry_run,
            "json": json_output,
            "no_pre_backup": no_pre_backup,
        },
        target={"kind": "backup", "id": backup_id},
    ) as op:
        try:
            entry = runtime.backups.find_by_id(backup_id)
        except BackupRegistryError as exc:
            console.print(f"[red]{exc}[/red]")
            op.error(str(exc), errors=[str(exc)], rc=2)
            raise typer.Exit(code=2) from exc

        if entry is None:
            _command_error(op, f"Backup '{backup_id}' is not registered.", rc=2)

        backup_instance = str(entry.get("instance", "")).strip()
        if not backup_instance:
            _command_error(op, "Backup entry is missing the instance name.", rc=2)

        if instance and instance.strip() and instance.strip() != backup_instance:
            message = (
                f"Backup '{backup_id}' belongs to instance '{backup_instance}',"
                f" not '{instance}'."
            )
            _command_error(op, message, rc=2)

        archive_path_value = entry.get("path")
        if not archive_path_value:
            message = "Backup entry does not record an archive path."
            console.print(f"[red]{message}[/red]")
            op.error(message, errors=[message], rc=2)
            raise typer.Exit(code=2)

        archive_path = Path(str(archive_path_value)).expanduser()
        if not archive_path.exists():
            message = f"Archive {archive_path} not found."
            console.print(f"[red]{message}[/red]")
            op.error(message, errors=[message], rc=2)
            raise typer.Exit(code=2)

        algorithm = _infer_backup_algorithm(entry, archive_path)
        data_only = _is_data_only(entry)
        checksum_map = entry.get("checksum") if isinstance(entry.get("checksum"), Mapping) else {}
        expected_checksum = ""
        if isinstance(checksum_map, Mapping):
            expected_checksum = str(checksum_map.get("value", "") or "")

        computed_checksum = _compute_checksum(archive_path)
        if expected_checksum and computed_checksum != expected_checksum:
            message = (
                "Checksum mismatch: archive contents differ from the recorded checksum."
            )
            console.print(f"[red]{message}[/red]")
            op.error(message, errors=[message], rc=2)
            raise typer.Exit(code=2)

        archive_size = archive_path.stat().st_size
        default_destination = (runtime.config.instance_root / backup_instance).expanduser()
        destination_dir = (destination or default_destination).expanduser()
        destination_parent = destination_dir.parent

        try:
            destination_is_live = destination_dir.resolve() == default_destination.resolve()
        except FileNotFoundError:
            destination_is_live = destination_dir == default_destination

        required_space = max(int(archive_size * 2.0), 50 * 1024 * 1024)
        try:
            _ensure_disk_space_available(destination_parent, required_space)
        except BackupError as exc:
            console.print(f"[red]{exc}[/red]")
            op.error(str(exc), errors=[str(exc)], rc=2)
            raise typer.Exit(code=2) from exc

        plan_actions: list[str] = [
            "verify-checksum",
            "extract-archive",
            "swap-data",
        ]
        if destination_is_live and not data_only:
            plan_actions.append("restore-service-assets")
        if destination_is_live:
            plan_actions.append("restart-service")

        plan: dict[str, object] = {
            "id": backup_id,
            "instance": backup_instance,
            "archive": str(archive_path),
            "algorithm": algorithm,
            "checksum": expected_checksum or computed_checksum,
            "destination": str(destination_dir),
            "data_only": data_only,
            "status": "planned" if dry_run else "pending",
            "actions": plan_actions,
            "metadata": entry.get("metadata", {}),
        }

        try:
            with runtime.locks.mutate_instances([backup_instance]) as bundle:
                op.set_lock_wait_ms(bundle.wait_ms)
                instance_entry = _require_instance(runtime, backup_instance, op)
                initial_status = str(instance_entry.get("status", "") or "").lower()
                should_restart = destination_is_live and initial_status in {"running"}

            created_backups: list[str] = []

            def _handle_pre_restore(scope: OperationScope) -> None:
                ids = _run_instance_backups(
                    runtime,
                    [backup_instance],
                    operation="backup restore",
                    backup_message=backup_message,
                    op=scope,
                    acquire_locks=False,
                )
                created_backups.extend(ids)

            _maybe_prompt_backup(
                operation="backup restore",
                op=op,
                skip_backup=no_pre_backup,
                auto_confirm=yes,
                backup_message=backup_message,
                on_accept=_handle_pre_restore,
            )

            if created_backups:
                plan["pre_restore_backups"] = list(created_backups)
                op.add_step(
                    "backup.restore.pre_backup",
                    status="success",
                    detail=",".join(created_backups),
                )

            op.add_step("backup.restore.plan", status="info", detail=str(plan))

            if dry_run:
                plan["status"] = "planned"
                if json_output:
                    console.print_json(data={"plan": plan})
                else:
                    console.print("[yellow]Dry run[/yellow]: restore plan follows:")
                    console.print(plan)
                op.success("Backup restore dry-run completed.", changed=0, context={"plan": plan})
                return
            timestamp = datetime.now(UTC)
            suffix = _format_restore_suffix(timestamp)
            try:
                staging_root_path = tempfile.mkdtemp(
                    prefix=f".abssctl-restore-{backup_id}-",
                    dir=str(destination_parent),
                )
            except (FileNotFoundError, PermissionError):
                staging_root_path = tempfile.mkdtemp(
                    prefix=f".abssctl-restore-{backup_id}-",
                )
            staging_root = Path(staging_root_path)
            data_backup_dir: Path | None = None
            file_backups: list[tuple[Path, Path]] = []
            restore_changed = 0
            try:
                payload_root = _extract_backup_archive(
                    archive_path,
                    algorithm=algorithm,
                    staging_root=staging_root,
                    expected_root=backup_id,
                )
                op.add_step(
                    "backup.restore.extract",
                    status="success",
                    detail=str(payload_root),
                )

                data_source = payload_root / "data"
                if not data_source.exists():
                    raise BackupError("Backup archive is missing the 'data' directory.")

                if destination_is_live:
                    try:
                        stop_result = runtime.systemd_provider.stop(backup_instance)
                        op.add_step(
                            "systemd.stop",
                            status="success",
                            detail=_format_systemd_detail(stop_result, dry_run=False),
                        )
                    except SystemdError as exc:
                        op.add_step(
                            "systemd.stop",
                            status="warning",
                            detail=str(exc),
                        )

                destination_parent.mkdir(parents=True, exist_ok=True)
                if destination_dir.exists():
                    backup_suffix = f"{destination_dir.name}.pre-restore-{suffix}"
                    data_backup_dir = destination_dir.parent / backup_suffix
                    destination_dir.rename(data_backup_dir)
                    op.add_step(
                        "backup.restore.stage.original",
                        status="success",
                        detail=str(data_backup_dir),
                    )

                copy_into(data_source, destination_dir)
                restore_changed += 1
                op.add_step(
                    "backup.restore.copy.data",
                    status="success",
                    detail=f"{data_source} -> {destination_dir}",
                )

                payload_snapshot = _load_backup_instance_snapshot(payload_root)

                if destination_is_live and not data_only:
                    systemd_dir = payload_root / "systemd"
                    if systemd_dir.exists():
                        for item in systemd_dir.iterdir():
                            if not item.is_file():
                                continue
                            unit_parent = runtime.systemd_provider.unit_path(backup_instance).parent
                            dest_path = unit_parent / item.name
                            _backup_and_copy_file(
                                item,
                                dest_path,
                                timestamp=timestamp,
                                label="systemd",
                                op=op,
                                backups=file_backups,
                            )
                            restore_changed += 1
                    nginx_dir = payload_root / "nginx"
                    if nginx_dir.exists():
                        for item in nginx_dir.iterdir():
                            if not item.is_file():
                                continue
                            nginx_parent = runtime.nginx_provider.site_path(backup_instance).parent
                            dest_path = nginx_parent / item.name
                            _backup_and_copy_file(
                                item,
                                dest_path,
                                timestamp=timestamp,
                                label="nginx",
                                op=op,
                                backups=file_backups,
                            )
                            restore_changed += 1

                if destination_is_live and not data_only:
                    try:
                        runtime.nginx_provider.enable(backup_instance)
                        op.add_step(
                            "nginx.enable",
                            status="success",
                            detail=str(runtime.nginx_provider.enabled_path(backup_instance)),
                        )
                        validation = runtime.nginx_provider.test_config()
                        op.add_step(
                            "nginx.validate",
                            status="success",
                            detail=_format_nginx_detail(validation),
                        )
                        reload_result = runtime.nginx_provider.reload()
                        op.add_step(
                            "nginx.reload",
                            status="success",
                            detail=_format_nginx_detail(reload_result),
                        )
                    except NginxError as exc:
                        raise BackupError(f"Failed to validate nginx configuration: {exc}") from exc

                final_status = "stopped"
                if destination_is_live:
                    try:
                        enable_result = runtime.systemd_provider.enable(backup_instance)
                        op.add_step(
                            "systemd.enable",
                            status="success",
                            detail=_format_systemd_detail(enable_result, dry_run=False),
                        )
                    except SystemdError as exc:
                        op.add_step(
                            "systemd.enable",
                            status="warning",
                            detail=str(exc),
                        )
                    if should_restart:
                        try:
                            start_result = runtime.systemd_provider.start(backup_instance)
                            op.add_step(
                                "systemd.start",
                                status="success",
                                detail=_format_systemd_detail(start_result, dry_run=False),
                            )
                            final_status = "running"
                        except SystemdError as exc:
                            raise BackupError(f"Failed to restart systemd unit: {exc}") from exc
                    else:
                        final_status = initial_status or "enabled"
                        op.add_step(
                            "systemd.start",
                            status="skipped",
                            detail="service not restarted",
                        )
                else:
                    final_status = initial_status or "unknown"

                restored_at = _iso_now()
                plan["status"] = "restored"
                plan["restored_at"] = restored_at
                plan["final_status"] = final_status

                registry_updates: dict[str, object] = {}
                for key in ("version", "domain", "port", "paths"):
                    value = payload_snapshot.get(key)
                    if value is not None:
                        registry_updates[key] = value
                registry_updates["status"] = final_status
                metadata_updates: dict[str, object] = {
                    "last_restored_at": restored_at,
                    "last_restore_source": backup_id,
                    "last_restore_destination": str(destination_dir),
                }
                actor_value = op.actor
                if isinstance(actor_value, Mapping):
                    metadata_updates["last_restore_actor"] = dict(actor_value)

                _update_instance_registry(
                    runtime,
                    backup_instance,
                    registry_updates,
                    metadata=metadata_updates,
                )

                metadata_raw = entry.get("metadata")
                if isinstance(metadata_raw, Mapping):
                    restore_metadata: dict[str, object] = {
                        str(key): value for key, value in metadata_raw.items()
                    }
                else:
                    restore_metadata = {}
                restore_metadata["last_restore_destination"] = str(destination_dir)
                restore_metadata["last_restored_at"] = restored_at
                if isinstance(actor_value, Mapping):
                    restore_metadata["last_restore_actor"] = dict(actor_value)
                restore_metadata.pop("verification_error", None)

                def mutator(payload: dict[str, object]) -> None:
                    payload["last_restored_at"] = restored_at
                    payload["status"] = payload.get("status") or "available"
                    payload["metadata"] = dict(restore_metadata)

                runtime.backups.update_entry(backup_id, mutator)

                if data_backup_dir and destination_dir.exists():
                    shutil.rmtree(data_backup_dir, ignore_errors=True)
                for _dest_path, backup_path in file_backups:
                    backup_path.unlink(missing_ok=True)

                console.print(
                    f"[green]Restored backup '{backup_id}' to {destination_dir} "
                    f"(instance {backup_instance}).[/green]"
                )
                result_payload = {
                    "plan": plan,
                    "restored_at": restored_at,
                    "restart_performed": should_restart,
                    "destination": str(destination_dir),
                }
                if json_output:
                    console.print_json(data=result_payload)
                op.success(
                    "Backup restore completed.",
                    changed=restore_changed,
                    context=result_payload,
                )
            except Exception:
                if destination_dir.exists() and data_backup_dir is not None:
                    shutil.rmtree(destination_dir, ignore_errors=True)
                if data_backup_dir is not None and data_backup_dir.exists():
                    data_backup_dir.rename(destination_dir)
                for _dest_path, backup_path in file_backups:
                    if backup_path.exists():
                        shutil.copy2(backup_path, _dest_path)
                        backup_path.unlink(missing_ok=True)
                raise
            finally:
                shutil.rmtree(staging_root, ignore_errors=True)
        except BackupError as exc:
            console.print(f"[red]Restore failed: {exc}[/red]")
            op.error("Backup restore failed.", errors=[str(exc)], rc=4)
            raise typer.Exit(code=4) from exc
        except Exception as exc:
            console.print(f"[red]Unexpected restore failure: {exc}[/red]")
            op.error("Backup restore failed unexpectedly.", errors=[str(exc)], rc=4)
            raise typer.Exit(code=4) from exc
@instances_app.command("logs")
def instance_logs(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Name of the instance to read logs for."),
    lines: int | None = typer.Option(
        None,
        "--lines",
        "-n",
        min=1,
        help="Show the last N log lines (default: systemd journal default).",
    ),
    since: str | None = typer.Option(
        None,
        "--since",
        help="Show logs since the given timestamp (passed to journalctl).",
    ),
) -> None:
    """Tail the systemd journal for an instance."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "instance logs",
        args={"name": name, "lines": lines, "since": since},
        target={"kind": "instance", "name": name},
    ) as op:
        _require_instance(runtime, name, op)
        try:
            result = runtime.systemd_provider.logs(
                name,
                lines=lines,
                since=since,
                follow=False,
            )
        except SystemdError as exc:
            _provider_error(op, f"systemd logs failed: {exc}")

        op.add_step(
            "systemd.logs",
            status="success",
            detail=_format_systemd_detail(result, dry_run=False),
        )

        stdout = (getattr(result, "stdout", "") or "").rstrip()
        stderr = (getattr(result, "stderr", "") or "").rstrip()
        if stdout:
            console.print(stdout)
        if stderr:
            console.print(stderr, style="red")

        _record_instance_state(
            runtime,
            name,
            metadata={"last_logs_at": datetime.now(UTC).isoformat()},
            update_last_changed=False,
        )

        op.success("Fetched instance logs.", changed=0)
@instances_app.command("env")
def instance_env(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Instance to describe."),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit environment variables as JSON object.",
    ),
) -> None:
    """Print environment variables for an instance."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "instance env",
        args={"name": name, "json": json_output},
        target={"kind": "instance", "name": name},
    ) as op:
        entry = _require_instance(runtime, name, op)
        paths = _instance_paths_from_entry(runtime.config, name, entry)
        config_payload = _read_instance_config(paths)

        port_value: object = entry.get("port")
        if port_value in (None, "", 0):
            reserved = runtime.ports.get_port(name)
            port_value = reserved if reserved is not None else config_payload.get("port")
        port_int = _coerce_port(port_value, runtime.config.ports.base)

        domain_value = str(entry.get("domain") or "").strip()
        if not domain_value:
            instance_section = config_payload.get("instance")
            if isinstance(instance_section, Mapping):
                domain_value = str(instance_section.get("domain", "")).strip()
        if not domain_value:
            domain_value = _default_instance_domain(runtime.config, name)

        version_value = (
            str(entry.get("version") or "").strip()
            or runtime.config.default_version
        )

        exec_path = _resolve_exec_path(runtime, version_value)
        systemd_context = _build_systemd_context(
            runtime.config,
            name,
            port=port_int,
            domain=domain_value,
            paths=paths,
            exec_path=exec_path,
            version=version_value,
        )
        env_raw = systemd_context.get("environment", [])
        env_list = list(env_raw) if isinstance(env_raw, list) else []
        env_mapping: dict[str, str] = {}
        for item in env_list:
            if not isinstance(item, str):
                continue
            key, _, value = item.partition("=")
            env_mapping[key] = value

        op.add_step("environment.build", status="success", detail=str(len(env_mapping)))

        if json_output:
            console.print_json(data=env_mapping)
        else:
            for key, value in sorted(env_mapping.items()):
                console.print(f"{key}={value}")

        op.success("Reported instance environment variables.", changed=0)


@instances_app.command("set-fqdn")
def instance_set_fqdn(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Instance to update."),
    fqdn: str = typer.Argument(..., help="New fully qualified domain name."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Report the actions that would be taken without applying changes.",
    ),
    no_backup: bool = typer.Option(
        False,
        "--no-backup",
        help="Skip the safety prompt to run a backup before continuing.",
    ),
    backup_message: str | None = typer.Option(
        None,
        "--backup-message",
        help="Annotate the recommended backup with a custom message.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Auto-confirm backup prompts (non-interactive mode).",
    ),
) -> None:
    """Update the instance domain and re-render nginx assets."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "instance set-fqdn",
        args={"name": name, "fqdn": fqdn, "dry_run": dry_run},
        target={"kind": "instance", "name": name},
    ) as op:
        new_domain: str
        try:
            new_domain = _validate_domain(fqdn)
        except ValueError as exc:
            _command_error(op, str(exc), rc=2)

        with runtime.locks.mutate_instances([name]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            entry = _require_instance(runtime, name, op)
            current_domain = str(entry.get("domain") or "").strip()
            if current_domain == new_domain:
                console.print("[yellow]Domain unchanged; nothing to do.[/yellow]")
                op.success("Domain unchanged.", changed=0)
                return

            paths = _instance_paths_from_entry(runtime.config, name, entry)
            config_payload = _read_instance_config(paths)
            port_value: object = entry.get("port")
            if port_value in (None, "", 0):
                port_value = runtime.ports.get_port(name)
            port_int = _coerce_port(port_value, runtime.config.ports.base)

            if dry_run:
                op.add_step("backup.prompt", status="skipped", detail="dry-run")
                op.add_step("config.write", status="skipped", detail="dry-run")
                op.add_step("nginx.render_site", status="skipped", detail="dry-run")
                op.add_step("registry.update", status="skipped", detail="dry-run")
                console.print(
                    f"[yellow]Dry run[/yellow]: Instance '{name}' domain would be updated "
                    f"from '{current_domain or '(default)'}' to '{new_domain}'."
                )
                op.success("Domain update dry-run complete.", changed=0)
                return

            _maybe_prompt_backup(
                operation="instance set-fqdn",
                op=op,
                skip_backup=no_backup,
                auto_confirm=yes,
                backup_message=backup_message,
                on_accept=lambda scope: None,
            )

            instance_section = config_payload.setdefault("instance", {})
            if not isinstance(instance_section, dict):
                instance_section = {}
                config_payload["instance"] = instance_section
            instance_section["domain"] = new_domain

            server_section = config_payload.setdefault("server", {})
            if not isinstance(server_section, dict):
                server_section = {}
                config_payload["server"] = server_section
            upstream = server_section.setdefault("upstream", {})
            if not isinstance(upstream, dict):
                upstream = {}
                server_section["upstream"] = upstream
            upstream["port"] = port_int
            upstream.setdefault("host", "127.0.0.1")
            server_section["public_url"] = f"https://{new_domain}"
            server_section.setdefault(
                "version",
                entry.get("version", runtime.config.default_version),
            )

            _write_instance_config(paths, config_payload)
            op.add_step("config.write", status="success", detail=str(paths.config_file))

            entry_for_nginx = dict(entry)
            entry_for_nginx["domain"] = new_domain
            entry_for_nginx["port"] = port_int
            try:
                nginx_context = _build_nginx_context(
                    runtime,
                    name,
                    domain=new_domain,
                    port=port_int,
                    entry=entry_for_nginx,
                )
            except TLSConfigurationError as exc:
                _provider_error(op, f"TLS configuration invalid for '{name}': {exc}")
            nginx_result = runtime.nginx_provider.render_site(name, nginx_context)
            if nginx_result.validation_error:
                _provider_error(
                    op,
                    f"nginx validation failed for '{name}': {nginx_result.validation_error}",
                )
            op.add_step(
                "nginx.render_site",
                status="success" if nginx_result.changed else "noop",
                detail=str(runtime.nginx_provider.site_path(name)),
            )
            if nginx_result.validation is not None:
                op.add_step(
                    "nginx.validate",
                    status="success",
                    detail=_format_nginx_detail(nginx_result.validation),
                )
            if nginx_result.reload is not None:
                op.add_step(
                    "nginx.reload",
                    status="success",
                    detail=_format_nginx_detail(nginx_result.reload),
                )

            runtime.nginx_provider.enable(name)
            op.add_step(
                "nginx.enable",
                status="success",
                detail=str(runtime.nginx_provider.enabled_path(name)),
            )

            _record_instance_state(
                runtime,
                name,
                domain=new_domain,
                metadata={"domain_changed_at": datetime.now(UTC).isoformat()},
                nginx_enabled=True,
            )
            op.add_step("registry.update", status="success", detail=f"domain={new_domain}")

            console.print(
                f"[green]Updated domain for instance '{name}' to {new_domain}.[/green]"
            )
            op.success("Instance domain updated.", changed=3)
@instances_app.command("set-port")
def instance_set_port(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Instance to update."),
    port: int = typer.Argument(..., min=1, help="New port to bind to Actual."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Report the actions that would be taken without applying changes.",
    ),
    no_backup: bool = typer.Option(
        False,
        "--no-backup",
        help="Skip the safety prompt to run a backup before continuing.",
    ),
    backup_message: str | None = typer.Option(
        None,
        "--backup-message",
        help="Annotate the recommended backup with a custom message.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Auto-confirm backup prompts (non-interactive mode).",
    ),
) -> None:
    """Update the instance port, re-render providers, and restart if needed."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "instance set-port",
        args={"name": name, "port": port, "dry_run": dry_run},
        target={"kind": "instance", "name": name},
    ) as op:
        if port < runtime.config.ports.base:
            message = (
                f"Port {port} is below the configured base {runtime.config.ports.base}."
            )
            _command_error(op, message, rc=2)

        with runtime.locks.mutate_instances([name]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            entry = _require_instance(runtime, name, op)

            current_port_raw: object = entry.get("port")
            if current_port_raw in (None, "", 0):
                current_port_raw = runtime.ports.get_port(name)
            current_port = _coerce_port(current_port_raw, runtime.config.ports.base)

            if current_port == port:
                console.print("[yellow]Port unchanged; nothing to do.[/yellow]")
                op.success("Port unchanged.", changed=0)
                return

            existing_ports = runtime.ports.list_entries()
            conflict = next(
                (item for item in existing_ports if item["port"] == port and item["name"] != name),
                None,
            )
            if conflict:
                message = (
                    f"Port {port} is already reserved by instance '{conflict['name']}'."
                )
                _command_error(op, message, rc=2)

            paths = _instance_paths_from_entry(runtime.config, name, entry)
            config_payload = _read_instance_config(paths)
            version_value = (
                str(entry.get("version") or "").strip()
                or runtime.config.default_version
            )
            domain_value = str(entry.get("domain") or "").strip() or _default_instance_domain(
                runtime.config, name
            )

            if dry_run:
                op.add_step("backup.prompt", status="skipped", detail="dry-run")
                op.add_step("ports.release", status="skipped", detail="dry-run")
                op.add_step("ports.reserve", status="skipped", detail="dry-run")
                op.add_step("config.write", status="skipped", detail="dry-run")
                op.add_step("systemd.render_unit", status="skipped", detail="dry-run")
                op.add_step("nginx.render_site", status="skipped", detail="dry-run")
                op.add_step("registry.update", status="skipped", detail="dry-run")
                console.print(
                    f"[yellow]Dry run[/yellow]: Instance '{name}' would be moved from port "
                    f"{current_port} to {port}."
                )
                op.success("Port update dry-run complete.", changed=0)
                return

            _maybe_prompt_backup(
                operation="instance set-port",
                op=op,
                skip_backup=no_backup,
                auto_confirm=yes,
                backup_message=backup_message,
                on_accept=lambda scope: None,
            )

            was_running = str(entry.get("status", "")).lower() == "running"

            try:
                stop_result: subprocess.CompletedProcess[str] | None = None
                if was_running:
                    stop_result = runtime.systemd_provider.stop(name)
                    op.add_step(
                        "systemd.stop",
                        status="success",
                        detail=_format_systemd_detail(stop_result, dry_run=False),
                    )
                else:
                    op.add_step("systemd.stop", status="skipped", detail="not-running")

                try:
                    runtime.ports.release(name)
                    op.add_step("ports.release", status="success", detail=str(current_port))
                except PortsRegistryError:
                    op.add_step("ports.release", status="warning", detail="not-found")

                try:
                    runtime.ports.reserve(name, requested_port=port)
                    op.add_step("ports.reserve", status="success", detail=str(port))
                except PortsRegistryError as exc:
                    # Attempt to restore previous reservation before aborting.
                    try:
                        runtime.ports.reserve(name, requested_port=current_port)
                    except PortsRegistryError:
                        pass
                    message = str(exc)
                    _command_error(op, message, rc=2)

                server_section = config_payload.setdefault("server", {})
                if not isinstance(server_section, dict):
                    server_section = {}
                    config_payload["server"] = server_section
                upstream = server_section.setdefault("upstream", {})
                if not isinstance(upstream, dict):
                    upstream = {}
                    server_section["upstream"] = upstream
                upstream["port"] = port
                upstream.setdefault("host", "127.0.0.1")
                _write_instance_config(paths, config_payload)
                op.add_step("config.write", status="success", detail=str(paths.config_file))

                exec_path = _resolve_exec_path(runtime, version_value)
                systemd_context = _build_systemd_context(
                    runtime.config,
                    name,
                    port=port,
                    domain=domain_value,
                    paths=paths,
                    exec_path=exec_path,
                    version=version_value,
                )
                unit_changed = runtime.systemd_provider.render_unit(name, systemd_context)
                op.add_step(
                    "systemd.render_unit",
                    status="success" if unit_changed else "noop",
                    detail=str(runtime.systemd_provider.unit_path(name)),
                )

                entry_for_nginx = dict(entry)
                entry_for_nginx["port"] = port
                nginx_context = _build_nginx_context(
                    runtime,
                    name,
                    domain=domain_value,
                    port=port,
                    entry=entry_for_nginx,
                )
                nginx_result = runtime.nginx_provider.render_site(name, nginx_context)
                if nginx_result.validation_error:
                    _provider_error(
                        op,
                        f"nginx validation failed for '{name}': {nginx_result.validation_error}",
                    )
                op.add_step(
                    "nginx.render_site",
                    status="success" if nginx_result.changed else "noop",
                    detail=str(runtime.nginx_provider.site_path(name)),
                )
                if nginx_result.validation is not None:
                    op.add_step(
                        "nginx.validate",
                        status="success",
                        detail=_format_nginx_detail(nginx_result.validation),
                    )
                if nginx_result.reload is not None:
                    op.add_step(
                        "nginx.reload",
                        status="success",
                        detail=_format_nginx_detail(nginx_result.reload),
                    )
                runtime.nginx_provider.enable(name)
                op.add_step(
                    "nginx.enable",
                    status="success",
                    detail=str(runtime.nginx_provider.enabled_path(name)),
                )

                if was_running:
                    start_result = runtime.systemd_provider.start(name)
                    op.add_step(
                        "systemd.start",
                        status="success",
                        detail=_format_systemd_detail(start_result, dry_run=False),
                    )
                    final_status = "running"
                else:
                    final_status = str(entry.get("status", "enabled") or "enabled")
                    op.add_step("systemd.start", status="skipped", detail="not-running")

                metadata_updates = {"port_changed_at": datetime.now(UTC).isoformat()}
                _record_instance_state(
                    runtime,
                    name,
                    status=final_status,
                    port=port,
                    domain=domain_value,
                    systemd_state="running" if final_status == "running" else final_status,
                    systemd_enabled=final_status != "disabled",
                    nginx_enabled=True,
                    metadata=metadata_updates,
                )
                op.add_step("registry.update", status="success", detail=f"port={port}")

                console.print(
                    "[green]Updated port for instance "
                    f"'{name}' from {current_port} to {port}.[/green]"
                )
                op.success("Instance port updated.", changed=6 if was_running else 5)
            except (SystemdError, NginxError, TLSConfigurationError) as exc:
                _provider_error(op, f"Port update failed: {exc}")
@instances_app.command("set-version")
def instance_set_version(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Instance to update."),
    version: str = typer.Argument(..., help="Version identifier or 'current'."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Report the actions that would be taken without applying changes.",
    ),
    no_backup: bool = typer.Option(
        False,
        "--no-backup",
        help="Skip the safety prompt to run a backup before continuing.",
    ),
    backup_message: str | None = typer.Option(
        None,
        "--backup-message",
        help="Annotate the recommended backup with a custom message.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Auto-confirm backup prompts (non-interactive mode).",
    ),
) -> None:
    """Bind the instance to a specific installed version and restart if needed."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "instance set-version",
        args={"name": name, "version": version, "dry_run": dry_run},
        target={"kind": "instance", "name": name},
    ) as op:
        normalized_version = version.strip()
        if not normalized_version:
            message = "Version must be a non-empty string."
            _command_error(op, message, rc=2)

        with runtime.locks.mutate_instances([name]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            entry = _require_instance(runtime, name, op)

            current_version = (
                str(entry.get("version") or "").strip()
                or runtime.config.default_version
            )
            if current_version == normalized_version:
                console.print("[yellow]Version unchanged; nothing to do.[/yellow]")
                op.success("Version unchanged.", changed=0)
                return

            version_entry = None
            if normalized_version != "current":
                version_entry = runtime.registry.get_version(normalized_version)
                if version_entry is None:
                    _command_error(op, f"Version '{normalized_version}' is not registered.", rc=2)

            paths = _instance_paths_from_entry(runtime.config, name, entry)
            config_payload = _read_instance_config(paths)
            port_value: object = entry.get("port")
            if port_value in (None, "", 0):
                port_value = runtime.ports.get_port(name)
            port_int = _coerce_port(port_value, runtime.config.ports.base)
            domain_value = str(entry.get("domain") or "").strip() or _default_instance_domain(
                runtime.config, name
            )

            if dry_run:
                op.add_step("backup.prompt", status="skipped", detail="dry-run")
                op.add_step("config.write", status="skipped", detail="dry-run")
                op.add_step("systemd.render_unit", status="skipped", detail="dry-run")
                op.add_step("systemd.restart", status="skipped", detail="dry-run")
                op.add_step("registry.update", status="skipped", detail="dry-run")
                console.print(
                    f"[yellow]Dry run[/yellow]: Instance '{name}' would switch "
                    f"from version '{current_version}' to '{normalized_version}'."
                )
                op.success("Version update dry-run complete.", changed=0)
                return

            _maybe_prompt_backup(
                operation="instance set-version",
                op=op,
                skip_backup=no_backup,
                auto_confirm=yes,
                backup_message=backup_message,
                on_accept=lambda scope: None,
            )

            was_running = str(entry.get("status", "")).lower() == "running"

            try:
                if was_running:
                    stop_result = runtime.systemd_provider.stop(name)
                    op.add_step(
                        "systemd.stop",
                        status="success",
                        detail=_format_systemd_detail(stop_result, dry_run=False),
                    )
                else:
                    op.add_step("systemd.stop", status="skipped", detail="not-running")

                server_section = config_payload.setdefault("server", {})
                if not isinstance(server_section, dict):
                    server_section = {}
                    config_payload["server"] = server_section
                server_section["version"] = normalized_version
                _write_instance_config(paths, config_payload)
                op.add_step("config.write", status="success", detail=str(paths.config_file))

                exec_path = _resolve_exec_path(runtime, normalized_version)
                systemd_context = _build_systemd_context(
                    runtime.config,
                    name,
                    port=port_int,
                    domain=domain_value,
                    paths=paths,
                    exec_path=exec_path,
                    version=normalized_version,
                )
                unit_changed = runtime.systemd_provider.render_unit(name, systemd_context)
                op.add_step(
                    "systemd.render_unit",
                    status="success" if unit_changed else "noop",
                    detail=str(runtime.systemd_provider.unit_path(name)),
                )

                if was_running:
                    start_result = runtime.systemd_provider.start(name)
                    op.add_step(
                        "systemd.start",
                        status="success",
                        detail=_format_systemd_detail(start_result, dry_run=False),
                    )
                    final_status = "running"
                else:
                    final_status = str(entry.get("status", "enabled") or "enabled")
                    op.add_step("systemd.start", status="skipped", detail="not-running")

                metadata_updates = {"version_changed_at": datetime.now(UTC).isoformat()}
                _record_instance_state(
                    runtime,
                    name,
                    status=final_status,
                    version=normalized_version,
                    systemd_state="running" if final_status == "running" else final_status,
                    systemd_enabled=final_status != "disabled",
                    nginx_enabled=True,
                    metadata=metadata_updates,
                )
                op.add_step(
                    "registry.update",
                    status="success",
                    detail=f"version={normalized_version}",
                )

                console.print(
                    f"[green]Updated version for instance '{name}' to {normalized_version}.[/green]"
                )
                op.success("Instance version updated.", changed=4 if was_running else 3)
            except SystemdError as exc:
                _provider_error(op, f"systemd operation failed: {exc}")


@instances_app.command("rename")
def instance_rename(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Current instance name."),
    new_name: str = typer.Argument(..., help="New instance name."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Report the actions that would be taken without applying changes.",
    ),
    no_backup: bool = typer.Option(
        False,
        "--no-backup",
        help="Skip the safety prompt to run a backup before continuing.",
    ),
    backup_message: str | None = typer.Option(
        None,
        "--backup-message",
        help="Annotate the recommended backup with a custom message.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Auto-confirm backup prompts (non-interactive mode).",
    ),
) -> None:
    """Rename an instance and associated assets."""
    runtime = _get_runtime(ctx)
    with runtime.logger.operation(
        "instance rename",
        args={"name": name, "new_name": new_name, "dry_run": dry_run},
        target={"kind": "instance", "name": name},
    ) as op:
        try:
            validated_new = _validate_instance_name(new_name)
        except ValueError as exc:
            _command_error(op, str(exc), rc=2)

        if validated_new == name:
            console.print("[yellow]Name unchanged; nothing to do.[/yellow]")
            op.success("Name unchanged.", changed=0)
            return

        with runtime.locks.mutate_instances([name, validated_new]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            entry = _require_instance(runtime, name, op)
            if runtime.registry.get_instance(validated_new) is not None:
                _command_error(op, f"Instance '{validated_new}' already exists.", rc=2)

            paths = _instance_paths_from_entry(runtime.config, name, entry)
            default_paths_old = _determine_instance_paths(runtime.config, name, None)
            default_paths_new = _determine_instance_paths(runtime.config, validated_new, None)
            supports_default_layout = (
                paths.root == default_paths_old.root
                and paths.runtime == default_paths_old.runtime
                and paths.logs == default_paths_old.logs
                and paths.state == default_paths_old.state
            )
            if not supports_default_layout:
                message = (
                    "Instance rename currently supports the default filesystem layout only."
                )
                _command_error(op, message, rc=2)

            config_payload = _read_instance_config(paths)
            port_value: object = entry.get("port")
            if port_value in (None, "", 0):
                port_value = runtime.ports.get_port(name)
            port_int = _coerce_port(port_value, runtime.config.ports.base)
            domain_value = str(entry.get("domain") or "").strip() or _default_instance_domain(
                runtime.config, name
            )
            version_value = (
                str(entry.get("version") or "").strip()
                or runtime.config.default_version
            )

            if dry_run:
                op.add_step("backup.prompt", status="skipped", detail="dry-run")
                op.add_step("systemd.stop", status="skipped", detail="dry-run")
                op.add_step("systemd.disable", status="skipped", detail="dry-run")
                op.add_step("nginx.disable", status="skipped", detail="dry-run")
                op.add_step("filesystem.move", status="skipped", detail="dry-run")
                op.add_step("ports.reserve", status="skipped", detail="dry-run")
                op.add_step("registry.rename", status="skipped", detail="dry-run")
                console.print(
                    "[yellow]Dry run[/yellow]: Instance '"
                    f"{name}' would be renamed to '{validated_new}'."
                )
                op.success("Instance rename dry-run complete.", changed=0)
                return

            _maybe_prompt_backup(
                operation="instance rename",
                op=op,
                skip_backup=no_backup,
                auto_confirm=yes,
                backup_message=backup_message,
                on_accept=lambda scope: None,
            )

            was_running = str(entry.get("status", "")).lower() == "running"

            try:
                if was_running:
                    stop_result = runtime.systemd_provider.stop(name)
                    op.add_step(
                        "systemd.stop",
                        status="success",
                        detail=_format_systemd_detail(stop_result, dry_run=False),
                    )
                else:
                    op.add_step("systemd.stop", status="skipped", detail="not-running")

                try:
                    disable_result = runtime.systemd_provider.disable(name)
                    op.add_step(
                        "systemd.disable",
                        status="success",
                        detail=_format_systemd_detail(disable_result, dry_run=False),
                    )
                except SystemdError:
                    op.add_step("systemd.disable", status="warning", detail="not-enabled")

                try:
                    runtime.nginx_provider.disable(name)
                    op.add_step("nginx.disable", status="success")
                except NginxError:
                    op.add_step("nginx.disable", status="warning", detail="not-enabled")

                runtime.systemd_provider.remove(name)
                op.add_step("systemd.remove", status="success")
                runtime.nginx_provider.remove(name)
                op.add_step("nginx.remove", status="success")

                try:
                    runtime.ports.release(name)
                    op.add_step("ports.release", status="success", detail=str(port_int))
                except PortsRegistryError:
                    op.add_step("ports.release", status="warning", detail="not-found")
                try:
                    runtime.ports.reserve(validated_new, requested_port=port_int)
                    op.add_step("ports.reserve", status="success", detail=str(port_int))
                except PortsRegistryError as exc:
                    message = str(exc)
                    _command_error(op, message, rc=2)

                moves: list[tuple[Path, Path]] = [
                    (paths.root, default_paths_new.root),
                    (paths.runtime, default_paths_new.runtime),
                    (paths.logs, default_paths_new.logs),
                    (paths.state, default_paths_new.state),
                ]
                moved_paths: list[str] = []
                for src, dest in moves:
                    if not src.exists():
                        continue
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(src), str(dest))
                    moved_paths.append(f"{src} -> {dest}")

                if moved_paths:
                    op.add_step("filesystem.move", status="success", detail="; ".join(moved_paths))

                instance_section = config_payload.setdefault("instance", {})
                if not isinstance(instance_section, dict):
                    instance_section = {}
                    config_payload["instance"] = instance_section
                instance_section["name"] = validated_new

                paths_section = config_payload.setdefault("paths", {})
                if not isinstance(paths_section, dict):
                    paths_section = {}
                    config_payload["paths"] = paths_section
                paths_section["root"] = str(default_paths_new.root)
                paths_section["data"] = str(default_paths_new.data)
                paths_section["config"] = str(default_paths_new.config_file)

                _write_instance_config(default_paths_new, config_payload)
                op.add_step(
                    "config.write",
                    status="success",
                    detail=str(default_paths_new.config_file),
                )

                exec_path = _resolve_exec_path(runtime, version_value)
                systemd_context = _build_systemd_context(
                    runtime.config,
                    validated_new,
                    port=port_int,
                    domain=domain_value,
                    paths=default_paths_new,
                    exec_path=exec_path,
                    version=version_value,
                )
                runtime.systemd_provider.render_unit(validated_new, systemd_context)
                op.add_step(
                    "systemd.render_unit",
                    status="success",
                    detail=str(runtime.systemd_provider.unit_path(validated_new)),
                )
                runtime.systemd_provider.enable(validated_new)
                op.add_step("systemd.enable", status="success", detail=validated_new)

                entry_for_nginx = dict(entry)
                entry_for_nginx["name"] = validated_new
                entry_for_nginx["domain"] = domain_value
                entry_for_nginx["port"] = port_int
                nginx_context = _build_nginx_context(
                    runtime,
                    validated_new,
                    domain=domain_value,
                    port=port_int,
                    entry=entry_for_nginx,
                )
                nginx_result = runtime.nginx_provider.render_site(validated_new, nginx_context)
                if nginx_result.validation_error:
                    _provider_error(
                        op,
                        (
                            "nginx validation failed for "
                            f"'{validated_new}': {nginx_result.validation_error}"
                        ),
                    )
                op.add_step(
                    "nginx.render_site",
                    status="success" if nginx_result.changed else "noop",
                    detail=str(runtime.nginx_provider.site_path(validated_new)),
                )
                runtime.nginx_provider.enable(validated_new)
                op.add_step(
                    "nginx.enable",
                    status="success",
                    detail=str(runtime.nginx_provider.enabled_path(validated_new)),
                )

                if was_running:
                    start_result = runtime.systemd_provider.start(validated_new)
                    op.add_step(
                        "systemd.start",
                        status="success",
                        detail=_format_systemd_detail(start_result, dry_run=False),
                    )
                    final_status = "running"
                else:
                    final_status = str(entry.get("status", "enabled") or "enabled")
                    op.add_step("systemd.start", status="skipped", detail="not-running")

                raw_instances = runtime.registry.read_instances().get("instances", [])
                entries_iterable = raw_instances if isinstance(raw_instances, list) else []
                updated_instances: list[object] = []
                now_iso = datetime.now(UTC).isoformat()
                for item in entries_iterable:
                    if (
                        isinstance(item, Mapping)
                        and str(item.get("name", "")).strip() == name
                    ):
                        new_entry = dict(item)
                        new_entry["name"] = validated_new
                        new_entry["status"] = final_status
                        new_entry["domain"] = domain_value
                        new_entry["port"] = port_int
                        new_entry["version"] = version_value
                        new_entry["paths"] = {
                            "root": str(default_paths_new.root),
                            "data": str(default_paths_new.data),
                            "config": str(default_paths_new.config_file),
                            "runtime": str(default_paths_new.runtime),
                            "logs": str(default_paths_new.logs),
                            "state": str(default_paths_new.state),
                            "systemd_unit": str(runtime.systemd_provider.unit_path(validated_new)),
                            "nginx_site": str(runtime.nginx_provider.site_path(validated_new)),
                            "nginx_enabled": str(
                                runtime.nginx_provider.enabled_path(validated_new)
                            ),
                        }
                        metadata = dict(new_entry.get("metadata", {}))
                        metadata["renamed_at"] = now_iso
                        metadata["last_changed"] = now_iso
                        metadata["previous_name"] = name
                        new_entry["metadata"] = metadata
                        updated_instances.append(new_entry)
                    else:
                        updated_instances.append(item)

                runtime.registry.write_instances(updated_instances)
                op.add_step(
                    "registry.rename",
                    status="success",
                    detail=f"{name}->{validated_new}",
                )

                _record_instance_state(
                    runtime,
                    validated_new,
                    status=final_status,
                    port=port_int,
                    domain=domain_value,
                    version=version_value,
                    systemd_state="running" if was_running else final_status,
                    systemd_enabled=final_status != "disabled",
                    nginx_enabled=True,
                    metadata={
                        "renamed_at": now_iso,
                        "previous_name": name,
                    },
                )

                console.print(
                    f"[green]Renamed instance '{name}' to '{validated_new}' "
                    f"({'restarted' if was_running else 'stopped'}).[/green]"
                )
                op.success("Instance renamed.", changed=9 if was_running else 8)
            except (SystemdError, NginxError, TLSConfigurationError) as exc:
                _provider_error(op, f"Rename failed: {exc}")
