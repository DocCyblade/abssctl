"""Typer-powered command line scaffold for ``abssctl``.

The Pre-Alpha milestone focuses on wiring foundational structure so later
phases can layer in real functionality without reworking entry points. Each
subcommand currently emits a friendly placeholder message and exits with a
success code to keep automated smoke tests green.
"""
from __future__ import annotations

import json
import textwrap
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import AppConfig, load_config
from .locking import LockManager
from .logging import StructuredLogger
from .providers import (
    InstanceStatusProvider,
    NginxProvider,
    SystemdProvider,
    VersionProvider,
)
from .state import StateRegistry
from .templates import TemplateEngine

console = Console()

CONFIG_FILE_OPTION = typer.Option(
    None,
    "--config-file",
    dir_okay=False,
    help="Override the path to abssctl's YAML config file.",
)

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
    version_provider: VersionProvider
    instance_status_provider: InstanceStatusProvider
    locks: LockManager
    logger: StructuredLogger
    templates: TemplateEngine
    systemd_provider: SystemdProvider
    nginx_provider: NginxProvider


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
    version_cache = registry.root / "remote-versions.json"
    version_provider = VersionProvider(cache_path=version_cache)
    instance_status_provider = InstanceStatusProvider()
    locks = LockManager(config.runtime_dir, config.lock_timeout)
    logger = StructuredLogger(config.logs_dir)
    templates = TemplateEngine.with_overrides(config.templates_dir)
    systemd_provider = SystemdProvider(
        templates=templates,
        logger=logger,
        locks=locks,
        systemd_dir=config.runtime_dir / "systemd",
    )
    nginx_provider = NginxProvider(
        templates=templates,
        sites_available=config.runtime_dir / "nginx" / "sites-available",
        sites_enabled=config.runtime_dir / "nginx" / "sites-enabled",
    )
    runtime = RuntimeContext(
        config=config,
        registry=registry,
        version_provider=version_provider,
        instance_status_provider=instance_status_provider,
        locks=locks,
        logger=logger,
        templates=templates,
        systemd_provider=systemd_provider,
        nginx_provider=nginx_provider,
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
            metadata = {k: v for k, v in entry.items() if k != "version"}
            metadata.setdefault("installed", True)
            metadata.setdefault("source", "registry")
            normalized.append({"version": version, "metadata": metadata})
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


def _build_systemd_context(config: AppConfig, instance: str) -> dict[str, object]:
    install_dir = config.install_root / "current"
    working_directory = config.instance_root / instance
    exec_start = install_dir / "server.js"
    environment = [
        "NODE_ENV=production",
        f"ABSSCTL_INSTANCE={instance}",
    ]
    return {
        "instance_name": instance,
        "service_user": config.service_user,
        "working_directory": str(working_directory),
        "exec_start": str(exec_start),
        "environment": environment,
    }


def _build_nginx_context(config: AppConfig, instance: str) -> dict[str, object]:
    listen_port = config.ports.base
    upstream = f"127.0.0.1:{config.ports.base}"
    server_name = f"{instance}.local"
    log_prefix = config.logs_dir / instance
    return {
        "listen_port": listen_port,
        "server_name": server_name,
        "access_log": str(log_prefix.with_suffix(".nginx.access.log")),
        "error_log": str(log_prefix.with_suffix(".nginx.error.log")),
        "upstream": upstream,
    }


@app.command()
def doctor(ctx: typer.Context) -> None:
    """Run environment and service health checks (coming soon)."""
    runtime = _get_runtime(ctx)
    message = "Doctor checks will be introduced in the Alpha milestone."
    with runtime.logger.operation(
        "doctor",
        target={"kind": "system", "scope": "health"},
    ) as op:
        _placeholder(message)
        op.warning(
            "Doctor placeholder executed.",
            warnings=["unimplemented"],
        )


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
versions_app = typer.Typer(help="Manage installed Sync Server versions.")
backups_app = typer.Typer(help="Create and reconcile instance backups.")
config_app = typer.Typer(help="Inspect and manage global configuration.")

app.add_typer(instances_app, name="instance")
app.add_typer(versions_app, name="version")
app.add_typer(backups_app, name="backup")
app.add_typer(config_app, name="config")


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
            console.print(f"[red]Instance '{name}' not found in registry.[/red]")
            message = f"Instance '{name}' not found."
            op.error(message, errors=[message], rc=1)
            raise typer.Exit(code=1)

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
) -> None:
    """Provision a new Actual Budget instance (coming soon)."""
    runtime = _get_runtime(ctx)
    message = (
        f"Instance '{name}' creation requires system provisioning hooks "
        "that ship in the Alpha milestone."
    )
    with runtime.logger.operation(
        "instance create",
        args={"name": name},
        target={"kind": "instance", "name": name},
    ) as op:
        with runtime.locks.mutate_instances([name]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            _placeholder(message)

            systemd_context = _build_systemd_context(runtime.config, name)
            systemd_changed = runtime.systemd_provider.render_unit(name, systemd_context)
            if systemd_changed:
                op.add_step(
                    "systemd.render_unit",
                    status="success",
                    detail=str(runtime.systemd_provider.unit_path(name)),
                )

            nginx_context = _build_nginx_context(runtime.config, name)
            nginx_changed = runtime.nginx_provider.render_site(name, nginx_context)
            if nginx_changed:
                op.add_step(
                    "nginx.render_site",
                    status="success",
                    detail=str(runtime.nginx_provider.site_path(name)),
                )

            op.warning(
                "Instance creation placeholder executed.",
                warnings=["unimplemented"],
            )


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
        help="Emit placeholder update information as JSON.",
    ),
) -> None:
    """Stub command describing how update checks will behave."""
    runtime = _get_runtime(ctx)
    payload = {
        "package": runtime.config.npm_package_name,
        "status": "unimplemented",
        "message": (
            "npm registry checks are not yet wired. This placeholder confirms "
            "configuration plumbing and will be replaced with real logic during Alpha."
        ),
    }

    with runtime.logger.operation(
        "version check-updates",
        args={"json": json_output},
        target={"kind": "version", "scope": "update-check"},
    ) as op:
        if json_output:
            console.print_json(data=payload)
            op.warning(
                "Version check placeholder executed (JSON).",
                warnings=["unimplemented"],
            )
            return

        console.print(
            "[yellow]Check-updates placeholder[/yellow]: {package}\n{message}".format(
                **payload
            )
        )
        op.warning(
            "Version check placeholder executed.",
            warnings=["unimplemented"],
        )


@backups_app.command("create")
def backup_create(
    ctx: typer.Context,
    instance: str = typer.Argument(..., help="Instance name to back up."),
) -> None:
    """Create a backup archive for an instance (coming soon)."""
    runtime = _get_runtime(ctx)
    message = (
        f"Backups for instance '{instance}' will be available after storage "
        "primitives stabilize."
    )
    with runtime.logger.operation(
        "backup create",
        args={"instance": instance},
        target={"kind": "backup", "instance": instance},
    ) as op:
        with runtime.locks.mutate_instances([instance]) as bundle:
            op.set_lock_wait_ms(bundle.wait_ms)
            _placeholder(message)
            op.warning(
                "Backup creation placeholder executed.",
                warnings=["unimplemented"],
            )


def main() -> None:
    """Console script entry point."""
    app()
