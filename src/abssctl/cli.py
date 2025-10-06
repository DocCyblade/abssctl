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
from .providers import VersionProvider
from .state import StateRegistry

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


def _ensure_runtime(ctx: typer.Context, config_file: Path | None) -> RuntimeContext:
    runtime = ctx.obj
    if isinstance(runtime, RuntimeContext):
        return runtime

    config = load_config(config_file=config_file)
    registry = StateRegistry(config.registry_dir)
    version_provider = VersionProvider()
    runtime = RuntimeContext(
        config=config,
        registry=registry,
        version_provider=version_provider,
    )
    ctx.obj = runtime
    return runtime


def _get_runtime(ctx: typer.Context) -> RuntimeContext:
    runtime = ctx.obj
    if isinstance(runtime, RuntimeContext):
        return runtime
    return _ensure_runtime(ctx, None)


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
) -> None:
    """Entry point callback invoked for every CLI execution."""
    if version:
        console.print(f"abssctl {__version__}")
        raise typer.Exit(code=0)

    _ensure_runtime(ctx, config_file)

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


@app.command()
def doctor() -> None:
    """Run environment and service health checks (coming soon)."""
    _placeholder("Doctor checks will be introduced in the Alpha milestone.")


@app.command()
def support_bundle() -> None:
    """Create a diagnostic bundle for support cases (coming soon)."""
    _placeholder("Support bundle generation is planned for the Beta milestone.")


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

    if json_output:
        console.print_json(data=data)
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

    if json_output:
        console.print_json(data={"instances": entries})
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
    target = next((entry for entry in entries if entry["name"] == name), None)

    if target is None:
        console.print(f"[red]Instance '{name}' not found in registry.[/red]")
        raise typer.Exit(code=1)

    if json_output:
        console.print_json(data=target)
        return

    table = Table(show_header=False)
    for key, value in target.items():
        if key == "metadata":
            continue
        if value in (None, ""):
            continue
        table.add_row(key.title(), str(value))

    console.print(table)


@instances_app.command("create")
def instance_create(
    name: str = typer.Argument(..., help="Name of the instance to create."),
) -> None:
    """Provision a new Actual Budget instance (coming soon)."""
    _placeholder(
        f"Instance '{name}' creation requires system provisioning hooks "
        "that ship in the Alpha milestone."
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

    if json_output:
        console.print_json(data={"versions": entries})
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

    if json_output:
        console.print_json(data=payload)
        return

    console.print(
        "[yellow]Check-updates placeholder[/yellow]: {package}\n{message}".format(**payload)
    )


@backups_app.command("create")
def backup_create(
    instance: str = typer.Argument(..., help="Instance name to back up."),
) -> None:
    """Create a backup archive for an instance (coming soon)."""
    _placeholder(
        f"Backups for instance '{instance}' will be available after storage "
        "primitives stabilize."
    )


def main() -> None:
    """Console script entry point."""
    app()
