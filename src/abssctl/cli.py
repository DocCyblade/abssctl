"""Typer-powered command line scaffold for ``abssctl``.

The Pre-Alpha milestone focuses on wiring foundational structure so later
phases can layer in real functionality without reworking entry points. Each
subcommand currently emits a friendly placeholder message and exits with a
success code to keep automated smoke tests green.
"""
from __future__ import annotations

import textwrap

import typer
from rich.console import Console

from . import __version__

console = Console()

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


@app.callback(invoke_without_command=True)
def _root(  # noqa: D401 - Typer displays help for us, docstring optional.
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show the abssctl version and exit.",
    ),
) -> None:
    """Entry point callback invoked for every CLI execution."""
    if version:
        console.print(f"abssctl {__version__}")
        raise typer.Exit(code=0)

    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit(code=0)


def _placeholder(message: str) -> None:
    console.print(f"[bold yellow]Pre-Alpha placeholder:[/bold yellow] {message}")


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

app.add_typer(instances_app, name="instance")
app.add_typer(versions_app, name="version")
app.add_typer(backups_app, name="backup")


@instances_app.command("list")
def instance_list() -> None:
    """List registered instances and their status (coming soon)."""
    _placeholder("Instance registry integration will land once state storage is ready.")


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
def version_list() -> None:
    """List available Actual Sync Server versions (coming soon)."""
    _placeholder("Version inventory depends on npm registry integration slated for Alpha.")


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
