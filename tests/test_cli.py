"""Tests for the abssctl CLI scaffold."""
from __future__ import annotations

from typer.testing import CliRunner

from abssctl import __version__
from abssctl.cli import app

runner = CliRunner()


def test_version_option_outputs_package_version() -> None:
    """CLI ``--version`` flag emits the package version."""
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_invocation_without_subcommand_shows_help() -> None:
    """Calling the CLI without a subcommand shows help output."""
    result = runner.invoke(app)

    assert result.exit_code == 0
    assert "Actual Budget Multi-Instance Sync Server Admin CLI" in result.stdout
