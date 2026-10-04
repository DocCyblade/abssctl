"""Shell completion script generation and install paths."""

from __future__ import annotations

import os
import sys
from pathlib import Path

SHELLS = ("bash", "zsh", "fish", "powershell")


class CompletionError(ValueError):
    """Raised when a completion shell or destination is invalid."""


def detect_shell() -> str:
    """Return the shell to target when the caller did not pass ``--shell``."""
    name = Path(os.environ.get("SHELL") or "").name
    if name in SHELLS:
        return name
    if sys.platform == "darwin":
        return "zsh"
    return "bash"


def normalize_shell(shell: str | None) -> str:
    """Return a supported shell name."""
    chosen = (shell or detect_shell()).strip().lower()
    if chosen not in SHELLS:
        raise CompletionError(f"Unsupported shell '{chosen}'. Choose from: {', '.join(SHELLS)}.")
    return chosen


def completion_dest(shell: str, *, system: bool, override: Path | None = None) -> Path:
    """Return the file path for an installed completion script."""
    if override is not None:
        return override
    home = Path.home()
    if shell == "bash":
        if system:
            return Path("/etc/bash_completion.d/abssctl")
        return home / ".local/share/bash-completion/completions/abssctl"
    if shell == "zsh":
        if system:
            return Path("/usr/local/share/zsh/site-functions/_abssctl")
        return home / ".zfunc/_abssctl"
    if shell == "fish":
        if system:
            return Path("/usr/share/fish/vendor_completions.d/abssctl.fish")
        return home / ".config/fish/completions/abssctl.fish"
    if system:
        raise CompletionError("PowerShell has no system completion directory. Use --user.")
    return home / ".config/abssctl/abssctl.ps1"


def render_completion(shell: str) -> str:
    """Return the Click completion script for *shell*."""
    import typer
    from click.shell_completion import get_completion_class

    from abssctl.cli import app

    chosen = normalize_shell(shell)
    completion_cls = get_completion_class(chosen)
    if completion_cls is None:
        raise CompletionError(f"Click has no completion implementation for '{chosen}'.")
    command = typer.main.get_command(app)
    complete = completion_cls(command, {}, "abssctl", "_ABSSCTL_COMPLETE")
    source = complete.source()
    if not source.endswith("\n"):
        source += "\n"
    return source


def install_completion(
    shell: str,
    *,
    system: bool = False,
    dest: Path | None = None,
) -> Path:
    """Write the completion script and return the destination path."""
    chosen = normalize_shell(shell)
    target = completion_dest(chosen, system=system, override=dest)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_completion(chosen), encoding="utf-8")
    target.chmod(0o644)
    return target


def uninstall_completion(
    shell: str,
    *,
    system: bool = False,
    dest: Path | None = None,
) -> Path:
    """Remove an installed completion script. Missing files are not an error."""
    chosen = normalize_shell(shell)
    target = completion_dest(chosen, system=system, override=dest)
    if target.is_file():
        target.unlink()
    return target


def install_hint(shell: str, dest: Path) -> str:
    """Return a one-line follow-up hint after install. Does not edit rc files."""
    if shell == "zsh":
        return (
            f"Ensure {dest.parent} is on fpath before compinit "
            f"(for example: fpath=({dest.parent} $fpath))."
        )
    if shell == "bash":
        return f"Bash loads {dest.name} from {dest.parent} when bash-completion is installed."
    if shell == "fish":
        return f"Fish loads {dest} automatically for new shells."
    return f"Dot-source {dest} from your PowerShell profile if you want it persisted."
