"""Tests for shell completion and man-page helpers."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from abssctl.cli import app
from abssctl.completions import (
    CompletionError,
    completion_dest,
    detect_shell,
    install_completion,
    normalize_shell,
    render_completion,
    uninstall_completion,
)
from abssctl.manpages import (
    ManPageError,
    install_man_page,
    man_page_path,
    resolve_install_dir,
)

runner = CliRunner()


def test_detect_shell_uses_shell_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """SHELL selects the completion target when it is a known shell."""
    monkeypatch.setenv("SHELL", "/bin/fish")
    assert detect_shell() == "fish"


def test_detect_shell_defaults_to_zsh_on_darwin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Darwin without a known SHELL name falls back to zsh."""
    monkeypatch.delenv("SHELL", raising=False)
    monkeypatch.setattr("abssctl.completions.sys.platform", "darwin")
    assert detect_shell() == "zsh"


def test_normalize_shell_rejects_unknown() -> None:
    """Unknown shells are a caller error."""
    with pytest.raises(CompletionError):
        normalize_shell("tcsh")


def test_completion_dest_user_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """User install paths follow ADR-020."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    assert completion_dest("bash", system=False) == (
        tmp_path / ".local/share/bash-completion/completions/abssctl"
    )
    assert completion_dest("zsh", system=False) == tmp_path / ".zfunc/_abssctl"
    assert completion_dest("fish", system=False) == (
        tmp_path / ".config/fish/completions/abssctl.fish"
    )


def test_render_and_install_round_trip(tmp_path: Path) -> None:
    """show/install/uninstall write a script that mentions the program name."""
    source = render_completion("bash")
    assert "abssctl" in source
    dest = tmp_path / "abssctl.bash"
    written = install_completion("bash", dest=dest)
    assert written.read_text(encoding="utf-8") == source
    uninstall_completion("bash", dest=dest)
    assert not dest.exists()


def test_cli_completion_show_and_man_path() -> None:
    """CLI surfaces print a script and the packaged man page path."""
    shown = runner.invoke(app, ["completion", "show", "--shell", "bash"])
    assert shown.exit_code == 0, shown.output
    assert "abssctl" in shown.stdout

    path = runner.invoke(app, ["docs", "man", "path"])
    assert path.exit_code == 0, path.output
    assert path.stdout.strip() == str(man_page_path())
    assert man_page_path().is_file()


def test_man_install_and_flag_conflict(tmp_path: Path) -> None:
    """Copy abssctl.1 and reject mixed location flags."""
    target, note = install_man_page(dest_dir=tmp_path)
    assert target.name == "abssctl.1"
    assert target.read_text(encoding="utf-8").startswith(".TH") or "abssctl" in target.read_text(
        encoding="utf-8"
    )
    assert note is None or isinstance(note, str)
    with pytest.raises(ManPageError):
        resolve_install_dir(system=True, user=True, prefix=None)


def test_cli_completion_rejects_both_scopes(tmp_path: Path) -> None:
    """--user and --system together is a validation error."""
    result = runner.invoke(
        app,
        ["completion", "install", "--user", "--system", "--path", str(tmp_path / "c.sh")],
    )
    assert result.exit_code == 2
