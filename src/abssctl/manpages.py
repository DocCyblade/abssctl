"""Locate and install the packaged abssctl man page."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent
MAN_DIR = _PACKAGE_DIR / "_man"
MAN_PAGE_NAME = "abssctl.1"


class ManPageError(RuntimeError):
    """Raised when the packaged man page cannot be installed."""


def man_page_path() -> Path:
    """Return the packaged ``abssctl.1`` path."""
    return MAN_DIR / MAN_PAGE_NAME


def default_install_dir() -> Path:
    """Return the man1 directory for this user (system path when root)."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/usr/local/share/man/man1")
    return Path.home() / ".local/share/man/man1"


def resolve_install_dir(*, system: bool, user: bool, prefix: Path | None) -> Path:
    """Pick the man1 directory from the caller's flags."""
    selected = sum(1 for flag in (system, user, prefix is not None) if flag)
    if selected > 1:
        raise ManPageError("Pass only one of --system, --user, or --prefix.")
    if prefix is not None:
        return prefix / "share/man/man1"
    if system:
        return Path("/usr/local/share/man/man1")
    if user:
        return Path.home() / ".local/share/man/man1"
    return default_install_dir()


def install_man_page(
    *,
    system: bool = False,
    user: bool = False,
    prefix: Path | None = None,
    dest_dir: Path | None = None,
) -> tuple[Path, str | None]:
    """Copy ``abssctl.1`` into a man1 directory.

    Returns the installed path and an optional ``mandb`` note.
    """
    source = man_page_path()
    if not source.is_file():
        raise ManPageError(f"Packaged man page is missing: {source}")
    directory = dest_dir or resolve_install_dir(system=system, user=user, prefix=prefix)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / MAN_PAGE_NAME
    shutil.copyfile(source, target)
    target.chmod(0o644)
    note = _refresh_mandb(directory) if _looks_like_man_dir(directory) else None
    return target, note


def _looks_like_man_dir(directory: Path) -> bool:
    """Return whether *directory* is a man1 path worth indexing."""
    return directory.name == "man1" and directory.parent.name == "man"


def _refresh_mandb(directory: Path) -> str | None:
    """Run ``mandb -q`` when it exists and we can write the man tree."""
    mandb = shutil.which("mandb")
    if mandb is None:
        return "mandb is not installed; the page is still readable via an explicit path."
    if not os.access(directory, os.W_OK):
        return f"Run `mandb -q` once you can write {directory}."
    result = subprocess.run(  # noqa: S603
        [mandb, "-q"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if detail:
            return f"mandb exited {result.returncode}: {detail}"
        return f"mandb exited {result.returncode}."
    return None
