"""Locate and install the packaged ``abssctl-node-run`` systemd wrapper."""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_WRAPPER_PATH = Path("/usr/local/bin/abssctl-node-run")
WRAPPER_PATH_ENV_VAR = "ABSSCTL_NODE_WRAPPER_PATH"
_PACKAGE_DATA = Path(__file__).resolve().parent / "data"
WRAPPER_SCRIPT_NAME = "abssctl-node-run.sh"


class NodeWrapperError(RuntimeError):
    """Raised when the packaged node wrapper cannot be installed."""


def packaged_wrapper_path() -> Path:
    """Return the packaged ``abssctl-node-run.sh`` path."""
    return _PACKAGE_DATA / WRAPPER_SCRIPT_NAME


def resolve_wrapper_path() -> Path:
    """Return the install/ExecStart path, honouring ``ABSSCTL_NODE_WRAPPER_PATH``."""
    override = os.environ.get(WRAPPER_PATH_ENV_VAR)
    if override:
        return Path(override)
    return DEFAULT_WRAPPER_PATH


def wrapper_needs_install(destination: Path | None = None) -> bool:
    """Return whether *destination* is missing or differs from the packaged script."""
    target = destination if destination is not None else resolve_wrapper_path()
    source = packaged_wrapper_path()
    if not source.is_file():
        raise NodeWrapperError(f"Packaged node wrapper is missing: {source}")
    if not target.is_file():
        return True
    return target.read_bytes() != source.read_bytes()


def install_node_wrapper(
    destination: Path | None = None,
    *,
    dry_run: bool = False,
) -> bool:
    """Install the packaged wrapper to *destination*.

    Returns ``True`` when the destination was written (or would be in dry-run).
    When *destination* is omitted, uses :func:`resolve_wrapper_path`.
    """
    target = destination if destination is not None else resolve_wrapper_path()
    source = packaged_wrapper_path()
    if not source.is_file():
        raise NodeWrapperError(f"Packaged node wrapper is missing: {source}")
    desired = source.read_bytes()
    if target.is_file() and target.read_bytes() == desired:
        return False
    if dry_run:
        return True
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(f".{target.name}.tmp")
    temp.write_bytes(desired)
    temp.chmod(0o755)
    temp.replace(target)
    return True


__all__ = [
    "DEFAULT_WRAPPER_PATH",
    "WRAPPER_PATH_ENV_VAR",
    "NodeWrapperError",
    "install_node_wrapper",
    "packaged_wrapper_path",
    "resolve_wrapper_path",
    "wrapper_needs_install",
]
