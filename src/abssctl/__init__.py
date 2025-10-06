"""abssctl package bootstrap.

This module exposes lightweight metadata that other modules (and packaging
machinery) rely upon. The Pre-Alpha release surface is intentionally small.
"""
from __future__ import annotations

__all__ = ["__version__", "get_version"]

# NOTE: The version is duplicated in ``pyproject.toml`` and managed by Hatch.
__version__ = "0.1.0a0"


def get_version() -> str:
    """Return the current package version."""
    return __version__
