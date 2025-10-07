"""abssctl package bootstrap.

This module exposes lightweight metadata that other modules (and packaging
machinery) rely upon. The Alpha release surface exports ``load_config`` so other
modules can easily obtain resolved configuration values.
"""
from __future__ import annotations

from .config import AppConfig, load_config

__all__ = ["__version__", "get_version", "AppConfig", "load_config"]

# NOTE: Hatch reads this value via ``tool.hatch.version`` to manage the project version.
__version__ = "0.1.0a9"


def get_version() -> str:
    """Return the current package version."""
    return __version__
