"""Enumerations for CLI exit codes following ADR-013."""
from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Well-known exit codes enforced across the CLI."""

    OK = 0
    VALIDATION = 2
    ENVIRONMENT = 3
    PROVIDER = 4
