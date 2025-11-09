"""Pytest configuration helpers for the test suite."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if _SRC.exists():
    sys.path.insert(0, str(_SRC))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip expensive tests during mutation runs."""
    if not os.environ.get("MUTANT_UNDER_TEST"):
        return
    skip_marker = pytest.mark.skip(reason="Skipped during mutation run to avoid timeouts.")
    for item in items:
        if "mutation_timeout" in item.keywords:
            item.add_marker(skip_marker)
