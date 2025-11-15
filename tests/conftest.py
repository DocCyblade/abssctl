"""Pytest configuration helpers for the test suite."""

from __future__ import annotations

import importlib
import os
import sys
from collections.abc import Mapping
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


@pytest.fixture(autouse=True)
def _fast_structured_logger(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace StructuredLogger with a fast stub during mutation testing."""
    if not os.environ.get("MUTANT_UNDER_TEST"):
        return

    from abssctl import logging as logging_mod

    class _FastStructuredLogger(logging_mod.StructuredLogger):  # type: ignore[misc]
        def __init__(self, logs_dir: Path | str) -> None:
            super().__init__(Path(logs_dir))

        def _ensure_directory(self) -> None:  # type: ignore[override]
            self._enabled = True

        def _write_human_log(self, line: str) -> None:  # type: ignore[override]
            return

        def _write_operations_log(self, record: Mapping[str, object]) -> None:  # type: ignore[override]
            return

    targets = (
        "abssctl.logging",
        "abssctl.cli",
        "abssctl.node_runtime",
        "abssctl.providers.systemd",
        "abssctl.doctor.models",
    )
    for module_name in targets:
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            continue
        if hasattr(module, "StructuredLogger"):
            monkeypatch.setattr(module, "StructuredLogger", _FastStructuredLogger, raising=False)
