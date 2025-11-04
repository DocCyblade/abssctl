"""Failure-mode tests for the structured logging subsystem."""
from __future__ import annotations

from pathlib import Path

import pytest

from abssctl.logging import StructuredLogger


def test_structured_logger_disables_when_directory_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logger gracefully disables itself when log directory cannot be created."""
    log_dir = tmp_path / "logs"

    original_mkdir = Path.mkdir

    def fail_mkdir(self: Path, *args: object, **kwargs: object) -> None:
        if self == log_dir:
            raise PermissionError("no access")
        original_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail_mkdir)

    logger = StructuredLogger(log_dir)
    assert logger._enabled is False  # type: ignore[attr-defined]

    with logger.operation("demo", args={"foo": "bar"}) as op:
        op.success("done", changed=0)


def test_structured_logger_disables_after_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Write failures mark the logger disabled so subsequent writes are skipped."""
    logger = StructuredLogger(tmp_path / "logs")
    operations_path = logger._operations_log_path  # type: ignore[attr-defined]

    original_open = Path.open

    def fail_once(self: Path, *args: object, **kwargs: object) -> object:
        if self == operations_path:
            raise OSError("disk full")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_once)

    with logger.operation("demo") as op:
        op.success("done", changed=0)

    assert logger._enabled is False  # type: ignore[attr-defined]

    # Subsequent operations should not raise even though logger is disabled.
    with logger.operation("demo-2") as op:
        op.success("done", changed=0)
