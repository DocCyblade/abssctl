"""Failure-mode tests for the structured logging subsystem."""
from __future__ import annotations

import json
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


def test_operation_scope_warning_sanitises_context(tmp_path: Path) -> None:
    """Warnings should be recorded with JSON-safe context values."""
    logger = StructuredLogger(tmp_path / "logs")

    class Custom:
        def __str__(self) -> str:
            return "<custom>"

    with logger.operation("demo", args={"path": Path("foo")}) as op:
        op.warning(
            "warned",
            warnings=("note",),
            errors=("err",),
            changed=1,
            backups=["backup.tar"],
            context={"path": Path("/var/lib"), "obj": Custom()},
        )

    record = json.loads(logger._operations_log_path.read_text(encoding="utf-8"))  # type: ignore[attr-defined]
    result = record["result"]
    assert result["status"] == "warning"
    assert result["warnings"] == ["note"]
    assert result["errors"] == ["err"]
    assert result["backups"] == ["backup.tar"]
    assert result["context"] == {"path": "/var/lib", "obj": "<custom>"}


def test_operation_scope_error_defaults_error_list(tmp_path: Path) -> None:
    """Errors should default to the message when not provided."""
    logger = StructuredLogger(tmp_path / "logs")

    with logger.operation("demo") as op:
        op.error("boom", errors=None, context={"value": {1, 2}})

    record = json.loads(logger._operations_log_path.read_text(encoding="utf-8"))  # type: ignore[attr-defined]
    result = record["result"]
    assert result["status"] == "error"
    assert result["errors"] == ["boom"]
    assert result["context"] == {"value": "{1, 2}"}
