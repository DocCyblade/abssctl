"""Failure-mode tests for the structured logging subsystem."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from abssctl.logging import (
    StructuredLogger,
    _detect_actor,
    _iso_timestamp,
    _sanitize,
)


@pytest.mark.mutation_timeout
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


@pytest.mark.mutation_timeout
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


@pytest.mark.mutation_timeout
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


@pytest.mark.mutation_timeout
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


def test_iso_timestamp_is_utc() -> None:
    """Internal timestamp helper should always emit UTC with Z suffix."""
    ts = _iso_timestamp()
    assert ts.endswith("Z")
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert parsed.tzinfo == timezone.utc  # noqa: UP017 - python3.11 lacks datetime.UTC


def test_sanitize_handles_mappings_sequences_and_paths(tmp_path: Path) -> None:
    """Sanitise helper should convert complex types into JSON-safe structures."""

    class Custom:
        def __repr__(self) -> str:
            return "<custom>"

    payload = {
        Path("key"): tmp_path,
        "items": [Path("child"), {"nested": Path("inner")}],
        "custom": Custom(),
    }
    sanitised = _sanitize(payload)
    assert sanitised == {
        "key": str(tmp_path),
        "items": ["child", {"nested": "inner"}],
        "custom": "<custom>",
    }


def test_detect_actor_user_and_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    """Actor detection should distinguish user sessions from CI."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setenv("SSH_TTY", "/dev/pts/1")
    monkeypatch.setattr("getpass.getuser", lambda: "tester")
    user_actor = _detect_actor()
    assert user_actor["type"] == "user"
    assert user_actor["name"] == "tester"
    assert user_actor["session"] == "/dev/pts/1"

    monkeypatch.setenv("CI", "1")
    monkeypatch.delenv("SSH_TTY", raising=False)
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    ci_actor = _detect_actor()
    assert ci_actor["type"] == "ci"
    assert ci_actor["session"] == "42"


@pytest.mark.mutation_timeout
def test_structured_logger_emits_human_and_json_logs(tmp_path: Path) -> None:
    """Successful operations should write both human and JSONL logs."""
    log_dir = tmp_path / "logs"
    logger = StructuredLogger(log_dir)
    with logger.operation("demo", args={"foo": "bar"}) as op:
        op.success("ok", changed=2)

    human_log = log_dir / "abssctl.log"
    operations_log = log_dir / "operations.jsonl"

    assert human_log.read_text(encoding="utf-8").strip()
    operations_records = operations_log.read_text(encoding="utf-8").splitlines()
    record = json.loads(operations_records[-1])
    assert record["command"] == "demo"
    assert record["args"] == {"foo": "bar"}
    assert record["result"]["status"] == "success"
