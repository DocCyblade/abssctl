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


def test_operation_scope_warning_default_lists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Warnings without optional arguments should default to empty collections."""
    logger = StructuredLogger(tmp_path / "logs")
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(logger, "_write_operations_log", lambda payload: captured.append(payload))
    monkeypatch.setattr(logger, "_write_human_log", lambda *_args, **_kwargs: None)

    with logger.operation("demo") as op:
        op.warning("attention")

    payload = captured[-1]
    result = payload["result"]
    assert payload["rc"] == 0
    assert result["warnings"] == []
    assert result["errors"] == []
    assert result["backups"] == []
    assert "context" not in result


def test_operation_scope_warning_respects_parameters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Warnings should propagate rc/changed/backups/context fields."""
    logger = StructuredLogger(tmp_path / "logs")
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(logger, "_write_operations_log", lambda payload: captured.append(payload))
    monkeypatch.setattr(logger, "_write_human_log", lambda *_args, **_kwargs: None)

    with logger.operation("demo") as op:
        op.warning(
            "partial success",
            warnings=("lag",),
            errors=("retry",),
            changed=3,
            rc=5,
            backups=("bundle.tar",),
            context={"path": Path("/srv/app")},
        )

    payload = captured[-1]
    assert payload["rc"] == 5
    result = payload["result"]
    assert result["status"] == "warning"
    assert result["changed"] == 3
    assert result["warnings"] == ["lag"]
    assert result["errors"] == ["retry"]
    assert result["backups"] == ["bundle.tar"]
    assert result["context"]["path"] == "/srv/app"


def test_iso_timestamp_is_utc() -> None:
    """Internal timestamp helper should always emit UTC with Z suffix."""
    ts = _iso_timestamp()
    assert ts.endswith("Z")
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert parsed.tzinfo == timezone.utc  # noqa: UP017 - python3.11 lacks datetime.UTC


def test_iso_timestamp_uses_millisecond_precision(monkeypatch: pytest.MonkeyPatch) -> None:
    """Timestamp helper should request UTC now() and emit millisecond precision."""

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz: object | None = None) -> datetime:
            if tz is None:
                raise AssertionError("tz must be provided for UTC timestamps")
            return cls(2024, 5, 6, 7, 8, 9, 654_321, tzinfo=tz)

    monkeypatch.setattr("abssctl.logging.datetime", FixedDatetime)

    assert _iso_timestamp() == "2024-05-06T07:08:09.654Z"


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


def test_sanitize_handles_tuple_and_bytes(tmp_path: Path) -> None:
    """Sanitise helper should convert tuples to lists and stringify bytes."""

    class Custom:
        def __str__(self) -> str:
            return "<custom>"

    payload = {
        "tuple": (Path("child"), 1, Custom()),
        "bytes": b"\x00abc",
        "nested": {"values": (Path(tmp_path.name),)},
    }
    sanitised = _sanitize(payload)
    assert sanitised["tuple"] == ["child", 1, "<custom>"]
    assert sanitised["bytes"] == "b'\\x00abc'"
    assert sanitised["nested"]["values"] == [tmp_path.name]


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


def test_detect_actor_prefers_ttypath_when_missing_ssh_tty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Local actor detection should fall back to TTYPATH when needed."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("SSH_TTY", raising=False)
    monkeypatch.setenv("TTYPATH", "/dev/pts/9")
    monkeypatch.setattr("getpass.getuser", lambda: "terminal-user")

    actor = _detect_actor()
    assert actor == {"type": "user", "name": "terminal-user", "session": "/dev/pts/9"}


def test_detect_actor_uses_ci_job_id_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI actor detection should prefer GITHUB_RUN_ID but fall back to CI_JOB_ID."""
    monkeypatch.setenv("CI", "1")
    monkeypatch.delenv("GITHUB_RUN_ID", raising=False)
    monkeypatch.setenv("CI_JOB_ID", "job-123")
    monkeypatch.setattr("getpass.getuser", lambda: "ci-user")

    actor = _detect_actor()
    assert actor == {"type": "ci", "name": "ci-user", "session": "job-123"}


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


def test_operation_scope_captures_steps_and_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Structured logger should record steps, lock waits, and sanitised context."""
    logger = StructuredLogger(tmp_path / "logs")
    timestamps = iter(
        [
            "2024-01-01T00:00:00.000Z",
            "2024-01-01T00:00:00.100Z",
            "2024-01-01T00:00:00.200Z",
        ]
    )
    monkeypatch.setattr("abssctl.logging._iso_timestamp", lambda: next(timestamps))

    captured: list[dict[str, object]] = []
    human_lines: list[str] = []
    monkeypatch.setattr(logger, "_write_operations_log", lambda record: captured.append(record))
    monkeypatch.setattr(logger, "_write_human_log", human_lines.append)

    with logger.operation(
        "demo",
        args={"foo": "bar"},
        target={"path": Path("/srv/data")},
        planned_actions=[{"path": Path("/srv/data")}],
        redactions=("token",),
    ) as op:
        op.set_lock_wait_ms(250)
        op.add_step("phase-1", status="running", detail="syncing")
        op.warning(
            "completed with warnings",
            warnings=("lag",),
            errors=("retry",),
            changed=1,
            backups=("bundle.tar",),
            context={"path": Path("/srv/data")},
        )

    assert captured, "operations log write should have been captured"
    payload = captured[-1]
    assert payload["lock_wait_ms"] == 250
    assert payload["steps"] == [
        {
            "name": "phase-1",
            "status": "running",
            "detail": "syncing",
            "ts": "2024-01-01T00:00:00.100Z",
        }
    ]
    assert payload["planned_actions"] == [{"path": "/srv/data"}]
    assert payload["redactions"] == ["token"]
    assert payload["result"]["warnings"] == ["lag"]
    assert payload["result"]["errors"] == ["retry"]
    assert payload["context"]["path"] == "/srv/data"
    assert human_lines and "demo" in human_lines[-1]
