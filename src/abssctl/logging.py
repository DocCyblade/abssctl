"""Structured logging facilities for abssctl.

This module implements the logging requirements defined in ADR-014 and
ADR-028. Every top-level command records a human-readable log line and an
operations JSONL entry under the configured logs directory.
"""
from __future__ import annotations

import getpass
import json
import os
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Literal

import typer

from . import __version__

SCHEMA_VERSION = 1
HUMAN_LOG_FILENAME = "abssctl.log"
OPERATIONS_LOG_FILENAME = "operations.jsonl"


def _iso_timestamp() -> str:
    """Return the current UTC timestamp in ISO-8601 format with millisecond precision."""
    now = datetime.now(tz=UTC)
    return now.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _sanitize(value: object) -> object:
    """Return a JSON-serialisable structure for *value*."""
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _sanitize(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_sanitize(item) for item in value]
    return str(value)


def _prune_none(mapping: Mapping[str, object | None]) -> dict[str, object]:
    """Return a copy of *mapping* without keys that have ``None`` values."""
    return {key: value for key, value in mapping.items() if value is not None}


def _detect_actor() -> dict[str, object]:
    """Derive caller identity information from the environment."""
    username = getpass.getuser()
    if os.environ.get("CI"):
        actor_type = "ci"
        session = os.environ.get("GITHUB_RUN_ID") or os.environ.get("CI_JOB_ID")
    else:
        actor_type = "user"
        session = os.environ.get("SSH_TTY") or os.environ.get("TTYPATH")
    actor: dict[str, object] = {"type": actor_type, "name": username}
    if session:
        actor["session"] = session
    return actor


@dataclass(slots=True)
class OperationResult:
    """Captured result information for an operation."""

    status: str
    message: str
    rc: int
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    changed: int = 0
    backups: list[str] = field(default_factory=list)
    context: Mapping[str, object] | None = None


class StructuredLogger:
    """Coordinator that emits human-readable and JSONL operation logs."""

    def __init__(self, logs_dir: Path) -> None:
        """Prepare log file handles rooted under *logs_dir*."""
        self._logs_dir = Path(logs_dir).expanduser()
        self._human_log_path = self._logs_dir / HUMAN_LOG_FILENAME
        self._operations_log_path = self._logs_dir / OPERATIONS_LOG_FILENAME
        self._lock = threading.Lock()
        self._enabled = True
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        try:
            self._logs_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            self._enabled = False

    def operation(
        self,
        command: str,
        *,
        args: Mapping[str, object] | None = None,
        actor: Mapping[str, object] | None = None,
        target: Mapping[str, object] | None = None,
        planned_actions: Sequence[Mapping[str, object]] | None = None,
        redactions: Sequence[str] | None = None,
    ) -> OperationScope:
        """Return a context manager for logging a single command execution."""
        resolved_actor = actor or _detect_actor()
        return OperationScope(
            logger=self,
            command=command,
            args=_sanitize(args or {}),
            actor=_sanitize(resolved_actor),
            target=_sanitize(target or {}),
            planned_actions=_sanitize(planned_actions or []),
            redactions=_sanitize(redactions or []),
        )

    # Internal helpers -------------------------------------------------
    def _write_human_log(self, line: str) -> None:
        if not self._enabled:
            return
        with self._lock:
            try:
                with self._human_log_path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
                try:
                    os.chmod(self._human_log_path, 0o640)
                except OSError:
                    pass
            except OSError:
                self._enabled = False

    def _write_operations_log(self, record: Mapping[str, object]) -> None:
        if not self._enabled:
            return
        payload = json.dumps(record, separators=(",", ":"))
        with self._lock:
            try:
                with self._operations_log_path.open("a", encoding="utf-8") as handle:
                    handle.write(payload + "\n")
                try:
                    os.chmod(self._operations_log_path, 0o640)
                except OSError:
                    pass
            except OSError:
                self._enabled = False


class OperationScope:
    """Context manager that records a single top-level command execution."""

    def __init__(
        self,
        *,
        logger: StructuredLogger,
        command: str,
        args: object,
        actor: object,
        target: object,
        planned_actions: object,
        redactions: object,
    ) -> None:
        """Initialise a structured logging scope for a single CLI invocation."""
        self._logger = logger
        self._command = command
        self._args = args
        self._actor = actor
        self._target = target
        self._planned_actions = planned_actions
        self._redactions = redactions
        self._start = time.monotonic()
        self._ts = _iso_timestamp()
        self._op_id = uuid.uuid4().hex
        self._result: OperationResult | None = None
        self._lock_wait_ms: int | None = None
        self._steps: list[dict[str, object]] | None = None
        self._emitted = False

    def __enter__(self) -> OperationScope:
        """Enter the logging scope."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> Literal[False]:
        """Emit final log records and propagate exceptions."""
        if exc is not None and self._result is None:
            if isinstance(exc, typer.Exit):
                rc = int(getattr(exc, "exit_code", 0))
                status = "success" if rc == 0 else "error"
                message = "Command exited early" if rc != 0 else "Command completed"
                self._result = OperationResult(
                    status=status,
                    message=message,
                    rc=rc,
                    errors=[] if rc == 0 else [message],
                    warnings=[],
                    changed=0,
                    backups=[],
                )
            else:
                message = str(exc) or exc.__class__.__name__
                self._result = OperationResult(
                    status="error",
                    message=message,
                    rc=1,
                    errors=[message],
                    warnings=[],
                    changed=0,
                    backups=[],
                )
        if self._result is None:
            self._result = OperationResult(
                status="success",
                message="Command completed",
                rc=0,
                warnings=[],
                errors=[],
                changed=0,
                backups=[],
            )

        self._emit()
        return False  # never suppress exceptions

    # ------------------------------------------------------------------
    def success(
        self,
        message: str,
        *,
        changed: int = 0,
        warnings: Sequence[str] | None = None,
    ) -> None:
        """Record a successful completion."""
        self._result = OperationResult(
            status="success",
            message=message,
            rc=0,
            warnings=list(warnings or []),
            errors=[],
            changed=changed,
            backups=[],
        )

    def warning(
        self,
        message: str,
        *,
        warnings: Sequence[str] | None = None,
        errors: Sequence[str] | None = None,
        changed: int = 0,
        rc: int = 0,
    ) -> None:
        """Record a completion with warnings."""
        self._result = OperationResult(
            status="warning",
            message=message,
            rc=rc,
            warnings=list(warnings or []),
            errors=list(errors or []),
            changed=changed,
            backups=[],
        )

    def error(
        self,
        message: str,
        *,
        errors: Sequence[str] | None = None,
        warnings: Sequence[str] | None = None,
        rc: int = 1,
    ) -> None:
        """Record an error outcome."""
        self._result = OperationResult(
            status="error",
            message=message,
            rc=rc,
            errors=list(errors or [message]),
            warnings=list(warnings or []),
            changed=0,
            backups=[],
        )

    def set_lock_wait_ms(self, value: int) -> None:
        """Record total time spent waiting on locks."""
        self._lock_wait_ms = max(0, int(value))

    def add_step(self, name: str, *, status: str, detail: str | None = None) -> None:
        """Append a breadcrumb step to the operations record."""
        step: dict[str, object] = {"name": name, "ts": _iso_timestamp(), "status": status}
        if detail:
            step["detail"] = detail
        if self._steps is None:
            self._steps = []
        self._steps.append(step)

    # Internal ---------------------------------------------------------
    def _emit(self) -> None:
        if self._emitted or self._result is None:
            return

        duration_ms = int((time.monotonic() - self._start) * 1000)
        payload: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "ts": self._ts,
            "op_id": self._op_id,
            "command": self._command,
            "args": self._args,
            "actor": self._actor,
            "target": self._target,
            "planned_actions": self._planned_actions,
            "result": _prune_none(
                {
                    "status": self._result.status,
                    "message": self._result.message,
                    "errors": self._result.errors,
                    "warnings": self._result.warnings,
                    "changed": self._result.changed,
                    "backups": self._result.backups,
                }
            ),
            "rc": self._result.rc,
            "duration_ms": duration_ms,
        }
        if self._lock_wait_ms is not None:
            payload["lock_wait_ms"] = self._lock_wait_ms
        if self._steps:
            payload["steps"] = self._steps
        if self._redactions:
            payload["redactions"] = self._redactions
        context: dict[str, object] = {"abssctl_version": __version__}
        if self._result.context:
            extra_context = _sanitize(self._result.context)
            if isinstance(extra_context, Mapping):
                context.update(extra_context)
        payload["context"] = context

        human_line = (
            f"{self._ts} | {self._command} | status={self._result.status} "
            f"rc={self._result.rc} | {self._result.message}"
        )

        try:
            self._logger._write_operations_log(payload)
        except Exception:
            # Fall back to a simplified human log when JSONL write fails.
            human_line = (
                f"{human_line} | operations_log_error"
            )
        try:
            self._logger._write_human_log(human_line)
        except Exception:
            # Silently ignore human log write failures.
            pass

        self._emitted = True


__all__ = ["StructuredLogger", "OperationScope", "OperationResult"]
