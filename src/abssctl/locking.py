"""Lock management primitives for abssctl.

Implements the global + per-instance flock strategy captured in ADR-027.
"""
from __future__ import annotations

import fcntl
import json
import os
import random
import time
from collections.abc import Sequence
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Literal


class LockError(RuntimeError):
    """Base exception for locking failures."""


class LockTimeoutError(LockError):
    """Raised when a lock cannot be acquired within the allotted timeout."""


@dataclass(slots=True)
class LockHandle(AbstractContextManager["LockHandle"]):
    """Represents an acquired filesystem lock."""

    path: Path
    timeout: float
    wait_ms: int = 0

    _fd: int | None = None

    def __enter__(self) -> LockHandle:
        """Acquire the underlying file lock."""
        self._fd, wait_seconds = _acquire_lock(self.path, self.timeout)
        self.wait_ms = int(wait_seconds * 1000)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        """Release the file lock."""
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None
        return False


class _LockBundle(AbstractContextManager["_LockBundle"]):
    """Context manager that acquires multiple locks in order."""

    def __init__(self, handles: Sequence[LockHandle]) -> None:
        self._handles = handles
        self.wait_ms: int = 0
        self._stack = ExitStack()

    def __enter__(self) -> _LockBundle:
        """Acquire all configured locks in order."""
        for handle in self._handles:
            entered = self._stack.enter_context(handle)
            self.wait_ms += entered.wait_ms
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        """Release locks in reverse order."""
        self._stack.__exit__(exc_type, exc, tb)
        return False


class LockManager:
    """Factory for acquiring abssctl lock handles."""

    def __init__(self, runtime_dir: Path, default_timeout: float) -> None:
        """Initialise the manager rooted at *runtime_dir*."""
        self._runtime_dir = runtime_dir.expanduser()
        self._runtime_dir.mkdir(parents=True, exist_ok=True)
        self._default_timeout = float(default_timeout)
        self._global_path = self._runtime_dir / "abssctl.lock"

    @property
    def default_timeout(self) -> float:
        """Return the default lock timeout in seconds."""
        return self._default_timeout

    def global_lock(self, *, timeout: float | None = None) -> LockHandle:
        """Acquire the global lock used for operations touching shared state."""
        return LockHandle(self._global_path, timeout or self._default_timeout)

    def instance_lock(self, name: str, *, timeout: float | None = None) -> LockHandle:
        """Acquire the per-instance lock for *name*."""
        safe_name = _sanitize_name(name)
        path = self._runtime_dir / f"{safe_name}.lock"
        return LockHandle(path, timeout or self._default_timeout)

    def mutate_instances(
        self,
        names: Sequence[str],
        *,
        timeout: float | None = None,
        include_global: bool = True,
    ) -> _LockBundle:
        """Acquire locks for mutating one or more instances."""
        timeout_value = timeout or self._default_timeout
        handles: list[LockHandle] = []
        if include_global:
            handles.append(self.global_lock(timeout=timeout_value))
        for name in names:
            handles.append(self.instance_lock(name, timeout=timeout_value))
        return _LockBundle(handles)


def _acquire_lock(path: Path, timeout: float) -> tuple[int, float]:
    """Acquire *path* with exclusive flock, returning ``(fd, wait_seconds)``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o640)
    start = time.monotonic()
    backoff = 0.05
    attempt = 0
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                wait_seconds = time.monotonic() - start
                _write_metadata(fd, path)
                return fd, wait_seconds
            except BlockingIOError:
                attempt += 1
                elapsed = time.monotonic() - start
                if elapsed >= timeout:
                    raise LockTimeoutError(f"Timed out waiting for lock {path}.") from None
                upper = min(0.5, backoff * (2**attempt))
                sleep_for = random.uniform(backoff, upper)
                time.sleep(sleep_for)
    except Exception:
        os.close(fd)
        raise


def _write_metadata(fd: int, path: Path) -> None:
    """Write metadata (pid + timestamp) to the lockfile."""
    metadata = {
        "pid": os.getpid(),
        "acquired_at": datetime.now(tz=UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "path": str(path),
    }
    payload = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    os.write(fd, payload)
    os.fsync(fd)
    try:
        os.fchmod(fd, 0o640)
    except PermissionError:
        # Ignore when running without permission to change mode.
        pass


def _sanitize_name(name: str) -> str:
    """Return a filesystem-safe lock filename."""
    sanitized = "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in name)
    return sanitized or "instance"


__all__ = [
    "LockError",
    "LockHandle",
    "LockManager",
    "LockTimeoutError",
]
