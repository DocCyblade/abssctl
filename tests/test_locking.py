"""Tests for the locking primitives."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from abssctl.locking import LockManager, LockTimeoutError


def test_instance_lock_creates_metadata(tmp_path: Path) -> None:
    """Acquiring a lock writes metadata and releases cleanly."""
    manager = LockManager(tmp_path / "run", default_timeout=1.0)

    lock_path = tmp_path / "run" / "alpha.lock"
    with manager.instance_lock("alpha") as handle:
        assert handle.wait_ms >= 0
        assert lock_path.exists()
        data = json.loads(lock_path.read_text(encoding="utf-8"))
        assert data["pid"] == os.getpid()
        assert data["path"] == str(lock_path)

    # Lockfile persists for diagnostics but no longer holds the lock.
    with manager.instance_lock("alpha", timeout=0.2):
        pass


def test_instance_lock_timeout(tmp_path: Path) -> None:
    """Second acquisition times out while the first lock is held."""
    manager = LockManager(tmp_path / "run", default_timeout=1.0)

    with manager.instance_lock("alpha"):
        with pytest.raises(LockTimeoutError):
            with manager.instance_lock("alpha", timeout=0.1):
                pass


def test_mutate_instances_acquires_global_then_instance(tmp_path: Path) -> None:
    """Lock bundles acquire global first followed by per-instance locks."""
    manager = LockManager(tmp_path / "run", default_timeout=1.0)

    with manager.mutate_instances(["alpha"]) as bundle:
        assert bundle.wait_ms >= 0
        assert (tmp_path / "run" / "abssctl.lock").exists()
        assert (tmp_path / "run" / "alpha.lock").exists()
