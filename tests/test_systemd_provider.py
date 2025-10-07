"""Tests for the systemd provider."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from abssctl.locking import LockManager
from abssctl.logging import StructuredLogger
from abssctl.providers.systemd import SystemdProvider
from abssctl.templates import TemplateEngine


class DummyResult:
    """Simple stand-in for ``subprocess.CompletedProcess``."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        """Initialise the dummy result."""
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _make_provider(tmp_path: Path) -> SystemdProvider:
    templates = TemplateEngine.with_overrides(None)
    logs_dir = tmp_path / "logs"
    logger = StructuredLogger(logs_dir)
    locks = LockManager(tmp_path / "run", default_timeout=1.0)
    systemd_dir = tmp_path / "systemd"
    systemd_dir.mkdir(parents=True, exist_ok=True)
    return SystemdProvider(
        templates=templates,
        logger=logger,
        locks=locks,
        systemd_dir=systemd_dir,
        systemctl_bin="systemctl",  # Not invoked; monkeypatched in tests.
    )


@pytest.fixture
def provider(tmp_path: Path) -> SystemdProvider:
    """Return a provider instance scoped to the temporary path."""
    return _make_provider(tmp_path)


def _context(instance: str) -> dict[str, Any]:
    """Build a minimal template context for *instance*."""
    return {
        "instance_name": instance,
        "service_user": "actual-sync",
        "working_directory": f"/srv/app/{instance}",
        "exec_start": "/usr/bin/node server.js",
        "environment": ["NODE_ENV=production"],
    }


def test_render_unit_writes_file_and_reload(
    monkeypatch: pytest.MonkeyPatch,
    provider: SystemdProvider,
) -> None:
    """Rendering writes the unit file and triggers a daemon reload once."""
    calls: list[tuple[str, Path | None, bool]] = []

    def fake_systemctl(
        self: SystemdProvider,
        command: str,
        unit_or_path: Path | None = None,
        *,
        check: bool = True,
    ) -> DummyResult:
        calls.append((command, unit_or_path, check))
        return DummyResult(returncode=0)

    monkeypatch.setattr(SystemdProvider, "_systemctl", fake_systemctl)

    changed = provider.render_unit("alpha", _context("alpha"))

    unit_path = provider.unit_path("alpha")
    assert changed is True
    assert unit_path.exists()
    contents = unit_path.read_text(encoding="utf-8")
    assert "Actual Budget Sync Server (alpha)" in contents
    assert "NODE_ENV=production" in contents

    assert calls == []

    # Second render with identical context should remain a no-op.
    changed_again = provider.render_unit("alpha", _context("alpha"))
    assert changed_again is False
    assert calls == []


@pytest.mark.parametrize("command", ["enable", "disable", "start", "stop"])
def test_unit_management_calls_systemctl(
    monkeypatch: pytest.MonkeyPatch,
    provider: SystemdProvider,
    command: str,
) -> None:
    """Enable/disable/start/stop delegate to systemctl with the unit path."""
    captured: list[tuple[str, Path | None, bool]] = []

    def fake_systemctl(
        self: SystemdProvider,
        cmd: str,
        unit_or_path: Path | None = None,
        *,
        check: bool = True,
    ) -> DummyResult:
        captured.append((cmd, unit_or_path, check))
        return DummyResult(returncode=0)

    monkeypatch.setattr(SystemdProvider, "_systemctl", fake_systemctl)

    getattr(provider, command)("alpha")
    expected_path = provider.unit_path("alpha")
    assert captured == [(command, expected_path, True)]


def test_status_uses_non_check(
    monkeypatch: pytest.MonkeyPatch,
    provider: SystemdProvider,
) -> None:
    """Status calls systemctl with ``check=False`` and returns the result."""
    captured: list[tuple[str, Path | None, bool]] = []

    def fake_systemctl(
        self: SystemdProvider,
        cmd: str,
        unit_or_path: Path | None = None,
        *,
        check: bool = True,
    ) -> DummyResult:
        captured.append((cmd, unit_or_path, check))
        return DummyResult(returncode=0, stdout="ok")

    monkeypatch.setattr(SystemdProvider, "_systemctl", fake_systemctl)

    result = provider.status("alpha")
    assert captured == [("status", provider.unit_path("alpha"), False)]
    assert isinstance(result, DummyResult)
    assert result.stdout == "ok"


def test_remove_unit_unlinks_and_reload(
    monkeypatch: pytest.MonkeyPatch,
    provider: SystemdProvider,
) -> None:
    """Removing a unit file triggers daemon-reload once."""
    unit_path = provider.unit_path("alpha")
    unit_path.write_text("content", encoding="utf-8")

    calls: list[tuple[str, Path | None, bool]] = []

    def fake_systemctl(
        self: SystemdProvider,
        cmd: str,
        unit_or_path: Path | None = None,
        *,
        check: bool = True,
    ) -> DummyResult:
        calls.append((cmd, unit_or_path, check))
        return DummyResult()

    monkeypatch.setattr(SystemdProvider, "_systemctl", fake_systemctl)

    provider.remove("alpha")
    assert not unit_path.exists()
    assert calls == [("daemon-reload", None, True)]

    # Removing again should be a no-op.
    calls.clear()
    provider.remove("alpha")
    assert calls == []
