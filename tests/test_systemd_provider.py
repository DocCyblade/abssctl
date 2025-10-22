"""Tests for the systemd provider."""
from __future__ import annotations

from collections.abc import Sequence
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
        "environment": [
            "NODE_ENV=production",
            f"ABSSCTL_INSTANCE={instance}",
            "PORT=5000",
            f"ABSSCTL_DOMAIN={instance}.local",
            "ABSSCTL_RUNTIME_DIR=/run/abssctl",
            "ABSSCTL_STATE_DIR=/var/lib/abssctl",
            "ABSSCTL_LOGS_DIR=/var/log/abssctl",
            "ABSSCTL_INSTALL_ROOT=/srv/app",
            "ABSSCTL_INSTANCE_ROOT=/srv",
            "ABSSCTL_CONFIG_FILE=/etc/abssctl/config.yml",
        ],
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
        dry_run: bool = False,
    ) -> DummyResult:
        calls.append((command, unit_or_path, check, dry_run))
        return DummyResult(returncode=0)

    monkeypatch.setattr(SystemdProvider, "_systemctl", fake_systemctl)

    changed = provider.render_unit("alpha", _context("alpha"))

    unit_path = provider.unit_path("alpha")
    assert changed is True
    assert unit_path.exists()
    contents = unit_path.read_text(encoding="utf-8")
    assert "Actual Budget Sync Server (alpha)" in contents
    assert "NODE_ENV=production" in contents
    assert "ABSSCTL_INSTANCE=alpha" in contents
    assert "PORT=5000" in contents
    assert "ABSSCTL_DOMAIN=alpha.local" in contents
    assert "ABSSCTL_RUNTIME_DIR=/run/abssctl" in contents
    assert "ABSSCTL_STATE_DIR=/var/lib/abssctl" in contents

    assert calls == [("daemon-reload", None, True, False)]

    # Second render with identical context should remain a no-op.
    calls.clear()
    changed_again = provider.render_unit("alpha", _context("alpha"))
    assert changed_again is False
    assert calls == []


@pytest.mark.parametrize("command", ["enable", "disable", "start", "stop"])
def test_unit_management_calls_systemctl(
    monkeypatch: pytest.MonkeyPatch,
    provider: SystemdProvider,
    command: str,
) -> None:
    """Enable/disable/start/stop delegate to systemctl with the unit name."""
    captured: list[tuple[str, Path | None, bool]] = []

    def fake_systemctl(
        self: SystemdProvider,
        cmd: str,
        unit_or_path: Path | None = None,
        *,
        check: bool = True,
        dry_run: bool = False,
    ) -> DummyResult:
        captured.append((cmd, unit_or_path, check, dry_run))
        return DummyResult(returncode=0)

    monkeypatch.setattr(SystemdProvider, "_systemctl", fake_systemctl)

    getattr(provider, command)("alpha")
    expected_unit = provider.unit_name("alpha")
    assert captured == [(command, expected_unit, True, False)]


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
        dry_run: bool = False,
    ) -> DummyResult:
        captured.append((cmd, unit_or_path, check, dry_run))
        return DummyResult(returncode=0, stdout="ok")

    monkeypatch.setattr(SystemdProvider, "_systemctl", fake_systemctl)

    result = provider.status("alpha")
    assert captured == [("status", provider.unit_name("alpha"), False, False)]
    assert isinstance(result, DummyResult)
    assert result.stdout == "ok"


def test_restart_calls_systemctl(
    monkeypatch: pytest.MonkeyPatch,
    provider: SystemdProvider,
) -> None:
    """Restart delegates to systemctl restart with the unit name."""
    captured: list[tuple[str, Path | None, bool]] = []

    def fake_systemctl(
        self: SystemdProvider,
        cmd: str,
        unit_or_path: Path | None = None,
        *,
        check: bool = True,
        dry_run: bool = False,
    ) -> DummyResult:
        captured.append((cmd, unit_or_path, check, dry_run))
        return DummyResult(returncode=0)

    monkeypatch.setattr(SystemdProvider, "_systemctl", fake_systemctl)

    provider.restart("alpha")
    assert captured == [("restart", provider.unit_name("alpha"), True, False)]


def test_logs_invokes_journalctl(
    monkeypatch: pytest.MonkeyPatch,
    provider: SystemdProvider,
) -> None:
    """Logs helper shells out to journalctl with expected arguments."""
    captured: list[tuple[list[str], bool, bool]] = []

    def fake_journalctl(
        self: SystemdProvider,
        args: Sequence[str],
        *,
        check: bool = True,
        capture_output: bool = True,
    ) -> DummyResult:
        captured.append((list(args), check, capture_output))
        return DummyResult(returncode=0, stdout="log lines")

    monkeypatch.setattr(SystemdProvider, "_journalctl", fake_journalctl)

    result = provider.logs("alpha", lines=50, since="2025-01-20")
    expected_args = [
        "--unit",
        provider.unit_name("alpha"),
        "--no-pager",
        "--lines",
        "50",
        "--since",
        "2025-01-20",
    ]
    assert captured == [(expected_args, True, True)]
    assert isinstance(result, DummyResult)

    captured.clear()
    provider.logs("alpha", follow=True)
    expected_follow = ["--unit", provider.unit_name("alpha"), "--no-pager", "--follow"]
    assert captured == [(expected_follow, True, False)]


def test_dry_run_skips_systemctl(
    monkeypatch: pytest.MonkeyPatch,
    provider: SystemdProvider,
) -> None:
    """Dry-run requests avoid executing systemctl and still report success."""
    captured: list[tuple[Sequence[str], bool]] = []

    def fake_run_command(
        self: SystemdProvider,
        args: Sequence[str],
        *,
        check: bool,
        error_prefix: str,
        capture_output: bool,
        dry_run: bool,
    ) -> DummyResult:
        captured.append((tuple(args), dry_run))
        return DummyResult(returncode=0)

    monkeypatch.setattr(SystemdProvider, "_run_command", fake_run_command)

    provider.enable("alpha", dry_run=True)
    assert captured == [(("systemctl", "enable", provider.unit_name("alpha")), True)]


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
        dry_run: bool = False,
    ) -> DummyResult:
        calls.append((cmd, unit_or_path, check, dry_run))
        return DummyResult()

    monkeypatch.setattr(SystemdProvider, "_systemctl", fake_systemctl)

    provider.remove("alpha")
    assert not unit_path.exists()
    assert calls == [("daemon-reload", None, True, False)]

    # Removing again should be a no-op.
    calls.clear()
    provider.remove("alpha")
    assert calls == []
