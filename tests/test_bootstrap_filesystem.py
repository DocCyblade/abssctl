"""Unit tests for bootstrap filesystem planning helpers."""
from __future__ import annotations

import os
from pathlib import Path

from abssctl.bootstrap.filesystem import (
    DirectorySpec,
    apply_directory_plan,
    plan_directories,
)


def test_plan_creates_missing_directory(tmp_path: Path) -> None:
    """Plan should create directories that are absent on disk."""
    target = tmp_path / "var" / "lib" / "abssctl"
    spec = DirectorySpec(path=target, mode=0o750)

    plan = plan_directories([spec])
    assert any(action.kind == "mkdir" for action in plan.actions)

    apply_directory_plan(plan)
    assert target.is_dir()
    mode = target.stat().st_mode & 0o777
    assert mode == 0o750


def test_plan_adjusts_permissions(tmp_path: Path) -> None:
    """Plan should adjust permissions when they differ from expectations."""
    target = tmp_path / "var" / "log" / "abssctl"
    target.mkdir(parents=True, mode=0o700)
    os.chmod(target, 0o700)

    spec = DirectorySpec(path=target, mode=0o750)
    plan = plan_directories([spec])

    kinds = [action.kind for action in plan.actions]
    assert "chmod" in kinds

    apply_directory_plan(plan)
    mode = target.stat().st_mode & 0o777
    assert mode == 0o750


def test_plan_warns_on_non_directory(tmp_path: Path) -> None:
    """Plan should warn when the target path is not a directory."""
    target = tmp_path / "var" / "lib" / "abssctl"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("not a directory", encoding="utf-8")

    spec = DirectorySpec(path=target)
    plan = plan_directories([spec])

    assert plan.actions == []
    assert plan.warnings
