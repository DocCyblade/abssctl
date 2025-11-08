"""Tests covering Node runtime helpers."""
from __future__ import annotations

from pathlib import Path

import pytest

from abssctl.node_runtime import NodeRuntimeError, NodeRuntimeManager


def test_detect_version_handles_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    """detect_version should return None when node is absent."""
    manager = NodeRuntimeManager()

    def _raise_file_not_found(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError()

    monkeypatch.setattr("subprocess.run", _raise_file_not_found)
    assert manager.detect_version() is None


def test_detect_version_parses_semver(monkeypatch: pytest.MonkeyPatch) -> None:
    """detect_version should parse semver strings returned by node."""

    class _Result:
        def __init__(self) -> None:
            self.stdout = "v18.19.1"
            self.stderr = ""
            self.returncode = 0

    def _return_result(*args: object, **kwargs: object) -> _Result:
        return _Result()

    monkeypatch.setattr("subprocess.run", _return_result)
    manager = NodeRuntimeManager()
    info = manager.detect_version()
    assert info is not None
    assert info.major == 18
    assert info.minor == 19
    assert info.patch == 1


def test_ensure_version_installs_when_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ensure_version should invoke n install when the version is absent."""
    manager = NodeRuntimeManager(env_file=tmp_path / "abssctl-node", node_bin="node")
    calls: dict[str, int] = {"install": 0, "which": 0}

    state = {"installed": False}

    def _fake_assert(self: NodeRuntimeManager) -> None:
        return None

    def _fake_which(self: NodeRuntimeManager, version: str) -> Path | None:
        calls["which"] += 1
        if state["installed"]:
            node_dir = tmp_path / "nodes"
            node_dir.mkdir(parents=True, exist_ok=True)
            path = node_dir / f"node-{version}"
            path.write_text("#!/bin/sh\n", encoding="utf-8")
            return path
        return None

    def _fake_run_n(self: NodeRuntimeManager, args: list[str]) -> None:
        calls["install"] += 1
        state["installed"] = True

    monkeypatch.setattr(NodeRuntimeManager, "_assert_n_available", _fake_assert)
    monkeypatch.setattr(NodeRuntimeManager, "_which_version", _fake_which)
    monkeypatch.setattr(NodeRuntimeManager, "_run_n", _fake_run_n)

    result = manager.ensure_version("18.17.0")
    assert result.installed is True
    assert result.installation_performed is True
    assert result.env_changed is True
    assert calls["install"] == 1
    assert calls["which"] >= 2  # initial check + post-install confirmation
    contents = manager.env_file.read_text(encoding="utf-8")
    assert 'REQUIRED_NODE="18.17.0"' in contents


def test_ensure_version_dry_run_skips_mutations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run ensure should report planned changes without touching disk."""
    manager = NodeRuntimeManager(env_file=tmp_path / "abssctl-node")
    monkeypatch.setattr(NodeRuntimeManager, "_assert_n_available", lambda self: None)
    monkeypatch.setattr(NodeRuntimeManager, "_which_version", lambda self, version: None)

    def _unexpected_run(self: NodeRuntimeManager, _args: list[str]) -> None:
        raise RuntimeError("should not run")

    monkeypatch.setattr(NodeRuntimeManager, "_run_n", _unexpected_run)
    result = manager.ensure_version("18.17.0", dry_run=True)
    assert result.dry_run is True
    assert result.env_changed is True
    assert not manager.env_file.exists()


def test_ensure_version_errors_when_n_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """ensure_version should raise when n is unavailable."""
    manager = NodeRuntimeManager(n_bin="nonexistent-n")
    monkeypatch.setattr(NodeRuntimeManager, "_which_version", lambda self, version: None)
    with pytest.raises(NodeRuntimeError):
        manager.ensure_version("18.17.0")
