"""Coverage for VersionProvider npm/cache behaviours."""
from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from abssctl.providers.version_provider import VersionProvider


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_list_remote_versions_skip_env_short_circuits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ABSSCTL_SKIP_NPM bypasses cache lookups and npm calls."""
    cache_path = tmp_path / "remote.json"
    provider = VersionProvider(cache_path=cache_path)

    monkeypatch.setenv("ABSSCTL_SKIP_NPM", "1")

    def _fail_cache(path: Path) -> list[str]:
        raise AssertionError("cache should not be consulted")

    def _fail_npm(package: str) -> list[str]:
        raise AssertionError("npm should not be invoked")

    monkeypatch.setattr(provider, "_from_cache", _fail_cache)
    monkeypatch.setattr(provider, "_from_npm", _fail_npm)

    assert provider.list_remote_versions("pkg") == []


def test_list_remote_versions_prefers_instance_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Instance-specific cache_path takes precedence over environment cache."""
    local_cache = tmp_path / "cache" / "local.json"
    env_cache = tmp_path / "cache" / "env.json"
    _write_json(local_cache, ["25.9.0", "25.8.0"])
    _write_json(env_cache, ["25.7.0"])

    provider = VersionProvider(cache_path=local_cache)
    monkeypatch.delenv("ABSSCTL_SKIP_NPM", raising=False)
    monkeypatch.setenv("ABSSCTL_VERSIONS_CACHE", str(env_cache))

    assert provider.list_remote_versions("pkg") == ["25.9.0", "25.8.0"]


def test_list_remote_versions_env_cache_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid instance cache falls back to ABSSCTL_VERSIONS_CACHE."""
    local_cache = tmp_path / "cache" / "local.json"
    local_cache.parent.mkdir(parents=True, exist_ok=True)
    local_cache.write_text("{not-valid-json", encoding="utf-8")

    env_cache = tmp_path / "cache" / "env.json"
    _write_json(env_cache, ["25.6.0"])

    provider = VersionProvider(cache_path=local_cache)
    monkeypatch.setenv("ABSSCTL_VERSIONS_CACHE", str(env_cache))

    assert provider.list_remote_versions("pkg") == ["25.6.0"]


def test_list_remote_versions_npm_missing_binary_returns_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing npm binary returns []."""
    cache_path = tmp_path / "cache.json"
    provider = VersionProvider(cache_path=cache_path)
    monkeypatch.delenv("ABSSCTL_SKIP_NPM", raising=False)

    def _missing_npm(*args: object, **kwargs: object) -> CompletedProcess[str]:
        raise FileNotFoundError("npm not installed")

    monkeypatch.setattr("abssctl.providers.version_provider.subprocess.run", _missing_npm)

    result = provider.list_remote_versions("pkg")

    assert result == []
    assert not cache_path.exists()


def test_list_remote_versions_npm_non_zero_exit_returns_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-zero npm exit returns [] and avoids cache writes."""
    cache_path = tmp_path / "cache.json"
    provider = VersionProvider(cache_path=cache_path)

    monkeypatch.setattr(
        "abssctl.providers.version_provider.subprocess.run",
        lambda *args, **kwargs: CompletedProcess(args[0], 1, stdout="", stderr="boom"),
    )

    result = provider.list_remote_versions("pkg")

    assert result == []
    assert not cache_path.exists()


def test_list_remote_versions_npm_malformed_json_returns_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed npm stdout returns [] without writing cache."""
    cache_path = tmp_path / "cache.json"
    provider = VersionProvider(cache_path=cache_path)

    monkeypatch.setattr(
        "abssctl.providers.version_provider.subprocess.run",
        lambda *args, **kwargs: CompletedProcess(args[0], 0, stdout="not-json", stderr=""),
    )

    result = provider.list_remote_versions("pkg")

    assert result == []
    assert not cache_path.exists()


def test_list_remote_versions_success_writes_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful npm call writes cache and returns versions."""
    cache_path = tmp_path / "cache.json"
    provider = VersionProvider(cache_path=cache_path)
    payload = ["25.9.0", "25.8.0"]

    monkeypatch.setattr(
        "abssctl.providers.version_provider.subprocess.run",
        lambda *args, **kwargs: CompletedProcess(args[0], 0, stdout=json.dumps(payload), stderr=""),
    )

    result = provider.list_remote_versions("pkg")

    assert result == payload
    assert json.loads(cache_path.read_text(encoding="utf-8")) == payload


def test_list_remote_versions_cache_write_failure_suppressed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cache write errors are suppressed and versions still returned."""
    cache_path = tmp_path / "cache.json"
    provider = VersionProvider(cache_path=cache_path)
    payload = ["30.0.0"]

    monkeypatch.setattr(provider, "_from_npm", lambda package: payload)

    original_write_text = Path.write_text

    def failing_write_text(self: Path, *args: object, **kwargs: object) -> int:
        if self == cache_path:
            raise OSError("disk full")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", failing_write_text)

    result = provider.list_remote_versions("pkg")

    assert result == payload
    assert not cache_path.exists()


def test_refresh_cache_writes_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """refresh_cache persists npm data when successful."""
    cache_path = tmp_path / "cache.json"
    provider = VersionProvider(cache_path=cache_path)
    payload = ["25.4.0", "25.3.0"]

    monkeypatch.setattr(provider, "_from_npm", lambda package: payload)

    result = provider.refresh_cache("pkg")

    assert result == payload
    assert json.loads(cache_path.read_text(encoding="utf-8")) == payload


def test_refresh_cache_write_failure_suppressed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """refresh_cache tolerates write failures."""
    cache_path = tmp_path / "cache.json"
    provider = VersionProvider(cache_path=cache_path)

    monkeypatch.setattr(provider, "_from_npm", lambda package: ["25.0.0"])

    original_write_text = Path.write_text

    def failing_write_text(self: Path, *args: object, **kwargs: object) -> int:
        if self == cache_path:
            raise OSError("read-only")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", failing_write_text)

    result = provider.refresh_cache("pkg")

    assert result == ["25.0.0"]
    assert not cache_path.exists()
