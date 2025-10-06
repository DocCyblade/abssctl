"""Configuration loader for abssctl.

This module centralises the logic for reading configuration values from
multiple sources following ADR-023:

1. Built-in defaults.
2. ``/etc/abssctl/config.yml`` (or an override path).
3. Environment variables prefixed with ``ABSSCTL_``.
4. Explicit overrides supplied programmatically (reserved for CLI flags).

Environment keys use double underscores to express nesting, e.g.::

    export ABSSCTL_PORTS__BASE=6000
    export ABSSCTL_TLS__ENABLED=false

Values are coerced via PyYAML's ``safe_load`` so that booleans and numbers are
parsed naturally. The resulting configuration is exposed as immutable
``dataclasses`` for convenient access and type safety.
"""
from __future__ import annotations

import os
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

try:  # PyYAML is a runtime dependency (declared in pyproject.toml).
    import yaml
except Exception as exc:  # pragma: no cover - import failure covered in tests
    raise RuntimeError(
        "PyYAML is required to load abssctl configuration. Install with "
        "`pip install abssctl` or ensure PyYAML>=6.0 is available."
    ) from exc


ENV_PREFIX = "ABSSCTL_"
CONFIG_ENV_VAR = f"{ENV_PREFIX}CONFIG_FILE"


class ConfigError(RuntimeError):
    """Raised when configuration parsing fails."""


@dataclass(frozen=True)
class PortsConfig:
    """Port allocation defaults."""

    base: int = 5000
    strategy: str = "sequential"

    def to_dict(self) -> dict[str, object]:
        """Return a serialisable representation."""
        return {"base": self.base, "strategy": self.strategy}


@dataclass(frozen=True)
class TLSSystemConfig:
    """System certificate bundle shipped on TurnKey Linux."""

    cert: Path = Path("/etc/ssl/private/cert.pem")
    key: Path = Path("/etc/ssl/private/cert.key")

    def to_dict(self) -> dict[str, object]:
        """Return a serialisable representation."""
        return {"cert": str(self.cert), "key": str(self.key)}


@dataclass(frozen=True)
class TLSLetsEncryptConfig:
    """Paths to the Let's Encrypt live directory."""

    live_dir: Path = Path("/etc/letsencrypt/live")

    def to_dict(self) -> dict[str, object]:
        """Return a serialisable representation."""
        return {"live_dir": str(self.live_dir)}


@dataclass(frozen=True)
class TLSConfig:
    """Aggregated TLS configuration values."""

    enabled: bool = True
    system: TLSSystemConfig = TLSSystemConfig()
    lets_encrypt: TLSLetsEncryptConfig = TLSLetsEncryptConfig()

    def to_dict(self) -> dict[str, object]:
        """Return a serialisable representation."""
        return {
            "enabled": self.enabled,
            "system": self.system.to_dict(),
            "lets_encrypt": self.lets_encrypt.to_dict(),
        }


@dataclass(frozen=True)
class AppConfig:
    """Resolved configuration values for abssctl."""

    config_file: Path
    install_root: Path
    instance_root: Path
    state_dir: Path
    registry_dir: Path
    logs_dir: Path
    runtime_dir: Path
    npm_package_name: str
    reverse_proxy: str
    service_user: str
    default_version: str
    ports: PortsConfig
    tls: TLSConfig

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable representation of the config."""
        return {
            "config_file": str(self.config_file),
            "install_root": str(self.install_root),
            "instance_root": str(self.instance_root),
            "state_dir": str(self.state_dir),
            "registry_dir": str(self.registry_dir),
            "logs_dir": str(self.logs_dir),
            "runtime_dir": str(self.runtime_dir),
            "npm_package_name": self.npm_package_name,
            "reverse_proxy": self.reverse_proxy,
            "service_user": self.service_user,
            "default_version": self.default_version,
            "ports": self.ports.to_dict(),
            "tls": self.tls.to_dict(),
        }


DEFAULTS: dict[str, object] = {
    "config_file": "/etc/abssctl/config.yml",
    "install_root": "/srv/app",
    "instance_root": "/srv",
    "state_dir": "/var/lib/abssctl",
    "registry_dir": None,  # derived from state_dir when absent
    "logs_dir": "/var/log/abssctl",
    "runtime_dir": "/run/abssctl",
    "npm_package_name": "@actual-app/sync-server",
    "reverse_proxy": "nginx",
    "service_user": "actual-sync",
    "default_version": "current",
    "ports": {
        "base": 5000,
        "strategy": "sequential",
    },
    "tls": {
        "enabled": True,
        "system": {
            "cert": "/etc/ssl/private/cert.pem",
            "key": "/etc/ssl/private/cert.key",
        },
        "lets_encrypt": {
            "live_dir": "/etc/letsencrypt/live",
        },
    },
}


def load_config(
    config_file: str | os.PathLike[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    overrides: Mapping[str, object] | None = None,
) -> AppConfig:
    """Load and merge configuration sources into an :class:`AppConfig`."""
    merged: dict[str, object] = _deep_copy(DEFAULTS)
    resolved_env = dict(os.environ if env is None else env)

    config_default = _expect_str(merged["config_file"], "config_file")
    config_path = _determine_config_path(config_default, config_file, resolved_env)

    file_values = _load_yaml_file(config_path)
    if file_values:
        _deep_merge(merged, file_values)

    env_values = _build_env_overrides(resolved_env)
    if env_values:
        _deep_merge(merged, env_values)

    if overrides:
        _deep_merge(merged, dict(overrides))

    merged["config_file"] = str(config_path)

    return _build_app_config(merged)


def _determine_config_path(
    default_path: str,
    cli_override: str | os.PathLike[str] | None,
    env: Mapping[str, str],
) -> Path:
    if cli_override:
        return Path(cli_override)
    if CONFIG_ENV_VAR in env:
        return Path(env[CONFIG_ENV_VAR])
    return Path(default_path)


def _load_yaml_file(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:  # pragma: no cover - PyYAML owns detailed error
        raise ConfigError(f"Failed to parse config file {path}: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ConfigError(f"Config file {path} must contain a mapping at the top level.")
    return _as_dict(data, f"file:{path}")


def _build_app_config(raw: Mapping[str, object]) -> AppConfig:
    config_file = _to_path(raw.get("config_file"))
    install_root = _to_path(raw.get("install_root"))
    instance_root = _to_path(raw.get("instance_root"))
    state_dir = _to_path(raw.get("state_dir"))
    logs_dir = _to_path(raw.get("logs_dir"))
    runtime_dir = _to_path(raw.get("runtime_dir"))

    registry_dir_value = raw.get("registry_dir")
    registry_dir = _to_path(registry_dir_value) if registry_dir_value else state_dir / "registry"

    ports_mapping = _as_dict(raw.get("ports"), "ports")
    ports = PortsConfig(
        base=_expect_int(ports_mapping.get("base"), "ports.base", default=5000),
        strategy=str(ports_mapping.get("strategy", "sequential")),
    )

    tls_mapping = _as_dict(raw.get("tls"), "tls")
    tls_enabled = bool(tls_mapping.get("enabled", True))
    system_mapping = _as_dict(tls_mapping.get("system"), "tls.system")
    lets_mapping = _as_dict(tls_mapping.get("lets_encrypt"), "tls.lets_encrypt")

    tls = TLSConfig(
        enabled=tls_enabled,
        system=TLSSystemConfig(
            cert=_to_path(system_mapping.get("cert", "/etc/ssl/private/cert.pem")),
            key=_to_path(system_mapping.get("key", "/etc/ssl/private/cert.key")),
        ),
        lets_encrypt=TLSLetsEncryptConfig(
            live_dir=_to_path(lets_mapping.get("live_dir", "/etc/letsencrypt/live")),
        ),
    )

    return AppConfig(
        config_file=config_file,
        install_root=install_root,
        instance_root=instance_root,
        state_dir=state_dir,
        registry_dir=registry_dir,
        logs_dir=logs_dir,
        runtime_dir=runtime_dir,
        npm_package_name=str(raw.get("npm_package_name", "@actual-app/sync-server")),
        reverse_proxy=str(raw.get("reverse_proxy", "nginx")),
        service_user=str(raw.get("service_user", "actual-sync")),
        default_version=str(raw.get("default_version", "current")),
        ports=ports,
        tls=tls,
    )


def _build_env_overrides(env: Mapping[str, str]) -> dict[str, object]:
    overrides: dict[str, object] = {}
    for key, value in env.items():
        if not key.startswith(ENV_PREFIX):
            continue
        suffix = key[len(ENV_PREFIX) :]
        path_segments = [segment.lower() for segment in suffix.split("__") if segment]
        if not path_segments:
            continue
        _assign_nested(overrides, path_segments, _coerce_value(value))
    return overrides


def _assign_nested(tree: MutableMapping[str, object], path: list[str], value: object) -> None:
    current: MutableMapping[str, object] = tree
    for segment in path[:-1]:
        existing = current.get(segment)
        if existing is None:
            new_child: MutableMapping[str, object] = {}
            current[segment] = new_child
            current = new_child
            continue
        if isinstance(existing, MutableMapping):
            current = cast(MutableMapping[str, object], existing)
            continue
        raise ConfigError(
            "Environment overrides conflict with existing scalar value at "
            f"{'.'.join(path)}"
        )
    current[path[-1]] = value


def _deep_merge(target: MutableMapping[str, object], overrides: Mapping[str, object]) -> None:
    for key, value in overrides.items():
        existing = target.get(key)
        if isinstance(existing, MutableMapping) and isinstance(value, Mapping):
            _deep_merge(existing, _as_dict(value, f"merge.{key}"))
            continue
        target[key] = value


def _deep_copy(source: Mapping[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in source.items():
        if isinstance(value, Mapping):
            result[key] = _deep_copy(_as_dict(value, f"copy.{key}"))
        else:
            result[key] = value
    return result


def _coerce_value(raw: str) -> object:
    raw = raw.strip()
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError:  # pragma: no cover - treat as string if parsing fails
        return raw
    return parsed


def _to_path(value: object) -> Path:
    if value is None:
        raise ConfigError("Expected a filesystem path, received None.")
    if isinstance(value, Path):
        return value.expanduser()
    if isinstance(value, str):
        return Path(value).expanduser()
    raise ConfigError(f"Cannot convert value {value!r} to Path.")


def _expect_int(value: object | None, label: str, *, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        raise ConfigError(f"Expected {label} to be an integer. Got boolean {value!r}.")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ConfigError(f"Invalid integer for {label}: {value!r}.") from exc
    raise ConfigError(f"Expected {label} to be an integer. Got {type(value).__name__}.")


def _expect_str(value: object, key: str) -> str:
    if isinstance(value, str):
        return value
    raise ConfigError(f"Expected {key} to resolve to a string. Got {value!r}.")


def _as_dict(value: object | None, label: str) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigError(f"Expected {label} to be a mapping. Got {type(value).__name__}.")
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ConfigError(f"Mapping {label} must use string keys. Got {key!r}.")
        result[key] = item
    return result


__all__ = [
    "AppConfig",
    "ConfigError",
    "PortsConfig",
    "TLSConfig",
    "TLSSystemConfig",
    "TLSLetsEncryptConfig",
    "load_config",
]
