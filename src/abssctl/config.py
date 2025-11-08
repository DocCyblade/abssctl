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
from collections.abc import Mapping, MutableMapping, Sequence
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
RESERVED_ENV_KEYS = {
    CONFIG_ENV_VAR,
    f"{ENV_PREFIX}SKIP_NPM",
    f"{ENV_PREFIX}VERSIONS_CACHE",
}


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
class TLSPermissionSpec:
    """Expected ownership and mode for a TLS-related file."""

    owner: str
    group: str | None
    mode: int

    def to_dict(self) -> dict[str, object]:
        """Return a serialisable representation."""
        return {
            "owner": self.owner,
            "group": self.group,
            "mode": f"{self.mode:04o}",
        }


@dataclass(frozen=True)
class TLSValidationConfig:
    """TLS validation expectations (permissions, expiry thresholds)."""

    warn_expiry_days: int = 30
    key_permissions: tuple[TLSPermissionSpec, ...] = (
        TLSPermissionSpec(owner="root", group="ssl-cert", mode=0o640),
        TLSPermissionSpec(owner="root", group="root", mode=0o600),
    )
    cert_permissions: TLSPermissionSpec = TLSPermissionSpec(
        owner="root",
        group="root",
        mode=0o644,
    )
    chain_permissions: TLSPermissionSpec = TLSPermissionSpec(
        owner="root",
        group="root",
        mode=0o644,
    )

    def to_dict(self) -> dict[str, object]:
        """Return a serialisable representation."""
        return {
            "warn_expiry_days": self.warn_expiry_days,
            "key_permissions": [permission.to_dict() for permission in self.key_permissions],
            "cert_permissions": self.cert_permissions.to_dict(),
            "chain_permissions": self.chain_permissions.to_dict(),
        }


@dataclass(frozen=True)
class TLSConfig:
    """Aggregated TLS configuration values."""

    enabled: bool = True
    system: TLSSystemConfig = TLSSystemConfig()
    lets_encrypt: TLSLetsEncryptConfig = TLSLetsEncryptConfig()
    validation: TLSValidationConfig = TLSValidationConfig()

    def to_dict(self) -> dict[str, object]:
        """Return a serialisable representation."""
        return {
            "enabled": self.enabled,
            "system": self.system.to_dict(),
            "lets_encrypt": self.lets_encrypt.to_dict(),
            "validation": self.validation.to_dict(),
        }


@dataclass(frozen=True)
class BackupConfig:
    """Backup storage and compression defaults."""

    root: Path
    index: Path
    compression: str = "auto"
    compression_level: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a serialisable representation."""
        return {
            "root": str(self.root),
            "index": str(self.index),
            "compression": {
                "algorithm": self.compression,
                "level": self.compression_level,
            },
        }


@dataclass(frozen=True)
class SystemdConfig:
    """Systemd integration configuration values."""

    unit_dir: Path | None = None
    systemctl_bin: str = "systemctl"
    journalctl_bin: str = "journalctl"

    def to_dict(self) -> dict[str, object]:
        """Return a serialisable representation."""
        return {
            "unit_dir": str(self.unit_dir) if self.unit_dir is not None else None,
            "systemctl_bin": self.systemctl_bin,
            "journalctl_bin": self.journalctl_bin,
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
    templates_dir: Path
    lock_timeout: float
    npm_package_name: str
    reverse_proxy: str
    service_user: str
    default_version: str
    ports: PortsConfig
    tls: TLSConfig
    backups: BackupConfig
    systemd: SystemdConfig
    node_compat_file: Path | None

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
            "templates_dir": str(self.templates_dir),
            "lock_timeout": self.lock_timeout,
            "npm_package_name": self.npm_package_name,
            "reverse_proxy": self.reverse_proxy,
            "service_user": self.service_user,
            "default_version": self.default_version,
            "ports": self.ports.to_dict(),
            "tls": self.tls.to_dict(),
            "backups": self.backups.to_dict(),
            "systemd": self.systemd.to_dict(),
            "node_compat_file": str(self.node_compat_file) if self.node_compat_file else None,
        }


DEFAULTS: dict[str, object] = {
    "config_file": "/etc/abssctl/config.yml",
    "install_root": "/srv/app",
    "instance_root": "/srv",
    "state_dir": "/var/lib/abssctl",
    "registry_dir": None,  # derived from state_dir when absent
    "logs_dir": "/var/log/abssctl",
    "runtime_dir": "/run/abssctl",
    "templates_dir": "/etc/abssctl/templates",
    "lock_timeout": 30.0,
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
        "validation": {
            "warn_expiry_days": 30,
            "key_permissions": [
                {"owner": "root", "group": "ssl-cert", "mode": "0640"},
                {"owner": "root", "group": "root", "mode": "0600"},
            ],
            "cert_permissions": {"owner": "root", "group": "root", "mode": "0644"},
            "chain_permissions": {"owner": "root", "group": "root", "mode": "0644"},
        },
    },
    "backups": {
        "root": "/srv/backups",
        "index": None,
        "compression": {
            "algorithm": "auto",
            "level": None,
        },
    },
    "systemd": {
        "unit_dir": None,
        "systemctl_bin": "systemctl",
        "journalctl_bin": "journalctl",
    },
    "node_compat_file": None,
}

ALLOWED_TOP_LEVEL_KEYS = set(DEFAULTS.keys())
ALLOWED_PORT_STRATEGIES = {"sequential"}
ALLOWED_BACKUP_COMPRESSION = {"auto", "zstd", "gzip", "none"}


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

    _validate_structure(merged)

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


def _validate_structure(raw: Mapping[str, object]) -> None:
    unknown_keys = set(raw.keys()) - ALLOWED_TOP_LEVEL_KEYS
    if unknown_keys:
        joined = ", ".join(sorted(unknown_keys))
        raise ConfigError(f"Unknown configuration keys: {joined}.")

    lock_timeout = raw.get("lock_timeout")
    if lock_timeout is not None:
        _expect_positive_float(lock_timeout, "lock_timeout", default=30.0)

    ports = raw.get("ports")
    if ports is not None:
        ports_map = _as_dict(ports, "ports")
        unknown = set(ports_map.keys()) - {"base", "strategy"}
        if unknown:
            joined = ", ".join(sorted(unknown))
            raise ConfigError(f"Unknown ports configuration keys: {joined}.")
        strategy = ports_map.get("strategy")
        if strategy is not None and str(strategy) not in ALLOWED_PORT_STRATEGIES:
            allowed = ", ".join(sorted(ALLOWED_PORT_STRATEGIES))
            raise ConfigError(
                f"Unsupported port allocation strategy '{strategy}'. Allowed: {allowed}."
            )

    tls = raw.get("tls")
    if tls is not None:
        tls_map = _as_dict(tls, "tls")
        unknown = set(tls_map.keys()) - {"enabled", "system", "lets_encrypt", "validation"}
        if unknown:
            joined = ", ".join(sorted(unknown))
            raise ConfigError(f"Unknown TLS configuration keys: {joined}.")

        system_map = _as_dict(tls_map.get("system"), "tls.system")
        unknown_system = set(system_map.keys()) - {"cert", "key"}
        if unknown_system:
            joined = ", ".join(sorted(unknown_system))
            raise ConfigError(f"Unknown TLS system keys: {joined}.")

        lets_map = _as_dict(tls_map.get("lets_encrypt"), "tls.lets_encrypt")
        unknown_lets = set(lets_map.keys()) - {"live_dir"}
        if unknown_lets:
            joined = ", ".join(sorted(unknown_lets))
            raise ConfigError(f"Unknown TLS lets_encrypt keys: {joined}.")

        validation_map = _as_dict(tls_map.get("validation"), "tls.validation")
        unknown_validation = set(validation_map.keys()) - {
            "warn_expiry_days",
            "key_permissions",
            "cert_permissions",
            "chain_permissions",
        }
        if unknown_validation:
            joined = ", ".join(sorted(unknown_validation))
            raise ConfigError(f"Unknown TLS validation keys: {joined}.")

        warn_value = validation_map.get("warn_expiry_days")
        if warn_value is not None:
            warn_days = _expect_int(warn_value, "tls.validation.warn_expiry_days", default=30)
            if warn_days < 0:
                raise ConfigError("tls.validation.warn_expiry_days must be non-negative.")

        key_permissions_raw = validation_map.get("key_permissions")
        if key_permissions_raw is not None:
            key_permissions = _as_sequence(key_permissions_raw, "tls.validation.key_permissions")
            for index, entry in enumerate(key_permissions):
                mapping = _as_dict(entry, f"tls.validation.key_permissions[{index}]")
                _validate_tls_permission_mapping(
                    mapping,
                    f"tls.validation.key_permissions[{index}]",
                )

        for field in ("cert_permissions", "chain_permissions"):
            permission_raw = validation_map.get(field)
            if permission_raw is not None:
                permission_map = _as_dict(permission_raw, f"tls.validation.{field}")
                _validate_tls_permission_mapping(permission_map, f"tls.validation.{field}")

    backups = raw.get("backups")
    if backups is not None:
        backups_map = _as_dict(backups, "backups")
        unknown = set(backups_map.keys()) - {"root", "index", "compression"}
        if unknown:
            joined = ", ".join(sorted(unknown))
            raise ConfigError(f"Unknown backups configuration keys: {joined}.")

        compression_map = _as_dict(backups_map.get("compression"), "backups.compression")
        unknown_comp = set(compression_map.keys()) - {"algorithm", "level"}
        if unknown_comp:
            joined = ", ".join(sorted(unknown_comp))
            raise ConfigError(f"Unknown backups compression keys: {joined}.")

        algorithm = str(compression_map.get("algorithm", "auto"))
        if algorithm not in ALLOWED_BACKUP_COMPRESSION:
            allowed = ", ".join(sorted(ALLOWED_BACKUP_COMPRESSION))
            raise ConfigError(
                f"Unsupported backup compression '{algorithm}'. Allowed: {allowed}."
            )

        level = compression_map.get("level")
        if level is not None and not isinstance(level, (int, str)):
            raise ConfigError("backups.compression.level must be an integer or string value.")
        if isinstance(level, str):
            try:
                int(level, 0)
            except ValueError as exc:
                raise ConfigError(
                    f"Invalid integer for backups.compression.level: {level!r}."
                ) from exc

    systemd = raw.get("systemd")
    if systemd is not None:
        systemd_map = _as_dict(systemd, "systemd")
        unknown = set(systemd_map.keys()) - {"unit_dir", "systemctl_bin", "journalctl_bin"}
        if unknown:
            joined = ", ".join(sorted(unknown))
            raise ConfigError(f"Unknown systemd configuration keys: {joined}.")


def _build_app_config(raw: Mapping[str, object]) -> AppConfig:
    config_file = _to_path(raw.get("config_file"))
    install_root = _to_path(raw.get("install_root"))
    instance_root = _to_path(raw.get("instance_root"))
    state_dir = _to_path(raw.get("state_dir"))
    logs_dir = _to_path(raw.get("logs_dir"))
    runtime_dir = _to_path(raw.get("runtime_dir"))
    templates_dir = _to_path(raw.get("templates_dir"))
    node_compat_value = raw.get("node_compat_file")
    node_compat_file: Path | None = None
    if isinstance(node_compat_value, (str, Path)):
        if str(node_compat_value).strip():
            node_compat_file = _to_path(node_compat_value)
    elif node_compat_value not in (None, ""):
        raise ConfigError("node_compat_file must be a string, Path, or null.")
    lock_timeout = _expect_positive_float(raw.get("lock_timeout"), "lock_timeout", default=30.0)

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
    validation_mapping = _as_dict(tls_mapping.get("validation"), "tls.validation")

    default_validation = TLSValidationConfig()
    warn_expiry_days = _expect_int(
        validation_mapping.get("warn_expiry_days"),
        "tls.validation.warn_expiry_days",
        default=default_validation.warn_expiry_days,
    )
    if warn_expiry_days < 0:
        raise ConfigError("tls.validation.warn_expiry_days must be non-negative.")

    raw_key_permissions = validation_mapping.get("key_permissions")
    key_permission_specs: tuple[TLSPermissionSpec, ...]
    if raw_key_permissions is None:
        key_permission_specs = default_validation.key_permissions
    else:
        sequence = list(_as_sequence(raw_key_permissions, "tls.validation.key_permissions"))
        if not sequence:
            key_permission_specs = default_validation.key_permissions
        else:
            parsed_permissions: list[TLSPermissionSpec] = []
            for index, entry in enumerate(sequence):
                mapping = _as_dict(entry, f"tls.validation.key_permissions[{index}]")
                default_entry = (
                    default_validation.key_permissions[index]
                    if index < len(default_validation.key_permissions)
                    else default_validation.key_permissions[-1]
                )
                parsed_permissions.append(
                    _build_tls_permission(
                        mapping,
                        default_owner=default_entry.owner,
                        default_group=default_entry.group,
                        default_mode=default_entry.mode,
                        context=f"tls.validation.key_permissions[{index}]",
                    )
                )
            key_permission_specs = tuple(parsed_permissions)

    cert_permissions = _build_tls_permission(
        _as_dict(validation_mapping.get("cert_permissions"), "tls.validation.cert_permissions"),
        default_owner=default_validation.cert_permissions.owner,
        default_group=default_validation.cert_permissions.group,
        default_mode=default_validation.cert_permissions.mode,
        context="tls.validation.cert_permissions",
    )

    chain_permissions = _build_tls_permission(
        _as_dict(validation_mapping.get("chain_permissions"), "tls.validation.chain_permissions"),
        default_owner=default_validation.chain_permissions.owner,
        default_group=default_validation.chain_permissions.group,
        default_mode=default_validation.chain_permissions.mode,
        context="tls.validation.chain_permissions",
    )

    validation = TLSValidationConfig(
        warn_expiry_days=warn_expiry_days,
        key_permissions=key_permission_specs,
        cert_permissions=cert_permissions,
        chain_permissions=chain_permissions,
    )

    tls = TLSConfig(
        enabled=tls_enabled,
        system=TLSSystemConfig(
            cert=_to_path(system_mapping.get("cert", "/etc/ssl/private/cert.pem")),
            key=_to_path(system_mapping.get("key", "/etc/ssl/private/cert.key")),
        ),
        lets_encrypt=TLSLetsEncryptConfig(
            live_dir=_to_path(lets_mapping.get("live_dir", "/etc/letsencrypt/live")),
        ),
        validation=validation,
    )

    backups_mapping = _as_dict(raw.get("backups"), "backups")
    backups_root = _to_path(backups_mapping.get("root", "/srv/backups"))
    backups_index_value = backups_mapping.get("index")
    backups_index = (
        _to_path(backups_index_value) if backups_index_value else backups_root / "backups.json"
    )
    compression_mapping = _as_dict(backups_mapping.get("compression"), "backups.compression")
    compression_algorithm = str(compression_mapping.get("algorithm", "auto"))
    compression_level_raw = compression_mapping.get("level")
    compression_level: int | None = None
    if compression_level_raw is not None:
        parsed_level = _expect_int(
            compression_level_raw, "backups.compression.level", default=1
        )
        if parsed_level <= 0:
            raise ConfigError(
                "backups.compression.level must be greater than zero when specified."
            )
        compression_level = parsed_level

    backups = BackupConfig(
        root=backups_root,
        index=backups_index,
        compression=compression_algorithm,
        compression_level=compression_level,
    )

    systemd_mapping = _as_dict(raw.get("systemd"), "systemd")
    unit_dir_value = systemd_mapping.get("unit_dir")
    systemd_unit_dir = _to_path(unit_dir_value) if unit_dir_value else None
    systemd = SystemdConfig(
        unit_dir=systemd_unit_dir,
        systemctl_bin=str(systemd_mapping.get("systemctl_bin", "systemctl")),
        journalctl_bin=str(systemd_mapping.get("journalctl_bin", "journalctl")),
    )

    return AppConfig(
        config_file=config_file,
        install_root=install_root,
        instance_root=instance_root,
        state_dir=state_dir,
        registry_dir=registry_dir,
        logs_dir=logs_dir,
        runtime_dir=runtime_dir,
        templates_dir=templates_dir,
        lock_timeout=lock_timeout,
        npm_package_name=str(raw.get("npm_package_name", "@actual-app/sync-server")),
        reverse_proxy=str(raw.get("reverse_proxy", "nginx")),
        service_user=str(raw.get("service_user", "actual-sync")),
        default_version=str(raw.get("default_version", "current")),
        ports=ports,
        tls=tls,
        backups=backups,
        systemd=systemd,
        node_compat_file=node_compat_file,
    )


def _build_env_overrides(env: Mapping[str, str]) -> dict[str, object]:
    overrides: dict[str, object] = {}
    for key, value in env.items():
        if key in RESERVED_ENV_KEYS:
            continue
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


def _as_sequence(value: object, label: str) -> Sequence[object]:
    if isinstance(value, (str, bytes)):
        raise ConfigError(f"Expected {label} to be a sequence. Got {type(value).__name__}.")
    if not isinstance(value, Sequence):
        raise ConfigError(f"Expected {label} to be a sequence. Got {type(value).__name__}.")
    return value


def _validate_tls_permission_mapping(mapping: Mapping[str, object], context: str) -> None:
    unknown = set(mapping.keys()) - {"owner", "group", "mode"}
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise ConfigError(f"Unknown keys for {context}: {joined}.")

    owner = mapping.get("owner")
    if owner is not None and not isinstance(owner, str):
        raise ConfigError(f"{context}.owner must be a string when provided.")

    group = mapping.get("group")
    if group is not None and not isinstance(group, str):
        raise ConfigError(f"{context}.group must be a string or null.")

    if "mode" in mapping:
        _parse_permission_mode(mapping["mode"], f"{context}.mode")


def _parse_permission_mode(value: object, label: str) -> int:
    if value is None:
        raise ConfigError(f"{label} must be specified.")
    if isinstance(value, bool):
        raise ConfigError(f"{label} must be an octal integer string. Got boolean {value!r}.")
    if isinstance(value, int):
        mode = value
    elif isinstance(value, str):
        text = value.strip().lower()
        if not text:
            raise ConfigError(f"{label} must be an octal integer string.")
        if text.startswith("0o"):
            text = text[2:]
        try:
            mode = int(text, 8)
        except ValueError as exc:
            raise ConfigError(f"{label} must be an octal integer string.") from exc
    else:
        raise ConfigError(f"{label} must be an octal integer or string.")
    if mode < 0 or mode > 0o777:
        raise ConfigError(f"{label} must be between 0000 and 0777 inclusive.")
    return mode


def _build_tls_permission(
    mapping: Mapping[str, object],
    *,
    default_owner: str,
    default_group: str | None,
    default_mode: int,
    context: str,
) -> TLSPermissionSpec:
    owner_value = mapping.get("owner")
    if owner_value is None:
        owner = default_owner
    elif isinstance(owner_value, str):
        owner = owner_value.strip()
        if not owner:
            raise ConfigError(f"{context}.owner must be a non-empty string.")
    else:
        raise ConfigError(f"{context}.owner must be a string.")

    group_value = mapping.get("group", default_group)
    if group_value is None or group_value == "":
        group = None
    elif isinstance(group_value, str):
        group = group_value
    else:
        raise ConfigError(f"{context}.group must be a string or null.")

    mode_value = mapping.get("mode", f"{default_mode:04o}")
    mode = _parse_permission_mode(mode_value, f"{context}.mode")

    return TLSPermissionSpec(owner=owner, group=group, mode=mode)


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


def _expect_positive_float(
    value: object | None,
    label: str,
    *,
    default: float,
) -> float:
    if value is None:
        return float(default)
    if isinstance(value, bool):
        raise ConfigError(f"Expected {label} to be a number. Got boolean {value!r}.")
    if isinstance(value, (int, float)):
        numeric = float(value)
    elif isinstance(value, str):
        try:
            numeric = float(value)
        except ValueError as exc:
            raise ConfigError(f"Invalid number for {label}: {value!r}.") from exc
    else:
        raise ConfigError(
            f"Expected {label} to be numeric. Got {type(value).__name__}."
        )
    if numeric <= 0:
        raise ConfigError(f"{label} must be greater than zero. Got {numeric}.")
    return numeric


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
    "BackupConfig",
    "PortsConfig",
    "SystemdConfig",
    "TLSValidationConfig",
    "TLSPermissionSpec",
    "TLSConfig",
    "TLSSystemConfig",
    "TLSLetsEncryptConfig",
    "load_config",
]
