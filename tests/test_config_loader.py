"""Configuration loader tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from abssctl.config import AppConfig, ConfigError, load_config


def test_load_config_defaults_when_file_missing(tmp_path: Path) -> None:
    """Defaults apply when no config file is present."""
    config = load_config(env={})

    assert isinstance(config, AppConfig)
    assert config.install_root == Path("/srv/app")
    assert config.registry_dir == Path("/var/lib/abssctl/registry")
    assert config.tls.enabled is True
    assert config.templates_dir == Path("/etc/abssctl/templates")
    assert config.backups.root == Path("/srv/backups")
    assert config.backups.index == Path("/srv/backups/backups.json")
    assert config.backups.compression == "auto"


def test_load_config_reads_yaml_file(tmp_path: Path) -> None:
    """Values are loaded from the YAML config file."""
    cfg = tmp_path / "abssctl.yml"
    cfg.write_text(
        "install_root: /opt/actual\n"
        "ports:\n"
        "  base: 6200\n"
        "tls:\n"
        "  enabled: false\n"
        "backups:\n"
        "  root: {root}\n"
        "  compression:\n"
        "    algorithm: gzip\n"
    )
    cfg.write_text(
        cfg.read_text().format(root=str(tmp_path / "backups"))
    )

    config = load_config(config_file=cfg, env={})

    assert config.config_file == cfg
    assert config.install_root == Path("/opt/actual")
    assert config.ports.base == 6200
    assert config.tls.enabled is False
    assert config.backups.root == tmp_path / "backups"
    assert config.backups.compression == "gzip"


def test_env_overrides_take_precedence(tmp_path: Path) -> None:
    """Environment variables override defaults and file settings."""
    state_dir = tmp_path / "state"
    env = {
        "ABSSCTL_PORTS__BASE": "6500",
        "ABSSCTL_TLS__ENABLED": "false",
        "ABSSCTL_STATE_DIR": str(state_dir),
        "ABSSCTL_LOCK_TIMEOUT": "45",
        "ABSSCTL_TEMPLATES_DIR": str(tmp_path / "templates"),
        "ABSSCTL_BACKUPS__ROOT": str(tmp_path / "bk"),
        "ABSSCTL_BACKUPS__COMPRESSION__ALGORITHM": "none",
        "ABSSCTL_BACKUPS__COMPRESSION__LEVEL": "5",
    }

    config = load_config(env=env)

    assert config.ports.base == 6500
    assert config.tls.enabled is False
    assert config.state_dir == state_dir
    assert config.registry_dir == state_dir / "registry"
    assert config.lock_timeout == 45.0
    assert config.templates_dir == tmp_path / "templates"
    assert config.backups.root == tmp_path / "bk"
    assert config.backups.index == (tmp_path / "bk" / "backups.json")
    assert config.backups.compression == "none"
    assert config.backups.compression_level == 5


def test_env_can_select_config_file(tmp_path: Path) -> None:
    """Environment variable selects an alternate config file."""
    cfg = tmp_path / "override.yml"
    cfg.write_text("npm_package_name: local-package\n")

    env = {"ABSSCTL_CONFIG_FILE": str(cfg)}
    config = load_config(env=env)

    assert config.config_file == cfg
    assert config.npm_package_name == "local-package"


def test_invalid_config_file_raises(tmp_path: Path) -> None:
    """Invalid YAML raises a ConfigError."""
    cfg = tmp_path / "bad.yml"
    cfg.write_text("- not-a-mapping\n")

    with pytest.raises(ConfigError):
        load_config(config_file=cfg, env={})


def test_unknown_top_level_key_raises(tmp_path: Path) -> None:
    """Unexpected top-level keys trigger ConfigError."""
    cfg = tmp_path / "config.yml"
    cfg.write_text("unknown: value\n")

    with pytest.raises(ConfigError, match="Unknown configuration keys"):
        load_config(config_file=cfg, env={})


def test_invalid_port_strategy_raises(tmp_path: Path) -> None:
    """Unsupported port strategies raise ConfigError."""
    cfg = tmp_path / "config.yml"
    cfg.write_text(
        "ports:\n"
        "  strategy: dynamic\n"
    )

    with pytest.raises(ConfigError, match="Unsupported port allocation strategy"):
        load_config(config_file=cfg, env={})


def test_unknown_tls_nested_keys_raise(tmp_path: Path) -> None:
    """Extra TLS keys produce ConfigError for clarity."""
    cfg = tmp_path / "config.yml"
    cfg.write_text(
        "tls:\n"
        "  enabled: true\n"
        "  extra: true\n"
    )

    with pytest.raises(ConfigError, match="Unknown TLS configuration keys"):
        load_config(config_file=cfg, env={})


def test_invalid_backup_compression_algorithm_raises(tmp_path: Path) -> None:
    """Unsupported backup compression algorithms raise errors."""
    cfg = tmp_path / "config.yml"
    cfg.write_text(
        "backups:\n"
        "  compression:\n"
        "    algorithm: invalid\n"
    )

    with pytest.raises(ConfigError, match="Unsupported backup compression"):
        load_config(config_file=cfg, env={})
