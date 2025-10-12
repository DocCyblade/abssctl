"""Tests for the abssctl CLI scaffold."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from abssctl import __version__
from abssctl.backups import BackupEntryBuilder, BackupsRegistry
from abssctl.cli import app
from abssctl.providers.nginx import NginxProvider
from abssctl.providers.systemd import SystemdProvider
from abssctl.providers.version_installer import VersionInstaller, VersionInstallResult
from abssctl.providers.version_provider import VersionProvider
from abssctl.state import StateRegistry

runner = CliRunner()

_TARBALL_DIGEST_BYTES = bytes(range(64))
FAKE_CLI_SHASUM = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
FAKE_CLI_INTEGRITY = f"sha512-{base64.b64encode(_TARBALL_DIGEST_BYTES).decode('ascii')}"
FAKE_CLI_DIGEST_HEX = _TARBALL_DIGEST_BYTES.hex()
FAKE_INTEGRITY_PAYLOAD = {
    "npm": {"shasum": FAKE_CLI_SHASUM, "integrity": FAKE_CLI_INTEGRITY},
    "tarball": {"algorithm": "sha512", "digest": FAKE_CLI_DIGEST_HEX},
}


def _prepare_environment(
    tmp_path: Path,
    *,
    config_overrides: dict[str, object] | None = None,
    versions: list[object] | None = None,
    instances: list[object] | None = None,
    remote_versions: list[str] | None = None,
) -> tuple[dict[str, str], Path]:
    state_dir = tmp_path / "state"
    logs_dir = tmp_path / "logs"
    runtime_dir = tmp_path / "run"
    templates_dir = tmp_path / "templates"
    config = {
        "state_dir": str(state_dir),
        "logs_dir": str(logs_dir),
        "runtime_dir": str(runtime_dir),
        "templates_dir": str(templates_dir),
        "backups": {"root": str(tmp_path / "backups")},
    }
    if config_overrides:
        config.update(config_overrides)

    config_file = tmp_path / "config.yml"
    config_file.write_text(yaml.safe_dump(config), encoding="utf-8")

    registry = StateRegistry(state_dir / "registry")

    if versions is not None:
        registry.write_versions(versions)

    if instances is not None:
        registry.write_instances(instances)

    env = {"ABSSCTL_CONFIG_FILE": str(config_file)}
    if remote_versions is not None:
        cache_file = tmp_path / "remote.json"
        cache_file.write_text(json.dumps(remote_versions), encoding="utf-8")
        env["ABSSCTL_VERSIONS_CACHE"] = str(cache_file)
        env.pop("ABSSCTL_SKIP_NPM", None)
    else:
        env["ABSSCTL_SKIP_NPM"] = "1"
    return env, state_dir


def test_version_option_outputs_package_version(tmp_path: Path) -> None:
    """CLI ``--version`` flag emits the package version."""
    env, _ = _prepare_environment(tmp_path)
    result = runner.invoke(app, ["--version"], env=env)

    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_invocation_without_subcommand_shows_help(tmp_path: Path) -> None:
    """Calling the CLI without a subcommand shows help output."""
    env, _ = _prepare_environment(tmp_path)
    result = runner.invoke(app, env=env)

    assert result.exit_code == 0
    assert "Actual Budget Multi-Instance Sync Server Admin CLI" in result.stdout


def test_config_show_renders_table(tmp_path: Path) -> None:
    """`config show` prints the merged configuration in a table."""
    env, state_dir = _prepare_environment(tmp_path)

    result = runner.invoke(app, ["config", "show"], env=env)

    assert result.exit_code == 0
    assert "state_dir" in result.stdout
    assert state_dir.name in result.stdout
    assert "lock_timeout" in result.stdout
    assert "templates_dir" in result.stdout


def test_config_show_json(tmp_path: Path) -> None:
    """`config show --json` emits JSON with the resolved configuration."""
    env, state_dir = _prepare_environment(
        tmp_path, config_overrides={"install_root": "/opt/abssctl"}
    )

    result = runner.invoke(app, ["config", "show", "--json"], env=env)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["install_root"] == "/opt/abssctl"
    assert payload["state_dir"] == str(state_dir)
    assert payload["lock_timeout"] == 30.0
    assert Path(payload["templates_dir"]).name == "templates"


def test_version_list_uses_registry(tmp_path: Path) -> None:
    """`version list` reports versions from the registry."""
    versions = ["25.8.0", {"version": "25.7.1", "source": "local"}]
    env, _ = _prepare_environment(tmp_path, versions=versions)

    result = runner.invoke(app, ["version", "list"], env=env)

    assert result.exit_code == 0
    assert "25.8.0" in result.stdout
    assert "yes" in result.stdout


def test_version_list_remote_merges(tmp_path: Path) -> None:
    """Remote flag merges npm responses with local installs."""
    versions = ["25.8.0"]
    remote = ["25.9.0", "25.8.0", "25.7.1"]
    env, _ = _prepare_environment(tmp_path, versions=versions, remote_versions=remote)

    result = runner.invoke(app, ["version", "list", "--remote"], env=env)

    assert result.exit_code == 0
    assert "25.9.0" in result.stdout
    assert "no" in result.stdout  # non-installed
    assert "yes" in result.stdout  # installed


def test_version_list_json(tmp_path: Path) -> None:
    """`version list --json` emits structured data."""
    versions = [
        "25.8.0",
        {
            "version": "25.7.1",
            "metadata": {"source": "local"},
            "integrity": {"npm": {"shasum": "12345"}},
        },
    ]
    instances = [{"name": "alpha", "version": "25.8.0"}]
    env, _ = _prepare_environment(tmp_path, versions=versions, instances=instances)

    backups_root = tmp_path / "backups"
    registry = BackupsRegistry(backups_root, backups_root / "backups.json")
    registry.ensure_root()
    entry = BackupEntryBuilder(
        instance="alpha",
        archive_path=backups_root / "alpha" / "demo.tar.gz",
        algorithm="gzip",
        checksum="deadbeef",
        size_bytes=1024,
        message="scheduled",
        labels=["pre-version-install"],
    ).build(backup_id="20250101-alpha-abc123")
    registry.append(entry)

    result = runner.invoke(app, ["version", "list", "--json"], env=env)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["versions"][0]["version"] == "25.8.0"
    assert payload["versions"][1]["metadata"]["source"] == "local"
    assert payload["versions"][1]["integrity"]["npm"]["shasum"] == "12345"
    last_backup = payload["versions"][0]["metadata"].get("last_backup")
    assert last_backup and last_backup["id"] == "20250101-alpha-abc123"


def test_backup_create_generates_archive(tmp_path: Path) -> None:
    """`backup create` writes archive, checksum, and index entry."""
    install_root = tmp_path / "srv" / "app"
    instance_root = tmp_path / "instances"
    env, state_dir = _prepare_environment(
        tmp_path,
        config_overrides={
            "install_root": str(install_root),
            "instance_root": str(instance_root),
        },
        instances=[{"name": "alpha", "port": 5000, "version": "current"}],
    )

    data_dir = instance_root / "alpha"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "db.sqlite").write_text("content", encoding="utf-8")

    runtime_dir = tmp_path / "run"
    systemd_path = runtime_dir / "systemd" / "abssctl-alpha.service"
    systemd_path.parent.mkdir(parents=True, exist_ok=True)
    systemd_path.write_text("[Unit]\nDescription=alpha\n", encoding="utf-8")

    nginx_site = runtime_dir / "nginx" / "sites-available" / "abssctl-alpha.conf"
    nginx_site.parent.mkdir(parents=True, exist_ok=True)
    nginx_site.write_text("server { }\n", encoding="utf-8")

    nginx_enabled = runtime_dir / "nginx" / "sites-enabled" / "abssctl-alpha.conf"
    nginx_enabled.parent.mkdir(parents=True, exist_ok=True)
    try:
        nginx_enabled.symlink_to(nginx_site)
    except FileExistsError:
        pass

    result = runner.invoke(
        app,
        ["backup", "create", "alpha", "--message", "pre-upgrade", "--label", "pre-version"],
        env=env,
    )

    assert result.exit_code == 0

    backups_root = tmp_path / "backups"
    archive_dir = backups_root / "alpha"
    archives = [path for path in archive_dir.glob("*.tar.*") if not path.name.endswith(".sha256")]
    assert len(archives) == 1
    archive = archives[0]
    checksum_path = archive_dir / f"{archive.name}.sha256"
    assert archive.exists()
    assert checksum_path.exists()

    index_path = backups_root / "backups.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    assert "backups" in index
    entry = index["backups"][0]
    assert entry["instance"] == "alpha"
    assert entry.get("message") == "pre-upgrade"
    assert "pre-version" in entry.get("metadata", {}).get("labels", [])

    expected_checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert entry["checksum"]["value"] == expected_checksum


def test_backup_create_dry_run(tmp_path: Path) -> None:
    """`backup create --dry-run` does not emit archives."""
    install_root = tmp_path / "srv" / "app"
    instance_root = tmp_path / "instances"
    env, state_dir = _prepare_environment(
        tmp_path,
        config_overrides={
            "install_root": str(install_root),
            "instance_root": str(instance_root),
        },
        instances=[{"name": "beta", "port": 5001, "version": "current"}],
    )

    result = runner.invoke(
        app,
        ["backup", "create", "beta", "--dry-run", "--json"],
        env=env,
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["plan"]["status"] == "planned"
    backup_dir = tmp_path / "backups" / "beta"
    if backup_dir.exists():
        assert not any(backup_dir.iterdir())


def test_backup_create_json_payload(tmp_path: Path) -> None:
    """`backup create --json` reports plan/result metadata."""
    install_root = tmp_path / "srv" / "app"
    instance_root = tmp_path / "instances"
    env, state_dir = _prepare_environment(
        tmp_path,
        config_overrides={
            "install_root": str(install_root),
            "instance_root": str(instance_root),
        },
        instances=[{"name": "gamma", "port": 5002, "version": "current"}],
    )

    data_dir = instance_root / "gamma"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "db.sqlite").write_text("content", encoding="utf-8")

    runtime_dir = tmp_path / "run"
    systemd_path = runtime_dir / "systemd" / "abssctl-gamma.service"
    systemd_path.parent.mkdir(parents=True, exist_ok=True)
    systemd_path.write_text("[Unit]\nDescription=gamma\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "backup",
            "create",
            "gamma",
            "--message",
            "pre-flight",
            "--label",
            "maintenance,precheck",
            "--json",
        ],
        env=env,
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    plan = payload["plan"]
    result_meta = payload["result"]
    assert plan["status"] == "created"
    assert plan["sources"]["data"]["exists"] is True
    assert result_meta["message"] == "pre-flight"
    assert "maintenance" in result_meta["labels"]
    assert result_meta["checksum"], "Checksum should be reported"


def test_backup_list_and_show(tmp_path: Path) -> None:
    """`backup list` and `backup show` expose registry entries."""
    env, _ = _prepare_environment(tmp_path)
    backups_root = tmp_path / "backups"
    registry = BackupsRegistry(backups_root, backups_root / "backups.json")
    registry.ensure_root()

    entry = BackupEntryBuilder(
        instance="alpha",
        archive_path=backups_root / "alpha" / "20250101-alpha.tar.gz",
        algorithm="gzip",
        checksum="deadbeef",
        size_bytes=1024,
        message="test backup",
        labels=["pre-version-install"],
    ).build(backup_id="20250101-alpha-abc123")
    registry.append(entry)

    list_result = runner.invoke(app, ["backup", "list", "--json"], env=env)
    assert list_result.exit_code == 0
    payload = json.loads(list_result.stdout)
    assert payload["backups"][0]["id"] == "20250101-alpha-abc123"

    show_result = runner.invoke(
        app,
        ["backup", "show", "20250101-alpha-abc123", "--json"],
        env=env,
    )
    assert show_result.exit_code == 0
    detail = json.loads(show_result.stdout)
    assert detail["backup"]["instance"] == "alpha"


def test_backup_show_missing(tmp_path: Path) -> None:
    """`backup show` returns error for unknown ids."""
    env, _ = _prepare_environment(tmp_path)
    result = runner.invoke(app, ["backup", "show", "does-not-exist"], env=env)
    assert result.exit_code == 1


def _create_backup_entry(
    registry: BackupsRegistry,
    *,
    instance: str,
    backup_id: str,
    archive_path: Path,
    checksum: str,
) -> None:
    entry = BackupEntryBuilder(
        instance=instance,
        archive_path=archive_path,
        algorithm="sha256",
        checksum=checksum,
        size_bytes=len(checksum),
        message="fixture",
        labels=["test"],
    ).build(backup_id=backup_id)
    registry.append(entry)


def test_backup_verify_reports_status(tmp_path: Path) -> None:
    """`backup verify` recalculates checksum and updates status."""
    env, _ = _prepare_environment(tmp_path)
    backups_root = tmp_path / "backups"
    registry = BackupsRegistry(backups_root, backups_root / "backups.json")
    registry.ensure_root()

    archive = backups_root / "alpha" / "valid.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    content = b"hello-world"
    archive.write_bytes(content)
    checksum = hashlib.sha256(content).hexdigest()
    backup_id = "20250101-alpha-abc123"
    _create_backup_entry(
        registry,
        instance="alpha",
        backup_id=backup_id,
        archive_path=archive,
        checksum=checksum,
    )

    result = runner.invoke(app, ["backup", "verify", backup_id, "--json"], env=env)
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["results"][0]["status"] == "available"


def test_backup_verify_detects_missing_archive(tmp_path: Path) -> None:
    """Verification marks missing archives."""
    env, _ = _prepare_environment(tmp_path)
    backups_root = tmp_path / "backups"
    registry = BackupsRegistry(backups_root, backups_root / "backups.json")
    registry.ensure_root()

    archive = backups_root / "alpha" / "missing.tar.gz"
    checksum = hashlib.sha256(b"placeholder").hexdigest()
    backup_id = "20250102-alpha-missing"
    _create_backup_entry(
        registry,
        instance="alpha",
        backup_id=backup_id,
        archive_path=archive,
        checksum=checksum,
    )

    result = runner.invoke(app, ["backup", "verify", backup_id, "--json"], env=env)
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["results"][0]["status"] == "missing"


def test_backup_prune_dry_run(tmp_path: Path) -> None:
    """`backup prune --dry-run` reports planned removals."""
    env, _ = _prepare_environment(tmp_path)
    backups_root = tmp_path / "backups"
    registry = BackupsRegistry(backups_root, backups_root / "backups.json")
    registry.ensure_root()

    backup_id = "20240101-alpha-old"
    archive = backups_root / "alpha" / "old.tar.gz"
    checksum = hashlib.sha256(b"old").hexdigest()
    _create_backup_entry(
        registry,
        instance="alpha",
        backup_id=backup_id,
        archive_path=archive,
        checksum=checksum,
    )

    old_timestamp = (
        datetime.now(tz=UTC) - timedelta(days=45)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    registry.update_entry(backup_id, lambda entry: entry.update({"created_at": old_timestamp}))

    result = runner.invoke(
        app,
        ["backup", "prune", "--older-than", "30", "--dry-run", "--json"],
        env=env,
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["results"][0]["status"] == "planned"


def test_backup_prune_removes_archives(tmp_path: Path) -> None:
    """`backup prune` deletes archives and marks entries removed."""
    env, _ = _prepare_environment(tmp_path)
    backups_root = tmp_path / "backups"
    registry = BackupsRegistry(backups_root, backups_root / "backups.json")
    registry.ensure_root()

    backup_id = "20240105-alpha-prune"
    archive = backups_root / "alpha" / "prune.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(b"data")
    checksum_path = archive.with_name(f"{archive.name}.sha256")
    checksum_path.write_text("deadbeef  prune.tar.gz\n", encoding="utf-8")
    checksum = hashlib.sha256(b"data").hexdigest()
    _create_backup_entry(
        registry,
        instance="alpha",
        backup_id=backup_id,
        archive_path=archive,
        checksum=checksum,
    )

    result = runner.invoke(
        app,
        ["backup", "prune", "--keep", "0", "--instance", "alpha"],
        env=env,
    )

    assert result.exit_code == 0
    entry = registry.find_by_id(backup_id)
    assert entry is not None
    assert entry.get("status") == "removed"
    assert archive.exists() is False
    assert checksum_path.exists() is False


def test_backup_restore_dry_run(tmp_path: Path) -> None:
    """`backup restore --dry-run` emits a plan."""
    env, _ = _prepare_environment(
        tmp_path,
        instances=[{"name": "alpha", "version": "25.8.0", "port": 5000}],
    )
    backups_root = tmp_path / "backups"
    registry = BackupsRegistry(backups_root, backups_root / "backups.json")
    registry.ensure_root()

    archive = backups_root / "alpha" / "restore.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(b"data")
    checksum = hashlib.sha256(b"data").hexdigest()
    backup_id = "20240107-alpha-restore"
    _create_backup_entry(
        registry,
        instance="alpha",
        backup_id=backup_id,
        archive_path=archive,
        checksum=checksum,
    )

    result = runner.invoke(
        app,
        [
            "backup",
            "restore",
            backup_id,
            "--dry-run",
            "--json",
            "--no-pre-backup",
        ],
        env=env,
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["plan"]["status"] == "planned"
    assert payload["plan"]["id"] == backup_id


def test_backup_restore_placeholder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`backup restore` placeholder succeeds and updates index."""
    env, state_dir = _prepare_environment(
        tmp_path,
        instances=[{"name": "alpha", "version": "25.8.0", "port": 5000}],
    )
    backups_root = tmp_path / "backups"
    registry = BackupsRegistry(backups_root, backups_root / "backups.json")
    registry.ensure_root()

    archive = backups_root / "alpha" / "restore.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(b"data")
    checksum = hashlib.sha256(b"data").hexdigest()
    backup_id = "20240108-alpha-restore"
    _create_backup_entry(
        registry,
        instance="alpha",
        backup_id=backup_id,
        archive_path=archive,
        checksum=checksum,
    )

    monkeypatch.setattr(SystemdProvider, "stop", lambda self, name: None)
    monkeypatch.setattr(SystemdProvider, "disable", lambda self, name: None)
    monkeypatch.setattr(SystemdProvider, "remove", lambda self, name: None)
    monkeypatch.setattr(NginxProvider, "disable", lambda self, name: None)
    monkeypatch.setattr(NginxProvider, "remove", lambda self, name: None)

    result = runner.invoke(
        app,
        [
            "backup",
            "restore",
            backup_id,
            "--no-pre-backup",
            "--dest",
            str(tmp_path / "restore-target"),
        ],
        env=env,
    )

    assert result.exit_code == 0
    updated = registry.find_by_id(backup_id)
    assert updated is not None
    assert updated.get("last_restored_at")


def test_instance_delete_triggers_backup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`instance delete` creates a backup when confirmed."""
    instances = [{"name": "alpha", "version": "25.8.0", "port": 5000}]
    env, state_dir = _prepare_environment(tmp_path, instances=instances)

    backups_root = tmp_path / "backups"
    data_dir = tmp_path / "instances" / "alpha"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "db.sqlite").write_text("content", encoding="utf-8")

    runtime_dir = tmp_path / "run"
    (runtime_dir / "systemd").mkdir(parents=True, exist_ok=True)
    (runtime_dir / "nginx" / "sites-available").mkdir(parents=True, exist_ok=True)
    (runtime_dir / "nginx" / "sites-enabled").mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(SystemdProvider, "stop", lambda self, name: None)
    monkeypatch.setattr(SystemdProvider, "disable", lambda self, name: None)
    monkeypatch.setattr(SystemdProvider, "remove", lambda self, name: None)
    monkeypatch.setattr(NginxProvider, "disable", lambda self, name: None)
    monkeypatch.setattr(NginxProvider, "remove", lambda self, name: None)

    result = runner.invoke(
        app,
        ["instance", "delete", "alpha", "--yes", "--backup-message", "pre-remove"],
        env=env,
    )

    assert result.exit_code == 0
    registry = BackupsRegistry(backups_root, backups_root / "backups.json")
    entries = registry.list_entries()
    assert entries
    assert entries[0]["message"] == "pre-remove"
    state_registry = StateRegistry(state_dir / "registry")
    assert state_registry.get_instance("alpha") is None


def test_version_check_updates_reports_upgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`version check-updates` surfaces available remote updates."""
    env, _ = _prepare_environment(
        tmp_path,
        versions=[{"version": "25.8.0"}],
        config_overrides={"npm_package_name": "demo"},
    )

    monkeypatch.setattr(
        VersionProvider,
        "list_remote_versions",
        lambda self, package: ["25.8.0", "25.9.0"],
    )

    result = runner.invoke(app, ["version", "check-updates"], env=env)

    assert result.exit_code == 0
    assert "25.9.0" in result.stdout
    assert "demo" in result.stdout


def test_version_check_updates_json_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JSON form of `version check-updates` reports metadata."""
    env, _ = _prepare_environment(
        tmp_path,
        versions=[{"version": "25.8.0"}],
        config_overrides={"npm_package_name": "demo"},
    )
    monkeypatch.setattr(
        VersionProvider,
        "list_remote_versions",
        lambda self, package: ["25.8.0", "25.9.0"],
    )

    result = runner.invoke(app, ["version", "check-updates", "--json"], env=env)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["package"] == "demo"
    assert payload["status"] == "updates-available"
    assert payload["available_updates"] == ["25.9.0"]


def test_version_check_updates_handles_remote_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No remote data yields remote-unavailable message."""
    env, _ = _prepare_environment(
        tmp_path,
        versions=[{"version": "25.8.0"}],
        config_overrides={"npm_package_name": "demo"},
    )
    monkeypatch.setattr(
        VersionProvider,
        "list_remote_versions",
        lambda self, package: [],
    )

    result = runner.invoke(app, ["version", "check-updates"], env=env)

    assert result.exit_code == 0
    assert "Unable to retrieve versions" in result.stdout


def test_version_switch_restart_none_skips(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`version switch --restart none` avoids systemd calls."""
    install_root = tmp_path / "srv" / "app"
    version_dir = install_root / "v25.8.0"
    version_dir.mkdir(parents=True, exist_ok=True)
    env, _ = _prepare_environment(
        tmp_path,
        config_overrides={"install_root": str(install_root)},
        versions=[{"version": "25.8.0", "path": str(version_dir)}],
        instances=[{"name": "alpha", "version": "current"}],
    )

    called: list[tuple[str, str]] = []
    monkeypatch.setattr(
        SystemdProvider,
        "stop",
        lambda self, name: called.append(("stop", name)),
    )
    monkeypatch.setattr(
        SystemdProvider,
        "start",
        lambda self, name: called.append(("start", name)),
    )

    result = runner.invoke(
        app,
        ["version", "switch", "25.8.0", "--restart", "none", "--no-backup"],
        env=env,
    )
    assert result.exit_code == 0
    assert called == []


def test_version_switch_restart_rolling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`version switch` default rolling restart stops/starts sequentially."""
    install_root = tmp_path / "srv" / "app"
    version_dir = install_root / "v25.8.0"
    version_dir.mkdir(parents=True, exist_ok=True)
    env, _ = _prepare_environment(
        tmp_path,
        config_overrides={"install_root": str(install_root)},
        versions=[{"version": "25.8.0", "path": str(version_dir)}],
        instances=[{"name": "alpha", "version": "current"}],
    )

    calls: list[tuple[str, str]] = []

    def fake_stop(self: SystemdProvider, name: str) -> None:
        calls.append(("stop", name))

    def fake_start(self: SystemdProvider, name: str) -> None:
        calls.append(("start", name))

    monkeypatch.setattr(SystemdProvider, "stop", fake_stop)
    monkeypatch.setattr(SystemdProvider, "start", fake_start)

    result = runner.invoke(app, ["version", "switch", "25.8.0", "--no-backup"], env=env)

    assert result.exit_code == 0
    assert calls == [("stop", "alpha"), ("start", "alpha")]


def test_version_switch_restart_all(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`version switch --restart all` stops all before starting them."""
    install_root = tmp_path / "srv" / "app"
    version_dir = install_root / "v25.8.0"
    version_dir.mkdir(parents=True, exist_ok=True)
    env, _ = _prepare_environment(
        tmp_path,
        config_overrides={"install_root": str(install_root)},
        versions=[{"version": "25.8.0", "path": str(version_dir)}],
        instances=[
            {"name": "alpha", "version": "current"},
            {"name": "beta", "version": "current"},
        ],
    )

    calls: list[tuple[str, str]] = []

    def fake_stop(self: SystemdProvider, name: str) -> None:
        calls.append(("stop", name))

    def fake_start(self: SystemdProvider, name: str) -> None:
        calls.append(("start", name))

    monkeypatch.setattr(SystemdProvider, "stop", fake_stop)
    monkeypatch.setattr(SystemdProvider, "start", fake_start)

    result = runner.invoke(
        app,
        ["version", "switch", "25.8.0", "--restart", "all", "--no-backup"],
        env=env,
    )

    assert result.exit_code == 0
    assert calls == [
        ("stop", "alpha"),
        ("stop", "beta"),
        ("start", "alpha"),
        ("start", "beta"),
    ]


def test_version_install_records_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`version install` records metadata in versions.yml."""
    install_root = tmp_path / "srv" / "app"
    env, state_dir = _prepare_environment(
        tmp_path,
        config_overrides={"install_root": str(install_root)},
    )
    target_dir = install_root / "v25.9.0"

    def fake_install(
        self: VersionInstaller,
        version: str,
        *,
        env: dict[str, str] | None = None,
        dry_run: bool = False,
    ) -> VersionInstallResult:
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "node_modules").mkdir(parents=True, exist_ok=True)
        return VersionInstallResult(
            version=version,
            path=target_dir,
            installed_at="2025-10-08T00:00:00Z",
            metadata={"package": self.package_name},
            integrity=FAKE_INTEGRITY_PAYLOAD,
        )

    monkeypatch.setattr(VersionInstaller, "install", fake_install)

    result = runner.invoke(app, ["version", "install", "25.9.0", "--no-backup"], env=env)
    assert result.exit_code == 0

    registry = StateRegistry(state_dir / "registry")
    entry = registry.get_version("25.9.0")
    assert entry is not None
    assert entry["path"] == str(target_dir)
    assert entry["metadata"]["installed"] is True
    assert entry["integrity"]["npm"]["shasum"] == FAKE_CLI_SHASUM
    assert entry["integrity"]["tarball"]["digest"] == FAKE_CLI_DIGEST_HEX

    logs_dir = state_dir.parent / "logs"
    operations_file = logs_dir / "operations.jsonl"
    last_record = operations_file.read_text(encoding="utf-8").splitlines()[-1]
    record = json.loads(last_record)
    assert record["command"] == "version install"


def test_version_install_triggers_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`version install` runs a backup when safety prompt is accepted."""
    install_root = tmp_path / "srv" / "app"
    instance_root = tmp_path / "instances"
    env, state_dir = _prepare_environment(
        tmp_path,
        config_overrides={
            "install_root": str(install_root),
            "instance_root": str(instance_root),
        },
        instances=[{"name": "alpha", "port": 5000, "version": "current"}],
    )

    data_dir = instance_root / "alpha"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "db.sqlite").write_text("content", encoding="utf-8")

    runtime_dir = tmp_path / "run"
    systemd_path = runtime_dir / "systemd" / "abssctl-alpha.service"
    systemd_path.parent.mkdir(parents=True, exist_ok=True)
    systemd_path.write_text("[Unit]\nDescription=alpha\n", encoding="utf-8")

    nginx_site = runtime_dir / "nginx" / "sites-available" / "abssctl-alpha.conf"
    nginx_site.parent.mkdir(parents=True, exist_ok=True)
    nginx_site.write_text("server { }\n", encoding="utf-8")

    def fake_install(
        self: VersionInstaller,
        version: str,
        *,
        env: dict[str, str] | None = None,
        dry_run: bool = False,
    ) -> VersionInstallResult:
        target_dir = install_root / f"v{version}"
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "node_modules").mkdir(parents=True, exist_ok=True)
        return VersionInstallResult(
            version=version,
            path=target_dir,
            installed_at="2025-10-11T00:00:00Z",
            metadata={"package": self.package_name},
            integrity={},
        )

    monkeypatch.setattr(VersionInstaller, "install", fake_install)

    result = runner.invoke(
        app,
        [
            "version",
            "install",
            "30.0.0",
            "--yes",
            "--backup-message",
            "pre-flight",
        ],
        env=env,
    )

    assert result.exit_code == 0

    backups_root = tmp_path / "backups"
    index_path = backups_root / "backups.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    assert index["backups"], "Expected a backup entry"
    entry = index["backups"][0]
    assert entry["instance"] == "alpha"
    assert entry.get("message") == "pre-flight"
    assert "pre-version-install" in entry.get("metadata", {}).get("labels", [])


def test_version_install_backup_prompt_records_step(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backup prompt adds a step when confirmed."""
    install_root = tmp_path / "srv" / "app"
    env, state_dir = _prepare_environment(
        tmp_path,
        config_overrides={"install_root": str(install_root)},
    )

    def fake_install(
        self: VersionInstaller,
        version: str,
        *,
        env: dict[str, str] | None = None,
        dry_run: bool = False,
    ) -> VersionInstallResult:
        target = install_root / f"v{version}"
        target.mkdir(parents=True, exist_ok=True)
        return VersionInstallResult(
            version=version,
            path=target,
            installed_at="2025-10-08T02:00:00Z",
            metadata={"package": self.package_name},
            integrity=FAKE_INTEGRITY_PAYLOAD,
        )

    monkeypatch.setattr(VersionInstaller, "install", fake_install)

    result = runner.invoke(
        app,
        [
            "version",
            "install",
            "27.0.0",
            "--yes",
            "--backup-message",
            "pre-upgrade",
        ],
        env=env,
    )
    assert result.exit_code == 0

    logs_dir = state_dir.parent / "logs"
    operations_file = logs_dir / "operations.jsonl"
    record = json.loads(operations_file.read_text(encoding="utf-8").splitlines()[-1])
    step_names = [step["name"] for step in record.get("steps", [])]
    assert "backup.requested" in step_names
def test_version_install_with_set_current_switches_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`version install --set-current` moves the current symlink."""
    install_root = tmp_path / "srv" / "app"
    env, state_dir = _prepare_environment(
        tmp_path,
        config_overrides={"install_root": str(install_root)},
    )
    target_dir = install_root / "v26.0.0"

    def fake_install(
        self: VersionInstaller,
        version: str,
        *,
        env: dict[str, str] | None = None,
        dry_run: bool = False,
    ) -> VersionInstallResult:
        target_dir.mkdir(parents=True, exist_ok=True)
        return VersionInstallResult(
            version=version,
            path=target_dir,
            installed_at="2025-10-08T01:00:00Z",
            metadata={"package": self.package_name},
            integrity=FAKE_INTEGRITY_PAYLOAD,
        )

    monkeypatch.setattr(VersionInstaller, "install", fake_install)

    result = runner.invoke(
        app,
        ["version", "install", "26.0.0", "--set-current", "--no-backup"],
        env=env,
    )
    assert result.exit_code == 0

    current_link = install_root / "current"
    assert current_link.is_symlink()
    assert current_link.resolve() == target_dir

    registry = StateRegistry(state_dir / "registry")
    entry = registry.get_version("26.0.0")
    assert entry is not None
    assert entry["metadata"]["current"] is True
    assert entry["integrity"]["npm"]["integrity"] == FAKE_CLI_INTEGRITY


def test_version_switch_updates_symlink(tmp_path: Path) -> None:
    """`version switch` updates the symlink for an existing version."""
    install_root = tmp_path / "srv" / "app"
    version_dir = install_root / "v25.8.0"
    version_dir.mkdir(parents=True, exist_ok=True)
    env, state_dir = _prepare_environment(
        tmp_path,
        config_overrides={"install_root": str(install_root)},
        versions=[
            {
                "version": "25.8.0",
                "path": str(version_dir),
                "metadata": {"installed": True},
            }
        ],
    )

    result = runner.invoke(app, ["version", "switch", "25.8.0", "--no-backup"], env=env)
    assert result.exit_code == 0

    current_link = install_root / "current"
    assert current_link.is_symlink()
    assert current_link.resolve() == version_dir

    registry = StateRegistry(state_dir / "registry")
    assert registry.get_version("25.8.0")["metadata"]["current"] is True


def test_version_uninstall_blocks_current(tmp_path: Path) -> None:
    """Uninstall refuses to remove the active version."""
    install_root = tmp_path / "srv" / "app"
    version_dir = install_root / "v25.9.0"
    version_dir.mkdir(parents=True, exist_ok=True)
    current_link = install_root / "current"
    install_root.mkdir(parents=True, exist_ok=True)
    if current_link.exists() or current_link.is_symlink():
        current_link.unlink()
    current_link.symlink_to(version_dir)

    env, _ = _prepare_environment(
        tmp_path,
        config_overrides={"install_root": str(install_root)},
        versions=[
            {
                "version": "25.9.0",
                "path": str(version_dir),
                "metadata": {"installed": True, "current": True},
            }
        ],
    )

    result = runner.invoke(app, ["version", "uninstall", "25.9.0", "--no-backup"], env=env)
    assert result.exit_code == 1
    assert version_dir.exists()


def test_version_uninstall_blocks_in_use(tmp_path: Path) -> None:
    """Uninstall refuses versions that instances depend on."""
    install_root = tmp_path / "srv" / "app"
    version_dir = install_root / "v25.9.0"
    version_dir.mkdir(parents=True, exist_ok=True)
    env, _ = _prepare_environment(
        tmp_path,
        config_overrides={"install_root": str(install_root)},
        versions=[
            {
                "version": "25.9.0",
                "path": str(version_dir),
                "metadata": {"installed": True},
            }
        ],
        instances=[{"name": "alpha", "version": "25.9.0"}],
    )

    result = runner.invoke(app, ["version", "uninstall", "25.9.0", "--no-backup"], env=env)
    assert result.exit_code == 1
    assert version_dir.exists()


def test_version_uninstall_removes_version(tmp_path: Path) -> None:
    """Successful uninstall removes the directory and registry entry."""
    install_root = tmp_path / "srv" / "app"
    version_dir = install_root / "v25.9.0"
    version_dir.mkdir(parents=True, exist_ok=True)
    env, state_dir = _prepare_environment(
        tmp_path,
        config_overrides={"install_root": str(install_root)},
        versions=[
            {
                "version": "25.9.0",
                "path": str(version_dir),
                "metadata": {"installed": True},
            }
        ],
    )

    result = runner.invoke(app, ["version", "uninstall", "25.9.0", "--no-backup"], env=env)
    assert result.exit_code == 0
    assert not version_dir.exists()

    registry = StateRegistry(state_dir / "registry")
    assert registry.get_version("25.9.0") is None


def test_instance_list_reads_registry(tmp_path: Path) -> None:
    """`instance list` reports entries from instances.yml."""
    instances = [
        {"name": "alpha", "version": "v25.8.0", "domain": "alpha.local", "port": 5000},
        {"name": "beta", "status": "stopped"},
    ]
    env, _ = _prepare_environment(tmp_path, instances=instances)

    result = runner.invoke(app, ["instance", "list"], env=env)

    assert result.exit_code == 0
    assert "alpha" in result.stdout
    assert "beta" in result.stdout
    assert "5000" in result.stdout


def test_instance_list_json(tmp_path: Path) -> None:
    """`instance list --json` emits structured data."""
    instances = [{"name": "alpha", "version": "v25.8.0"}]
    env, _ = _prepare_environment(tmp_path, instances=instances)

    backups_root = tmp_path / "backups"
    registry = BackupsRegistry(backups_root, backups_root / "backups.json")
    registry.ensure_root()
    entry = BackupEntryBuilder(
        instance="alpha",
        archive_path=backups_root / "alpha" / "demo.tar.gz",
        algorithm="gzip",
        checksum="deadbeef",
        size_bytes=512,
        message="nightly",
        labels=["pre-maintenance"],
    ).build(backup_id="20250202-alpha-xyz987")
    registry.append(entry)

    result = runner.invoke(app, ["instance", "list", "--json"], env=env)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["instances"][0]["name"] == "alpha"
    assert payload["instances"][0]["version"] == "v25.8.0"
    assert payload["instances"][0]["status"] in {"enabled", "disabled", "unknown"}
    last_backup = payload["instances"][0]["metadata"].get("last_backup")
    assert last_backup and last_backup["id"] == "20250202-alpha-xyz987"


def test_instance_show_success(tmp_path: Path) -> None:
    """`instance show` renders details for the requested instance."""
    instances = [{"name": "alpha", "version": "v25.8.0", "domain": "alpha.local"}]
    env, _ = _prepare_environment(tmp_path, instances=instances)

    result = runner.invoke(app, ["instance", "show", "alpha"], env=env)

    assert result.exit_code == 0
    assert "alpha" in result.stdout
    assert "alpha.local" in result.stdout


def test_instance_show_json(tmp_path: Path) -> None:
    """JSON form of `instance show`."""
    instances = [{"name": "alpha", "version": "v25.8.0"}]
    env, _ = _prepare_environment(tmp_path, instances=instances)

    result = runner.invoke(app, ["instance", "show", "alpha", "--json"], env=env)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["name"] == "alpha"
    assert payload["version"] == "v25.8.0"


def test_instance_show_missing(tmp_path: Path) -> None:
    """Missing instances exit with a non-zero status."""
    env, _ = _prepare_environment(tmp_path, instances=[])

    result = runner.invoke(app, ["instance", "show", "alpha"], env=env)

    assert result.exit_code == 1
    assert "not found" in result.stdout


def test_instance_create_acquires_lock(tmp_path: Path) -> None:
    """`instance create` acquires the expected lock and logs wait duration."""
    env, state_dir = _prepare_environment(tmp_path)

    result = runner.invoke(app, ["instance", "create", "alpha"], env=env)

    assert result.exit_code == 0

    runtime_dir = tmp_path / "run"
    lock_path = runtime_dir / "alpha.lock"
    assert lock_path.exists()
    lock_metadata = json.loads(lock_path.read_text(encoding="utf-8"))
    assert lock_metadata["pid"] == os.getpid()

    systemd_unit = runtime_dir / "systemd" / "abssctl-alpha.service"
    assert systemd_unit.exists()
    assert "Actual Budget Sync Server" in systemd_unit.read_text(encoding="utf-8")

    nginx_site = runtime_dir / "nginx" / "sites-available" / "abssctl-alpha.conf"
    assert nginx_site.exists()
    assert "server_name alpha.local" in nginx_site.read_text(encoding="utf-8")

    logs_dir = state_dir.parent / "logs"
    operations_log = logs_dir / "operations.jsonl"
    log_lines = operations_log.read_text(encoding="utf-8").splitlines()
    record = json.loads(log_lines[-1])
    assert record["command"] == "instance create"
    assert record.get("lock_wait_ms") is not None
    assert record["result"]["status"] == "success"
    steps = record.get("steps", [])
    assert any(step.get("name") == "systemd.render_unit" for step in steps)
    assert any(step.get("name") == "nginx.render_site" for step in steps)
    assert any(step.get("name") == "registry.write_instances" for step in steps)

    registry_file = state_dir / "registry" / "instances.yml"
    registry_data = yaml.safe_load(registry_file.read_text(encoding="utf-8"))
    instances = registry_data.get("instances", [])
    assert any(item.get("name") == "alpha" for item in instances)


def test_operations_logging_creates_records(tmp_path: Path) -> None:
    """Commands emit structured logging records in the configured logs directory."""
    env, state_dir = _prepare_environment(tmp_path)

    result = runner.invoke(app, ["config", "show", "--json"], env=env)

    assert result.exit_code == 0

    logs_dir = state_dir.parent / "logs"
    operations_log = logs_dir / "operations.jsonl"
    human_log = logs_dir / "abssctl.log"

    assert operations_log.exists()
    assert human_log.exists()

    record = json.loads(operations_log.read_text(encoding="utf-8").splitlines()[-1])
    assert record["command"] == "config show"
    assert record["args"] == {"json": True}
    assert record["result"]["status"] == "success"
    assert record["context"]["abssctl_version"] == __version__

    human_content = human_log.read_text(encoding="utf-8")
    assert "config show" in human_content


def _create_instance(env: dict[str, str], name: str = "alpha") -> None:
    result = runner.invoke(app, ["instance", "create", name], env=env)
    assert result.exit_code == 0


def _registry_instances(state_dir: Path) -> list[dict[str, object]]:
    registry_file = state_dir / "registry" / "instances.yml"
    data = yaml.safe_load(registry_file.read_text(encoding="utf-8"))
    return data.get("instances", [])


def test_instance_enable_updates_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Enable command invokes providers and marks instance enabled."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    calls: list[tuple[str, str]] = []

    def fake_systemd_enable(self: SystemdProvider, name: str) -> None:
        calls.append(("systemd", name))

    def fake_nginx_enable(self: NginxProvider, name: str) -> None:
        calls.append(("nginx", name))

    monkeypatch.setattr(SystemdProvider, "enable", fake_systemd_enable)
    monkeypatch.setattr(NginxProvider, "enable", fake_nginx_enable)

    result = runner.invoke(app, ["instance", "enable", "alpha"], env=env)
    assert result.exit_code == 0
    assert ("systemd", "alpha") in calls
    assert ("nginx", "alpha") in calls

    instance = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert instance["status"] == "enabled"


def test_instance_disable_updates_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Disable command invokes providers and marks instance disabled."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    monkeypatch.setattr(SystemdProvider, "disable", lambda self, name: None)
    monkeypatch.setattr(NginxProvider, "disable", lambda self, name: None)

    result = runner.invoke(app, ["instance", "disable", "alpha"], env=env)
    assert result.exit_code == 0
    instance = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert instance["status"] == "disabled"


def test_instance_start_updates_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Start command sets registry status to running."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    monkeypatch.setattr(SystemdProvider, "start", lambda self, name: None)

    result = runner.invoke(app, ["instance", "start", "alpha"], env=env)
    assert result.exit_code == 0
    instance = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert instance["status"] == "running"


def test_instance_stop_updates_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stop command sets registry status to stopped."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    monkeypatch.setattr(SystemdProvider, "stop", lambda self, name: None)

    result = runner.invoke(app, ["instance", "stop", "alpha"], env=env)
    assert result.exit_code == 0
    instance = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert instance["status"] == "stopped"


def test_instance_restart_calls_stop_and_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Restart delegates to systemd stop then start and sets running status."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    calls: list[str] = []

    def fake_stop(self: SystemdProvider, name: str) -> None:
        calls.append("stop")

    def fake_start(self: SystemdProvider, name: str) -> None:
        calls.append("start")

    monkeypatch.setattr(SystemdProvider, "stop", fake_stop)
    monkeypatch.setattr(SystemdProvider, "start", fake_start)

    result = runner.invoke(app, ["instance", "restart", "alpha"], env=env)
    assert result.exit_code == 0
    assert calls == ["stop", "start"]
    instance = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert instance["status"] == "running"


def test_instance_delete_removes_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Delete removes provider assets and unregisters the instance."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    monkeypatch.setattr(SystemdProvider, "stop", lambda self, name: None)
    monkeypatch.setattr(SystemdProvider, "disable", lambda self, name: None)
    monkeypatch.setattr(SystemdProvider, "remove", lambda self, name: None)
    monkeypatch.setattr(NginxProvider, "disable", lambda self, name: None)
    monkeypatch.setattr(NginxProvider, "remove", lambda self, name: None)

    result = runner.invoke(app, ["instance", "delete", "alpha", "--no-backup"], env=env)
    assert result.exit_code == 0
    instances = _registry_instances(state_dir)
    assert all(item.get("name") != "alpha" for item in instances)
