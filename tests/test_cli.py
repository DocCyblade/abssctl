"""Tests for the abssctl CLI scaffold."""
from __future__ import annotations

import base64
import grp
import hashlib
import json
import os
import pwd
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from typer.testing import CliRunner

from abssctl import __version__
from abssctl.backups import BackupEntryBuilder, BackupsRegistry
from abssctl.cli import app
from abssctl.providers.nginx import NginxProvider
from abssctl.providers.systemd import SystemdError, SystemdProvider
from abssctl.providers.version_installer import VersionInstaller, VersionInstallResult
from abssctl.providers.version_provider import VersionProvider
from abssctl.state import StateRegistry

runner = CliRunner()


def _create_tls_fixture(tmp_path: Path, name: str = "alpha.example") -> tuple[Path, Path]:
    """Create a self-signed certificate/key pair for testing."""
    now = datetime.now(UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=60))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    safe = name.replace(".", "_")
    cert_path = tmp_path / f"{safe}.pem"
    key_path = tmp_path / f"{safe}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.chmod(0o644)
    key_path.chmod(0o600)
    return cert_path, key_path


def _create_backup(
    env: dict[str, str],
    instance: str,
    *,
    compression: str = "none",
) -> tuple[str, dict[str, object]]:
    """Run ``backup create`` and return (backup_id, payload)."""
    result = runner.invoke(
        app,
        [
            "backup",
            "create",
            instance,
            "--compression",
            compression,
            "--json",
        ],
        env=env,
    )

    assert result.exit_code == 0, result.stdout
    payload = _extract_json(result.stdout)
    result_block = payload.get("result") or {}
    backup_id = result_block.get("id") or payload.get("plan", {}).get("id")
    assert backup_id, "backup create did not return an id"
    return backup_id, payload


def _extract_json(output: str) -> dict[str, object]:
    """Extract the first JSON object embedded in *output*."""
    start = output.find("{")
    end = output.rfind("}")
    assert start != -1 and end != -1, f"No JSON payload found in output: {output}"
    return json.loads(output[start : end + 1])

_TARBALL_DIGEST_BYTES = bytes(range(64))
FAKE_CLI_SHASUM = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
FAKE_CLI_INTEGRITY = f"sha512-{base64.b64encode(_TARBALL_DIGEST_BYTES).decode('ascii')}"
FAKE_CLI_DIGEST_HEX = _TARBALL_DIGEST_BYTES.hex()
FAKE_INTEGRITY_PAYLOAD = {
    "npm": {"shasum": FAKE_CLI_SHASUM, "integrity": FAKE_CLI_INTEGRITY},
    "tarball": {"algorithm": "sha512", "digest": FAKE_CLI_DIGEST_HEX},
}


def _stub_restore_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub systemd/nginx provider methods used during restore."""
    monkeypatch.setattr(
        SystemdProvider,
        "stop",
        lambda self, name: _fake_systemctl("stop", name),
    )
    monkeypatch.setattr(
        SystemdProvider,
        "start",
        lambda self, name: _fake_systemctl("start", name),
    )
    monkeypatch.setattr(
        SystemdProvider,
        "enable",
        lambda self, name: _fake_systemctl("enable", name),
    )
    monkeypatch.setattr(
        SystemdProvider,
        "status",
        lambda self, name: _fake_systemctl("status", name),
    )
    monkeypatch.setattr(
        NginxProvider,
        "test_config",
        lambda self: _fake_completed(["nginx", "-t"]),
    )
    monkeypatch.setattr(
        NginxProvider,
        "reload",
        lambda self: _fake_completed(["nginx", "-s", "reload"]),
    )


def _fake_systemctl(action: str, name: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        ["systemctl", action, f"abssctl-{name}.service"], returncode=0
    )


def _fake_completed(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode=0, stdout="", stderr="")


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
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    nginx_stub = bin_dir / "nginx"
    nginx_stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    nginx_stub.chmod(0o755)
    owner = pwd.getpwuid(os.getuid()).pw_name
    group = grp.getgrgid(os.getgid()).gr_name
    tls_root = tmp_path / "tls"
    tls_root.mkdir(parents=True, exist_ok=True)
    system_cert, system_key = _create_tls_fixture(tls_root, name="system-cert")
    config = {
        "state_dir": str(state_dir),
        "logs_dir": str(logs_dir),
        "runtime_dir": str(runtime_dir),
        "templates_dir": str(templates_dir),
        "instance_root": str(tmp_path / "instances"),
        "backups": {"root": str(tmp_path / "backups")},
        "systemd": {
            "systemctl_bin": str(bin_dir / "systemctl"),
            "journalctl_bin": str(bin_dir / "journalctl"),
        },
        "tls": {
            "system": {
                "cert": str(system_cert),
                "key": str(system_key),
            },
            "lets_encrypt": {
                "live_dir": str(tls_root / "le"),
            },
            "validation": {
                "warn_expiry_days": 30,
                "key_permissions": [
                    {"owner": owner, "group": group, "mode": "0600"},
                    {"owner": owner, "group": group, "mode": "0640"},
                ],
                "cert_permissions": {
                    "owner": owner,
                    "group": group,
                    "mode": "0644",
                },
                "chain_permissions": {
                    "owner": owner,
                    "group": group,
                    "mode": "0644",
                },
            },
        },
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

    env = {
        "ABSSCTL_CONFIG_FILE": str(config_file),
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
    }
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
    payload = _extract_json(result.stdout)
    assert payload["install_root"] == "/opt/abssctl"
    assert payload["state_dir"] == str(state_dir)


def test_ports_list_reports_reservations(tmp_path: Path) -> None:
    """`ports list` renders current port reservations."""
    env, state_dir = _prepare_environment(tmp_path)
    registry = StateRegistry(state_dir / "registry")
    registry.write_ports([
        {"name": "alpha", "port": 5000},
        {"name": "beta", "port": 5001},
    ])

    result = runner.invoke(app, ["ports", "list"], env=env)

    assert result.exit_code == 0
    output = result.stdout
    assert "alpha" in output
    assert "5000" in output
    assert "beta" in output

    json_result = runner.invoke(app, ["ports", "list", "--json"], env=env)
    assert json_result.exit_code == 0
    payload = json.loads(json_result.stdout)
    assert payload == {"ports": [{"name": "alpha", "port": 5000}, {"name": "beta", "port": 5001}]}


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
    payload = _extract_json(result.stdout)
    assert payload["versions"][0]["version"] == "25.8.0"
    assert payload["versions"][1]["metadata"]["source"] == "local"
    assert payload["versions"][1]["integrity"]["npm"]["shasum"] == "12345"
    last_backup = payload["versions"][0]["metadata"].get("last_backup")
    assert last_backup and last_backup["id"] == "20250101-alpha-abc123"


def test_tls_verify_manual_reports_success(tmp_path: Path) -> None:
    """`tls verify` validates manual certificate paths."""
    env, _ = _prepare_environment(tmp_path)
    cert_path, key_path = _create_tls_fixture(tmp_path)

    result = runner.invoke(
        app,
        [
            "tls",
            "verify",
            "--cert",
            str(cert_path),
            "--key",
            str(key_path),
        ],
        env=env,
    )

    assert result.exit_code == 0
    assert "TLS validation" in result.stdout
    assert "OK" in result.stdout


def test_tls_install_updates_registry(tmp_path: Path) -> None:
    """`tls install` copies files and records registry state."""
    instances = [{"name": "alpha", "port": 5000, "version": "current"}]
    env, state_dir = _prepare_environment(tmp_path, instances=instances)
    cert_path, key_path = _create_tls_fixture(tmp_path, name="alpha.example")

    result = runner.invoke(
        app,
        [
            "tls",
            "install",
            "alpha",
            "--cert",
            str(cert_path),
            "--key",
            str(key_path),
            "--yes",
        ],
        env=env,
    )

    assert result.exit_code == 0
    registry = StateRegistry(state_dir / "registry")
    entry = registry.get_instance("alpha")
    assert entry is not None
    tls_block = entry.get("tls", {})
    assert tls_block.get("source") == "custom"
    assert Path(str(tls_block.get("cert"))).exists()
    assert Path(str(tls_block.get("key"))).exists()

    runtime_dir = tmp_path / "run"
    site_path = runtime_dir / "nginx" / "sites-available" / "abssctl-alpha.conf"
    assert site_path.exists()
    contents = site_path.read_text(encoding="utf-8")
    assert f"ssl_certificate {tls_block['cert']};" in contents
    assert f"ssl_certificate_key {tls_block['key']};" in contents


def test_tls_use_system_switches_source(tmp_path: Path) -> None:
    """`tls use-system` updates TLS source metadata."""
    instances = [{"name": "alpha", "port": 5000, "version": "current"}]
    env, state_dir = _prepare_environment(tmp_path, instances=instances)
    cert_path, key_path = _create_tls_fixture(tmp_path, name="alpha.example")
    runner.invoke(
        app,
        [
            "tls",
            "install",
            "alpha",
            "--cert",
            str(cert_path),
            "--key",
            str(key_path),
            "--yes",
        ],
        env=env,
    )

    result = runner.invoke(app, ["tls", "use-system", "alpha"], env=env)

    assert result.exit_code == 0
    registry = StateRegistry(state_dir / "registry")
    entry = registry.get_instance("alpha")
    assert entry is not None
    tls_block = entry.get("tls", {})
    assert tls_block.get("source") == "system"
    runtime_dir = tmp_path / "run"
    site_path = runtime_dir / "nginx" / "sites-available" / "abssctl-alpha.conf"
    contents = site_path.read_text(encoding="utf-8")
    assert f"ssl_certificate {tls_block['cert']};" in contents
    assert f"ssl_certificate_key {tls_block['key']};" in contents


def test_tls_install_dry_run_skips_changes(tmp_path: Path) -> None:
    """Dry-run install previews actions without copying or updating the registry."""
    instances = [{"name": "alpha", "port": 5000, "version": "current"}]
    env, state_dir = _prepare_environment(tmp_path, instances=instances)
    cert_path, key_path = _create_tls_fixture(tmp_path, name="alpha.example")

    result = runner.invoke(
        app,
        [
            "tls",
            "install",
            "alpha",
            "--cert",
            str(cert_path),
            "--key",
            str(key_path),
            "--dry-run",
        ],
        env=env,
    )

    assert result.exit_code == 0
    registry = StateRegistry(state_dir / "registry")
    entry = registry.get_instance("alpha")
    assert entry is not None
    assert "tls" not in entry

    tls_root = tmp_path / "tls"
    assert not (tls_root / "abssctl-alpha.pem").exists()
    assert not (tls_root / "abssctl-alpha.key").exists()


def test_tls_install_permission_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ownership adjustment failures abort the install."""
    instances = [{"name": "alpha", "port": 5000, "version": "current"}]
    env, state_dir = _prepare_environment(tmp_path, instances=instances)
    cert_path, key_path = _create_tls_fixture(tmp_path, name="alpha.example")

    def fail_chown(path: str | os.PathLike[str], user: str, group: str) -> None:
        raise PermissionError("simulated")

    monkeypatch.setattr(shutil, "chown", fail_chown)

    result = runner.invoke(
        app,
        [
            "tls",
            "install",
            "alpha",
            "--cert",
            str(cert_path),
            "--key",
            str(key_path),
            "--yes",
        ],
        env=env,
    )

    assert result.exit_code == 1
    assert "Failed to adjust ownership" in result.stdout
    registry = StateRegistry(state_dir / "registry")
    entry = registry.get_instance("alpha")
    assert entry is not None
    assert "tls" not in entry


def test_tls_verify_detects_lets_encrypt(tmp_path: Path) -> None:
    """`tls verify` can target detected Let's Encrypt assets."""
    instances = [
        {"name": "alpha", "port": 5000, "version": "current", "domain": "alpha.example"}
    ]
    env, _ = _prepare_environment(tmp_path, instances=instances)

    config_path = Path(env["ABSSCTL_CONFIG_FILE"])
    config_data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    live_dir = Path(config_data["tls"]["lets_encrypt"]["live_dir"]) / "alpha.example"
    live_dir.mkdir(parents=True, exist_ok=True)

    fullchain_src, key_src = _create_tls_fixture(tmp_path, name="alpha.example")
    shutil.copy2(fullchain_src, live_dir / "fullchain.pem")
    shutil.copy2(fullchain_src, live_dir / "chain.pem")
    shutil.copy2(key_src, live_dir / "privkey.pem")
    (live_dir / "fullchain.pem").chmod(0o644)
    (live_dir / "chain.pem").chmod(0o644)
    (live_dir / "privkey.pem").chmod(0o640)

    result = runner.invoke(
        app,
        ["tls", "verify", "--instance", "alpha", "--source", "lets-encrypt"],
        env=env,
    )

    assert result.exit_code == 0
    assert "resolved=lets-encrypt" in result.stdout


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
    payload = _extract_json(result.stdout)
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
    payload = _extract_json(result.stdout)
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
    payload = _extract_json(result.stdout)
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
    payload = _extract_json(result.stdout)
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
    payload = _extract_json(result.stdout)
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


def test_backup_restore_dry_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`backup restore --dry-run` emits a plan without touching data."""
    env, _ = _prepare_environment(
        tmp_path,
        instances=[{"name": "alpha", "version": "current", "port": 5000, "status": "running"}],
    )
    data_dir = tmp_path / "instances" / "alpha"
    data_dir.mkdir(parents=True, exist_ok=True)
    db_file = data_dir / "db.sqlite"
    db_file.write_text("original", encoding="utf-8")

    backup_id, _ = _create_backup(env, "alpha")

    db_file.write_text("mutated", encoding="utf-8")

    _stub_restore_providers(monkeypatch)

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
    payload = _extract_json(result.stdout)
    assert payload["plan"]["status"] == "planned"
    assert "extract-archive" in payload["plan"]["actions"]
    assert db_file.read_text(encoding="utf-8") == "mutated"
    assert not list(data_dir.parent.glob("alpha.pre-restore-*"))


def test_backup_restore_restores_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`backup restore` rehydrates instance data and updates metadata."""
    env, state_dir = _prepare_environment(
        tmp_path,
        instances=[{"name": "alpha", "version": "current", "port": 5000, "status": "running"}],
    )
    data_dir = tmp_path / "instances" / "alpha"
    data_dir.mkdir(parents=True, exist_ok=True)
    db_file = data_dir / "db.sqlite"
    db_file.write_text("original", encoding="utf-8")
    extra_file = data_dir / "extra.txt"
    extra_file.write_text("extra", encoding="utf-8")

    backup_id, _ = _create_backup(env, "alpha")

    db_file.write_text("mutated", encoding="utf-8")
    extra_file.unlink()
    (data_dir / "after.txt").write_text("after", encoding="utf-8")

    _stub_restore_providers(monkeypatch)

    result = runner.invoke(
        app,
        ["backup", "restore", backup_id, "--no-pre-backup", "--json"],
        env=env,
    )

    assert result.exit_code == 0
    payload = _extract_json(result.stdout)
    assert payload["plan"]["status"] == "restored"
    assert db_file.read_text(encoding="utf-8") == "original"
    assert extra_file.exists()
    assert not (data_dir / "after.txt").exists()
    assert not list(data_dir.parent.glob("alpha.pre-restore-*"))

    registry = StateRegistry(state_dir / "registry")
    entry = registry.get_instance("alpha")
    assert entry is not None
    metadata = entry.get("metadata", {})
    assert metadata.get("last_restored_at")

    backups_root = tmp_path / "backups"
    registry_index = BackupsRegistry(backups_root, backups_root / "backups.json")
    updated = registry_index.find_by_id(backup_id)
    assert updated is not None
    assert updated.get("last_restored_at")
    assert updated.get("metadata", {}).get("last_restore_destination")


def test_backup_reconcile_reports_mismatches(tmp_path: Path) -> None:
    """`backup reconcile` surfaces missing entries and orphaned archives."""
    env, _ = _prepare_environment(tmp_path)
    backups_root = tmp_path / "backups"
    registry = BackupsRegistry(backups_root, backups_root / "backups.json")
    registry.ensure_root()

    missing_id = "20240101-alpha-missing"
    archive_path = backups_root / "alpha" / "missing.tar.gz"
    _create_backup_entry(
        registry,
        instance="alpha",
        backup_id=missing_id,
        archive_path=archive_path,
        checksum="deadbeef" * 8,
    )

    orphan_path = backups_root / "alpha" / "orphan.tar.gz"
    orphan_path.parent.mkdir(parents=True, exist_ok=True)
    orphan_path.write_bytes(b"orphan")

    result = runner.invoke(app, ["backup", "reconcile", "--json"], env=env)

    assert result.exit_code == 0
    payload = _extract_json(result.stdout)
    assert any(item["id"] == missing_id for item in payload["missing"])
    assert any(str(orphan_path) == item["path"] for item in payload["orphaned"])


def test_backup_reconcile_apply_updates_index(tmp_path: Path) -> None:
    """`backup reconcile --apply` updates index status for missing archives."""
    env, _ = _prepare_environment(tmp_path)
    backups_root = tmp_path / "backups"
    registry = BackupsRegistry(backups_root, backups_root / "backups.json")
    registry.ensure_root()

    missing_id = "20240102-alpha-missing"
    archive_path = backups_root / "alpha" / "missing.tar.gz"
    _create_backup_entry(
        registry,
        instance="alpha",
        backup_id=missing_id,
        archive_path=archive_path,
        checksum="cafebabe" * 8,
    )

    result = runner.invoke(app, ["backup", "reconcile", "--apply"], env=env)

    assert result.exit_code == 0
    updated = registry.find_by_id(missing_id)
    assert updated is not None
    assert updated.get("status") == "missing"
    metadata = updated.get("metadata", {})
    assert metadata.get("reconciled_at")


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

    monkeypatch.setattr(
        SystemdProvider,
        "stop",
        lambda self, name: _fake_systemctl("stop", name),
    )
    monkeypatch.setattr(
        SystemdProvider,
        "disable",
        lambda self, name: _fake_systemctl("disable", name),
    )
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

    def fake_stop(self: SystemdProvider, name: str) -> subprocess.CompletedProcess:
        calls.append(("stop", name))
        return _fake_systemctl("stop", name)

    def fake_start(self: SystemdProvider, name: str) -> subprocess.CompletedProcess:
        calls.append(("start", name))
        return _fake_systemctl("start", name)

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

    def fake_stop(self: SystemdProvider, name: str) -> subprocess.CompletedProcess:
        calls.append(("stop", name))
        return _fake_systemctl("stop", name)

    def fake_start(self: SystemdProvider, name: str) -> subprocess.CompletedProcess:
        calls.append(("start", name))
        return _fake_systemctl("start", name)

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

    instance_root = tmp_path / "instances" / "alpha"
    data_dir = instance_root / "data"
    runtime_instance_dir = runtime_dir / "instances" / "alpha"
    logs_instance_dir = (tmp_path / "logs") / "alpha"
    state_instance_dir = state_dir / "instances" / "alpha"

    assert instance_root.exists()
    assert data_dir.exists()
    assert runtime_instance_dir.exists()
    assert logs_instance_dir.exists()
    assert state_instance_dir.exists()

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
    steps_by_name = {step.get("name"): step for step in steps}
    assert "filesystem.mkdir.root" in steps_by_name
    assert "config.write" in steps_by_name
    assert "systemd.render_unit" in steps_by_name
    assert "systemd.enable" in steps_by_name
    assert steps_by_name["systemd.enable"]["status"] == "skipped"
    assert "nginx.render_site" in steps_by_name
    assert "nginx.enable" in steps_by_name
    assert "registry.write_instances" in steps_by_name
    assert "registry.update" in steps_by_name

    registry_file = state_dir / "registry" / "instances.yml"
    registry_data = yaml.safe_load(registry_file.read_text(encoding="utf-8"))
    instances = registry_data.get("instances", [])
    entry = next(item for item in instances if item.get("name") == "alpha")
    assert entry["status"] == "enabled"
    assert entry["port"] == 5000
    assert entry["paths"]["root"] == str(instance_root)
    assert entry["paths"]["data"] == str(data_dir)
    assert entry["paths"]["runtime"] == str(runtime_instance_dir)
    assert entry["metadata"]["auto_start"] is True
    assert "activated_at" in entry["metadata"]
    metadata = entry["metadata"]
    assert metadata["port"] == 5000
    assert metadata["domain"] == "alpha.local"
    diagnostics = metadata.get("diagnostics", {})
    assert isinstance(diagnostics, dict)
    systemd_diag = diagnostics.get("systemd", {})
    assert isinstance(systemd_diag, dict)
    assert systemd_diag.get("unit_path", "").endswith("abssctl-alpha.service")
    nginx_diag = diagnostics.get("nginx", {})
    assert isinstance(nginx_diag, dict)
    assert nginx_diag.get("site_path", "").endswith("abssctl-alpha.conf")
    # nginx validation/reload steps recorded
    assert "nginx.validate" in steps_by_name
    assert "nginx.reload" in steps_by_name

    config_payload = json.loads((data_dir / "config.json").read_text(encoding="utf-8"))
    assert config_payload["instance"]["name"] == "alpha"
    assert config_payload["instance"]["domain"] == "alpha.local"
    assert config_payload["server"]["upstream"]["port"] == 5000
    assert config_payload["server"]["version"] == "current"
    assert config_payload["paths"]["root"] == str(instance_root)
    assert config_payload["paths"]["data"] == str(data_dir)


def test_instance_create_rolls_back_on_systemd_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failures during provisioning roll back filesystem, registry, and ports."""
    env, state_dir = _prepare_environment(tmp_path)

    def fail_render(
        self: SystemdProvider,
        name: str,
        context: dict[str, object],
    ) -> bool:
        raise SystemdError("boom")

    monkeypatch.setattr(SystemdProvider, "render_unit", fail_render)

    result = runner.invoke(app, ["instance", "create", "alpha"], env=env)

    assert result.exit_code == 1

    instance_root = tmp_path / "instances" / "alpha"
    assert not instance_root.exists()

    runtime_dir = tmp_path / "run"
    assert not (runtime_dir / "systemd" / "abssctl-alpha.service").exists()
    assert not (runtime_dir / "nginx" / "sites-available" / "abssctl-alpha.conf").exists()

    registry_instances = _registry_instances(state_dir)
    assert all(item.get("name") != "alpha" for item in registry_instances)

    ports_file = state_dir / "registry" / "ports.yml"
    ports_data = yaml.safe_load(ports_file.read_text(encoding="utf-8"))
    assert ports_data.get("ports", []) == []


def test_instance_create_no_start_skips_service(tmp_path: Path) -> None:
    """`--no-start` skips the systemd start step and updates registry metadata."""
    env, state_dir = _prepare_environment(tmp_path)

    result = runner.invoke(app, ["instance", "create", "alpha", "--no-start"], env=env)
    assert result.exit_code == 0

    operations_log = (state_dir.parent / "logs" / "operations.jsonl").read_text(
        encoding="utf-8"
    )
    record = json.loads(operations_log.splitlines()[-1])
    steps = {step.get("name"): step for step in record.get("steps", [])}
    assert steps["systemd.start"]["status"] == "skipped"
    assert steps["systemd.start"]["detail"] == "--no-start requested"

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert entry["metadata"]["auto_start"] is False
    assert entry["status"] == "enabled"


def test_instance_status_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`instance status --json` reports registry and systemd information."""
    instances = [{"name": "alpha", "status": "enabled"}]
    env, _ = _prepare_environment(tmp_path, instances=instances)

    def fake_status(self: SystemdProvider, name: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            ["systemctl", "status", f"abssctl-{name}.service"],
            returncode=0,
            stdout="active (running)\n",
            stderr="",
        )

    monkeypatch.setattr(SystemdProvider, "status", fake_status)

    result = runner.invoke(app, ["instance", "status", "alpha", "--json"], env=env)
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["name"] == "alpha"
    assert payload["registry_status"] == "enabled"
    assert "active" in payload["systemd_output"]
    assert isinstance(payload.get("diagnostics"), dict)


def test_instance_logs_outputs_journal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`instance logs` streams the systemd journal output."""
    instances = [{"name": "alpha"}]
    env, _ = _prepare_environment(tmp_path, instances=instances)

    def fake_logs(
        self: SystemdProvider,
        name: str,
        *,
        lines: int | None = None,
        since: str | None = None,
        follow: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            ["journalctl", "--unit", f"abssctl-{name}.service"],
            returncode=0,
            stdout="line1\nline2\n",
            stderr="",
        )

    monkeypatch.setattr(SystemdProvider, "logs", fake_logs)

    result = runner.invoke(app, ["instance", "logs", "alpha"], env=env)
    assert result.exit_code == 0
    assert "line1" in result.stdout
    assert "line2" in result.stdout


def test_instance_env_json(tmp_path: Path) -> None:
    """`instance env --json` emits environment variables."""
    env, _ = _prepare_environment(tmp_path)
    _create_instance(env)

    result = runner.invoke(app, ["instance", "env", "alpha", "--json"], env=env)
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ABSSCTL_INSTANCE"] == "alpha"
    assert payload["PORT"] == "5000"
    assert payload["ABSSCTL_INSTANCE_ROOT"].endswith("/instances")


def test_instance_set_fqdn_updates_registry(tmp_path: Path) -> None:
    """`set-fqdn` updates domain in config and registry."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    result = runner.invoke(
        app,
        ["instance", "set-fqdn", "alpha", "alpha.example.com", "--no-backup", "--yes"],
        env=env,
    )
    assert result.exit_code == 0

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert entry["domain"] == "alpha.example.com"
    metadata = entry["metadata"]
    assert metadata["domain"] == "alpha.example.com"
    history = metadata.get("domain_history", [])
    assert history
    assert history[-1]["domain"] == "alpha.local"

    config_path = tmp_path / "instances" / "alpha" / "data" / "config.json"
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["instance"]["domain"] == "alpha.example.com"
    assert payload["server"]["public_url"] == "https://alpha.example.com"


def test_instance_set_port_updates_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`set-port` rewrites config, ports registry, and restarts service."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    def fake_stop(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        return _fake_completed(["systemctl", "stop", name])

    def fake_start(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        return _fake_completed(["systemctl", "start", name])

    monkeypatch.setattr(SystemdProvider, "stop", fake_stop)
    monkeypatch.setattr(SystemdProvider, "start", fake_start)

    result = runner.invoke(
        app,
        ["instance", "set-port", "alpha", "6000", "--no-backup", "--yes"],
        env=env,
    )
    assert result.exit_code == 0

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert entry["port"] == 6000
    assert entry["status"] == "enabled"
    metadata = entry["metadata"]
    assert metadata["port"] == 6000
    history = metadata.get("port_history", [])
    assert history
    assert history[-1]["port"] == 5000

    ports_file = state_dir / "registry" / "ports.yml"
    ports_data = yaml.safe_load(ports_file.read_text(encoding="utf-8"))
    reserved_ports = {item["port"] for item in ports_data.get("ports", [])}
    assert 6000 in reserved_ports
    assert 5000 not in reserved_ports


def test_instance_set_version_updates_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`set-version` binds to a registered version."""
    install_root = tmp_path / "srv" / "app"
    version_path = install_root / "v25.9.0"
    version_path.mkdir(parents=True, exist_ok=True)

    env, state_dir = _prepare_environment(
        tmp_path,
        config_overrides={"install_root": str(install_root)},
        versions=[{"version": "25.9.0", "path": str(version_path)}],
    )
    _create_instance(env)

    monkeypatch.setattr(
        SystemdProvider,
        "stop",
        lambda self, name, dry_run=False: _fake_completed(["systemctl", "stop", name]),
    )
    monkeypatch.setattr(
        SystemdProvider,
        "start",
        lambda self, name, dry_run=False: _fake_completed(["systemctl", "start", name]),
    )

    result = runner.invoke(
        app,
        ["instance", "set-version", "alpha", "25.9.0", "--no-backup", "--yes"],
        env=env,
    )
    assert result.exit_code == 0

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert entry["version"] == "25.9.0"
    metadata = entry["metadata"]
    assert metadata.get("version_changed_at")

    config_path = tmp_path / "instances" / "alpha" / "data" / "config.json"
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["server"]["version"] == "25.9.0"


def test_instance_delete_purge_data_removes_root(tmp_path: Path) -> None:
    """`instance delete --purge-data` removes the instance root directory."""
    env, _ = _prepare_environment(tmp_path)
    _create_instance(env)

    root_path = tmp_path / "instances" / "alpha"
    assert root_path.exists()

    result = runner.invoke(
        app,
        ["instance", "delete", "alpha", "--purge-data", "--no-backup", "--yes"],
        env=env,
    )
    assert result.exit_code == 0
    assert not root_path.exists()


def test_instance_rename_moves_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`instance rename` moves directories and updates the registry."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    monkeypatch.setattr(
        SystemdProvider,
        "stop",
        lambda self, name, dry_run=False: _fake_completed(["systemctl", "stop", name]),
    )
    monkeypatch.setattr(
        SystemdProvider,
        "start",
        lambda self, name, dry_run=False: _fake_completed(["systemctl", "start", name]),
    )
    monkeypatch.setattr(
        SystemdProvider,
        "enable",
        lambda self, name, dry_run=False: _fake_completed(["systemctl", "enable", name]),
    )
    monkeypatch.setattr(
        SystemdProvider,
        "disable",
        lambda self, name, dry_run=False: _fake_completed(["systemctl", "disable", name]),
    )

    result = runner.invoke(
        app,
        ["instance", "rename", "alpha", "beta", "--no-backup", "--yes"],
        env=env,
    )
    assert result.exit_code == 0

    instances = _registry_instances(state_dir)
    assert any(item.get("name") == "beta" for item in instances)
    assert all(item.get("name") != "alpha" for item in instances)

    old_root = tmp_path / "instances" / "alpha"
    new_root = tmp_path / "instances" / "beta"
    assert not old_root.exists()
    assert new_root.exists()

    ports_file = state_dir / "registry" / "ports.yml"
    ports_data = yaml.safe_load(ports_file.read_text(encoding="utf-8"))
    reserved_names = {item["name"] for item in ports_data.get("ports", [])}
    assert "beta" in reserved_names
    assert "alpha" not in reserved_names


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


def _latest_operation(state_dir: Path) -> dict[str, object]:
    """Return the most recent structured operations log record."""
    log_path = state_dir.parent / "logs" / "operations.jsonl"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert lines, "operations log is empty"
    return json.loads(lines[-1])


def _index_steps(record: dict[str, object]) -> dict[str, dict[str, object]]:
    """Index operation steps by name for convenient lookup."""
    steps_raw = record.get("steps", [])
    steps: dict[str, dict[str, object]] = {}
    if isinstance(steps_raw, list):
        for item in steps_raw:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if isinstance(name, str):
                steps[name] = item
    return steps


def test_instance_enable_updates_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Enable command invokes providers and marks instance enabled."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    calls: list[tuple[str, str]] = []

    def fake_systemd_enable(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(("systemd", name))
        return subprocess.CompletedProcess(
            ["systemctl", "enable", f"abssctl-{name}.service"], returncode=0
        )

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
    metadata = instance["metadata"]
    assert metadata.get("enabled_at")


def test_instance_enable_dry_run_skips_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run enable avoids provider calls and metadata updates."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    def _fail_systemd_enable(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        raise AssertionError("systemd enable should not execute during dry-run")

    def _fail_nginx_enable(self: NginxProvider, name: str) -> None:
        raise AssertionError("nginx enable should not execute during dry-run")

    monkeypatch.setattr(SystemdProvider, "enable", _fail_systemd_enable)
    monkeypatch.setattr(NginxProvider, "enable", _fail_nginx_enable)

    result = runner.invoke(app, ["instance", "enable", "alpha", "--dry-run"], env=env)
    assert result.exit_code == 0

    record = _latest_operation(state_dir)
    steps = _index_steps(record)
    assert steps["systemd.enable"]["status"] == "skipped"
    assert steps["systemd.enable"]["detail"] == "dry-run"
    assert steps["nginx.enable"]["status"] == "skipped"
    assert steps["nginx.enable"]["detail"] == "dry-run"

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    metadata = entry.get("metadata", {})
    assert isinstance(metadata, dict)
    assert "enabled_at" not in metadata
    assert entry["status"] == "enabled"


def test_instance_enable_systemd_failure_preserves_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Systemd failures surface an error and keep registry metadata unchanged."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    def _boom_systemd_enable(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        raise SystemdError("boom")

    def _fail_nginx_enable(self: NginxProvider, name: str) -> None:
        raise AssertionError("nginx enable should not execute when systemd fails")

    monkeypatch.setattr(SystemdProvider, "enable", _boom_systemd_enable)
    monkeypatch.setattr(NginxProvider, "enable", _fail_nginx_enable)

    result = runner.invoke(app, ["instance", "enable", "alpha"], env=env)
    assert result.exit_code == 1

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    metadata = entry.get("metadata", {})
    assert isinstance(metadata, dict)
    assert "enabled_at" not in metadata
    assert entry["status"] == "enabled"

    record = _latest_operation(state_dir)
    assert record["command"] == "instance enable"
    result_payload = record.get("result", {})
    assert result_payload.get("status") == "error"
    assert result_payload.get("errors")


def test_instance_disable_updates_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Disable command invokes providers and marks instance disabled."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    monkeypatch.setattr(
        SystemdProvider,
        "disable",
        lambda self, name, dry_run=False: subprocess.CompletedProcess(
            ["systemctl", "disable", f"abssctl-{name}.service"], returncode=0
        ),
    )
    monkeypatch.setattr(NginxProvider, "disable", lambda self, name: None)

    result = runner.invoke(app, ["instance", "disable", "alpha"], env=env)
    assert result.exit_code == 0
    instance = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert instance["status"] == "disabled"
    metadata = instance["metadata"]
    assert metadata.get("disabled_at")
    diagnostics = metadata.get("diagnostics", {})
    systemd_diag = diagnostics.get("systemd", {}) if isinstance(diagnostics, dict) else {}
    assert systemd_diag.get("enabled") is False


def test_instance_disable_dry_run_skips_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run disable avoids provider calls and leaves registry untouched."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    def _fail_systemd_disable(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        raise AssertionError("systemd disable should not execute during dry-run")

    def _fail_nginx_disable(self: NginxProvider, name: str) -> None:
        raise AssertionError("nginx disable should not execute during dry-run")

    monkeypatch.setattr(SystemdProvider, "disable", _fail_systemd_disable)
    monkeypatch.setattr(NginxProvider, "disable", _fail_nginx_disable)

    result = runner.invoke(app, ["instance", "disable", "alpha", "--dry-run"], env=env)
    assert result.exit_code == 0

    record = _latest_operation(state_dir)
    steps = _index_steps(record)
    assert steps["systemd.disable"]["status"] == "skipped"
    assert steps["systemd.disable"]["detail"] == "dry-run"
    assert steps["nginx.disable"]["status"] == "skipped"
    assert steps["nginx.disable"]["detail"] == "dry-run"

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    metadata = entry.get("metadata", {})
    assert isinstance(metadata, dict)
    assert "disabled_at" not in metadata
    assert entry["status"] == "enabled"


def test_instance_disable_systemd_failure_preserves_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Systemd disable failures exit with an error and keep state unchanged."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    def _boom_systemd_disable(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        raise SystemdError("boom")

    def _fail_nginx_disable(self: NginxProvider, name: str) -> None:
        raise AssertionError("nginx disable should not run when systemd fails")

    monkeypatch.setattr(SystemdProvider, "disable", _boom_systemd_disable)
    monkeypatch.setattr(NginxProvider, "disable", _fail_nginx_disable)

    result = runner.invoke(app, ["instance", "disable", "alpha"], env=env)
    assert result.exit_code == 1

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    metadata = entry.get("metadata", {})
    assert isinstance(metadata, dict)
    assert "disabled_at" not in metadata
    assert entry["status"] == "enabled"

    record = _latest_operation(state_dir)
    assert record["command"] == "instance disable"
    result_payload = record.get("result", {})
    assert result_payload.get("status") == "error"
    assert result_payload.get("errors")


def test_instance_start_updates_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Start command sets registry status to running."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    monkeypatch.setattr(
        SystemdProvider,
        "start",
        lambda self, name, dry_run=False: subprocess.CompletedProcess(
            ["systemctl", "start", f"abssctl-{name}.service"], returncode=0
        ),
    )

    result = runner.invoke(app, ["instance", "start", "alpha"], env=env)
    assert result.exit_code == 0
    instance = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert instance["status"] == "running"
    assert instance["metadata"].get("last_started_at")


def test_instance_start_dry_run_skips_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run start avoids provider execution and metadata updates."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    def _fail_systemd_start(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        raise AssertionError("systemd start should not execute during dry-run")

    monkeypatch.setattr(SystemdProvider, "start", _fail_systemd_start)

    result = runner.invoke(app, ["instance", "start", "alpha", "--dry-run"], env=env)
    assert result.exit_code == 0

    record = _latest_operation(state_dir)
    steps = _index_steps(record)
    assert steps["systemd.start"]["status"] == "skipped"
    assert steps["systemd.start"]["detail"] == "dry-run"

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    metadata = entry.get("metadata", {})
    assert isinstance(metadata, dict)
    assert "last_started_at" not in metadata
    assert entry["status"] == "enabled"


def test_instance_start_systemd_failure_preserves_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Start failure reports an error and leaves registry intact."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    def _boom_systemd_start(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        raise SystemdError("boom")

    monkeypatch.setattr(SystemdProvider, "start", _boom_systemd_start)

    result = runner.invoke(app, ["instance", "start", "alpha"], env=env)
    assert result.exit_code == 1

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    metadata = entry.get("metadata", {})
    assert isinstance(metadata, dict)
    assert "last_started_at" not in metadata
    assert entry["status"] == "enabled"

    record = _latest_operation(state_dir)
    assert record["command"] == "instance start"
    result_payload = record.get("result", {})
    assert result_payload.get("status") == "error"
    assert result_payload.get("errors")


def test_instance_stop_updates_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stop command sets registry status to stopped."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    monkeypatch.setattr(
        SystemdProvider,
        "stop",
        lambda self, name: subprocess.CompletedProcess(
            ["systemctl", "stop", f"abssctl-{name}.service"], returncode=0
        ),
    )

    result = runner.invoke(app, ["instance", "stop", "alpha"], env=env)
    assert result.exit_code == 0
    instance = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert instance["status"] == "stopped"
    assert instance["metadata"].get("last_stopped_at")


def test_instance_stop_dry_run_skips_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run stop avoids provider execution and registry updates."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    def _fail_systemd_stop(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        raise AssertionError("systemd stop should not execute during dry-run")

    monkeypatch.setattr(SystemdProvider, "stop", _fail_systemd_stop)

    result = runner.invoke(app, ["instance", "stop", "alpha", "--dry-run"], env=env)
    assert result.exit_code == 0

    record = _latest_operation(state_dir)
    steps = _index_steps(record)
    assert steps["systemd.stop"]["status"] == "skipped"
    assert steps["systemd.stop"]["detail"] == "dry-run"

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    metadata = entry.get("metadata", {})
    assert isinstance(metadata, dict)
    assert "last_stopped_at" not in metadata
    assert entry["status"] == "enabled"


def test_instance_stop_systemd_failure_preserves_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stop failure reports an error without altering registry data."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    def _boom_systemd_stop(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        raise SystemdError("boom")

    monkeypatch.setattr(SystemdProvider, "stop", _boom_systemd_stop)

    result = runner.invoke(app, ["instance", "stop", "alpha"], env=env)
    assert result.exit_code == 1

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    metadata = entry.get("metadata", {})
    assert isinstance(metadata, dict)
    assert "last_stopped_at" not in metadata
    assert entry["status"] == "enabled"

    record = _latest_operation(state_dir)
    assert record["command"] == "instance stop"
    result_payload = record.get("result", {})
    assert result_payload.get("status") == "error"
    assert result_payload.get("errors")


def test_instance_restart_calls_stop_and_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Restart delegates to systemd stop then start and sets running status."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    calls: list[str] = []

    def fake_stop(self: SystemdProvider, name: str) -> subprocess.CompletedProcess:
        calls.append("stop")
        return subprocess.CompletedProcess(
            ["systemctl", "stop", f"abssctl-{name}.service"], returncode=0
        )

    def fake_start(self: SystemdProvider, name: str) -> subprocess.CompletedProcess:
        calls.append("start")
        return subprocess.CompletedProcess(
            ["systemctl", "start", f"abssctl-{name}.service"], returncode=0
        )

    monkeypatch.setattr(SystemdProvider, "stop", fake_stop)
    monkeypatch.setattr(SystemdProvider, "start", fake_start)

    result = runner.invoke(app, ["instance", "restart", "alpha"], env=env)
    assert result.exit_code == 0
    assert calls == ["stop", "start"]
    instance = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert instance["status"] == "running"
    assert instance["metadata"].get("last_restarted_at")


def test_instance_restart_dry_run_skips_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run restart records skipped steps and keeps registry untouched."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    def _fail_systemd_stop(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        raise AssertionError("systemd stop should not execute during dry-run")

    def _fail_systemd_start(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        raise AssertionError("systemd start should not execute during dry-run")

    monkeypatch.setattr(SystemdProvider, "stop", _fail_systemd_stop)
    monkeypatch.setattr(SystemdProvider, "start", _fail_systemd_start)

    result = runner.invoke(app, ["instance", "restart", "alpha", "--dry-run"], env=env)
    assert result.exit_code == 0

    record = _latest_operation(state_dir)
    steps = _index_steps(record)
    assert steps["systemd.stop"]["status"] == "skipped"
    assert steps["systemd.stop"]["detail"] == "dry-run"
    assert steps["systemd.start"]["status"] == "skipped"
    assert steps["systemd.start"]["detail"] == "dry-run"

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    metadata = entry.get("metadata", {})
    assert isinstance(metadata, dict)
    assert "last_restarted_at" not in metadata
    assert entry["status"] == "enabled"


def test_instance_restart_systemd_failure_preserves_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Restart surfaces provider errors without mutating registry metadata."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    calls: list[str] = []

    def _ok_systemd_stop(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        calls.append("stop")
        return _fake_systemctl("stop", name)

    def _boom_systemd_start(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        raise SystemdError("boom")

    monkeypatch.setattr(SystemdProvider, "stop", _ok_systemd_stop)
    monkeypatch.setattr(SystemdProvider, "start", _boom_systemd_start)

    result = runner.invoke(app, ["instance", "restart", "alpha"], env=env)
    assert result.exit_code == 1
    assert calls == ["stop"]

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    metadata = entry.get("metadata", {})
    assert isinstance(metadata, dict)
    assert "last_restarted_at" not in metadata
    assert entry["status"] == "enabled"

    record = _latest_operation(state_dir)
    assert record["command"] == "instance restart"
    result_payload = record.get("result", {})
    assert result_payload.get("status") == "error"
    assert result_payload.get("errors")


def test_instance_delete_removes_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Delete removes provider assets and unregisters the instance."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    monkeypatch.setattr(
        SystemdProvider,
        "stop",
        lambda self, name: subprocess.CompletedProcess(
            ["systemctl", "stop", f"abssctl-{name}.service"], returncode=0
        ),
    )
    monkeypatch.setattr(
        SystemdProvider,
        "disable",
        lambda self, name: subprocess.CompletedProcess(
            ["systemctl", "disable", f"abssctl-{name}.service"], returncode=0
        ),
    )
    monkeypatch.setattr(SystemdProvider, "remove", lambda self, name: None)
    monkeypatch.setattr(NginxProvider, "disable", lambda self, name: None)
    monkeypatch.setattr(NginxProvider, "remove", lambda self, name: None)

    result = runner.invoke(app, ["instance", "delete", "alpha", "--no-backup"], env=env)
    assert result.exit_code == 0
    instances = _registry_instances(state_dir)
    assert all(item.get("name") != "alpha" for item in instances)


def test_instance_delete_dry_run_keeps_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run delete skips side effects and retains registry/ports."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    def _fail_systemd_stop(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        raise AssertionError("systemd stop should not execute during dry-run")

    def _fail_systemd_disable(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        raise AssertionError("systemd disable should not execute during dry-run")

    def _fail_systemd_remove(self: SystemdProvider, name: str) -> None:
        raise AssertionError("systemd remove should not execute during dry-run")

    def _fail_nginx_disable(self: NginxProvider, name: str) -> None:
        raise AssertionError("nginx disable should not execute during dry-run")

    def _fail_nginx_remove(self: NginxProvider, name: str) -> None:
        raise AssertionError("nginx remove should not execute during dry-run")

    monkeypatch.setattr(SystemdProvider, "stop", _fail_systemd_stop)
    monkeypatch.setattr(SystemdProvider, "disable", _fail_systemd_disable)
    monkeypatch.setattr(SystemdProvider, "remove", _fail_systemd_remove)
    monkeypatch.setattr(NginxProvider, "disable", _fail_nginx_disable)
    monkeypatch.setattr(NginxProvider, "remove", _fail_nginx_remove)

    result = runner.invoke(app, ["instance", "delete", "alpha", "--dry-run"], env=env)
    assert result.exit_code == 0

    record = _latest_operation(state_dir)
    steps = _index_steps(record)
    for name in [
        "backup.prompt",
        "systemd.stop",
        "systemd.disable",
        "nginx.disable",
        "systemd.remove",
        "nginx.remove",
        "filesystem.cleanup",
        "registry.remove",
        "ports.release",
    ]:
        assert steps[name]["status"] == "skipped"
        assert steps[name]["detail"] == "dry-run"
    assert record["result"]["status"] == "success"
    assert record["result"]["changed"] == 0

    entry = next(item for item in _registry_instances(state_dir) if item["name"] == "alpha")
    assert entry["status"] == "enabled"

    ports_path = state_dir / "registry" / "ports.yml"
    ports_data = yaml.safe_load(ports_path.read_text(encoding="utf-8"))
    reserved = {item["name"] for item in ports_data.get("ports", [])}
    assert "alpha" in reserved

    instance_root = tmp_path / "instances" / "alpha"
    runtime_instance_dir = (tmp_path / "run" / "instances" / "alpha")
    logs_instance_dir = tmp_path / "logs" / "alpha"
    state_instance_dir = state_dir / "instances" / "alpha"
    assert instance_root.exists()
    assert runtime_instance_dir.exists()
    assert logs_instance_dir.exists()
    assert state_instance_dir.exists()


def test_instance_delete_cleans_files_and_releases_port(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Delete removes runtime artifacts and frees the reserved port."""
    env, state_dir = _prepare_environment(tmp_path)
    _create_instance(env)

    monkeypatch.setattr(
        SystemdProvider,
        "start",
        lambda self, name, dry_run=False: _fake_systemctl("start", name),
    )
    start_result = runner.invoke(app, ["instance", "start", "alpha"], env=env)
    assert start_result.exit_code == 0

    runtime_dir = tmp_path / "run"
    instance_root = tmp_path / "instances" / "alpha"
    runtime_instance_dir = runtime_dir / "instances" / "alpha"
    logs_instance_dir = tmp_path / "logs" / "alpha"
    state_instance_dir = state_dir / "instances" / "alpha"
    systemd_unit = runtime_dir / "systemd" / "abssctl-alpha.service"
    nginx_site = runtime_dir / "nginx" / "sites-available" / "abssctl-alpha.conf"
    nginx_enabled = runtime_dir / "nginx" / "sites-enabled" / "abssctl-alpha.conf"

    assert systemd_unit.exists()
    assert nginx_site.exists()
    assert nginx_enabled.exists()
    assert runtime_instance_dir.exists()
    assert logs_instance_dir.exists()
    assert state_instance_dir.exists()

    calls: list[str] = []
    original_systemd_remove = SystemdProvider.remove
    original_nginx_disable = NginxProvider.disable
    original_nginx_remove = NginxProvider.remove

    def _ok_systemd_stop(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        calls.append("systemd.stop")
        return _fake_systemctl("stop", name)

    def _ok_systemd_disable(
        self: SystemdProvider,
        name: str,
        *,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        calls.append("systemd.disable")
        return _fake_systemctl("disable", name)

    def _wrap_systemd_remove(self: SystemdProvider, name: str) -> None:
        calls.append("systemd.remove")
        original_systemd_remove(self, name)

    def _wrap_nginx_disable(self: NginxProvider, name: str) -> None:
        calls.append("nginx.disable")
        original_nginx_disable(self, name)

    def _wrap_nginx_remove(self: NginxProvider, name: str) -> None:
        calls.append("nginx.remove")
        original_nginx_remove(self, name)

    monkeypatch.setattr(SystemdProvider, "stop", _ok_systemd_stop)
    monkeypatch.setattr(SystemdProvider, "disable", _ok_systemd_disable)
    monkeypatch.setattr(SystemdProvider, "remove", _wrap_systemd_remove)
    monkeypatch.setattr(NginxProvider, "disable", _wrap_nginx_disable)
    monkeypatch.setattr(NginxProvider, "remove", _wrap_nginx_remove)

    result = runner.invoke(
        app,
        ["instance", "delete", "alpha", "--no-backup", "--yes", "--purge-data"],
        env=env,
    )
    assert result.exit_code == 0
    assert set(calls) == {
        "systemd.stop",
        "systemd.disable",
        "systemd.remove",
        "nginx.disable",
        "nginx.remove",
    }

    assert not instance_root.exists()
    assert not runtime_instance_dir.exists()
    assert not logs_instance_dir.exists()
    assert not state_instance_dir.exists()
    assert not systemd_unit.exists()
    assert not nginx_site.exists()
    assert not nginx_enabled.exists()

    ports_path = state_dir / "registry" / "ports.yml"
    ports_data = yaml.safe_load(ports_path.read_text(encoding="utf-8"))
    assert ports_data.get("ports", []) == []

    instances = _registry_instances(state_dir)
    assert all(item.get("name") != "alpha" for item in instances)

    record = _latest_operation(state_dir)
    steps = _index_steps(record)
    assert steps["ports.release"]["status"] == "success"
    assert steps["registry.remove"]["status"] == "success"
