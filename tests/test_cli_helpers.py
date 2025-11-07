"""Unit tests for CLI helper functions (bootstrap, updates, backup prompts)."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer

from abssctl.backups import BackupError
from abssctl.cli import (
    _build_backup_plan_context,
    _build_update_payload,
    _collect_backup_sources,
    _compose_backup_metadata,
    _compression_extension,
    _create_archive,
    _create_backup,
    _discover_backup_archives,
    _infer_backup_algorithm,
    _latest_backups_by_instance,
    _load_backup_instance_snapshot,
    _materialise_backup_payload,
    _maybe_prompt_backup,
    _merge_versions,
    _resolve_backup_algorithm,
    _resolve_bootstrap_options,
    _run_instance_backups,
)
from abssctl.logging import OperationScope, StructuredLogger


def _make_config(root: Path) -> SimpleNamespace:
    """Return a minimal AppConfig-like namespace for bootstrap helpers."""
    return SimpleNamespace(
        service_user="abssctl",
        install_root=root / "install",
        instance_root=root / "instances",
        state_dir=root / "state",
        logs_dir=root / "logs",
        runtime_dir=root / "run",
        templates_dir=root / "templates",
        backups=SimpleNamespace(
            root=root / "backups",
            compression="gzip",
            compression_level=3,
        ),
        registry_dir=root / "registry",
        config_file=root / "etc" / "config.yaml",
    )


def _operation_scope(tmp_path: Path) -> OperationScope:
    """Return a structured logging scope rooted at *tmp_path*."""
    logger = StructuredLogger(tmp_path / "logs")
    return logger.operation("cli-helper-test")


class DummyBackups:
    """Minimal backups registry stand-in."""

    def __init__(self, root: Path) -> None:
        """Initialise a stub backing store rooted under *root*."""
        self.root = root / "backups"
        self.root.mkdir(parents=True, exist_ok=True)
        self.index = self.root / "backups.json"
        self.appended: list[dict[str, object]] = []

    def generate_identifier(self, instance: str) -> str:
        """Return a deterministic identifier for the instance."""
        return f"{instance}-id"

    def archive_directory(self, instance: str) -> Path:
        """Return/create the archive directory for *instance*."""
        path = self.root / instance
        path.mkdir(parents=True, exist_ok=True)
        return path

    def append(self, entry: Mapping[str, object]) -> None:
        """Record an appended entry for assertions."""
        self.appended.append(dict(entry))


class DummyLocks:
    """Stub lock manager for _run_instance_backups tests."""

    def __init__(self) -> None:
        """Initialise storage for recorded lock calls."""
        self.calls: list[tuple[tuple[str, ...], bool]] = []

    class _Bundle:
        """Context bundle exposing wait_ms."""

        wait_ms = 0

    class _Context:
        def __init__(self, bundle: DummyLocks._Bundle) -> None:
            self.bundle = bundle

        def __enter__(self) -> DummyLocks._Bundle:
            return self.bundle

        def __exit__(
            self,
            exc_type: object,
            exc: object,
            tb: object,
        ) -> bool:
            return False

    def mutate_instances(
        self,
        names: Sequence[str],
        include_global: bool = True,
    ) -> DummyLocks._Context:
        """Return a context manager yielding a bundle with wait_ms."""
        self.calls.append((tuple(names), include_global))
        return DummyLocks._Context(DummyLocks._Bundle())


def test_resolve_bootstrap_options_respects_overrides(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provided overrides should propagate through load_config."""
    base_config = _make_config(tmp_path)
    final_config = _make_config(tmp_path / "final")
    recorded_overrides: dict[str, object] | None = None

    def fake_load_config(
        *,
        config_file: Path | None,
        overrides: dict[str, object] | None = None,
    ) -> SimpleNamespace:
        nonlocal recorded_overrides
        if overrides is None:
            return base_config
        recorded_overrides = overrides
        return final_config

    monkeypatch.setattr("abssctl.cli.load_config", fake_load_config)

    result = _resolve_bootstrap_options(
        config_file=tmp_path / "config.yaml",
        service_user="custom ",
        service_group=None,
        install_root=None,
        instance_root=None,
        state_dir=None,
        logs_dir=None,
        runtime_dir=None,
        templates_dir=None,
        backups_root=None,
        defaults=True,
        interactive=False,
    )

    assert result.config is final_config
    assert result.service_user == "custom"
    assert result.service_group == "custom"
    assert recorded_overrides is not None
    assert recorded_overrides["service_user"] == "custom"
    assert Path(recorded_overrides["install_root"]).name == "install"


def test_resolve_bootstrap_options_rejects_empty_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Blank service user input should raise an error."""
    monkeypatch.setattr("abssctl.cli.load_config", lambda **_: _make_config(tmp_path))
    with pytest.raises(typer.BadParameter):
        _resolve_bootstrap_options(
            config_file=None,
            service_user="  ",
            service_group=None,
            install_root=None,
            instance_root=None,
            state_dir=None,
            logs_dir=None,
            runtime_dir=None,
            templates_dir=None,
            backups_root=None,
            defaults=True,
            interactive=False,
        )


def test_build_update_payload_remote_unavailable() -> None:
    """No remote versions should signal remote-unavailable."""
    payload = _build_update_payload("pkg", {"1.0.0"}, [])
    assert payload["status"] == "remote-unavailable"
    assert "Unable to retrieve" in payload["message"]


def test_build_update_payload_reports_updates() -> None:
    """A newer remote version should be reported in available_updates."""
    payload = _build_update_payload("pkg", {"1.0.0"}, ["1.0.0", "1.1.0"])
    assert payload["status"] == "updates-available"
    assert payload["available_updates"] == ["1.1.0"]
    assert "1.1.0" in payload["message"]


def test_build_update_payload_up_to_date() -> None:
    """When installed versions cover the latest remote, status should be up-to-date."""
    payload = _build_update_payload("pkg", {"1.1.0"}, ["1.0.0", "1.1.0"])
    assert payload["status"] == "up-to-date"
    assert "up to date" in payload["message"]


def test_build_update_payload_requires_stable_versions() -> None:
    """Remote prerelease-only data should be treated as unavailable."""
    payload = _build_update_payload("pkg", {"0.9.0"}, ["1.0.0-beta.1"])
    assert payload["status"] == "remote-unavailable"
    assert "No stable versions" in payload["message"]


def test_compose_backup_metadata_defaults() -> None:
    """Default backup metadata should use Pre prefix and label slug."""
    message, labels = _compose_backup_metadata("version switch", None)
    assert message == "Pre version switch"
    assert labels == ["pre-version-switch"]


def test_resolve_backup_algorithm_auto_prefers_zstd(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auto compression should pick zstd when available."""
    monkeypatch.setattr("abssctl.cli._detect_zstd_support", lambda: True)
    assert _resolve_backup_algorithm("auto", "gzip") == "zstd"


def test_resolve_backup_algorithm_auto_falls_back_gzip(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auto compression should fall back when zstd unsupported."""
    monkeypatch.setattr("abssctl.cli._detect_zstd_support", lambda: False)
    assert _resolve_backup_algorithm("auto", "zstd") == "gzip"


def test_resolve_backup_algorithm_rejects_invalid() -> None:
    """Unsupported algorithms should raise BackupError."""
    with pytest.raises(BackupError):
        _resolve_backup_algorithm("bzip2", "gzip")


def test_compression_extension_mappings() -> None:
    """Compression extension helper should map algorithms."""
    assert _compression_extension("gzip") == "tar.gz"
    assert _compression_extension("zstd") == "tar.zst"
    assert _compression_extension("tar") == "tar"


def test_infer_backup_algorithm_from_entry_and_suffix(tmp_path: Path) -> None:
    """Explicit algorithm should win; otherwise suffix detection kicks in."""
    entry = {"algorithm": "gzip"}
    assert _infer_backup_algorithm(entry, tmp_path / "archive.tar.zst") == "gzip"
    entry = {}
    assert _infer_backup_algorithm(entry, tmp_path / "archive.tar.zst") == "zstd"


def test_merge_versions_combines_remote_and_local() -> None:
    """_merge_versions should mark installed versions while preserving extras."""
    local = [
        {"version": "1.0.0", "metadata": {"notes": "local"}},
        {"version": "0.9.0", "metadata": {}},
    ]
    remote = ["1.0.0", "1.1.0"]

    combined = _merge_versions(local, remote)

    assert combined[0]["version"] == "1.1.0"
    assert combined[0]["metadata"] == {"installed": False, "source": "npm"}
    assert any(entry["version"] == "1.0.0" and entry["metadata"]["installed"] for entry in combined)
    assert any(entry["version"] == "0.9.0" for entry in combined)


def test_merge_versions_returns_local_when_remote_empty() -> None:
    """Remote outages should return local entries untouched."""
    local = [
        {"version": "1.0.0", "metadata": {"installed": True}},
        {"version": "0.9.0", "metadata": {"installed": True}},
    ]

    combined = _merge_versions(local, [])

    assert combined is local
    assert combined == local


def test_maybe_prompt_backup_skips_when_requested(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--no-backup should bypass prompts."""
    monkeypatch.setattr("abssctl.cli.typer.confirm", lambda *args, **kwargs: False)
    with _operation_scope(tmp_path) as op:
        _maybe_prompt_backup(
            operation="danger",
            op=op,
            skip_backup=True,
            auto_confirm=False,
            backup_message=None,
        )
    assert op._steps and op._steps[-1]["name"] == "backup.skip"  # type: ignore[attr-defined]


def test_maybe_prompt_backup_records_deferred(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """User-declined backups should record a warning step."""
    monkeypatch.setattr("abssctl.cli.typer.confirm", lambda *args, **kwargs: False)
    with _operation_scope(tmp_path) as op:
        _maybe_prompt_backup(
            operation="danger",
            op=op,
            skip_backup=False,
            auto_confirm=False,
            backup_message=None,
        )
    assert op._steps[-1]["name"] == "backup.deferred"  # type: ignore[attr-defined]


def test_maybe_prompt_backup_invokes_on_accept(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accepting the prompt should run the provided callback."""
    monkeypatch.setattr("abssctl.cli.typer.confirm", lambda *args, **kwargs: True)
    invoked: list[str] = []

    def _on_accept(scope: OperationScope) -> None:
        invoked.append("called")
        scope.add_step("backup.create", status="success", detail="test-backup")

    with _operation_scope(tmp_path) as op:
        _maybe_prompt_backup(
            operation="danger",
            op=op,
            skip_backup=False,
            auto_confirm=False,
            backup_message="perform backup",
            on_accept=_on_accept,
        )
    assert invoked == ["called"]
    assert any(step["name"] == "backup.create" for step in op._steps)  # type: ignore[attr-defined]


def test_maybe_prompt_backup_propagates_backup_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failures inside on_accept should translate into typer.Exit."""
    monkeypatch.setattr("abssctl.cli.typer.confirm", lambda *args, **kwargs: True)

    def _on_accept(scope: OperationScope) -> None:
        raise BackupError("boom")

    with pytest.raises(typer.Exit) as exc:
        with _operation_scope(tmp_path) as op:
            _maybe_prompt_backup(
                operation="danger",
                op=op,
                skip_backup=False,
                auto_confirm=False,
                backup_message=None,
                on_accept=_on_accept,
            )
    assert exc.value.exit_code == 4


def test_collect_backup_sources_with_services(tmp_path: Path) -> None:
    """_collect_backup_sources should capture service paths when requested."""
    config = _make_config(tmp_path)
    runtime = SimpleNamespace(
        config=config,
        systemd_provider=SimpleNamespace(
            unit_path=lambda name: tmp_path / "systemd" / f"{name}.service"
        ),
        nginx_provider=SimpleNamespace(
            site_path=lambda name: tmp_path / "nginx" / f"{name}.conf",
            enabled_path=lambda name: tmp_path / "nginx-enabled" / f"{name}.conf",
        ),
    )
    # create files for existence checks
    (tmp_path / "systemd").mkdir()
    (tmp_path / "systemd" / "alpha.service").write_text("", encoding="utf-8")
    (tmp_path / "nginx").mkdir()
    (tmp_path / "nginx" / "alpha.conf").write_text("", encoding="utf-8")
    (tmp_path / "nginx-enabled").mkdir()
    (tmp_path / "nginx-enabled" / "alpha.conf").write_text("", encoding="utf-8")
    config.registry_dir.mkdir(parents=True, exist_ok=True)
    (config.registry_dir / "instances.yml").write_text("instances: []", encoding="utf-8")

    sources = _collect_backup_sources(runtime, "alpha", include_services=True)

    assert sources["data"]["path"].endswith("instances/alpha")
    assert sources["systemd"]["exists"] is True
    assert sources["registry"]["exists"] is True


def test_collect_backup_sources_without_services(tmp_path: Path) -> None:
    """Data-only backups should omit service entries but still report metadata."""
    config = _make_config(tmp_path)
    runtime = SimpleNamespace(
        config=config,
        systemd_provider=SimpleNamespace(
            unit_path=lambda name: tmp_path / "systemd" / f"{name}.service"
        ),
        nginx_provider=SimpleNamespace(
            site_path=lambda name: tmp_path / "nginx" / f"{name}.conf",
            enabled_path=lambda name: tmp_path / "nginx-enabled" / f"{name}.conf",
        ),
    )

    sources = _collect_backup_sources(runtime, "alpha", include_services=False)

    assert "systemd" not in sources
    assert "nginx_site" not in sources
    assert sources["data"]["exists"] is False
    assert sources["registry"]["path"].endswith("registry/instances.yml")
    assert sources["metadata_instance"]["exists"] is True


def test_materialise_backup_payload_copies_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Payload creation should copy present sources and emit metadata."""
    data_dir = tmp_path / "data-src"
    data_dir.mkdir()
    (data_dir / "file.txt").write_text("payload", encoding="utf-8")
    systemd_dir = tmp_path / "systemd-src"
    systemd_dir.mkdir()
    (systemd_dir / "alpha.service").write_text("service", encoding="utf-8")

    copies: list[tuple[Path, Path]] = []

    def fake_copy(src: Path, dest: Path) -> None:
        copies.append((src, dest))
        if src.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    monkeypatch.setattr("abssctl.cli.copy_into", fake_copy)

    sources = {
        "data": {"path": str(data_dir), "exists": True},
        "systemd": {"path": str(systemd_dir / "alpha.service"), "exists": True},
        "nginx_site": {"path": str(tmp_path / "nginx.conf"), "exists": False},
        "registry": {"path": str(tmp_path / "registry.yml"), "exists": False},
    }
    payload_root = tmp_path / "payload"
    instance_entry = {"name": "alpha", "meta": "value"}

    _materialise_backup_payload(payload_root, sources, instance_entry)

    assert (payload_root / "metadata" / "instance.json").exists()
    assert any(dest.match("*/data") for _, dest in copies)
    assert any(dest.match("*/systemd/alpha.service") for _, dest in copies)


def test_materialise_backup_payload_handles_optional_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Optional nginx/registry sources should be copied when present."""
    nginx_site = tmp_path / "alpha.conf"
    nginx_site.parent.mkdir(parents=True, exist_ok=True)
    nginx_site.write_text("site", encoding="utf-8")
    nginx_enabled = tmp_path / "alpha-enabled.conf"
    nginx_enabled.write_text("enabled", encoding="utf-8")
    registry_file = tmp_path / "instances.yml"
    registry_file.write_text("instances: []", encoding="utf-8")

    copies: list[tuple[Path, Path]] = []

    def fake_copy(src: Path, dest: Path) -> None:
        copies.append((src, dest))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    monkeypatch.setattr("abssctl.cli.copy_into", fake_copy)

    sources = {
        "data": {"path": str(tmp_path / "missing"), "exists": False},
        "nginx_site": {"path": str(nginx_site), "exists": True},
        "nginx_enabled": {"path": str(nginx_enabled), "exists": True},
        "registry": {"path": str(registry_file), "exists": True},
    }
    payload_root = tmp_path / "payload"

    _materialise_backup_payload(payload_root, sources, {"name": "alpha"})

    assert (payload_root / "data").is_dir()
    assert (payload_root / "metadata" / "instance.json").exists()
    assert any(dest.match("*/nginx/alpha.conf") for _, dest in copies)
    assert any(dest.match("*/nginx-enabled/alpha-enabled.conf") for _, dest in copies)
    assert any(dest.match("*/metadata/instances.yml") for _, dest in copies)
    metadata = json.loads((payload_root / "metadata" / "instance.json").read_text())
    assert metadata["name"] == "alpha"


def test_discover_backup_archives_filters(tmp_path: Path) -> None:
    """Only matching archives under instances should be returned."""
    backup_root = tmp_path / "backups"
    archive_dir = backup_root / "alpha"
    archive_dir.mkdir(parents=True, exist_ok=True)
    (archive_dir / "20240101-alpha.tar.gz").write_text("", encoding="utf-8")
    (archive_dir / "notes.txt").write_text("", encoding="utf-8")
    beta_dir = backup_root / "beta"
    beta_dir.mkdir()
    (beta_dir / "20240102-beta.tar.gz").write_text("", encoding="utf-8")

    archives = _discover_backup_archives(backup_root, instance_filter="alpha")
    assert len(archives) == 1
    assert archives[0].name == "20240101-alpha.tar.gz"


def test_run_instance_backups_creates_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_run_instance_backups should invoke _create_backup for each instance."""
    locks = DummyLocks()
    runtime = SimpleNamespace(locks=locks)
    created: list[str] = []

    def fake_create_backup(
        runtime_arg: object,
        instance: str,
        **kwargs: object,
    ) -> tuple[dict[str, object], dict[str, object]]:
        created.append(instance)
        return {"id": f"{instance}-plan"}, {"id": f"{instance}-backup"}

    monkeypatch.setattr("abssctl.cli._create_backup", fake_create_backup)
    monkeypatch.setattr(
        "abssctl.cli._compose_backup_metadata",
        lambda *args, **kwargs: ("msg", ["label"]),
    )
    monkeypatch.setattr("abssctl.cli.console.print", lambda *args, **kwargs: None)

    with _operation_scope(tmp_path) as op:
        ids = _run_instance_backups(
            runtime,
            ["alpha", "beta"],
            operation="version switch",
            backup_message=None,
            op=op,
        )

    assert ids == ["alpha-backup", "beta-backup"]
    assert created == ["alpha", "beta"]
    assert locks.calls[0][0] == ("alpha",)


def test_run_instance_backups_skips_when_empty(tmp_path: Path) -> None:
    """No instances should result in a skip step."""
    runtime = SimpleNamespace(locks=DummyLocks())
    with _operation_scope(tmp_path) as op:
        ids = _run_instance_backups(
            runtime,
            [],
            operation="op",
            backup_message=None,
            op=op,
        )
    assert ids == []


def test_create_backup_dry_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Dry-run mode should return plan context without appending entries."""
    runtime = SimpleNamespace(
        config=_make_config(tmp_path),
        backups=DummyBackups(tmp_path),
    )
    monkeypatch.setattr(
        "abssctl.cli._require_instance",
        lambda runtime, instance, op: {"name": instance},
    )
    monkeypatch.setattr(
        "abssctl.cli._collect_backup_sources",
        lambda *args, **kwargs: {"data": {"path": str(tmp_path / "data"), "exists": True}},
    )

    with _operation_scope(tmp_path) as op:
        plan, result = _create_backup(
            runtime,
            "alpha",
            message="test",
            labels=["label"],
            data_only=False,
            out_dir=None,
            compression="gzip",
            compression_level=3,
            dry_run=True,
            actor=None,
            op=op,
        )

    assert result is None
    assert plan["status"] == "planned"
    assert runtime.backups.appended == []


def test_create_backup_happy_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful backups should append entries and return result context."""
    runtime = SimpleNamespace(
        config=_make_config(tmp_path),
        backups=DummyBackups(tmp_path),
    )
    monkeypatch.setattr(
        "abssctl.cli._require_instance",
        lambda runtime, instance, op: {"name": instance},
    )
    monkeypatch.setattr(
        "abssctl.cli._collect_backup_sources",
        lambda *args, **kwargs: {"data": {"path": str(tmp_path / "data"), "exists": True}},
    )
    monkeypatch.setattr("abssctl.cli._materialise_backup_payload", lambda *args, **kwargs: None)

    def fake_create_archive(
        source_dir: Path,
        archive_path: Path,
        algorithm: str,
        compression_level: int | None,
    ) -> None:
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        archive_path.write_bytes(b"data")

    monkeypatch.setattr("abssctl.cli._create_archive", fake_create_archive)
    monkeypatch.setattr("abssctl.cli._compute_checksum", lambda path: "checksum")
    monkeypatch.setattr(
        "abssctl.cli._write_checksum_file",
        lambda path, checksum: path.with_suffix(".sha256"),
    )

    with _operation_scope(tmp_path) as op:
        plan, result = _create_backup(
            runtime,
            "alpha",
            message=None,
            labels=[],
            data_only=False,
            out_dir=None,
            compression=None,
            compression_level=None,
            dry_run=False,
            actor=None,
            op=op,
        )

    assert result is not None
    assert result["checksum"] == "checksum"
    assert runtime.backups.appended


def test_create_backup_respects_data_only_and_output_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_create_backup should skip service sources and honour custom out_dir."""
    runtime = SimpleNamespace(
        config=_make_config(tmp_path),
        backups=DummyBackups(tmp_path),
    )
    monkeypatch.setattr(
        "abssctl.cli._require_instance",
        lambda runtime_arg, instance_arg, op: {"name": instance_arg, "meta": "value"},
    )

    captured: dict[str, object] = {}

    def fake_collect(
        runtime_arg: object,
        instance_arg: str,
        include_services: bool,
    ) -> dict[str, object]:
        captured["include_services"] = include_services
        data_dir = tmp_path / "instance-data"
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "file").write_text("payload", encoding="utf-8")
        return {"data": {"path": str(data_dir), "exists": True}}

    monkeypatch.setattr("abssctl.cli._collect_backup_sources", fake_collect)
    monkeypatch.setattr("abssctl.cli._materialise_backup_payload", lambda *args, **kwargs: None)

    def fake_create_archive(
        source_dir: Path,
        archive_path: Path,
        algorithm: str,
        compression_level: int | None,
    ) -> None:
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        archive_path.write_bytes(b"archive")

    monkeypatch.setattr("abssctl.cli._create_archive", fake_create_archive)
    monkeypatch.setattr("abssctl.cli._compute_checksum", lambda path: "abc123")
    monkeypatch.setattr(
        "abssctl.cli._write_checksum_file",
        lambda path, checksum: path.with_suffix(".sha256"),
    )

    out_dir = tmp_path / "custom-out"
    actor = {"user": "tester"}

    with _operation_scope(tmp_path) as op:
        plan, result = _create_backup(
            runtime,
            "alpha",
            message="backup",
            labels=["pre-op"],
            data_only=True,
            out_dir=out_dir,
            compression="none",
            compression_level=None,
            dry_run=False,
            actor=actor,
            op=op,
        )

    assert captured["include_services"] is False
    assert plan["status"] == "created"
    assert plan["checksum"] == "abc123"
    assert result is not None and result["archive"].startswith(str(out_dir))
    assert runtime.backups.appended and runtime.backups.appended[0]["id"] == "alpha-id"


def test_create_archive_invokes_tar_with_gzip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_create_archive should construct gzip tar command with env overrides."""
    archive = tmp_path / "backup.tar.gz"
    called: dict[str, object] = {}

    monkeypatch.setattr("abssctl.cli.shutil.which", lambda cmd: "/usr/bin/tar")

    def fake_run(
        cmd: list[str],
        capture_output: bool,
        text: bool,
        env: dict[str, str],
        check: bool,
    ) -> SimpleNamespace:
        called["cmd"] = cmd
        called["env"] = env
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("abssctl.cli.subprocess.run", fake_run)
    monkeypatch.setattr("abssctl.cli.os.chmod", lambda *args, **kwargs: None)

    source = tmp_path / "payload"
    (source / "data").mkdir(parents=True)
    _create_archive(source, archive, "gzip", 9)

    assert "/usr/bin/tar" in called["cmd"][0]
    assert "-czf" in called["cmd"]
    assert called["env"]["GZIP"] == "-9"


def test_create_archive_raises_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tar failures should raise BackupError with stderr context."""
    monkeypatch.setattr("abssctl.cli.shutil.which", lambda cmd: "/usr/bin/tar")

    def fake_run(*args: object, **kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(returncode=1, stdout="out", stderr="error")

    monkeypatch.setattr("abssctl.cli.subprocess.run", fake_run)

    with pytest.raises(BackupError):
        _create_archive(tmp_path / "payload", tmp_path / "backup.tar", "tar", None)


def test_build_backup_plan_context_serialises_sources(tmp_path: Path) -> None:
    """Plan context should capture algorithm, labels, and sources."""
    context = _build_backup_plan_context(
        "backup-id",
        tmp_path / "archive.tar.gz",
        "gzip",
        5,
        {"data": {"path": "/data", "exists": True}},
        data_only=False,
        message="test",
        labels=["pre-op"],
    )
    assert context["id"] == "backup-id"
    assert context["algorithm"] == "gzip"
    assert context["sources"]["data"]["path"] == "/data"
    assert context["labels"] == ["pre-op"]


def test_latest_backups_by_instance_tracks_newest() -> None:
    """Only the newest entry per instance should be retained."""
    entries = [
        {"instance": "alpha", "created_at": "2024-01-01T00:00:00Z", "status": "ok"},
        {"instance": "alpha", "created_at": "2024-02-01T00:00:00Z", "status": "new"},
        {"instance": "beta", "created_at": "2024-03-01T00:00:00Z", "status": "beta"},
    ]
    latest = _latest_backups_by_instance(entries)
    assert set(latest.keys()) == {"alpha", "beta"}
    assert latest["alpha"]["status"] == "new"


def test_load_backup_instance_snapshot_handles_missing(tmp_path: Path) -> None:
    """Missing snapshot files should return an empty mapping."""
    assert _load_backup_instance_snapshot(tmp_path) == {}

    payload_dir = tmp_path / "payload"
    (payload_dir / "metadata").mkdir(parents=True, exist_ok=True)
    snapshot_path = payload_dir / "metadata" / "instance.json"
    snapshot_path.write_text('{"name": "alpha"}', encoding="utf-8")
    assert _load_backup_instance_snapshot(payload_dir) == {"name": "alpha"}
