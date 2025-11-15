"""Support bundle builder unit tests."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from abssctl import support_bundle as support_bundle_module
from abssctl.backups import BackupError
from abssctl.exit_codes import ExitCode
from abssctl.support_bundle import (
    DEFAULT_LOG_BYTES,
    SupportBundleBuilder,
    SupportBundleError,
)


@dataclass
class _DummyRegistry:
    base: Path

    def path_for(self, name: str) -> Path:
        path = self.base / name
        if not path.exists():
            path.write_text(f"{name}\n", encoding="utf-8")
        return path


class _DummyConfig:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.config_file = root / "abssctl.yml"
        config_contents = "state_dir: {state}\n".format(state=root / "state")
        self.config_file.write_text(config_contents, encoding="utf-8")

        self.logs_dir = root / "logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        (self.logs_dir / "support-bundles").mkdir(parents=True, exist_ok=True)
        (self.logs_dir / "abssctl.log").write_text("log entry", encoding="utf-8")

        self.state_dir = root / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.registry_dir = root / "registry"
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        for name in ("instances.yml", "versions.yml", "ports.yml"):
            (self.registry_dir / name).write_text(f"{name}\n", encoding="utf-8")

        self.runtime_dir = root / "runtime"
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.install_root = root / "install"
        self.install_root.mkdir(parents=True, exist_ok=True)
        self.instance_root = root / "instances"
        self.instance_root.mkdir(parents=True, exist_ok=True)
        self.templates_dir = root / "templates"
        self.templates_dir.mkdir(parents=True, exist_ok=True)

        backups_root = root / "backups"
        backups_root.mkdir(parents=True, exist_ok=True)
        backups_index = backups_root / "backups.json"
        backups_index.write_text("{}", encoding="utf-8")
        self.backups = SimpleNamespace(root=backups_root, index=backups_index)

        tls_root = root / "tls"
        tls_root.mkdir(parents=True, exist_ok=True)
        cert = tls_root / "cert.pem"
        cert.write_text("cert", encoding="utf-8")
        key = tls_root / "key.pem"
        key.write_text("key", encoding="utf-8")
        le_live = tls_root / "live"
        le_live.mkdir(parents=True, exist_ok=True)
        self.tls = SimpleNamespace(
            system=SimpleNamespace(cert=cert, key=key),
            lets_encrypt=SimpleNamespace(live_dir=le_live),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "state_dir": str(self.state_dir),
            "registry_dir": str(self.registry_dir),
            "logs_dir": str(self.logs_dir),
            "install_root": str(self.install_root),
            "instance_root": str(self.instance_root),
            "templates_dir": str(self.templates_dir),
            "tls": {
                "system": {
                    "cert": str(self.tls.system.cert),
                    "key": str(self.tls.system.key),
                },
                "lets_encrypt": {"live_dir": str(self.tls.lets_encrypt.live_dir)},
            },
        }


def _make_runtime(tmp_path: Path) -> SimpleNamespace:
    config = _DummyConfig(tmp_path)
    registry = _DummyRegistry(config.registry_dir)
    return SimpleNamespace(config=config, registry=registry)


def _patch_archive(
    monkeypatch: pytest.MonkeyPatch,
    *,
    detect_zstd: bool,
    archive_contents: str | None = None,
) -> None:
    monkeypatch.setattr(
        "abssctl.support_bundle.archive_utils.detect_zstd_support",
        lambda: detect_zstd,
    )

    def fake_create_archive(
        source_dir: Path,
        archive_path: Path,
        algorithm: str,
        compression_level: int | None,
    ) -> None:
        payload = archive_contents
        if payload is None:
            payload = f"{algorithm}:{source_dir}"
        archive_path.write_text(payload, encoding="utf-8")

    monkeypatch.setattr(
        "abssctl.support_bundle.archive_utils.create_archive",
        fake_create_archive,
    )
    monkeypatch.setattr(
        "abssctl.support_bundle.archive_utils.compute_checksum",
        lambda path: "checksum",
    )
    monkeypatch.setattr(
        "abssctl.support_bundle.archive_utils.write_checksum_file",
        lambda archive_path, checksum: archive_path.with_name(f"{archive_path.name}.sha256"),
    )


def _prepare_builder(
    tmp_path: Path,
    *,
    redacted: bool = True,
    max_log_bytes: int = DEFAULT_LOG_BYTES,
) -> tuple[SupportBundleBuilder, Path]:
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime, redacted=redacted, max_log_bytes=max_log_bytes)
    payload_root = tmp_path / "payload"
    payload_root.mkdir(parents=True, exist_ok=True)
    builder._payload_root = payload_root  # type: ignore[attr-defined]
    builder._files = []  # type: ignore[attr-defined]
    builder._applied_redactions = set()  # type: ignore[attr-defined]
    builder._staged_bytes = 0  # type: ignore[attr-defined]
    return builder, payload_root


def _patch_doctor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "abssctl.support_bundle.create_probe_context",
        lambda runtime: {"runtime": str(runtime.config.config_file)},
    )
    monkeypatch.setattr(
        "abssctl.support_bundle.collect_probes",
        lambda context: ["probe"],
    )

    class DummyEngine:
        def __init__(self, context: object) -> None:
            self.context = context

        def run(self, probes: list[str], metadata: dict[str, object]) -> dict[str, object]:
            return {"context": self.context, "probes": probes, "metadata": metadata}

    monkeypatch.setattr("abssctl.support_bundle.DoctorEngine", DummyEngine)
    monkeypatch.setattr(
        "abssctl.support_bundle.serialize_report",
        lambda report: {
            "summary": {"status": "green"},
            "metadata": {"source": "unit-test"},
            "results": [],
        },
    )


def test_support_bundle_builder_reports_manifest_and_redactions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Builder should honour zstd support, manifest entries, and redactions."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime, redacted=True)
    _patch_archive(monkeypatch, detect_zstd=True)
    _patch_doctor(monkeypatch)

    result = builder.build(out_path=None)

    assert result.algorithm == "zstd"
    assert result.path.name.endswith(".tar.zst")
    assert result.manifest["algorithm"] == "zstd"
    file_paths = {entry["path"] for entry in result.manifest["files"]}
    assert {
        "config/config-summary.json",
        "registry/instances.yml",
        "registry/versions.yml",
        "registry/ports.yml",
        "logs/abssctl.log",
        "doctor/report.json",
        "manifest.json",
    }.issubset(file_paths)
    assert result.manifest["doctor"]["summary"]["status"] == "green"
    assert "<STATE_DIR>" in result.manifest["redactions"]
    assert result.manifest["config"]["state_dir"] == "<STATE_DIR>"


def test_support_bundle_base_manifest_shape(tmp_path: Path) -> None:
    """Base manifest should contain canonical keys with sensible defaults."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)

    manifest = builder._base_manifest("gzip")  # type: ignore[attr-defined]

    expected_keys = {
        "schema",
        "generated_at",
        "abssctl_version",
        "redacted",
        "max_bundle_bytes",
        "max_log_bytes",
        "algorithm",
        "files",
        "redactions",
        "doctor",
    }
    assert set(manifest.keys()) == expected_keys
    assert manifest["schema"] == 1
    assert manifest["algorithm"] == "gzip"
    assert manifest["files"] == []
    assert manifest["redactions"] == []
    assert manifest["doctor"] == {}
    assert manifest["generated_at"].endswith("Z")


def test_support_bundle_builder_enforces_staged_bytes_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Builder should raise SupportBundleError when staged bytes exceed the cap."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(
        runtime,
        redacted=False,
        max_bundle_bytes=1,
        max_log_bytes=1,
    )
    _patch_archive(monkeypatch, detect_zstd=False)
    _patch_doctor(monkeypatch)

    with pytest.raises(SupportBundleError) as excinfo:
        builder.build(out_path=None)

    assert excinfo.value.exit_code is ExitCode.ENVIRONMENT
    assert "size limit" in str(excinfo.value).lower()


def test_support_bundle_builder_flags_large_archive_after_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Archive size checks should run after tar creation and checksum."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(
        runtime,
        redacted=True,
        max_bundle_bytes=10**6,
        max_log_bytes=1024,
    )
    _patch_archive(monkeypatch, detect_zstd=False, archive_contents="X" * (1024 * 2))
    _patch_doctor(monkeypatch)

    def fake_checksum(path: Path) -> str:
        builder._max_bundle_bytes = 64  # tighten limit after staging completes
        return "abc123"

    monkeypatch.setattr("abssctl.support_bundle.archive_utils.compute_checksum", fake_checksum)

    with pytest.raises(SupportBundleError) as excinfo:
        builder.build(out_path=None)

    assert excinfo.value.exit_code is ExitCode.ENVIRONMENT
    assert "size limit" in str(excinfo.value).lower()


def test_resolve_archive_path_handles_default_and_overrides(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_resolve_archive_path should adapt to default, directories, and file targets."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz: object | None = None) -> datetime:
            return cls(2024, 1, 2, 3, 4, 5, tzinfo=tz)

    monkeypatch.setattr("abssctl.support_bundle.datetime", FixedDatetime)

    default_path = builder._resolve_archive_path(None, "gzip")
    expected_name = "support-bundle-20240102-030405.tar.gz"
    assert default_path.parent == runtime.config.logs_dir / "support-bundles"
    assert default_path.name == expected_name

    override_dir = tmp_path / "dest"
    override_dir.mkdir()
    dir_path = builder._resolve_archive_path(override_dir, "gzip")
    assert dir_path.parent == override_dir
    assert dir_path.name == expected_name

    explicit_file = tmp_path / "custom-bundle.tar.zst"
    file_path = builder._resolve_archive_path(explicit_file, "zstd")
    assert file_path == explicit_file

    implicit_dir = tmp_path / "custom"
    implicit_path = builder._resolve_archive_path(implicit_dir, "gzip")
    assert implicit_path.parent == implicit_dir
    assert implicit_path.name == expected_name


def test_support_bundle_builder_initialises_attributes(tmp_path: Path) -> None:
    """__init__ should persist runtime, redaction flag, and limits."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime, redacted=False, max_bundle_bytes=123, max_log_bytes=456)

    assert builder._runtime is runtime  # type: ignore[attr-defined]
    assert builder._redacted is False  # type: ignore[attr-defined]
    assert builder._max_bundle_bytes == 123  # type: ignore[attr-defined]
    assert builder._max_log_bytes == 456  # type: ignore[attr-defined]


def test_support_bundle_builder_defaults(tmp_path: Path) -> None:
    """Default constructor should enable redaction and unset payload root."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)

    assert builder._redacted is True  # type: ignore[attr-defined]
    assert builder._payload_root is None  # type: ignore[attr-defined]


def test_support_bundle_builder_falls_back_to_gzip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When zstd is unavailable the builder should use gzip archives."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime, redacted=True)
    _patch_archive(monkeypatch, detect_zstd=False)
    _patch_doctor(monkeypatch)

    result = builder.build(out_path=None)

    assert result.algorithm == "gzip"
    assert result.path.name.endswith(".tar.gz")


def test_support_bundle_resolve_archive_path_uses_utc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default archive naming should call datetime.now with UTC."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz: object | None = None) -> datetime:
            assert tz == support_bundle_module.UTC
            return cls(2024, 2, 3, 4, 5, 6, tzinfo=support_bundle_module.UTC)

    monkeypatch.setattr("abssctl.support_bundle.datetime", FixedDatetime)
    path = builder._resolve_archive_path(None, "gzip")  # type: ignore[attr-defined]
    assert "20240203-040506" in path.name


def test_support_bundle_resolve_archive_path_accepts_directory_override(tmp_path: Path) -> None:
    """Explicit directory overrides should suffix the generated filename."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)
    override_dir = tmp_path / "override"
    override_dir.mkdir()

    path = builder._resolve_archive_path(override_dir, "gzip")  # type: ignore[attr-defined]

    assert path.parent == override_dir
    assert path.name.startswith("support-bundle-")


def test_support_bundle_classifies_archive_errors(tmp_path: Path) -> None:
    """_classify_archive_error should distinguish env vs provider exits."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)

    env_exc = builder._classify_archive_error(BackupError("tar is required for zstd"))  # type: ignore[attr-defined]
    provider_exc = builder._classify_archive_error(BackupError("permission denied"))  # type: ignore[attr-defined]

    assert env_exc is ExitCode.ENVIRONMENT
    assert provider_exc is ExitCode.PROVIDER


def test_support_bundle_collect_logs_marks_truncation(tmp_path: Path) -> None:
    """Log collection should record truncation metadata."""
    builder, payload_root = _prepare_builder(tmp_path, max_log_bytes=4)
    log_path = builder._runtime.config.logs_dir / "abssctl.log"  # type: ignore[attr-defined]
    log_path.write_text("abcdefgh", encoding="utf-8")

    builder._collect_logs(payload_root)  # type: ignore[attr-defined]

    entry = next(item for item in builder._files if item["path"] == "logs/abssctl.log")  # type: ignore[attr-defined]
    assert entry["truncated"] is True
    assert entry["size_bytes"] == len("efgh")
    assert entry["source"].endswith("abssctl.log")
    assert entry["truncated"] is True


def test_support_bundle_collect_logs_handles_missing_logs(tmp_path: Path) -> None:
    """collect_logs should succeed even when no log files are present."""
    builder, payload_root = _prepare_builder(tmp_path)
    builder._runtime.config.logs_dir = tmp_path / "logs"  # type: ignore[attr-defined]
    builder._runtime.config.logs_dir.mkdir(parents=True, exist_ok=True)  # type: ignore[attr-defined]
    for pattern in builder._runtime.config.logs_dir.glob("abssctl.log*"):  # type: ignore[attr-defined]
        pattern.unlink()

    builder._collect_logs(payload_root)  # type: ignore[attr-defined]

    assert not any(
        item["path"].startswith("logs/")
        for item in builder._files  # type: ignore[attr-defined]
    )
def test_support_bundle_copy_text_file_tracks_files(tmp_path: Path) -> None:
    """copy_text_file should register byte counts and relative paths."""
    builder, payload_root = _prepare_builder(tmp_path, redacted=False)
    source = tmp_path / "source.txt"
    source.write_text("payload", encoding="utf-8")
    destination = payload_root / "config" / "source.txt"

    builder._copy_text_file(source, destination)  # type: ignore[attr-defined]

    entry = builder._files[-1]  # type: ignore[attr-defined]
    assert entry["path"] == "config/source.txt"
    assert entry["size_bytes"] == len(b"payload")


def test_support_bundle_builder_handles_archive_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BackupError raised during archive creation should be wrapped."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)
    _patch_doctor(monkeypatch)

    monkeypatch.setattr("abssctl.support_bundle.archive_utils.detect_zstd_support", lambda: False)

    def boom(*_args: object, **_kwargs: object) -> None:
        raise BackupError("tar is required to create archives")

    monkeypatch.setattr("abssctl.support_bundle.archive_utils.create_archive", boom)
    monkeypatch.setattr(
        "abssctl.support_bundle.archive_utils.compute_checksum",
        lambda _path: "deadbeef",
    )
    monkeypatch.setattr(
        "abssctl.support_bundle.archive_utils.write_checksum_file",
        lambda archive_path, checksum: archive_path.with_name(f"{archive_path.name}.sha256"),
    )

    with pytest.raises(SupportBundleError) as excinfo:
        builder.build(out_path=None)

    assert excinfo.value.exit_code is ExitCode.ENVIRONMENT


def test_support_bundle_build_respects_out_path_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit out_path should be honoured."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)
    _patch_archive(monkeypatch, detect_zstd=False)
    _patch_doctor(monkeypatch)
    override = tmp_path / "custom" / "bundle.tar.gz"

    result = builder.build(out_path=override)

    assert result.path == override


def test_support_bundle_build_includes_doctor_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full build should populate manifest doctor summary/metadata."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)
    _patch_archive(monkeypatch, detect_zstd=False)
    _patch_doctor(monkeypatch)

    result = builder.build(out_path=None)

    doctor_manifest = result.manifest["doctor"]
    assert doctor_manifest["summary"]["status"] == "green"
    assert doctor_manifest["metadata"]["source"] == "unit-test"


def test_support_bundle_register_bytes_starts_from_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_register_bytes should start counting from zero for each build."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)
    _patch_archive(monkeypatch, detect_zstd=False)
    _patch_doctor(monkeypatch)

    original_register = SupportBundleBuilder._register_bytes
    seen: list[int] = []

    def tracking(self: SupportBundleBuilder, amount: int) -> None:
        seen.append(self._staged_bytes)  # type: ignore[attr-defined]
        return original_register(self, amount)

    monkeypatch.setattr(SupportBundleBuilder, "_register_bytes", tracking)

    builder.build(out_path=None)

    assert seen
    assert seen[0] == 0


def test_support_bundle_register_bytes_ignores_negative_values(tmp_path: Path) -> None:
    """Negative byte deltas should not reduce staged bytes."""
    builder = SupportBundleBuilder(_make_runtime(tmp_path), max_bundle_bytes=100)
    builder._staged_bytes = 50  # type: ignore[attr-defined]

    builder._register_bytes(-25)  # type: ignore[attr-defined]
    builder._register_bytes(0)  # type: ignore[attr-defined]

    assert builder._staged_bytes == 50  # type: ignore[attr-defined]


def test_support_bundle_register_bytes_allows_exact_limit(tmp_path: Path) -> None:
    """Staged bytes may equal the limit without raising."""
    builder = SupportBundleBuilder(_make_runtime(tmp_path), max_bundle_bytes=10)
    builder._staged_bytes = 0  # type: ignore[attr-defined]
    builder._register_bytes(4)  # type: ignore[attr-defined]
    builder._register_bytes(6)  # type: ignore[attr-defined]

    assert builder._staged_bytes == 10  # type: ignore[attr-defined]


def test_support_bundle_build_records_expected_steps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Structured logging steps should use the canonical identifiers."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)
    _patch_archive(monkeypatch, detect_zstd=False)
    _patch_doctor(monkeypatch)

    class DummyOp:
        def __init__(self) -> None:
            self.steps: list[tuple[str, str, str]] = []

        def add_step(self, name: str, *, status: str, detail: Path) -> None:
            self.steps.append((name, status, detail))

    op = DummyOp()
    builder.build(out_path=None, op=op)

    expected = [
        "support-bundle.config",
        "support-bundle.registry",
        "support-bundle.logs",
        "support-bundle.doctor",
        "support-bundle.manifest",
        "support-bundle.archive",
        "support-bundle.checksum",
    ]
    assert [name for name, _, _ in op.steps] == expected
    assert all(status == "success" for _, status, _ in op.steps)
    assert all(detail != "None" for _, _, detail in op.steps)


def test_support_bundle_log_step_handles_none_op(tmp_path: Path) -> None:
    """_log_step should no-op when operation scope is None."""
    builder = SupportBundleBuilder(_make_runtime(tmp_path))
    builder._log_step(None, "demo", Path("/tmp/demo"))


def test_support_bundle_log_step_records_success_and_detail(tmp_path: Path) -> None:
    """_log_step should record success status with the provided detail."""
    builder = SupportBundleBuilder(_make_runtime(tmp_path))

    class DummyOp:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def add_step(self, name: str, *, status: str, detail: str) -> None:
            self.calls.append((status, detail))

    op = DummyOp()
    target = Path("/tmp/demo-detail")
    builder._log_step(op, "demo", target)

    assert op.calls == [("success", str(target))]


def test_support_bundle_archive_dir_created_with_parents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Archive directory creation should always use parents=True."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)
    target_dir = runtime.config.logs_dir / "support-bundles"
    _patch_archive(monkeypatch, detect_zstd=False)
    _patch_doctor(monkeypatch)

    original_mkdir = Path.mkdir
    calls: list[tuple[Path, dict[str, object]]] = []

    def tracking_mkdir(self: Path, *args: object, **kwargs: object) -> None:
        calls.append((self, dict(kwargs)))
        return original_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", tracking_mkdir)
    chmod_calls: list[tuple[Path, int]] = []

    def tracking_chmod(path: Path, mode: int) -> None:
        chmod_calls.append((path, mode))

    monkeypatch.setattr("abssctl.support_bundle.os.chmod", tracking_chmod)

    builder.build(out_path=None)

    archive_call = next((kw for path, kw in calls if path == target_dir), None)
    assert archive_call is not None
    assert archive_call.get("parents") is True
    assert archive_call.get("exist_ok") is True
    assert any(path == target_dir and mode == 0o750 for path, mode in chmod_calls)


def test_support_bundle_staging_dir_created_with_expected_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tempfile.mkdtemp should be invoked with deterministic prefix and dir."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)
    _patch_archive(monkeypatch, detect_zstd=False)
    _patch_doctor(monkeypatch)

    archive_dir = runtime.config.logs_dir / "support-bundles"

    def fake_mkdtemp(*, prefix: str | None, dir: str | None) -> str:
        assert prefix == ".abssctl-support-"
        assert dir == str(archive_dir)
        staging = Path(dir) / f"{prefix}test"
        staging.mkdir(parents=True, exist_ok=True)
        return str(staging)

    monkeypatch.setattr("abssctl.support_bundle.tempfile.mkdtemp", fake_mkdtemp)

    builder.build(out_path=None)

    assert builder._payload_root is not None  # type: ignore[attr-defined]
    assert (
        builder._payload_root.parent.parent == archive_dir
    )  # type: ignore[attr-defined]
    assert builder._payload_root.name == "support-bundle"  # type: ignore[attr-defined]


def test_support_bundle_payload_root_mkdir_uses_parents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Payload root mkdir should always run with parents/exist_ok."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime)
    _patch_archive(monkeypatch, detect_zstd=False)
    _patch_doctor(monkeypatch)

    original_mkdir = Path.mkdir
    calls: list[tuple[Path, dict[str, object]]] = []

    def tracking_mkdir(self: Path, *args: object, **kwargs: object) -> None:
        calls.append((self, dict(kwargs)))
        return original_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", tracking_mkdir)

    builder.build(out_path=None)

    payload_call = next(
        (
            kw
            for path, kw in calls
            if path.name == "support-bundle" and "support-bundles" in str(path.parent)
        ),
        None,
    )
    assert payload_call is not None
    assert payload_call.get("parents") is True
    assert payload_call.get("exist_ok") is True


def test_support_bundle_collect_config_writes_summary(tmp_path: Path) -> None:
    """_collect_config should emit redacted config summary and track bytes."""
    builder, payload_root = _prepare_builder(tmp_path)
    manifest = builder._base_manifest("gzip")  # type: ignore[attr-defined]

    builder._collect_config(payload_root, manifest)  # type: ignore[attr-defined]

    summary_path = payload_root / "config" / "config-summary.json"
    assert summary_path.exists()
    assert manifest["config"]["state_dir"] == "<STATE_DIR>"
    entry = next(item for item in builder._files if item["path"] == "config/config-summary.json")  # type: ignore[attr-defined]
    assert entry["description"] == "Resolved configuration summary"
    assert "size_bytes" in entry


def test_support_bundle_collect_config_populates_manifest(tmp_path: Path) -> None:
    """_collect_config should append manifest entries and config metadata."""
    builder, payload_root = _prepare_builder(tmp_path)
    manifest = builder._base_manifest("gzip")  # type: ignore[attr-defined]

    builder._collect_config(payload_root, manifest)  # type: ignore[attr-defined]

    assert "config" in manifest
    assert manifest["config"]["logs_dir"] == "<LOGS_DIR>"
    file_paths = [item["path"] for item in builder._files]  # type: ignore[attr-defined]
    assert "config/config-summary.json" in file_paths
    assert "config/config.yml.redacted" in file_paths
    assert all("size_bytes" in item for item in builder._files)  # type: ignore[attr-defined]


def test_support_bundle_collect_config_handles_missing_config_file(tmp_path: Path) -> None:
    """When config file is absent, only the summary should be written."""
    builder, payload_root = _prepare_builder(tmp_path)
    manifest = builder._base_manifest("gzip")  # type: ignore[attr-defined]
    builder._runtime.config.config_file.unlink(missing_ok=True)  # type: ignore[attr-defined]

    builder._collect_config(payload_root, manifest)  # type: ignore[attr-defined]

    file_paths = [entry["path"] for entry in builder._files]  # type: ignore[attr-defined]
    assert file_paths == ["config/config-summary.json"]


def test_support_bundle_get_redaction_map_cached(tmp_path: Path) -> None:
    """_get_redaction_map should cache and return stable mappings."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime, redacted=True)

    first = builder._get_redaction_map()  # type: ignore[attr-defined]
    second = builder._get_redaction_map()  # type: ignore[attr-defined]

    assert first is second
    assert "<STATE_DIR>" in first.values()


def test_support_bundle_collect_registry_copies_known_files(tmp_path: Path) -> None:
    """Registry collection should copy known metadata files into payload."""
    builder, payload_root = _prepare_builder(tmp_path)
    builder._collect_registry(payload_root)  # type: ignore[attr-defined]

    entries = {item["path"] for item in builder._files}  # type: ignore[attr-defined]
    expected = {"registry/instances.yml", "registry/versions.yml", "registry/ports.yml"}
    assert expected.issubset(entries)
    manifest_paths = [
        item["path"]
        for item in builder._files  # type: ignore[attr-defined]
        if item["path"].startswith("registry/")
    ]
    assert manifest_paths == [
        "registry/instances.yml",
        "registry/versions.yml",
        "registry/ports.yml",
    ]


def test_support_bundle_register_bytes_enforces_limit(tmp_path: Path) -> None:
    """_register_bytes should raise SupportBundleError when exceeding cap."""
    runtime = _make_runtime(tmp_path)
    builder = SupportBundleBuilder(runtime, max_bundle_bytes=16)
    builder._staged_bytes = 10  # type: ignore[attr-defined]

    with pytest.raises(SupportBundleError) as excinfo:
        builder._register_bytes(10)  # type: ignore[attr-defined]

    assert "Support bundle contents exceed the configured size limit" in str(excinfo.value)
