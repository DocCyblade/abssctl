"""Support bundle assembly helpers."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import __version__
from . import archive as archive_utils
from .backups import BackupError
from .doctor import DoctorEngine, collect_probes, create_probe_context
from .doctor.utils import serialize_report

if TYPE_CHECKING:
    from .cli import RuntimeContext
    from .logging import OperationScope
else:  # pragma: no cover - typing helper only
    RuntimeContext = object  # type: ignore[misc]
    OperationScope = object  # type: ignore[misc]


DEFAULT_MAX_BUNDLE_BYTES = 50 * 1024 * 1024
DEFAULT_LOG_BYTES = 5 * 1024 * 1024
LOG_PATTERNS = (
    "abssctl.log",
    "abssctl.log.*",
    "operations.jsonl",
    "operations.jsonl.*",
)


class SupportBundleError(RuntimeError):
    """Raised when support bundle creation fails."""


@dataclass(slots=True)
class SupportBundleResult:
    """Result metadata for a support bundle run."""

    path: Path
    checksum: str
    size_bytes: int
    algorithm: str
    redacted: bool
    checksum_file: Path
    manifest: dict[str, Any]
    doctor_report: dict[str, Any]

    def to_payload(self) -> dict[str, Any]:
        """Return a JSON-serialisable payload describing the bundle."""
        return {
            "path": str(self.path),
            "checksum": self.checksum,
            "size_bytes": self.size_bytes,
            "algorithm": self.algorithm,
            "redacted": self.redacted,
            "checksum_file": str(self.checksum_file),
            "manifest": self.manifest,
            "doctor": self.doctor_report,
        }


class SupportBundleBuilder:
    """Coordinator that stages and archives support bundles."""

    def __init__(
        self,
        runtime: RuntimeContext,
        *,
        redacted: bool = True,
        max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES,
        max_log_bytes: int = DEFAULT_LOG_BYTES,
    ) -> None:
        """Initialise builder defaults for the given runtime context."""
        self._runtime = runtime
        self._redacted = redacted
        self._max_bundle_bytes = max_bundle_bytes
        self._max_log_bytes = max_log_bytes
        self._redaction_cache: dict[str, str] | None = None
        self._payload_root: Path | None = None

    # Public API -----------------------------------------------------
    def build(
        self,
        *,
        out_path: Path | None,
        op: OperationScope | None = None,
    ) -> SupportBundleResult:
        """Create a support bundle and return the resulting metadata."""
        self._files: list[dict[str, Any]] = []
        self._applied_redactions: set[str] = set()
        self._staged_bytes = 0

        algorithm = "zstd" if archive_utils.detect_zstd_support() else "gzip"
        archive_path = self._resolve_archive_path(out_path, algorithm)
        archive_dir = archive_path.parent
        archive_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(archive_dir, 0o750)
        except OSError:
            pass

        staging_root = Path(
            tempfile.mkdtemp(prefix=".abssctl-support-", dir=str(archive_dir))
        )
        payload_root = staging_root / "support-bundle"
        payload_root.mkdir(parents=True, exist_ok=True)
        self._payload_root = payload_root

        manifest = self._base_manifest(algorithm)
        doctor_payload: dict[str, Any] | None = None

        try:
            self._collect_config(payload_root, manifest)
            self._log_step(op, "support-bundle.config", payload_root)

            self._collect_registry(payload_root)
            self._log_step(op, "support-bundle.registry", payload_root)

            self._collect_logs(payload_root)
            self._log_step(op, "support-bundle.logs", payload_root)

            doctor_payload = self._capture_doctor_report(payload_root)
            manifest["doctor"] = {
                "summary": doctor_payload["summary"],
                "metadata": doctor_payload.get("metadata", {}),
            }
            self._log_step(op, "support-bundle.doctor", payload_root)

            manifest["files"] = self._files
            manifest["redactions"] = sorted(self._applied_redactions)
            manifest["staged_bytes"] = self._staged_bytes

            manifest_path = payload_root / "manifest.json"
            manifest_text = json.dumps(manifest, indent=2)
            manifest_path.write_text(manifest_text, encoding="utf-8")
            self._register_bytes(manifest_path.stat().st_size)
            self._files.append(
                {
                    "path": "manifest.json",
                    "size_bytes": manifest_path.stat().st_size,
                    "description": "Bundle manifest",
                }
            )

            self._log_step(op, "support-bundle.manifest", manifest_path)

            archive_utils.create_archive(payload_root, archive_path, algorithm, None)
            self._log_step(op, "support-bundle.archive", archive_path)

            checksum = archive_utils.compute_checksum(archive_path)
            checksum_path = archive_utils.write_checksum_file(archive_path, checksum)
            self._log_step(op, "support-bundle.checksum", checksum_path)

            size_bytes = archive_path.stat().st_size
            if size_bytes > self._max_bundle_bytes:
                raise SupportBundleError(
                    "Support bundle exceeds the configured size limit "
                    f"({size_bytes} bytes > {self._max_bundle_bytes}).",
                )

            return SupportBundleResult(
                path=archive_path,
                checksum=checksum,
                size_bytes=size_bytes,
                algorithm=algorithm,
                redacted=self._redacted,
                checksum_file=checksum_path,
                manifest=manifest,
                doctor_report=doctor_payload or {},
            )
        except BackupError as exc:
            # Promote archive errors to support bundle failures for clearer messaging.
            raise SupportBundleError(str(exc)) from exc
        finally:
            shutil.rmtree(staging_root, ignore_errors=True)

    # Internal helpers -----------------------------------------------
    def _base_manifest(self, algorithm: str) -> dict[str, Any]:
        return {
            "schema": 1,
            "generated_at": datetime.now(tz=UTC)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "abssctl_version": __version__,
            "redacted": self._redacted,
            "max_bundle_bytes": self._max_bundle_bytes,
            "max_log_bytes": self._max_log_bytes,
            "algorithm": algorithm,
            "files": [],
            "redactions": [],
            "doctor": {},
        }

    def _log_step(
        self,
        op: OperationScope | None,
        step: str,
        detail: Path,
    ) -> None:
        if op is None:
            return
        op.add_step(step, status="success", detail=str(detail))

    def _resolve_archive_path(self, override: Path | None, algorithm: str) -> Path:
        default_dir = self._runtime.config.logs_dir / "support-bundles"
        timestamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
        extension = archive_utils.compression_extension(algorithm)
        default_name = f"support-bundle-{timestamp}.{extension}"

        if override is None:
            return default_dir / default_name

        candidate = override.expanduser()
        if candidate.exists() and candidate.is_dir():
            return candidate / default_name

        if self._looks_like_archive(candidate):
            return candidate

        return candidate / default_name

    @staticmethod
    def _looks_like_archive(path: Path) -> bool:
        suffixes = "".join(path.suffixes[-2:]) if path.suffixes else path.suffix
        return suffixes in {".tar", ".tar.gz", ".tar.zst"}

    def _register_bytes(self, amount: int) -> None:
        self._staged_bytes += max(amount, 0)
        if self._staged_bytes > self._max_bundle_bytes:
            raise SupportBundleError(
                "Support bundle contents exceed the configured size limit "
                f"({self._staged_bytes} bytes > {self._max_bundle_bytes})."
            )

    def _collect_config(self, payload_root: Path, manifest: dict[str, Any]) -> None:
        config_dir = payload_root / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        config_dict = self._runtime.config.to_dict()
        manifest["config"] = self._redact_value(config_dict)
        summary_path = config_dir / "config-summary.json"
        text = json.dumps(manifest["config"], indent=2, sort_keys=True)
        summary_path.write_text(text, encoding="utf-8")
        self._register_bytes(len(text.encode("utf-8")))
        self._files.append(
            {
                "path": "config/config-summary.json",
                "size_bytes": len(text.encode("utf-8")),
                "description": "Resolved configuration summary",
            }
        )

        config_file = self._runtime.config.config_file
        if config_file.exists():
            dest_name = (
                "config.yml" if not self._redacted else "config.yml.redacted"
            )
            dest_path = config_dir / dest_name
            self._copy_text_file(config_file, dest_path)

    def _collect_registry(self, payload_root: Path) -> None:
        registry_dir = payload_root / "registry"
        registry_dir.mkdir(parents=True, exist_ok=True)
        for name in ("instances.yml", "versions.yml", "ports.yml"):
            source = self._runtime.registry.path_for(name)
            if source.exists():
                self._copy_text_file(source, registry_dir / name)

    def _collect_logs(self, payload_root: Path) -> None:
        logs_dir = payload_root / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        source_dir = self._runtime.config.logs_dir
        for pattern in LOG_PATTERNS:
            for source in sorted(source_dir.glob(pattern)):
                if source.is_file():
                    truncated = self._copy_log_file(source, logs_dir / source.name)
                    self._files.append(
                        {
                            "path": f"logs/{source.name}",
                            "size_bytes": truncated["size_bytes"],
                            "source": str(source),
                            "truncated": truncated["truncated"],
                        }
                    )

    def _capture_doctor_report(self, payload_root: Path) -> dict[str, Any]:
        context = create_probe_context(self._runtime)
        engine = DoctorEngine(context)
        probes = collect_probes(context)
        report = engine.run(
            probes,
            metadata={"source": "support-bundle"},
        )
        payload = serialize_report(report)
        report_path = payload_root / "doctor" / "report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(payload, indent=2)
        report_path.write_text(text, encoding="utf-8")
        self._register_bytes(len(text.encode("utf-8")))
        self._files.append(
            {
                "path": "doctor/report.json",
                "size_bytes": len(text.encode("utf-8")),
                "description": "Doctor JSON report",
            }
        )
        return payload

    def _copy_text_file(self, source: Path, destination: Path) -> None:
        text = source.read_text(encoding="utf-8")
        redacted = self._redact_text(text)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(redacted, encoding="utf-8")
        size_bytes = len(redacted.encode("utf-8"))
        self._register_bytes(size_bytes)
        if self._payload_root is None:
            rel_path = destination.name
        else:
            rel_path = destination.relative_to(self._payload_root).as_posix()
        self._files.append(
            {
                "path": rel_path,
                "size_bytes": size_bytes,
                "source": str(source),
                "redacted": self._redacted,
            }
        )

    def _copy_log_file(self, source: Path, destination: Path) -> dict[str, Any]:
        raw_size = source.stat().st_size
        start = max(0, raw_size - self._max_log_bytes)
        truncated = start > 0
        with source.open("rb") as handle:
            handle.seek(start)
            data = handle.read()
        text = data.decode("utf-8", errors="replace")
        redacted = self._redact_text(text)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(redacted, encoding="utf-8")
        size_bytes = len(redacted.encode("utf-8"))
        self._register_bytes(size_bytes)
        return {"size_bytes": size_bytes, "truncated": truncated}

    def _redact_text(self, text: str) -> str:
        if not self._redacted:
            return text
        result = text
        for value, token in self._get_redaction_map().items():
            if value and value in result:
                result = result.replace(value, token)
                self._applied_redactions.add(token)
        return result

    def _redact_value(self, value: object) -> object:
        if not self._redacted:
            return value
        if isinstance(value, dict):
            return {key: self._redact_value(val) for key, val in value.items()}
        if isinstance(value, list):
            return [self._redact_value(item) for item in value]
        if isinstance(value, str):
            return self._redact_text(value)
        return value

    def _get_redaction_map(self) -> dict[str, str]:
        if not self._redacted:
            return {}
        if self._redaction_cache is not None:
            return self._redaction_cache
        config = self._runtime.config
        replacements = {
            str(config.config_file): "<CONFIG_FILE>",
            str(config.state_dir): "<STATE_DIR>",
            str(config.registry_dir): "<REGISTRY_DIR>",
            str(config.logs_dir): "<LOGS_DIR>",
            str(config.runtime_dir): "<RUNTIME_DIR>",
            str(config.install_root): "<INSTALL_ROOT>",
            str(config.instance_root): "<INSTANCE_ROOT>",
            str(config.templates_dir): "<TEMPLATES_DIR>",
            str(config.backups.root): "<BACKUPS_ROOT>",
            str(config.backups.index): "<BACKUPS_INDEX>",
            str(config.tls.system.cert): "<TLS_SYSTEM_CERT>",
            str(config.tls.system.key): "<TLS_SYSTEM_KEY>",
            str(config.tls.lets_encrypt.live_dir): "<LE_LIVE_DIR>",
        }
        self._redaction_cache = {
            key: value for key, value in replacements.items() if key
        }
        return self._redaction_cache
