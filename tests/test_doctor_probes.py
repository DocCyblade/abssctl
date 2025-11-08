"""Unit tests covering individual doctor probes."""

from __future__ import annotations

from collections import namedtuple
from datetime import UTC
from pathlib import Path
from types import SimpleNamespace
from typing import Never

import pytest

from abssctl.bootstrap.discovery import DiscoveredInstance, DiscoveryReport
from abssctl.doctor import (
    DoctorImpact,
    ProbeContext,
    ProbeExecutorOptions,
    ProbeStatus,
    collect_probes,
)
from abssctl.doctor import probes as doctor_probes
from abssctl.node_compat import ActualVersionSpec, NodeCompatibilityMatrix, NodeVersionSpec
from abssctl.node_runtime import NodeVersionInfo
from abssctl.ports import PortsRegistryError
from abssctl.providers.instance_status_provider import InstanceStatus
from abssctl.providers.nginx import NginxError
from abssctl.providers.systemd import SystemdError
from abssctl.tls import TLSConfigurationError, TLSValidationSeverity

_SENTINEL = object()


class DummyRegistry:
    """Minimal registry stub returning pre-seeded entries."""

    def __init__(self, instances: list[dict[str, object]]) -> None:
        """Initialise the registry stub with saved instance entries."""
        self._instances = instances

    def read_instances(self) -> dict[str, object]:
        """Return registry content shaped like the real implementation."""
        return {"instances": list(self._instances)}


class DummyNodeRuntime:
    """Simple stub that returns a fixed Node version for probes."""

    def __init__(self, version: str | None = "18.18.0") -> None:
        """Record the version string to emit."""
        self._version = version

    def detect_version(self) -> NodeVersionInfo | None:
        """Return a synthetic NodeVersionInfo for tests."""
        if self._version is None:
            return None
        parts = [int(part) for part in self._version.split(".")]
        while len(parts) < 3:
            parts.append(0)
        return NodeVersionInfo(
            raw=f"v{self._version}",
            version=self._version,
            major=parts[0],
            minor=parts[1],
            patch=parts[2],
        )


def _compat_matrix(node_versions: list[NodeVersionSpec]) -> NodeCompatibilityMatrix:
    """Return a minimal compatibility matrix for tests."""
    return NodeCompatibilityMatrix(
        schema_version=1,
        generated_at=None,
        package=None,
        source=None,
        limit=None,
        node_versions=tuple(node_versions),
        actual_versions=tuple(
            [
                ActualVersionSpec(
                    version="0.0.0",
                    release_date=None,
                    node_constraint=None,
                    node_major=None,
                    status="untested",
                    tested_at=None,
                    notes=None,
                    npm_dist_tags=(),
                )
            ]
        ),
        path=None,
    )


def _build_context(
    *,
    config: object | None = None,
    registry: DummyRegistry | None = None,
    ports: object | None = None,
    version_provider: object | None = None,
    version_installer: object | None = None,
    instance_status_provider: object | None = None,
    locks: object | None = None,
    logger: object | None = None,
    templates: object | None = None,
    systemd_provider: object | None = None,
    nginx_provider: object | None = None,
    backups: object | None = None,
    tls_inspector: object | None = None,
    tls_validator: object | None = None,
    options: ProbeExecutorOptions | None = None,
    node_runtime: object | None = None,
    node_compat: object | None = None,
) -> ProbeContext:
    """Return a ProbeContext populated with defaults and overrides."""
    return ProbeContext(
        config=config or SimpleNamespace(),
        registry=registry or DummyRegistry([]),
        ports=ports or _SENTINEL,
        version_provider=version_provider or _SENTINEL,
        version_installer=version_installer or _SENTINEL,
        instance_status_provider=instance_status_provider or _SENTINEL,
        locks=locks or _SENTINEL,
        logger=logger or _SENTINEL,
        templates=templates or _SENTINEL,
        systemd_provider=systemd_provider or _SENTINEL,
        nginx_provider=nginx_provider or _SENTINEL,
        backups=backups or _SENTINEL,
        tls_inspector=tls_inspector or _SENTINEL,
        tls_validator=tls_validator or _SENTINEL,
        options=options or ProbeExecutorOptions(),
        node_runtime=node_runtime or _SENTINEL,
        node_compat=node_compat,
    )


def _discovered_instance(
    tmp_path: Path,
    name: str,
    *,
    warnings: list[str] | None = None,
) -> DiscoveredInstance:
    """Return a discovery record rooted under the tmp_path."""
    root = tmp_path / "instances" / name
    data_dir = root / "data"
    config_path = data_dir / "config.json"
    return DiscoveredInstance(
        name=name,
        root=root,
        data_dir=data_dir,
        config_path=config_path,
        warnings=warnings or [],
    )


# ---------------------------------------------------------------------------
# State reconciliation
# ---------------------------------------------------------------------------


def test_probe_state_reconcile_reports_discovery_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Discovery errors should downgrade the probe to a validation failure."""
    report = DiscoveryReport(errors=["missing root"])
    monkeypatch.setattr(doctor_probes, "discover_instances", lambda *args, **kwargs: report)

    config = SimpleNamespace(
        instance_root=tmp_path / "instances",
        runtime_dir=tmp_path / "run",
        logs_dir=tmp_path / "logs",
        state_dir=tmp_path / "state",
    )
    context = _build_context(config=config, registry=DummyRegistry([]))

    result = doctor_probes._probe_state_reconcile(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.VALIDATION
    assert result.warnings == tuple(report.errors)
    assert result.data is None


def test_probe_state_reconcile_highlights_registry_mismatches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Filesystem/register discrepancies should be surfaced with detailed payload."""

    def _instance(name: str) -> DiscoveredInstance:
        root = tmp_path / "instances" / name
        data_dir = root / "data"
        config_path = data_dir / "config.json"
        return DiscoveredInstance(name=name, root=root, data_dir=data_dir, config_path=config_path)

    report = DiscoveryReport(instances=[_instance("alpha"), _instance("gamma")])
    monkeypatch.setattr(doctor_probes, "discover_instances", lambda *args, **kwargs: report)

    registry = DummyRegistry([{"name": "alpha"}, {"name": "beta"}])
    config = SimpleNamespace(
        instance_root=tmp_path / "instances",
        runtime_dir=tmp_path / "run",
        logs_dir=tmp_path / "logs",
        state_dir=tmp_path / "state",
    )
    context = _build_context(config=config, registry=registry)

    result = doctor_probes._probe_state_reconcile(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.VALIDATION
    assert result.data == {
        "discovered_only": ["gamma"],
        "registry_only": ["beta"],
    }
    assert "filesystem instances not registered: gamma" in result.message
    assert "registry entries missing on disk: beta" in result.message


def test_probe_state_reconcile_reports_filesystem_only_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Filesystem additions with missing registry entries should be reported."""
    report = DiscoveryReport(
        instances=[
            _discovered_instance(tmp_path, "alpha"),
            _discovered_instance(tmp_path, "beta"),
        ]
    )
    monkeypatch.setattr(doctor_probes, "discover_instances", lambda *args, **kwargs: report)
    registry = DummyRegistry([{"name": "alpha"}])
    config = SimpleNamespace(
        instance_root=tmp_path / "instances",
        runtime_dir=tmp_path / "run",
        logs_dir=tmp_path / "logs",
        state_dir=tmp_path / "state",
    )
    context = _build_context(config=config, registry=registry)

    result = doctor_probes._probe_state_reconcile(context)
    assert result.status is ProbeStatus.RED
    assert result.data == {"discovered_only": ["beta"]}
    assert "filesystem instances not registered: beta" in result.message
    assert "registry entries missing on disk" not in result.message


def test_probe_state_reconcile_reports_registry_only_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Registry entries missing on disk should be highlighted independently."""
    report = DiscoveryReport(instances=[_discovered_instance(tmp_path, "alpha")])
    monkeypatch.setattr(doctor_probes, "discover_instances", lambda *args, **kwargs: report)
    registry = DummyRegistry([{"name": "alpha"}, {"name": "beta"}])
    config = SimpleNamespace(
        instance_root=tmp_path / "instances",
        runtime_dir=tmp_path / "run",
        logs_dir=tmp_path / "logs",
        state_dir=tmp_path / "state",
    )
    context = _build_context(config=config, registry=registry)

    result = doctor_probes._probe_state_reconcile(context)
    assert result.status is ProbeStatus.RED
    assert result.data == {"registry_only": ["beta"]}
    assert "registry entries missing on disk: beta" in result.message
    assert "filesystem instances not registered" not in result.message


def test_probe_state_reconcile_handles_discovery_warnings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Warnings from discovery should downgrade the probe without failing."""
    alpha = DiscoveredInstance(
        name="alpha",
        root=tmp_path / "instances" / "alpha",
        data_dir=tmp_path / "instances" / "alpha" / "data",
        config_path=tmp_path / "instances" / "alpha" / "data" / "config.json",
        warnings=["config.json missing"],
    )
    report = DiscoveryReport(instances=[alpha], warnings=["No instances discovered under ..."])
    monkeypatch.setattr(doctor_probes, "discover_instances", lambda *args, **kwargs: report)

    registry = DummyRegistry([{"name": "alpha"}])
    config = SimpleNamespace(
        instance_root=tmp_path / "instances",
        runtime_dir=tmp_path / "run",
        logs_dir=tmp_path / "logs",
        state_dir=tmp_path / "state",
    )
    context = _build_context(config=config, registry=registry)

    result = doctor_probes._probe_state_reconcile(context)
    assert result.status is ProbeStatus.YELLOW
    assert result.impact is DoctorImpact.OK
    assert result.warnings == tuple(report.warnings)
    assert result.data == {
        "instance_warnings": {"alpha": ["config.json missing"]},
    }


def test_probe_state_reconcile_warns_on_instance_only_warnings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Instance-level warnings without global warnings should still downgrade."""
    report = DiscoveryReport(
        instances=[
            _discovered_instance(tmp_path, "alpha", warnings=["config missing"]),
        ]
    )
    monkeypatch.setattr(doctor_probes, "discover_instances", lambda *args, **kwargs: report)
    registry = DummyRegistry([{"name": "alpha"}])
    config = SimpleNamespace(
        instance_root=tmp_path / "instances",
        runtime_dir=tmp_path / "run",
        logs_dir=tmp_path / "logs",
        state_dir=tmp_path / "state",
    )
    context = _build_context(config=config, registry=registry)

    result = doctor_probes._probe_state_reconcile(context)
    assert result.status is ProbeStatus.YELLOW
    assert result.warnings == ()
    assert result.data == {"instance_warnings": {"alpha": ["config missing"]}}


def test_probe_state_reconcile_green_when_registry_matches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A clean discovery should produce a green result."""
    alpha = DiscoveredInstance(
        name="alpha",
        root=tmp_path / "instances" / "alpha",
        data_dir=tmp_path / "instances" / "alpha" / "data",
        config_path=tmp_path / "instances" / "alpha" / "data" / "config.json",
    )
    report = DiscoveryReport(instances=[alpha])
    monkeypatch.setattr(doctor_probes, "discover_instances", lambda *args, **kwargs: report)

    registry = DummyRegistry([{"name": "alpha"}])
    config = SimpleNamespace(
        instance_root=tmp_path / "instances",
        runtime_dir=tmp_path / "run",
        logs_dir=tmp_path / "logs",
        state_dir=tmp_path / "state",
    )
    context = _build_context(config=config, registry=registry)

    result = doctor_probes._probe_state_reconcile(context)
    assert result.status is ProbeStatus.GREEN
    assert result.impact is DoctorImpact.OK
    assert result.data is None


def test_probe_state_reconcile_when_no_instances(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Empty registry/discovery should report a neutral message."""
    report = DiscoveryReport(instances=[])
    monkeypatch.setattr(doctor_probes, "discover_instances", lambda *args, **kwargs: report)
    registry = DummyRegistry([])
    config = SimpleNamespace(
        instance_root=tmp_path / "instances",
        runtime_dir=tmp_path / "run",
        logs_dir=tmp_path / "logs",
        state_dir=tmp_path / "state",
    )
    context = _build_context(config=config, registry=registry)

    result = doctor_probes._probe_state_reconcile(context)
    assert result.status is ProbeStatus.GREEN
    assert result.message == "No instances discovered; registry is empty"


# ---------------------------------------------------------------------------
# Environment probes
# ---------------------------------------------------------------------------


def test_probe_env_command_required_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fatal env commands should report environment impact when missing."""
    monkeypatch.setattr(doctor_probes, "_command_exists", lambda command: False)
    runner = doctor_probes._probe_env_command("node", fatal=True)
    result = runner(_build_context())
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.ENVIRONMENT


def test_probe_env_command_optional_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Optional env commands should degrade to a warning."""
    monkeypatch.setattr(doctor_probes, "_command_exists", lambda command: False)
    runner = doctor_probes._probe_env_command("zstd", fatal=False)
    result = runner(_build_context())
    assert result.status is ProbeStatus.YELLOW
    assert result.warnings == ("missing:zstd",)


def test_probe_env_command_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """Commands present on PATH should report green status."""
    monkeypatch.setattr(doctor_probes, "_command_exists", lambda command: True)
    runner = doctor_probes._probe_env_command("node", fatal=True)
    result = runner(_build_context())
    assert result.status is ProbeStatus.GREEN
    assert result.impact is DoctorImpact.OK


def test_probe_env_node_compat_green_when_version_meets_min() -> None:
    """Node versions that meet the compatibility matrix should stay green."""
    compat = _compat_matrix([NodeVersionSpec(major=18, min_patch="18.17.0")])
    context = _build_context(
        node_runtime=DummyNodeRuntime("18.18.0"),
        node_compat=compat,
    )
    result = doctor_probes._probe_env_node_compat(context)
    assert result.status is ProbeStatus.GREEN
    assert "Node 18.18.0" in result.message


def test_probe_env_node_compat_warns_when_version_too_low() -> None:
    """Older Node versions should trigger a warning per ADR-018."""
    compat = _compat_matrix([NodeVersionSpec(major=18, min_patch="18.17.0")])
    context = _build_context(
        node_runtime=DummyNodeRuntime("18.16.0"),
        node_compat=compat,
    )
    result = doctor_probes._probe_env_node_compat(context)
    assert result.status is ProbeStatus.YELLOW
    assert ">= 18.17.0" in result.message


def test_probe_env_node_compat_warns_without_data() -> None:
    """Missing compatibility data should result in a warning."""
    context = _build_context(
        node_runtime=DummyNodeRuntime("18.18.0"),
        node_compat=None,
    )
    result = doctor_probes._probe_env_node_compat(context)
    assert result.status is ProbeStatus.YELLOW
    assert "compatibility data unavailable" in result.message


def test_probe_env_node_compat_warns_when_node_missing() -> None:
    """Absent node binary should surface as a warning for this probe."""
    compat = _compat_matrix([NodeVersionSpec(major=18, min_patch="18.17.0")])
    context = _build_context(
        node_runtime=DummyNodeRuntime(None),
        node_compat=compat,
    )
    result = doctor_probes._probe_env_node_compat(context)
    assert result.status is ProbeStatus.YELLOW
    assert "Node binary not detected" in result.message


def test_probe_env_nginx_reports_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Missing nginx binary should be treated as an environment failure."""
    monkeypatch.setattr(doctor_probes, "_command_exists", lambda command: False)
    provider = DummyNginxProvider(tmp_path)
    context = _build_context(nginx_provider=provider)

    result = doctor_probes._probe_env_nginx(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.ENVIRONMENT


def test_probe_env_nginx_reports_present(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Existing nginx binary should ensure a green result."""
    monkeypatch.setattr(doctor_probes, "_command_exists", lambda command: True)
    provider = DummyNginxProvider(tmp_path)
    context = _build_context(nginx_provider=provider)

    result = doctor_probes._probe_env_nginx(context)
    assert result.status is ProbeStatus.GREEN
    assert result.message.startswith("nginx binary")


def test_probe_env_systemctl_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Missing systemctl should emit a warning."""
    monkeypatch.setattr(doctor_probes, "_command_exists", lambda command: False)
    provider = DummySystemdProvider(tmp_path)
    context = _build_context(systemd_provider=provider)

    result = doctor_probes._probe_env_systemctl(context)
    assert result.status is ProbeStatus.YELLOW
    assert result.warnings == ("missing:systemctl",)


def test_probe_env_systemctl_available(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Available systemctl should result in a green status."""
    monkeypatch.setattr(doctor_probes, "_command_exists", lambda command: True)
    provider = DummySystemdProvider(tmp_path)
    context = _build_context(systemd_provider=provider)

    result = doctor_probes._probe_env_systemctl(context)
    assert result.status is ProbeStatus.GREEN
    assert result.message.startswith("systemctl binary")


def test_env_probes_include_expected_ids() -> None:
    """Env probe catalogue should include the standard binary checks."""
    definitions = doctor_probes._env_probes()
    ids = {definition.id for definition in definitions}
    assert {
        "env-python",
        "env-abssctl",
        "env-platform",
        "env-node",
        "env-npm",
        "env-systemctl",
    }.issubset(ids)


# ---------------------------------------------------------------------------
# Systemd probes
# ---------------------------------------------------------------------------


class DummySystemdProvider:
    """Simple systemd provider exposing unit lookups and status calls."""

    def __init__(self, unit_base: Path, *, status_map: dict[str, object] | None = None) -> None:
        """Record unit directory and optional status override mapping."""
        self._unit_base = unit_base
        self._status_map = status_map or {}
        self.systemctl_bin = "systemctl"

    def unit_path(self, name: str) -> Path:
        """Return the expected unit path for *name*."""
        return self._unit_base / f"{name}.service"

    def status(self, name: str) -> object:
        """Return a fake CompletedProcess or raise a configured exception."""
        handler = self._status_map.get(name)
        if isinstance(handler, Exception):
            raise handler
        if callable(handler):
            return handler()
        return handler


def test_probe_systemd_units_flags_missing_files(tmp_path: Path) -> None:
    """Missing unit files should be reported as validation failures."""
    provider = DummySystemdProvider(tmp_path)
    (provider.unit_path("alpha")).write_text("[Unit]", encoding="utf-8")
    registry = DummyRegistry([{"name": "alpha"}, {"name": "beta"}])
    context = _build_context(systemd_provider=provider, registry=registry)

    result = doctor_probes._probe_systemd_units(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.VALIDATION
    assert "beta" in result.message
    assert "Missing systemd unit files" in result.message


def test_probe_systemd_units_green_when_all_present(tmp_path: Path) -> None:
    """All present unit files should yield a green result."""
    provider = DummySystemdProvider(tmp_path)
    for name in ("alpha", "beta"):
        provider.unit_path(name).write_text("[Unit]", encoding="utf-8")
    registry = DummyRegistry([{"name": "alpha"}, {"name": "beta"}])
    context = _build_context(systemd_provider=provider, registry=registry)

    result = doctor_probes._probe_systemd_units(context)
    assert result.status is ProbeStatus.GREEN
    assert result.impact is DoctorImpact.OK


class DummyCompletedProcess:
    """Mimic subprocess.CompletedProcess for systemd probe tests."""

    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        """Capture the result fields required by the probe under test."""
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_probe_systemd_status_collects_failures(tmp_path: Path) -> None:
    """Failed status commands should surface provider failures and diagnostics."""
    provider = DummySystemdProvider(
        tmp_path,
        status_map={
            "alpha": DummyCompletedProcess(returncode=1, stderr="unit failed"),
        },
    )
    registry = DummyRegistry([{"name": "alpha"}])
    context = _build_context(systemd_provider=provider, registry=registry)

    result = doctor_probes._probe_systemd_status(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.PROVIDER
    assert result.data == {"failures": {"alpha": "unit failed"}}


def test_probe_systemd_status_surfaces_other_systemd_errors(tmp_path: Path) -> None:
    """Systemd errors unrelated to missing binaries should bubble up as failures."""
    provider = DummySystemdProvider(
        tmp_path,
        status_map={"alpha": SystemdError("start limit hit")},
    )
    registry = DummyRegistry([{"name": "alpha"}])
    context = _build_context(systemd_provider=provider, registry=registry)

    result = doctor_probes._probe_systemd_status(context)
    assert result.status is ProbeStatus.RED
    assert result.data == {"failures": {"alpha": "start limit hit"}}
    assert "Systemd status checks failed." in result.message


def test_probe_systemd_status_handles_missing_systemctl(tmp_path: Path) -> None:
    """SystemdError indicating missing binary should translate to a warning."""
    provider = DummySystemdProvider(
        tmp_path,
        status_map={"alpha": SystemdError("systemctl not found")},
    )
    registry = DummyRegistry([{"name": "alpha"}])
    context = _build_context(systemd_provider=provider, registry=registry)

    result = doctor_probes._probe_systemd_status(context)
    assert result.status is ProbeStatus.YELLOW
    assert result.impact is DoctorImpact.OK
    assert result.warnings == ("systemd:missing",)


def test_probe_systemd_status_green(tmp_path: Path) -> None:
    """Healthy systemd status should yield a green result."""
    provider = DummySystemdProvider(
        tmp_path,
        status_map={"alpha": DummyCompletedProcess(returncode=0, stdout="ok", stderr="")},
    )
    registry = DummyRegistry([{"name": "alpha"}])
    context = _build_context(systemd_provider=provider, registry=registry)

    result = doctor_probes._probe_systemd_status(context)
    assert result.status is ProbeStatus.GREEN
    assert result.impact is DoctorImpact.OK


# ---------------------------------------------------------------------------
# Nginx probes
# ---------------------------------------------------------------------------


class DummyNginxProvider:
    """Stub nginx provider tracking existing/enabled sites."""

    def __init__(
        self,
        base: Path,
        *,
        existing: set[str] | None = None,
        enabled: set[str] | None = None,
        test_result: DummyCompletedProcess | None = None,
        test_error: Exception | None = None,
    ) -> None:
        """Populate fake filesystem state for nginx site checks."""
        self._base = base
        self._existing = existing or set()
        self._enabled = enabled or set()
        self.nginx_bin = "nginx"
        self._test_result = test_result or DummyCompletedProcess(returncode=0)
        self._test_error = test_error
        for name in self._existing:
            self.site_path(name).parent.mkdir(parents=True, exist_ok=True)
            self.site_path(name).write_text("server {}", encoding="utf-8")

    def site_path(self, name: str) -> Path:
        """Return the config path for *name*."""
        return self._base / f"{name}.conf"

    def is_enabled(self, name: str) -> bool:
        """Return True when the site is tracked as enabled."""
        return name in self._enabled

    def test_config(self) -> DummyCompletedProcess:
        """Return the configured nginx -t result or raise an error."""
        if self._test_error is not None:
            raise self._test_error
        return self._test_result


def test_probe_nginx_sites_reports_missing_configs(tmp_path: Path) -> None:
    """Missing nginx configs should trigger a validation failure."""
    provider = DummyNginxProvider(tmp_path, existing={"alpha"})
    registry = DummyRegistry([{"name": "alpha"}, {"name": "beta"}])
    context = _build_context(nginx_provider=provider, registry=registry)

    result = doctor_probes._probe_nginx_sites(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.VALIDATION
    assert "beta" in result.message


def test_probe_nginx_sites_warns_when_not_enabled(tmp_path: Path) -> None:
    """Sites that exist but are not enabled should raise a warning."""
    provider = DummyNginxProvider(tmp_path, existing={"alpha", "beta"}, enabled={"alpha"})
    registry = DummyRegistry([{"name": "alpha"}, {"name": "beta"}])
    context = _build_context(nginx_provider=provider, registry=registry)

    result = doctor_probes._probe_nginx_sites(context)
    assert result.status is ProbeStatus.YELLOW
    assert result.impact is DoctorImpact.OK
    assert result.warnings == ("nginx:disabled",)
    assert "beta" in result.message


def test_probe_nginx_sites_green_when_all_enabled(tmp_path: Path) -> None:
    """All enabled configs should mark the probe green."""
    provider = DummyNginxProvider(tmp_path, existing={"alpha"}, enabled={"alpha"})
    registry = DummyRegistry([{"name": "alpha"}])
    context = _build_context(nginx_provider=provider, registry=registry)

    result = doctor_probes._probe_nginx_sites(context)
    assert result.status is ProbeStatus.GREEN
    assert result.impact is DoctorImpact.OK


def test_probe_nginx_config_success(tmp_path: Path) -> None:
    """Successful nginx config validation should report green."""
    provider = DummyNginxProvider(tmp_path)
    context = _build_context(nginx_provider=provider)

    result = doctor_probes._probe_nginx_config(context)
    assert result.status is ProbeStatus.GREEN
    assert result.message == "nginx -t validation succeeded."


def test_probe_nginx_config_handles_error(tmp_path: Path) -> None:
    """NginxError should produce a provider failure."""
    provider = DummyNginxProvider(tmp_path, test_error=NginxError("boom"))
    context = _build_context(nginx_provider=provider)

    result = doctor_probes._probe_nginx_config(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.PROVIDER
    assert "boom" in result.message


def test_probe_nginx_config_nonzero_exit(tmp_path: Path) -> None:
    """Non-zero nginx -t exit codes should be captured."""
    provider = DummyNginxProvider(
        tmp_path,
        test_result=DummyCompletedProcess(returncode=1, stdout="bad config", stderr="error"),
    )
    context = _build_context(nginx_provider=provider)

    result = doctor_probes._probe_nginx_config(context)
    assert result.status is ProbeStatus.RED
    assert "nginx -t exited with 1" in result.message


# ---------------------------------------------------------------------------
# Ports probes
# ---------------------------------------------------------------------------


class DummyPortsRegistry:
    """Stub ports registry returning canned entries or raising errors."""

    def __init__(
        self,
        *,
        entries: list[dict[str, object]] | None = None,
        error: Exception | None = None,
    ) -> None:
        """Initialise the stub with optional entries or an error to raise."""
        self._entries = entries or []
        self._error = error

    def list_entries(self) -> list[dict[str, object]]:
        """Return configured entries or raise the configured error."""
        if self._error is not None:
            raise self._error
        return list(self._entries)


def test_probe_ports_registry_handles_errors() -> None:
    """Ports registry failures should surface validation errors."""
    registry = DummyRegistry([{"name": "alpha"}])
    ports = DummyPortsRegistry(error=PortsRegistryError("registry missing"))
    context = _build_context(ports=ports, registry=registry)

    result = doctor_probes._probe_ports_registry(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.VALIDATION
    assert "registry missing" in result.message


def test_probe_ports_registry_detects_duplicate_ports() -> None:
    """Duplicate port numbers should be reported."""
    registry = DummyRegistry([{"name": "alpha"}, {"name": "beta"}])
    ports = DummyPortsRegistry(
        entries=[
            {"name": "alpha", "port": 5100},
            {"name": "beta", "port": 5100},
        ]
    )
    context = _build_context(ports=ports, registry=registry)

    result = doctor_probes._probe_ports_registry(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.VALIDATION
    assert "Duplicate ports detected: 5100" in result.message


def test_probe_ports_registry_detects_duplicate_names() -> None:
    """Duplicate reservations by name should be flagged."""
    registry = DummyRegistry([{"name": "alpha"}, {"name": "beta"}])
    ports = DummyPortsRegistry(
        entries=[
            {"name": "alpha", "port": 5100},
            {"name": "alpha", "port": 5200},
        ]
    )
    context = _build_context(ports=ports, registry=registry)

    result = doctor_probes._probe_ports_registry(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.VALIDATION
    assert "Duplicate port reservations detected: alpha" in result.message


def test_probe_ports_registry_warns_on_missing_ports() -> None:
    """Instances without reserved ports should produce a warning."""
    registry = DummyRegistry([{"name": "alpha"}, {"name": "beta"}])
    ports = DummyPortsRegistry(entries=[{"name": "alpha", "port": 5100}])
    context = _build_context(ports=ports, registry=registry)

    result = doctor_probes._probe_ports_registry(context)
    assert result.status is ProbeStatus.YELLOW
    assert result.warnings == ("ports:missing",)
    assert "beta" in result.message


def test_probe_ports_registry_green_when_all_reserved() -> None:
    """Healthy port reservations should yield a green result."""
    registry = DummyRegistry([{"name": "alpha"}, {"name": "beta"}])
    ports = DummyPortsRegistry(
        entries=[
            {"name": "alpha", "port": 5100},
            {"name": "beta", "port": 5200},
        ]
    )
    context = _build_context(ports=ports, registry=registry)

    result = doctor_probes._probe_ports_registry(context)
    assert result.status is ProbeStatus.GREEN
    assert result.impact is DoctorImpact.OK
    assert result.message == "2 port reservation(s) recorded."


def test_probe_ports_registry_green_reports_count_message() -> None:
    """Healthy registries should report the actual reservation count."""
    registry = DummyRegistry([{"name": "alpha"}, {"name": "beta"}, {"name": "gamma"}])
    ports = DummyPortsRegistry(
        entries=[
            {"name": "alpha", "port": 5100},
            {"name": "beta", "port": 5200},
            {"name": "gamma", "port": 5300},
        ]
    )
    context = _build_context(ports=ports, registry=registry)

    result = doctor_probes._probe_ports_registry(context)
    assert result.status is ProbeStatus.GREEN
    assert result.message == "3 port reservation(s) recorded."


# ---------------------------------------------------------------------------
# TLS probe
# ---------------------------------------------------------------------------


class DummyTLSInspector:
    """TLS inspector stub returning a sentinel selection."""

    def __init__(self, selection: object) -> None:
        """Store the selection object returned for every resolve call."""
        self._selection = selection
        self.last_args: tuple[tuple[object, ...], dict[str, object]] | None = None

    def resolve_manual(self, *args: object, **kwargs: object) -> object:
        """Record invocation arguments and return the canned selection."""
        self.last_args = (args, kwargs)
        return self._selection


class DummyTLSValidator:
    """TLS validator stub yielding preconfigured reports."""

    def __init__(self, report: object) -> None:
        """Persist the report object returned on each validate call."""
        self._report = report
        self.calls: list[dict[str, object]] = []

    def validate(self, selection: object, *, now: object) -> object:
        """Record call metadata and yield the canned report."""
        self.calls.append({"selection": selection, "now": now})
        return self._report


class DummyFinding:
    """Simple TLS finding structure."""

    def __init__(self, scope: str, check: str, severity: TLSValidationSeverity) -> None:
        """Capture data used when summarising TLS findings."""
        self.scope = scope
        self.check = check
        self.severity = severity


class DummyTLSReport:
    """TLS validation report stub."""

    def __init__(
        self,
        status: TLSValidationSeverity,
        findings: list[DummyFinding],
        data: dict[str, object],
    ) -> None:
        """Store TLS report fields consumed by the probe."""
        self.status = status
        self.findings = findings
        self._data = data

    def to_dict(self) -> dict[str, object]:
        """Return a shallow copy of the canned report data."""
        return dict(self._data)


def _tls_config(tmp_path: Path) -> object:
    return SimpleNamespace(
        tls=SimpleNamespace(
            system=SimpleNamespace(
                cert=tmp_path / "system-cert.pem",
                key=tmp_path / "system-key.pem",
            )
        )
    )


def test_probe_tls_system_certificate_green(tmp_path: Path) -> None:
    """Successful TLS validation should produce a green result."""
    data = {
        "findings": [{"scope": "scope", "check": "match", "severity": "ok"}],
        "not_valid_after": None,
    }
    report = DummyTLSReport(
        TLSValidationSeverity.OK,
        [DummyFinding("scope", "match", TLSValidationSeverity.OK)],
        data,
    )
    inspector = DummyTLSInspector(selection=object())
    validator = DummyTLSValidator(report)
    context = _build_context(
        config=_tls_config(tmp_path),
        tls_inspector=inspector,
        tls_validator=validator,
    )

    result = doctor_probes._probe_tls_system_certificate(context)
    assert result.status is ProbeStatus.GREEN
    assert result.impact is DoctorImpact.OK
    assert result.data == {
        "not_valid_after": None,
        "findings": data["findings"],
        "summary": "scope:match:ok",
    }
    assert not result.warnings


def test_probe_tls_system_certificate_warn(tmp_path: Path) -> None:
    """TLS warnings should downgrade the probe and include warning codes."""
    data = {
        "findings": [{"scope": "scope", "check": "expiry", "severity": "warning"}],
        "not_valid_after": "2025-12-11T00:00:00+00:00",
    }
    report = DummyTLSReport(
        TLSValidationSeverity.WARNING,
        [DummyFinding("scope", "expiry", TLSValidationSeverity.WARNING)],
        data,
    )
    inspector = DummyTLSInspector(selection=object())
    validator = DummyTLSValidator(report)
    context = _build_context(
        config=_tls_config(tmp_path),
        tls_inspector=inspector,
        tls_validator=validator,
    )

    result = doctor_probes._probe_tls_system_certificate(context)
    assert result.status is ProbeStatus.YELLOW
    assert result.impact is DoctorImpact.OK
    assert result.warnings == ("tls:warning",)
    assert result.data == {
        "not_valid_after": data["not_valid_after"],
        "findings": data["findings"],
        "summary": "scope:expiry:warning",
    }


def test_probe_tls_system_certificate_errors(tmp_path: Path) -> None:
    """TLS error findings should mark the probe as a provider failure."""
    data = {
        "findings": [{"scope": "scope", "check": "match", "severity": "error"}],
        "not_valid_after": None,
    }
    report = DummyTLSReport(
        TLSValidationSeverity.ERROR,
        [DummyFinding("scope", "match", TLSValidationSeverity.ERROR)],
        data,
    )
    inspector = DummyTLSInspector(selection=object())
    validator = DummyTLSValidator(report)
    context = _build_context(
        config=_tls_config(tmp_path),
        tls_inspector=inspector,
        tls_validator=validator,
    )

    result = doctor_probes._probe_tls_system_certificate(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.PROVIDER
    assert result.data == {
        "not_valid_after": None,
        "findings": data["findings"],
        "summary": "scope:match:error",
    }


def test_probe_tls_system_certificate_handles_config_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Configuration errors while resolving TLS assets should be surfaced."""
    inspector = DummyTLSInspector(selection=object())

    def _broken_resolve(*args: object, **kwargs: object) -> Never:
        raise TLSConfigurationError("boom")

    monkeypatch.setattr(inspector, "resolve_manual", _broken_resolve)
    context = _build_context(
        config=_tls_config(tmp_path),
        tls_inspector=inspector,
        tls_validator=DummyTLSValidator(None),
    )

    result = doctor_probes._probe_tls_system_certificate(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.VALIDATION
    assert "Failed to resolve system TLS assets" in result.message


def test_probe_tls_system_certificate_passes_current_time_to_validator(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Validator should receive the current UTC timestamp and the inspector selection."""
    inspector = DummyTLSInspector(selection=object())
    sentinel_now = object()

    class _DummyDateTime:
        @staticmethod
        def now(tz: object) -> object:
            assert tz is UTC
            return sentinel_now

    monkeypatch.setattr(doctor_probes, "datetime", _DummyDateTime)
    report = DummyTLSReport(
        TLSValidationSeverity.OK,
        [],
        {"findings": [], "not_valid_after": None},
    )
    validator = DummyTLSValidator(report)
    context = _build_context(
        config=_tls_config(tmp_path),
        tls_inspector=inspector,
        tls_validator=validator,
    )

    doctor_probes._probe_tls_system_certificate(context)
    assert validator.calls[0]["now"] is sentinel_now
    assert validator.calls[0]["selection"] is inspector._selection


# ---------------------------------------------------------------------------
# Filesystem probes
# ---------------------------------------------------------------------------


def _filesystem_config(root: Path) -> object:
    config_file = root / "etc" / "abssctl" / "config.yaml"
    registry_dir = root / "var" / "lib" / "abssctl" / "registry"
    state_dir = root / "var" / "lib" / "abssctl"
    logs_dir = root / "var" / "log" / "abssctl"
    runtime_dir = root / "run" / "abssctl"
    templates_dir = root / "usr" / "share" / "abssctl" / "templates"
    backups_root = root / "var" / "backups" / "abssctl"

    return SimpleNamespace(
        config_file=config_file,
        state_dir=state_dir,
        registry_dir=registry_dir,
        logs_dir=logs_dir,
        runtime_dir=runtime_dir,
        templates_dir=templates_dir,
        backups=SimpleNamespace(root=backups_root),
    )


def test_probe_filesystem_directories_reports_missing(tmp_path: Path) -> None:
    """Missing directories should be reported as validation failures."""
    config = _filesystem_config(tmp_path)
    config.config_file.parent.mkdir(parents=True, exist_ok=True)
    context = _build_context(config=config)

    result = doctor_probes._probe_filesystem_directories(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.VALIDATION
    assert "Required directories missing" in result.message


def test_probe_filesystem_directories_green(tmp_path: Path) -> None:
    """When all directories exist probe should return green with permissions."""
    config = _filesystem_config(tmp_path)
    for path in [
        config.config_file.parent,
        config.state_dir,
        config.registry_dir,
        config.logs_dir,
        config.runtime_dir,
        config.templates_dir,
        config.backups.root,
    ]:
        Path(path).mkdir(parents=True, exist_ok=True)
    config.config_file.touch()
    context = _build_context(config=config)

    result = doctor_probes._probe_filesystem_directories(context)
    assert result.status is ProbeStatus.GREEN
    assert result.data is not None
    assert "permissions" in result.data


# ---------------------------------------------------------------------------
# State probes
# ---------------------------------------------------------------------------


def test_probe_state_instances_detects_duplicates() -> None:
    """Duplicate instance names should trigger a validation failure."""
    registry = DummyRegistry([{"name": "alpha"}, {"name": "alpha"}])
    context = _build_context(registry=registry)

    result = doctor_probes._probe_state_instances(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.VALIDATION
    assert "Duplicate instance names detected" in result.message


def test_probe_state_instances_reports_counts() -> None:
    """Healthy registry entries should produce a green status."""
    registry = DummyRegistry([{"name": "alpha"}, {"name": "beta"}])
    context = _build_context(registry=registry)

    result = doctor_probes._probe_state_instances(context)
    assert result.status is ProbeStatus.GREEN
    assert "2 instance(s) registered." in result.message


# ---------------------------------------------------------------------------
# Application probes
# ---------------------------------------------------------------------------


class DummyInstanceStatusProvider:
    """Stub instance status provider returning precomputed statuses."""

    def __init__(self, mapping: dict[str, InstanceStatus]) -> None:
        """Store mapping from instance name to status."""
        self._mapping = mapping

    def status(self, name: str, entry: object) -> InstanceStatus:
        """Return the configured status or a default unknown placeholder."""
        return self._mapping.get(
            name,
            InstanceStatus(state="unknown", detail="Status checks not implemented yet."),
        )


def test_probe_app_instance_status_reports_failures() -> None:
    """Failure states should produce provider failures with diagnostics."""
    provider = DummyInstanceStatusProvider(
        {
            "alpha": InstanceStatus(state="running", detail="ok"),
            "beta": InstanceStatus(state="failed", detail="boom"),
        }
    )
    registry = DummyRegistry([{"name": "alpha"}, {"name": "beta"}])
    context = _build_context(instance_status_provider=provider, registry=registry)

    result = doctor_probes._probe_app_instance_status(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.PROVIDER
    assert result.data == {
        "states": {"alpha": "running", "beta": "failed"},
        "failures": {"beta": "boom"},
    }


def test_probe_app_instance_status_warns_on_unknown() -> None:
    """Unexpected states should downgrade to a warning."""
    provider = DummyInstanceStatusProvider(
        {
            "alpha": InstanceStatus(state="pending", detail="warming up"),
        }
    )
    registry = DummyRegistry([{"name": "alpha"}])
    context = _build_context(instance_status_provider=provider, registry=registry)

    result = doctor_probes._probe_app_instance_status(context)
    assert result.status is ProbeStatus.YELLOW
    assert result.impact is DoctorImpact.OK
    assert result.warnings == ("app:status",)
    assert result.data["warnings"] == {"alpha": "warming up"}


def test_probe_app_instance_status_green_for_running() -> None:
    """Healthy states should produce a green result."""
    provider = DummyInstanceStatusProvider(
        {"alpha": InstanceStatus(state="running", detail="ok")}
    )
    registry = DummyRegistry([{"name": "alpha"}])
    context = _build_context(instance_status_provider=provider, registry=registry)

    result = doctor_probes._probe_app_instance_status(context)
    assert result.status is ProbeStatus.GREEN
    assert result.data == {"states": {"alpha": "running"}}


def test_probe_app_instance_status_handles_case_insensitive_failures() -> None:
    """Failure detection should be case-insensitive."""
    provider = DummyInstanceStatusProvider({"alpha": InstanceStatus(state="FAILED", detail="boom")})
    registry = DummyRegistry([{"name": "alpha"}])
    context = _build_context(instance_status_provider=provider, registry=registry)

    result = doctor_probes._probe_app_instance_status(context)
    assert result.status is ProbeStatus.RED
    assert result.data["failures"] == {"alpha": "boom"}


# ---------------------------------------------------------------------------
# Disk usage probe
# ---------------------------------------------------------------------------


def test_probe_disk_usage_missing_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing state directory should be treated as a validation failure."""
    config = SimpleNamespace(state_dir=tmp_path / "missing")
    context = _build_context(config=config)

    def _raise_missing(_path: Path) -> Never:
        raise FileNotFoundError

    monkeypatch.setattr(doctor_probes.shutil, "disk_usage", _raise_missing)

    result = doctor_probes._probe_disk_usage(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.VALIDATION
    assert "does not exist" in result.message


DiskUsage = namedtuple("DiskUsage", "total used free")


def test_probe_disk_usage_red_when_below_five_percent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Critical low free space should produce a provider failure."""
    config = SimpleNamespace(state_dir=tmp_path)
    context = _build_context(config=config)
    monkeypatch.setattr(
        doctor_probes.shutil,
        "disk_usage",
        lambda path: DiskUsage(total=100, used=96, free=4),
    )

    result = doctor_probes._probe_disk_usage(context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.PROVIDER
    assert result.data["percent_free"] == pytest.approx(4.0)


def test_probe_disk_usage_yellow_when_below_ten_percent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Low but non-critical free space should emit a warning."""
    config = SimpleNamespace(state_dir=tmp_path)
    context = _build_context(config=config)
    monkeypatch.setattr(
        doctor_probes.shutil,
        "disk_usage",
        lambda path: DiskUsage(total=100, used=91, free=9),
    )

    result = doctor_probes._probe_disk_usage(context)
    assert result.status is ProbeStatus.YELLOW
    assert result.impact is DoctorImpact.OK
    assert result.warnings == ("disk:low-free",)


def test_probe_disk_usage_exactly_five_percent_warns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exactly 5% free space should emit a warning instead of a failure."""
    config = SimpleNamespace(state_dir=tmp_path)
    context = _build_context(config=config)
    monkeypatch.setattr(
        doctor_probes.shutil,
        "disk_usage",
        lambda path: DiskUsage(total=100, used=95, free=5),
    )

    result = doctor_probes._probe_disk_usage(context)
    assert result.status is ProbeStatus.YELLOW
    assert result.warnings == ("disk:low-free",)
    assert result.data["percent_free"] == pytest.approx(5.0)


def test_probe_disk_usage_green_with_healthy_space(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Healthy free space should keep the probe green."""
    config = SimpleNamespace(state_dir=tmp_path)
    context = _build_context(config=config)
    monkeypatch.setattr(
        doctor_probes.shutil,
        "disk_usage",
        lambda path: DiskUsage(total=200, used=50, free=150),
    )

    result = doctor_probes._probe_disk_usage(context)
    assert result.status is ProbeStatus.GREEN
    assert result.impact is DoctorImpact.OK
    assert result.data["percent_free"] == pytest.approx(75.0)


def test_probe_disk_usage_ten_percent_is_green(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Free space at the 10% boundary should remain green."""
    config = SimpleNamespace(state_dir=tmp_path)
    context = _build_context(config=config)
    monkeypatch.setattr(
        doctor_probes.shutil,
        "disk_usage",
        lambda path: DiskUsage(total=100, used=90, free=10),
    )

    result = doctor_probes._probe_disk_usage(context)
    assert result.status is ProbeStatus.GREEN
    assert result.data["percent_free"] == pytest.approx(10.0)


def test_collect_probes_captures_expected_categories(tmp_path: Path) -> None:
    """collect_probes should include representative probe identifiers."""
    config = _filesystem_config(tmp_path)
    context = _build_context(config=config)
    definitions = collect_probes(context)
    ids = {definition.id for definition in definitions}
    assert {"env-python", "state-reconcile", "fs-directories", "disk-usage"}.issubset(ids)
