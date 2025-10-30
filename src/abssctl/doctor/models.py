"""Data models and helpers for doctor probes."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from ..backups import BackupsRegistry
    from ..config import AppConfig
    from ..locking import LockManager
    from ..logging import StructuredLogger
    from ..ports import PortsRegistry
    from ..providers.instance_status_provider import InstanceStatusProvider
    from ..providers.nginx import NginxProvider
    from ..providers.systemd import SystemdProvider
    from ..providers.version_installer import VersionInstaller
    from ..providers.version_provider import VersionProvider
    from ..state.registry import StateRegistry
    from ..templates import TemplateEngine
    from ..tls import TLSInspector, TLSValidator


class ProbeStatus(str, Enum):
    """High-level outcome for a doctor probe."""

    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"

    @property
    def is_failure(self) -> bool:
        """Return ``True`` when the status represents a failure."""
        return self is ProbeStatus.RED

    @property
    def is_warning(self) -> bool:
        """Return ``True`` when the status represents a warning."""
        return self is ProbeStatus.YELLOW


class DoctorImpact(Enum):
    """Impact tier used to derive the doctor exit code."""

    OK = 0
    VALIDATION = 2
    ENVIRONMENT = 3
    PROVIDER = 4

    @classmethod
    def from_exit_code(cls, code: int) -> DoctorImpact:
        """Translate an exit code back into a DoctorImpact."""
        for impact in cls:
            if impact.value == code:
                return impact
        raise ValueError(f"Unsupported doctor exit code: {code}")


ProbeCategory = Literal[
    "env",
    "config",
    "state",
    "fs",
    "ports",
    "systemd",
    "nginx",
    "tls",
    "app",
    "disk",
]

# Ordered tuple of all recognised probe categories. Keep this in sync with ``ProbeCategory``.
PROBE_CATEGORY_VALUES: tuple[ProbeCategory, ...] = (
    "env",
    "config",
    "state",
    "fs",
    "ports",
    "systemd",
    "nginx",
    "tls",
    "app",
    "disk",
)


@dataclass(slots=True, frozen=True)
class ProbeExecutorOptions:
    """Runtime tunables for executing doctor probes."""

    max_concurrency: int = 8
    exec_timeout: float = 5.0
    connect_timeout: float = 1.0
    request_timeout: float = 3.0
    retries: int = 2


@dataclass(slots=True, frozen=True)
class ProbeContext:
    """Execution context provided to doctor probes."""

    config: AppConfig
    registry: StateRegistry
    ports: PortsRegistry
    version_provider: VersionProvider
    version_installer: VersionInstaller
    instance_status_provider: InstanceStatusProvider
    locks: LockManager
    logger: StructuredLogger
    templates: TemplateEngine
    systemd_provider: SystemdProvider
    nginx_provider: NginxProvider
    backups: BackupsRegistry
    tls_inspector: TLSInspector
    tls_validator: TLSValidator
    options: ProbeExecutorOptions


@dataclass(slots=True, frozen=True)
class ProbeResult:
    """Outcome of running a probe."""

    id: str
    category: ProbeCategory
    status: ProbeStatus
    impact: DoctorImpact
    message: str
    remediation: str | None = None
    duration_ms: int | None = None
    data: Mapping[str, Any] | None = None
    warnings: Sequence[str] = field(default_factory=tuple)

    @property
    def is_failure(self) -> bool:
        """Return ``True`` when the probe result represents a failure."""
        return self.status.is_failure

    @property
    def is_warning(self) -> bool:
        """Return ``True`` when the probe result represents a warning."""
        return self.status.is_warning


@dataclass(slots=True, frozen=True)
class ProbeDefinition:
    """Metadata + callable for a probe."""

    id: str
    category: ProbeCategory
    run: Callable[[ProbeContext], ProbeResult]


@dataclass(slots=True, frozen=True)
class DoctorSummary:
    """Aggregated summary derived from probe results."""

    status: ProbeStatus
    impact: DoctorImpact
    exit_code: int
    totals: Mapping[ProbeStatus, int]


@dataclass(slots=True, frozen=True)
class DoctorReport:
    """Complete report for a doctor run."""

    results: Sequence[ProbeResult]
    summary: DoctorSummary
    metadata: Mapping[str, Any] | None = None


STATUS_ORDER: Mapping[ProbeStatus, int] = {
    ProbeStatus.GREEN: 0,
    ProbeStatus.YELLOW: 1,
    ProbeStatus.RED: 2,
}


def aggregate_results(results: Iterable[ProbeResult]) -> DoctorSummary:
    """Compute overall status + exit code following ADR-029 rules."""
    totals: dict[ProbeStatus, int] = {
        ProbeStatus.GREEN: 0,
        ProbeStatus.YELLOW: 0,
        ProbeStatus.RED: 0,
    }
    worst_impact = DoctorImpact.OK
    worst_status = ProbeStatus.GREEN
    for result in results:
        totals[result.status] += 1
        if result.impact.value > worst_impact.value:
            worst_impact = result.impact
        if STATUS_ORDER[result.status] > STATUS_ORDER[worst_status]:
            worst_status = result.status

    summary_status = worst_status
    exit_code = worst_impact.value
    return DoctorSummary(
        status=summary_status,
        impact=worst_impact,
        exit_code=exit_code,
        totals=totals,
    )


def build_report(
    results: Sequence[ProbeResult],
    metadata: Mapping[str, Any] | None = None,
) -> DoctorReport:
    """Create a full DoctorReport from probe results."""
    summary = aggregate_results(results)
    return DoctorReport(results=tuple(results), summary=summary, metadata=metadata)
