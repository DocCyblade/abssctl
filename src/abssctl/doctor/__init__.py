"""Doctor command infrastructure."""

from __future__ import annotations

from .engine import DoctorEngine, create_probe_context, run_probes
from .models import (
    PROBE_CATEGORY_VALUES,
    DoctorImpact,
    DoctorReport,
    DoctorSummary,
    ProbeCategory,
    ProbeContext,
    ProbeDefinition,
    ProbeExecutorOptions,
    ProbeResult,
    ProbeStatus,
    aggregate_results,
    build_report,
)
from .probes import collect_probes

__all__ = [
    "DoctorEngine",
    "DoctorImpact",
    "DoctorReport",
    "DoctorSummary",
    "ProbeCategory",
    "PROBE_CATEGORY_VALUES",
    "ProbeContext",
    "ProbeDefinition",
    "ProbeExecutorOptions",
    "ProbeResult",
    "ProbeStatus",
    "aggregate_results",
    "build_report",
    "create_probe_context",
    "collect_probes",
    "run_probes",
]
