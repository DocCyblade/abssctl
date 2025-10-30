"""Probe execution harness for the doctor command."""

from __future__ import annotations

import concurrent.futures
import time
import traceback
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import TYPE_CHECKING

from .models import (
    DoctorImpact,
    DoctorReport,
    ProbeContext,
    ProbeDefinition,
    ProbeExecutorOptions,
    ProbeResult,
    ProbeStatus,
    build_report,
)

if TYPE_CHECKING:
    from ..cli import RuntimeContext


def _duration_ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


def _coerce_result(
    probe: ProbeDefinition,
    result: ProbeResult,
    duration_ms: int,
) -> ProbeResult:
    coerced = result
    if result.id != probe.id:
        coerced = replace(coerced, id=probe.id)
    if result.category != probe.category:
        coerced = replace(coerced, category=probe.category)
    if result.duration_ms is None:
        coerced = replace(coerced, duration_ms=duration_ms)
    return coerced


def _unexpected_failure(
    probe: ProbeDefinition,
    exc: Exception,
    duration_ms: int,
) -> ProbeResult:
    message = f"Probe '{probe.id}' raised an unexpected error: {exc}"
    data = {
        "exception": repr(exc),
        "traceback": traceback.format_exc(),
    }
    return ProbeResult(
        id=probe.id,
        category=probe.category,
        status=ProbeStatus.RED,
        impact=DoctorImpact.PROVIDER,
        message=message,
        remediation=None,
        duration_ms=duration_ms,
        data=data,
        warnings=("unhandled-exception",),
    )


def _run_single_probe(
    probe: ProbeDefinition,
    context: ProbeContext,
) -> ProbeResult:
    start = time.perf_counter()
    try:
        result = probe.run(context)
    except Exception as exc:  # pragma: no cover - defensive catch
        return _unexpected_failure(probe, exc, _duration_ms(start))
    duration_ms = _duration_ms(start)
    return _coerce_result(probe, result, duration_ms)


def run_probes(
    context: ProbeContext,
    probes: Sequence[ProbeDefinition],
) -> list[ProbeResult]:
    """Execute probes with bounded concurrency."""
    if not probes:
        return []

    max_workers = max(1, context.options.max_concurrency)
    if max_workers == 1:
        return [_run_single_probe(probe, context) for probe in probes]

    results: list[ProbeResult | None] = [None] * len(probes)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_index: dict[concurrent.futures.Future[ProbeResult], int] = {}
        for index, probe in enumerate(probes):
            future = executor.submit(_run_single_probe, probe, context)
            future_to_index[future] = index

        for future in concurrent.futures.as_completed(future_to_index):
            index = future_to_index[future]
            results[index] = future.result()

    return [result for result in results if result is not None]


def create_probe_context(
    runtime: RuntimeContext,
    options: ProbeExecutorOptions | None = None,
) -> ProbeContext:
    """Build a ProbeContext from the CLI runtime context."""
    effective_options = options or ProbeExecutorOptions()
    return ProbeContext(
        config=runtime.config,
        registry=runtime.registry,
        ports=runtime.ports,
        version_provider=runtime.version_provider,
        version_installer=runtime.version_installer,
        instance_status_provider=runtime.instance_status_provider,
        locks=runtime.locks,
        logger=runtime.logger,
        templates=runtime.templates,
        systemd_provider=runtime.systemd_provider,
        nginx_provider=runtime.nginx_provider,
        backups=runtime.backups,
        tls_inspector=runtime.tls_inspector,
        tls_validator=runtime.tls_validator,
        options=effective_options,
    )


class DoctorEngine:
    """Coordinator that executes probes and aggregates the overall report."""

    def __init__(self, context: ProbeContext) -> None:
        """Store the probe execution context."""
        self._context = context

    @property
    def options(self) -> ProbeExecutorOptions:
        """Return the execution options associated with this engine."""
        return self._context.options

    def run(
        self,
        probes: Sequence[ProbeDefinition],
        *,
        metadata: Mapping[str, object] | None = None,
    ) -> DoctorReport:
        """Run the supplied probes and build a doctor report."""
        start = time.perf_counter()
        results = run_probes(self._context, probes)
        total_ms = _duration_ms(start)
        run_metadata: dict[str, object] = {
            "duration_ms": total_ms,
            "probe_count": len(results),
            "requested_probes": len(probes),
            "concurrency": self.options.max_concurrency,
        }
        if metadata:
            run_metadata.update(metadata)
        return build_report(results, metadata=run_metadata)
