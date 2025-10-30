"""Tests for the doctor probe execution engine."""

from __future__ import annotations

import time
from types import SimpleNamespace

from abssctl.cli import RuntimeContext
from abssctl.doctor import (
    DoctorEngine,
    DoctorImpact,
    ProbeContext,
    ProbeDefinition,
    ProbeExecutorOptions,
    ProbeResult,
    ProbeStatus,
    aggregate_results,
    create_probe_context,
    run_probes,
)


def _dummy_context(options: ProbeExecutorOptions) -> ProbeContext:
    """Return a probe context populated with sentinel dependencies."""
    sentinel = object()
    return ProbeContext(
        config=sentinel,
        registry=sentinel,
        ports=sentinel,
        version_provider=sentinel,
        version_installer=sentinel,
        instance_status_provider=sentinel,
        locks=sentinel,
        logger=sentinel,
        templates=sentinel,
        systemd_provider=sentinel,
        nginx_provider=sentinel,
        backups=sentinel,
        tls_inspector=sentinel,
        tls_validator=sentinel,
        options=options,
    )


def _result(
    status: ProbeStatus,
    impact: DoctorImpact,
    *,
    message: str = "ok",
) -> ProbeResult:
    return ProbeResult(
        id="probe",
        category="env",
        status=status,
        impact=impact,
        message=message,
    )


def test_aggregate_results_yellow_overrides_green() -> None:
    """A yellow result should promote the summary to yellow without failing."""
    summary = aggregate_results(
        [
            _result(ProbeStatus.GREEN, DoctorImpact.OK),
            _result(ProbeStatus.YELLOW, DoctorImpact.OK),
        ]
    )
    assert summary.status is ProbeStatus.YELLOW
    assert summary.exit_code == 0
    assert summary.totals[ProbeStatus.YELLOW] == 1


def test_aggregate_results_red_provider_wins() -> None:
    """A provider failure should dominate the summary and exit code."""
    summary = aggregate_results(
        [
            _result(ProbeStatus.GREEN, DoctorImpact.OK),
            _result(ProbeStatus.RED, DoctorImpact.PROVIDER, message="nginx failed"),
        ]
    )
    assert summary.status is ProbeStatus.RED
    assert summary.exit_code == DoctorImpact.PROVIDER.value
    assert summary.impact is DoctorImpact.PROVIDER


def test_run_probes_sequential_order_and_duration() -> None:
    """Sequential execution should preserve ordering and record durations."""
    options = ProbeExecutorOptions(max_concurrency=1)
    context = _dummy_context(options)

    def first_probe(ctx: ProbeContext) -> ProbeResult:
        assert ctx is context
        return ProbeResult(
            id="mismatch",
            category="ports",
            status=ProbeStatus.GREEN,
            impact=DoctorImpact.OK,
            message="first",
        )

    def second_probe(ctx: ProbeContext) -> ProbeResult:
        assert ctx is context
        return ProbeResult(
            id="second",
            category="env",
            status=ProbeStatus.YELLOW,
            impact=DoctorImpact.OK,
            message="second",
        )

    probes = [
        ProbeDefinition(id="probe-1", category="env", run=first_probe),
        ProbeDefinition(id="probe-2", category="config", run=second_probe),
    ]

    results = run_probes(context, probes)
    assert [result.id for result in results] == ["probe-1", "probe-2"]
    assert [result.category for result in results] == ["env", "config"]
    assert all(result.duration_ms is not None for result in results)
    assert results[1].status is ProbeStatus.YELLOW


def test_run_probes_parallel_preserves_order_and_handles_timing() -> None:
    """Parallel execution should still return results in probe order."""
    options = ProbeExecutorOptions(max_concurrency=4)
    context = _dummy_context(options)

    def slow_probe(ctx: ProbeContext) -> ProbeResult:
        time.sleep(0.01)
        return ProbeResult(
            id="slow",
            category="env",
            status=ProbeStatus.GREEN,
            impact=DoctorImpact.OK,
            message="slow",
        )

    def fast_probe(ctx: ProbeContext) -> ProbeResult:
        return ProbeResult(
            id="fast",
            category="env",
            status=ProbeStatus.GREEN,
            impact=DoctorImpact.OK,
            message="fast",
        )

    probes = [
        ProbeDefinition(id="slow-probe", category="env", run=slow_probe),
        ProbeDefinition(id="fast-probe", category="env", run=fast_probe),
    ]

    results = run_probes(context, probes)
    assert [result.id for result in results] == ["slow-probe", "fast-probe"]


def test_run_probes_converts_exceptions_to_provider_failures() -> None:
    """Unhandled probe exceptions should become provider failures."""
    options = ProbeExecutorOptions(max_concurrency=2)
    context = _dummy_context(options)

    def boom(ctx: ProbeContext) -> ProbeResult:
        raise RuntimeError("kaboom")

    probes = [
        ProbeDefinition(id="broken", category="systemd", run=boom),
    ]

    results = run_probes(context, probes)
    assert results[0].status is ProbeStatus.RED
    assert results[0].impact is DoctorImpact.PROVIDER
    assert "unexpected error" in results[0].message
    assert results[0].data is not None
    assert "kaboom" in str(results[0].data)


def test_doctor_engine_run_returns_report_with_metadata() -> None:
    """Running the engine should produce a report with aggregated metadata."""
    options = ProbeExecutorOptions(max_concurrency=1)
    context = _dummy_context(options)

    probes = [
        ProbeDefinition(
            id="healthy",
            category="env",
            run=lambda ctx: ProbeResult(
                id="healthy",
                category="env",
                status=ProbeStatus.GREEN,
                impact=DoctorImpact.OK,
                message="ok",
            ),
        ),
    ]
    engine = DoctorEngine(context)
    report = engine.run(probes, metadata={"session": "test"})
    assert report.summary.status is ProbeStatus.GREEN
    assert report.summary.exit_code == 0
    assert report.metadata is not None
    assert report.metadata["probe_count"] == 1
    assert report.metadata["requested_probes"] == 1
    assert report.metadata["concurrency"] == 1
    assert report.metadata["session"] == "test"


def test_create_probe_context_mirrors_runtime() -> None:
    """Probe context should mirror a runtime context and retain options."""
    sentinel = SimpleNamespace()
    runtime = RuntimeContext(
        config=sentinel,
        registry=sentinel,
        ports=sentinel,
        version_provider=sentinel,
        version_installer=sentinel,
        instance_status_provider=sentinel,
        locks=sentinel,
        logger=sentinel,
        templates=sentinel,
        systemd_provider=sentinel,
        nginx_provider=sentinel,
        backups=sentinel,
        tls_inspector=sentinel,
        tls_validator=sentinel,
    )

    options = ProbeExecutorOptions(max_concurrency=3)
    context = create_probe_context(runtime, options)
    assert context.config is sentinel
    assert context.nginx_provider is sentinel
    assert context.options.max_concurrency == 3
