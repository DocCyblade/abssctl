"""Tests for the doctor probe execution engine."""

from __future__ import annotations

import concurrent.futures
import time
from collections.abc import Callable
from types import SimpleNamespace

import pytest

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
from abssctl.doctor.engine import (
    _duration_ms,
    _run_single_probe,
    _unexpected_failure,
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
        node_runtime=sentinel,
        node_compat=sentinel,
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
        node_runtime=sentinel,
        node_compat=sentinel,
    )

    options = ProbeExecutorOptions(max_concurrency=3)
    context = create_probe_context(runtime, options)
    assert context.config is sentinel
    assert context.nginx_provider is sentinel
    assert context.options.max_concurrency == 3


def test_create_probe_context_defaults_options() -> None:
    """create_probe_context should supply default options when none provided."""
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
        node_runtime=sentinel,
        node_compat=sentinel,
    )

    defaults = ProbeExecutorOptions()
    context = create_probe_context(runtime)
    assert isinstance(context.options, ProbeExecutorOptions)
    assert context.options.max_concurrency == defaults.max_concurrency


def test_create_probe_context_mirrors_all_runtime_fields() -> None:
    """Every runtime dependency should be mirrored into the ProbeContext."""
    runtime = RuntimeContext(
        config="cfg",
        registry="registry",
        ports="ports",
        version_provider="vp",
        version_installer="vi",
        instance_status_provider="status",
        locks="locks",
        logger="logger",
        templates="templates",
        systemd_provider="systemd",
        nginx_provider="nginx",
        backups="backups",
        tls_inspector="inspector",
        tls_validator="validator",
        node_runtime="node-runtime",
        node_compat="compat",
    )
    options = ProbeExecutorOptions(max_concurrency=5)
    context = create_probe_context(runtime, options)
    assert context.config == "cfg"
    assert context.registry == "registry"
    assert context.ports == "ports"
    assert context.version_provider == "vp"
    assert context.version_installer == "vi"
    assert context.instance_status_provider == "status"
    assert context.locks == "locks"
    assert context.logger == "logger"
    assert context.templates == "templates"
    assert context.systemd_provider == "systemd"
    assert context.nginx_provider == "nginx"
    assert context.backups == "backups"
    assert context.tls_inspector == "inspector"
    assert context.tls_validator == "validator"
    assert context.node_runtime == "node-runtime"
    assert context.node_compat == "compat"
    assert context.options is options


def test_duration_ms_tracks_elapsed(monkeypatch: pytest.MonkeyPatch) -> None:
    """_duration_ms should convert perf_counter deltas to milliseconds."""
    monkeypatch.setattr("abssctl.doctor.engine.time.perf_counter", lambda: 10.5)
    assert _duration_ms(10.0) == 500


def test_unexpected_failure_wraps_exception() -> None:
    """_unexpected_failure should capture metadata about probe errors."""
    probe = ProbeDefinition(
        id="failing",
        category="env",
        run=lambda ctx: ProbeResult(
            id="failing",
            category="env",
            status=ProbeStatus.GREEN,
            impact=DoctorImpact.OK,
            message="ok",
        ),
    )
    result: ProbeResult
    exc: RuntimeError | None = None
    try:
        raise RuntimeError("boom")
    except RuntimeError as caught:
        exc = caught
        result = _unexpected_failure(probe, caught, 42)
    assert exc is not None
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.PROVIDER
    assert "failing" in result.message and "boom" in result.message
    assert result.duration_ms == 42
    assert result.warnings == ("unhandled-exception",)
    assert isinstance(result.data, dict)
    assert result.data["exception"] == repr(exc)
    assert "RuntimeError" in result.data["traceback"]


def test_run_single_probe_coerces_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    """_run_single_probe should align id/category and populate duration."""
    probe = ProbeDefinition(
        id="expected-id",
        category="env",
        run=lambda ctx: ProbeResult(
            id="mismatch",
            category="config",
            status=ProbeStatus.GREEN,
            impact=DoctorImpact.OK,
            message="done",
        ),
    )

    monkeypatch.setattr("abssctl.doctor.engine.time.perf_counter", lambda: 0.0)
    monkeypatch.setattr("abssctl.doctor.engine._duration_ms", lambda start: 100)
    context = _dummy_context(ProbeExecutorOptions())
    result = _run_single_probe(probe, context)
    assert result.id == "expected-id"
    assert result.category == "env"
    assert result.duration_ms == 100


def test_run_single_probe_handles_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exceptions inside probe.run should be wrapped via _unexpected_failure."""
    def _broken(ctx: ProbeContext) -> ProbeResult:
        raise RuntimeError("fail")

    probe = ProbeDefinition(id="broken", category="state", run=_broken)
    monkeypatch.setattr("abssctl.doctor.engine.time.perf_counter", lambda: 0.0)
    monkeypatch.setattr("abssctl.doctor.engine._duration_ms", lambda start: 50)
    context = _dummy_context(ProbeExecutorOptions())
    result = _run_single_probe(probe, context)
    assert result.status is ProbeStatus.RED
    assert result.impact is DoctorImpact.PROVIDER
    assert result.duration_ms == 50


def test_run_probes_honours_max_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    """ThreadPoolExecutor should honour the configured max_concurrency."""
    captured: dict[str, object] = {}

    class FakeExecutor:
        def __init__(self, max_workers: int) -> None:
            captured["max_workers"] = max_workers
            self._futures: list[concurrent.futures.Future] = []

        def __enter__(self) -> FakeExecutor:
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            tb: BaseException | None,
        ) -> bool:
            return False

        def submit(
            self,
            func: Callable[..., ProbeResult],
            *args: object,
            **kwargs: object,
        ) -> concurrent.futures.Future:
            future: concurrent.futures.Future = concurrent.futures.Future()
            try:
                result = func(*args, **kwargs)
                future.set_result(result)
            except Exception as exc:  # pragma: no cover - defensive
                future.set_exception(exc)
            self._futures.append(future)
            return future

    monkeypatch.setattr(concurrent.futures, "ThreadPoolExecutor", FakeExecutor)

    options = ProbeExecutorOptions(max_concurrency=4)
    context = _dummy_context(options)
    probes = [
        ProbeDefinition(
            id="p1",
            category="env",
            run=lambda ctx: ProbeResult(
                id="p1",
                category="env",
                status=ProbeStatus.GREEN,
                impact=DoctorImpact.OK,
                message="ok",
            ),
        )
    ]
    run_probes(context, probes)
    assert captured["max_workers"] == 4
