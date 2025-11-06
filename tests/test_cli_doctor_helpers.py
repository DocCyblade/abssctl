"""Focused tests for doctor helper utilities in the CLI."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from typing import Any

import pytest

from abssctl.cli import _render_doctor_report, _sanitize_doctor_payload, _serialize_doctor_report
from abssctl.doctor import DoctorImpact, DoctorReport, DoctorSummary, ProbeResult, ProbeStatus


class _Unserialisable:
    """Custom object that stringifies to a helpful message."""

    def __str__(self) -> str:
        return "<unserialisable>"


def _build_report(*results: ProbeResult, metadata: dict[str, Any] | None = None) -> DoctorReport:
    """Return a DoctorReport with a simple summary derived from *results*."""
    totals = {
        ProbeStatus.GREEN: 0,
        ProbeStatus.YELLOW: 0,
        ProbeStatus.RED: 0,
    }
    impact = DoctorImpact.OK
    status = ProbeStatus.GREEN
    for result in results:
        totals[result.status] += 1
        if result.status is ProbeStatus.RED:
            status = ProbeStatus.RED
        elif result.status is ProbeStatus.YELLOW and status is ProbeStatus.GREEN:
            status = ProbeStatus.YELLOW
        if result.impact.value > impact.value:
            impact = result.impact
    summary = DoctorSummary(
        status=status,
        impact=impact,
        exit_code=impact.value,
        totals=totals,
    )
    return DoctorReport(results=results, summary=summary, metadata=metadata)


def test_sanitize_doctor_payload_handles_paths_and_objects(tmp_path: Path) -> None:
    """Non-serialisable doctor payload values should become JSON-safe."""
    payload = {
        tmp_path / "key.pem": tmp_path,
        "values": [
            Path("logs"),
            {"set": {1, 2}},
            _Unserialisable(),
        ],
    }

    result = _sanitize_doctor_payload(payload)

    assert result == {
        str(tmp_path / "key.pem"): str(tmp_path),
        "values": [
            str(Path("logs")),
            {"set": "{1, 2}"},
            "<unserialisable>",
        ],
    }


def test_serialize_doctor_report_includes_sanitised_results(tmp_path: Path) -> None:
    """Serialisation should emit human/JSON friendly structures."""
    red_result = ProbeResult(
        id="state-reconcile",
        category="state",
        status=ProbeStatus.RED,
        impact=DoctorImpact.VALIDATION,
        message="Mismatch detected",
        remediation="Fix registry entries",
        duration_ms=125,
        data={"path": tmp_path, "warnings": ("note",)},
        warnings=("state:mismatch",),
    )
    yellow_result = ProbeResult(
        id="env-zstd",
        category="env",
        status=ProbeStatus.YELLOW,
        impact=DoctorImpact.OK,
        message="Optional binary missing",
        warnings=("missing:zstd",),
    )
    report = _build_report(
        red_result,
        yellow_result,
        metadata={"paths": {Path("/var/lib"): Path("/tmp")}},
    )

    payload = _serialize_doctor_report(report)

    assert payload["summary"]["status"] == "red"
    assert payload["summary"]["exit_code"] == DoctorImpact.VALIDATION.value
    assert payload["summary"]["totals"] == {"green": 0, "yellow": 1, "red": 1}
    assert payload["results"][0]["data"] == {
        "path": str(tmp_path),
        "warnings": ["note"],
    }
    assert payload["metadata"] == {"paths": {"/var/lib": "/tmp"}}


def test_render_doctor_report_outputs_expected_sections(monkeypatch: pytest.MonkeyPatch) -> None:
    """Human rendering should emit summary, totals, and probe details."""
    green = ProbeResult(
        id="env-python",
        category="env",
        status=ProbeStatus.GREEN,
        impact=DoctorImpact.OK,
        message="Python detected",
        duration_ms=12,
    )
    yellow = ProbeResult(
        id="env-zstd",
        category="env",
        status=ProbeStatus.YELLOW,
        impact=DoctorImpact.OK,
        message="Optional binary missing",
        warnings=("missing:zstd",),
    )
    red = ProbeResult(
        id="state-reconcile",
        category="state",
        status=ProbeStatus.RED,
        impact=DoctorImpact.VALIDATION,
        message="Registry mismatch",
        remediation="Run abssctl system init --rebuild-state",
    )
    report = _build_report(green, yellow, red)

    stream = StringIO()

    class DummyConsole:
        """Minimal console stand-in capturing printed output."""

        def __init__(self, io_stream: StringIO) -> None:
            self._stream = io_stream

        def print(self, *args: object, **kwargs: object) -> None:
            """Capture printed text similar to rich.Console.print."""
            end = kwargs.get("end", "\n")
            sep = kwargs.get("sep", " ")
            text = sep.join(str(arg) for arg in args) if args else ""
            self._stream.write(text + end)

    fake_console = DummyConsole(stream)
    monkeypatch.setattr("abssctl.cli.console", fake_console)

    _render_doctor_report(report)

    output = stream.getvalue()
    assert "Doctor summary: [red]RED[/red] (impact=validation, exit=2)" in output
    assert "Totals: green=1 warn=1 red=1" in output
    assert "[red]FAIL[/red] [state] state-reconcile: Registry mismatch" in output
    assert "remediation: Run abssctl system init --rebuild-state" in output
    assert "[yellow]WARN[/yellow] [env] env-zstd: Optional binary missing" in output
