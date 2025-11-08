"""Utility helpers for serialising doctor reports."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from .models import DoctorReport, ProbeStatus


def _sanitize_payload(value: object) -> object:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _sanitize_payload(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_sanitize_payload(item) for item in value]
    return str(value)


def serialize_report(report: DoctorReport) -> dict[str, object]:
    """Convert a doctor report into a JSON-serialisable mapping."""
    totals = {
        status.value: int(report.summary.totals.get(status, 0))
        for status in ProbeStatus
    }
    summary_payload = {
        "status": report.summary.status.value,
        "impact": report.summary.impact.name.lower(),
        "impact_code": report.summary.impact.value,
        "exit_code": report.summary.exit_code,
        "totals": totals,
    }
    results_payload: list[dict[str, object]] = []
    for result in report.results:
        result_payload: dict[str, object] = {
            "id": result.id,
            "category": result.category,
            "status": result.status.value,
            "impact": result.impact.name.lower(),
            "impact_code": result.impact.value,
            "message": result.message,
        }
        if result.remediation:
            result_payload["remediation"] = result.remediation
        if result.duration_ms is not None:
            result_payload["duration_ms"] = result.duration_ms
        if result.data:
            result_payload["data"] = _sanitize_payload(result.data)
        if result.warnings:
            result_payload["warnings"] = list(result.warnings)
        results_payload.append(result_payload)

    metadata_payload = _sanitize_payload(report.metadata) if report.metadata else {}
    return {
        "summary": summary_payload,
        "results": results_payload,
        "metadata": metadata_payload,
    }
