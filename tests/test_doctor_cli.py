"""Tests for the ``abssctl doctor`` CLI command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from abssctl.cli import app
from abssctl.doctor import (
    DoctorImpact,
    ProbeContext,
    ProbeDefinition,
    ProbeResult,
    ProbeStatus,
)
from tests.test_cli import _prepare_environment

runner = CliRunner()


def _probe_factory(
    *,
    probe_id: str,
    category: str,
    status: ProbeStatus,
    impact: DoctorImpact,
    message: str,
    remediation: str | None = None,
) -> ProbeDefinition:
    """Return a probe definition that yields a static result."""

    def _run(_context: ProbeContext) -> ProbeResult:
        return ProbeResult(
            id=probe_id,
            category=category,
            status=status,
            impact=impact,
            message=message,
            remediation=remediation,
        )

    return ProbeDefinition(id=probe_id, category=category, run=_run)


def _patch_probes(
    monkeypatch: pytest.MonkeyPatch,
    probes: list[ProbeDefinition],
) -> None:
    """Patch ``collect_probes`` to return *probes*."""
    def factory(_context: ProbeContext) -> tuple[ProbeDefinition, ...]:
        return tuple(probes)

    monkeypatch.setattr("abssctl.cli.collect_probes", factory)
    monkeypatch.setattr("abssctl.doctor.collect_probes", factory)


def test_doctor_cli_reports_warnings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Doctor command should report warnings without failing."""
    env, _ = _prepare_environment(tmp_path)
    probes = [
        _probe_factory(
            probe_id="env-python",
            category="env",
            status=ProbeStatus.GREEN,
            impact=DoctorImpact.OK,
            message="Python runtime detected.",
        ),
        _probe_factory(
            probe_id="tls-expiry",
            category="tls",
            status=ProbeStatus.YELLOW,
            impact=DoctorImpact.OK,
            message="TLS certificate expires in 20 days.",
            remediation="Renew certificate soon.",
        ),
    ]
    _patch_probes(monkeypatch, probes)

    result = runner.invoke(app, ["doctor"], env=env)

    assert result.exit_code == 0, result.stdout
    assert "Doctor summary: WARN" in result.stdout
    assert "WARN  tls-expiry" in result.stdout
    assert "tls-expiry" in result.stdout
    assert "Totals: green=1 warn=1 red=0" in result.stdout


def test_doctor_cli_reports_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Doctor command should surface provider failures with exit code 4."""
    env, _ = _prepare_environment(tmp_path)
    probes = [
        _probe_factory(
            probe_id="nginx-config",
            category="nginx",
            status=ProbeStatus.RED,
            impact=DoctorImpact.PROVIDER,
            message="nginx -t reported a syntax error.",
            remediation="Run nginx -t manually to inspect errors.",
        ),
    ]
    _patch_probes(monkeypatch, probes)

    result = runner.invoke(app, ["doctor"], env=env)

    assert result.exit_code == DoctorImpact.PROVIDER.value
    assert "Doctor summary: RED" in result.stdout
    assert "FAIL  nginx-config" in result.stdout
    assert "provider/service failures" in result.stdout


def test_doctor_cli_json_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Doctor command should emit structured JSON when requested."""
    env, _ = _prepare_environment(tmp_path)
    probes = [
        _probe_factory(
            probe_id="missing-tool",
            category="env",
            status=ProbeStatus.RED,
            impact=DoctorImpact.ENVIRONMENT,
            message="`node` binary not found on PATH.",
        ),
    ]
    _patch_probes(monkeypatch, probes)

    result = runner.invoke(app, ["doctor", "--json"], env=env)

    assert result.exit_code == DoctorImpact.ENVIRONMENT.value
    payload = json.loads(result.stdout)
    assert payload["summary"]["status"] == "red"
    assert payload["summary"]["exit_code"] == DoctorImpact.ENVIRONMENT.value
    assert payload["results"][0]["id"] == "missing-tool"
    assert payload["metadata"]["matched_probes"] == 1


def test_doctor_cli_only_filter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Doctor command should honour --only category filters."""
    env, _ = _prepare_environment(tmp_path)
    probes = [
        _probe_factory(
            probe_id="env-python",
            category="env",
            status=ProbeStatus.GREEN,
            impact=DoctorImpact.OK,
            message="Python runtime detected.",
        ),
        _probe_factory(
            probe_id="config-state",
            category="config",
            status=ProbeStatus.GREEN,
            impact=DoctorImpact.OK,
            message="Registry schema matches.",
        ),
    ]
    _patch_probes(monkeypatch, probes)

    result = runner.invoke(app, ["doctor", "--json", "--only", "config"], env=env)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert len(payload["results"]) == 1
    assert payload["results"][0]["category"] == "config"
    assert payload["metadata"]["matched_probes"] == 1


def test_doctor_cli_only_filter_no_matches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Doctor command should warn when filters match no probes."""
    env, _ = _prepare_environment(tmp_path)
    probes = [
        _probe_factory(
            probe_id="env-python",
            category="env",
            status=ProbeStatus.GREEN,
            impact=DoctorImpact.OK,
            message="Python runtime detected.",
        ),
    ]
    _patch_probes(monkeypatch, probes)

    result = runner.invoke(app, ["doctor", "--only", "config"], env=env)

    assert result.exit_code == 0
    assert "No probes matched the provided filters" in result.stdout


def test_doctor_cli_fix_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Doctor command should acknowledge --fix without performing actions."""
    env, _ = _prepare_environment(tmp_path)
    _patch_probes(monkeypatch, [])

    result = runner.invoke(app, ["doctor", "--fix"], env=env)

    assert result.exit_code == 0
    assert "--fix is not implemented yet" in result.stdout


def test_doctor_cli_rejects_invalid_category(tmp_path: Path) -> None:
    """Doctor command should reject unknown categories."""
    env, _ = _prepare_environment(tmp_path)
    result = runner.invoke(app, ["doctor", "--only", "unknown"], env=env)

    assert result.exit_code == 2
    assert "Unknown probe categories" in result.stdout
