"""Unit tests for TLS helper utilities."""
from __future__ import annotations

import grp
import os
import pwd
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from abssctl.config import TLSPermissionSpec, TLSValidationConfig, load_config
from abssctl.tls import (
    TLSConfigurationError,
    TLSInspector,
    TLSMaterial,
    TLSSourceSelection,
    TLSValidationSeverity,
    TLSValidator,
    _load_certificate,
    _load_private_key,
    _permission_matches,
    _public_keys_match,
)


def _current_owner_group() -> tuple[str, str]:
    uid = os.getuid()
    gid = os.getgid()
    owner = pwd.getpwuid(uid).pw_name
    group = grp.getgrgid(gid).gr_name
    return owner, group


def _create_self_signed_cert(
    tmp_path: Path,
    *,
    common_name: str = "example.test",
    valid_from: datetime | None = None,
    valid_to: datetime | None = None,
) -> tuple[Path, Path]:
    default_now = datetime.now(UTC)
    if valid_to is not None and (valid_from is None or valid_from >= valid_to):
        valid_from = valid_to - timedelta(days=30)
    valid_from = valid_from or (default_now - timedelta(days=1))
    valid_to = valid_to or (default_now + timedelta(days=90))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_path = tmp_path / f"{common_name.replace('.', '_')}.key"
    cert_path = tmp_path / f"{common_name.replace('.', '_')}.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.chmod(0o640)
    cert_path.chmod(0o644)
    return cert_path, key_path


def _create_validation_config() -> TLSValidationConfig:
    owner, group = _current_owner_group()
    return TLSValidationConfig(
        warn_expiry_days=30,
        key_permissions=(
            TLSPermissionSpec(owner=owner, group=group, mode=0o640),
            TLSPermissionSpec(owner=owner, group=group, mode=0o600),
        ),
        cert_permissions=TLSPermissionSpec(owner=owner, group=group, mode=0o644),
        chain_permissions=TLSPermissionSpec(owner=owner, group=group, mode=0o644),
    )


def _build_config(tmp_path: Path, validation: TLSValidationConfig) -> tuple[Path, object]:
    owner, group = _current_owner_group()
    system_cert = tmp_path / "system-cert.pem"
    system_key = tmp_path / "system-key.pem"
    system_cert.write_text("system-cert\n", encoding="utf-8")
    system_key.write_text("system-key\n", encoding="utf-8")
    system_cert.chmod(0o644)
    system_key.chmod(0o640)

    overrides = {
        "install_root": str(tmp_path / "app"),
        "instance_root": str(tmp_path / "instances"),
        "state_dir": str(tmp_path / "state"),
        "logs_dir": str(tmp_path / "logs"),
        "runtime_dir": str(tmp_path / "run"),
        "templates_dir": str(tmp_path / "templates"),
        "backups": {"root": str(tmp_path / "backups")},
        "service_user": owner,
        "tls": {
            "system": {"cert": str(system_cert), "key": str(system_key)},
            "lets_encrypt": {"live_dir": str(tmp_path / "le")},
            "validation": {
                "warn_expiry_days": validation.warn_expiry_days,
                "key_permissions": [
                    {
                        "owner": perm.owner,
                        "group": perm.group,
                        "mode": f"{perm.mode:04o}",
                    }
                    for perm in validation.key_permissions
                ],
                "cert_permissions": {
                    "owner": validation.cert_permissions.owner,
                    "group": validation.cert_permissions.group,
                    "mode": f"{validation.cert_permissions.mode:04o}",
                },
                "chain_permissions": {
                    "owner": validation.chain_permissions.owner,
                    "group": validation.chain_permissions.group,
                    "mode": f"{validation.chain_permissions.mode:04o}",
                },
            },
        },
    }
    config = load_config(overrides=overrides)
    return config, overrides


def test_tls_validator_reports_success(tmp_path: Path) -> None:
    """TLSValidator returns OK when files match and permissions align."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)
    validator = TLSValidator(validation)
    cert_path, key_path = _create_self_signed_cert(tmp_path)
    selection = inspector.resolve_manual(certificate=cert_path, key=key_path, source="custom")

    report = validator.validate(selection, now=datetime.now(UTC))

    assert report.status is TLSValidationSeverity.OK
    assert not report.has_errors
    assert any(
        finding.check == "match"
        and finding.severity is TLSValidationSeverity.OK
        for finding in report.findings
    )
    assert any(
        finding.scope == "certificate"
        and finding.check == "permissions"
        and finding.severity is TLSValidationSeverity.OK
        for finding in report.findings
    )
    assert any(
        finding.scope == "key"
        and finding.check == "permissions"
        and finding.severity is TLSValidationSeverity.OK
        for finding in report.findings
    )


def test_tls_validator_detects_mismatched_key(tmp_path: Path) -> None:
    """Validator surfaces mismatch between certificate and private key."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)
    validator = TLSValidator(validation)
    cert_path, key_path = _create_self_signed_cert(tmp_path)
    other_cert, other_key = _create_self_signed_cert(tmp_path, common_name="other.test")
    other_cert.unlink()  # only need the alternate key
    selection = inspector.resolve_manual(certificate=cert_path, key=other_key, source="custom")

    report = validator.validate(selection, now=datetime.now(UTC))

    assert report.status is TLSValidationSeverity.ERROR
    assert report.has_errors
    assert any(
        finding.check == "match"
        and finding.severity is TLSValidationSeverity.ERROR
        for finding in report.findings
    )


def test_tls_validator_warns_when_cert_expiring(tmp_path: Path) -> None:
    """Validator issues warnings when certificate expiry approaches threshold."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)
    validator = TLSValidator(validation)
    soon = datetime.now(UTC) + timedelta(days=5)
    cert_path, key_path = _create_self_signed_cert(
        tmp_path,
        valid_to=soon,
    )
    selection = inspector.resolve_manual(certificate=cert_path, key=key_path)

    report = validator.validate(selection, now=datetime.now(UTC))

    assert report.status is TLSValidationSeverity.WARNING
    assert report.has_warnings
    assert any(f.check == "expiry" for f in report.findings)


def test_tls_validator_errors_on_expired_cert(tmp_path: Path) -> None:
    """Validator errors when certificate is expired."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)
    validator = TLSValidator(validation)
    expired_at = datetime.now(UTC) - timedelta(days=1)
    cert_path, key_path = _create_self_signed_cert(
        tmp_path,
        valid_to=expired_at,
    )
    selection = inspector.resolve_manual(certificate=cert_path, key=key_path)

    report = validator.validate(selection, now=datetime.now(UTC))

    assert report.status is TLSValidationSeverity.ERROR
    assert report.has_errors
    assert any(
        f.check == "expiry" and f.severity is TLSValidationSeverity.ERROR for f in report.findings
    )


def test_tls_inspector_detects_lets_encrypt(tmp_path: Path) -> None:
    """TLSInspector resolves Let's Encrypt assets when present."""
    validation = _create_validation_config()
    config, overrides = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)

    live_dir = Path(overrides["tls"]["lets_encrypt"]["live_dir"])
    domain_dir = live_dir / "app.example"
    domain_dir.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = _create_self_signed_cert(tmp_path, common_name="le.test")
    le_cert = domain_dir / "fullchain.pem"
    le_key = domain_dir / "privkey.pem"
    le_cert.write_bytes(cert_path.read_bytes())
    le_key.write_bytes(key_path.read_bytes())
    (domain_dir / "chain.pem").write_bytes(cert_path.read_bytes())

    entry = {"name": "app", "domain": "app.example"}
    selection = inspector.resolve_for_instance("app", entry)

    assert selection.resolved == "lets-encrypt"
    assert selection.material.certificate == le_cert
    assert selection.material.key == le_key


def test_tls_inspector_falls_back_to_system(tmp_path: Path) -> None:
    """TLSInspector falls back to system defaults when no LE cert is present."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)
    entry = {"name": "app", "domain": "app.example"}

    selection = inspector.resolve_for_instance("app", entry)

    assert selection.resolved == "system"
    assert selection.material.certificate == config.tls.system.cert
    assert selection.material.key == config.tls.system.key


def test_tls_inspector_requires_custom_paths(tmp_path: Path) -> None:
    """Custom source without stored paths raises TLSConfigurationError."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)
    entry = {"name": "app", "domain": "app.example", "tls": {"source": "custom"}}

    with pytest.raises(TLSConfigurationError):
        inspector.resolve_for_instance("app", entry, source_override="custom")


def test_tls_inspector_manual_override_short_circuits(tmp_path: Path) -> None:
    """Explicit certificate and key parameters should bypass registry lookups."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)
    cert = tmp_path / "manual.pem"
    key = tmp_path / "manual.key"
    cert.write_text("cert", encoding="utf-8")
    key.write_text("key", encoding="utf-8")

    selection = inspector.resolve_for_instance(
        "alpha",
        {},
        certificate=cert,
        key=key,
    )

    assert selection.requested == "custom"
    assert selection.material.certificate == cert
    assert selection.material.key == key


def test_tls_inspector_destination_for_instance_sanitises_name(tmp_path: Path) -> None:
    """Derive destination paths using a normalised instance name."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)

    material = inspector.destination_for_instance("foo/bar")

    assert material.certificate.name == "abssctl-foo-bar.pem"
    assert material.key.name == "abssctl-foo-bar.key"
    assert material.chain and material.chain.name == "abssctl-foo-bar.chain.pem"


def test_tls_inspector_resolve_custom_from_entry(tmp_path: Path) -> None:
    """Registry custom entries should resolve to expanded paths."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)
    cert_path = tmp_path / "custom-cert.pem"
    key_path = tmp_path / "custom-key.pem"
    chain_path = tmp_path / "custom-chain.pem"
    for path in (cert_path, key_path, chain_path):
        path.write_text(path.name, encoding="utf-8")
    entry = {
        "name": "alpha",
        "tls": {
            "source": "custom",
            "cert": str(cert_path),
            "key": str(key_path),
            "chain": str(chain_path),
        },
    }

    selection = inspector.resolve_for_instance("alpha", entry)

    assert selection.resolved == "custom"
    assert selection.material.certificate == cert_path
    assert selection.material.chain == chain_path


def test_tls_inspector_expands_user_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Custom entries containing a tilde should expand to absolute paths."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_text("cert", encoding="utf-8")
    key_path.write_text("key", encoding="utf-8")

    monkeypatch.setenv("HOME", str(tmp_path))
    entry = {
        "name": "alpha",
        "tls": {"source": "custom", "cert": "~/cert.pem", "key": "~/key.pem"},
    }

    selection = inspector.resolve_for_instance("alpha", entry)
    assert selection.material.certificate == cert_path
    assert selection.material.key == key_path


def test_tls_validator_reports_missing_files(tmp_path: Path) -> None:
    """Validator should highlight missing TLS artefacts."""
    validation = _create_validation_config()
    validator = TLSValidator(validation)
    material = TLSMaterial(
        certificate=tmp_path / "missing-cert.pem",
        key=tmp_path / "missing-key.pem",
        chain=None,
    )
    selection = TLSSourceSelection(
        requested="custom",
        resolved="custom",
        material=material,
        domain="alpha.example",
    )

    report = validator.validate(selection, now=datetime.now(UTC))

    findings = {(finding.scope, finding.check) for finding in report.findings}
    assert ("certificate", "exists") in findings
    assert ("key", "exists") in findings
    assert report.status is TLSValidationSeverity.ERROR


def test_tls_validator_flags_permission_mismatch(tmp_path: Path) -> None:
    """Incorrect permission modes should be reported as errors."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)
    validator = TLSValidator(validation)
    cert_path, key_path = _create_self_signed_cert(tmp_path)
    key_path.chmod(0o400)
    selection = inspector.resolve_manual(certificate=cert_path, key=key_path)

    report = validator.validate(selection, now=datetime.now(UTC))

    assert any(
        finding.check == "permissions" and finding.severity is TLSValidationSeverity.ERROR
        for finding in report.findings
    )


def test_tls_validator_handles_unreadable_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Files failing readability checks should produce errors."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)
    validator = TLSValidator(validation)
    cert_path, key_path = _create_self_signed_cert(tmp_path)

    original_access = os.access

    def deny_read(path: Path, mode: int) -> bool:
        if path == key_path:
            return False
        return original_access(path, mode)

    monkeypatch.setattr(os, "access", deny_read)
    selection = inspector.resolve_manual(certificate=cert_path, key=key_path)

    report = validator.validate(selection, now=datetime.now(UTC))

    assert any(
        finding.scope == "key"
        and finding.check == "readable"
        and finding.severity is TLSValidationSeverity.ERROR
        for finding in report.findings
    )


def test_tls_validator_chain_permission_error(tmp_path: Path) -> None:
    """Chain files should respect configured permission policies."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)
    validator = TLSValidator(validation)
    cert_path, key_path = _create_self_signed_cert(tmp_path)
    chain_path = tmp_path / "chain.pem"
    chain_path.write_text("chain", encoding="utf-8")
    chain_path.chmod(0o600)  # more restrictive than allowed 0644

    selection = inspector.resolve_manual(
        certificate=cert_path,
        key=key_path,
        chain=chain_path,
    )

    report = validator.validate(selection, now=datetime.now(UTC))
    assert any(
        finding.scope == "chain"
        and finding.check == "permissions"
        and finding.severity is TLSValidationSeverity.ERROR
        for finding in report.findings
    )


def test_tls_validator_detects_directory_certificate(tmp_path: Path) -> None:
    """Directory paths should be flagged as invalid certificate locations."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    validator = TLSValidator(validation)
    cert_dir = tmp_path / "certdir"
    cert_dir.mkdir()
    key_path = tmp_path / "key.pem"
    key_path.write_text("key", encoding="utf-8")
    selection = TLSSourceSelection(
        requested="custom",
        resolved="custom",
        material=TLSMaterial(certificate=cert_dir, key=key_path, chain=None),
        domain="alpha.example",
    )

    report = validator.validate(selection, now=datetime.now(UTC))
    assert any(
        finding.scope == "certificate"
        and finding.check == "type"
        and finding.severity is TLSValidationSeverity.ERROR
        for finding in report.findings
    )


def test_tls_validator_reports_parse_errors(tmp_path: Path) -> None:
    """Malformed certificate/key files should record parse errors."""
    validation = _create_validation_config()
    config, _ = _build_config(tmp_path, validation)
    inspector = TLSInspector(config)
    validator = TLSValidator(validation)
    cert_path = tmp_path / "broken-cert.pem"
    key_path = tmp_path / "broken-key.pem"
    cert_path.write_text("not-a-cert", encoding="utf-8")
    key_path.write_text("not-a-key", encoding="utf-8")
    selection = inspector.resolve_manual(certificate=cert_path, key=key_path)

    report = validator.validate(selection, now=datetime.now(UTC))

    assert any(
        finding.scope == "certificate"
        and finding.check == "parse"
        and finding.severity is TLSValidationSeverity.ERROR
        for finding in report.findings
    )
    assert any(
        finding.scope == "key"
        and finding.check == "parse"
        and finding.severity is TLSValidationSeverity.ERROR
        for finding in report.findings
    )


def test_permission_matches_respects_owner_group_mode() -> None:
    """_permission_matches should honour owner/group/mode requirements."""
    owner, group = _current_owner_group()
    spec = TLSPermissionSpec(owner=owner, group=group, mode=0o640)
    assert _permission_matches(spec, owner, group, 0o640)
    assert not _permission_matches(spec, owner, "other", 0o640)
    assert not _permission_matches(spec, owner, group, 0o600)


def test_load_certificate_and_private_key_round_trip(tmp_path: Path) -> None:
    """Loading certificate/private key should produce matching public keys."""
    cert_path, key_path = _create_self_signed_cert(tmp_path)

    cert = _load_certificate(cert_path)
    key = _load_private_key(key_path)

    assert cert.serial_number > 0
    assert _public_keys_match(cert, key)

    other_key_path = tmp_path / "other.key"
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_key_bytes = other_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    other_key_path.write_bytes(other_key_bytes)
    mismatched_key = _load_private_key(other_key_path)
    assert not _public_keys_match(cert, mismatched_key)
