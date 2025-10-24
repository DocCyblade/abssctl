"""TLS helpers for abssctl commands."""
from __future__ import annotations

import os
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Protocol, cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .config import AppConfig, TLSPermissionSpec, TLSValidationConfig


class TLSConfigurationError(RuntimeError):
    """Raised when TLS configuration cannot be resolved."""


class TLSValidationSeverity(Enum):
    """Validation severities for TLS checks."""

    OK = "ok"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class TLSValidationFinding:
    """Individual validation check outcome."""

    scope: str
    check: str
    severity: TLSValidationSeverity
    message: str
    path: Path | None = None


@dataclass(frozen=True)
class TLSMaterial:
    """Concrete TLS assets (certificate, private key, optional chain)."""

    certificate: Path
    key: Path
    chain: Path | None = None


@dataclass(frozen=True)
class TLSSourceSelection:
    """Resolved TLS material including source metadata."""

    requested: str
    resolved: str
    material: TLSMaterial
    domain: str | None


@dataclass(frozen=True)
class TLSValidationReport:
    """Aggregate validation results for a TLS material."""

    selection: TLSSourceSelection
    findings: tuple[TLSValidationFinding, ...]
    not_valid_before: datetime | None
    not_valid_after: datetime | None

    @property
    def has_errors(self) -> bool:
        """Return True when any finding is classified as an error."""
        return any(f.severity is TLSValidationSeverity.ERROR for f in self.findings)

    @property
    def has_warnings(self) -> bool:
        """Return True when the report includes warning findings."""
        return any(f.severity is TLSValidationSeverity.WARNING for f in self.findings)

    @property
    def status(self) -> TLSValidationSeverity:
        """Return the overall status derived from the findings."""
        if self.has_errors:
            return TLSValidationSeverity.ERROR
        if self.has_warnings:
            return TLSValidationSeverity.WARNING
        return TLSValidationSeverity.OK

    def to_dict(self) -> dict[str, object]:
        """Return a serialisable representation of the report."""
        return {
            "requested_source": self.selection.requested,
            "resolved_source": self.selection.resolved,
            "domain": self.selection.domain,
            "paths": {
                "certificate": str(self.selection.material.certificate),
                "key": str(self.selection.material.key),
                "chain": (
                    str(self.selection.material.chain)
                    if self.selection.material.chain is not None
                    else None
                ),
            },
            "status": self.status.value,
            "not_valid_before": (
                self.not_valid_before.isoformat() if self.not_valid_before else None
            ),
            "not_valid_after": (
                self.not_valid_after.isoformat() if self.not_valid_after else None
            ),
            "findings": [
                {
                    "scope": finding.scope,
                    "check": finding.check,
                    "severity": finding.severity.value,
                    "message": finding.message,
                    "path": str(finding.path) if finding.path is not None else None,
                }
                for finding in self.findings
            ],
        }


class PublicKeyProtocol(Protocol):
    """Protocol covering public keys exposing ``public_bytes``."""

    def public_bytes(
        self,
        *,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        """Return the public key bytes in the requested encoding/format."""


class PrivateKeyProtocol(Protocol):
    """Protocol for private keys that can provide a matching public key."""

    def public_key(self) -> PublicKeyProtocol:
        """Return the associated public key object."""


class TLSInspector:
    """Resolve TLS assets for instances or manual verification."""

    def __init__(self, config: AppConfig) -> None:
        """Initialise the inspector with loaded application configuration."""
        self._config = config

    def resolve_manual(
        self,
        *,
        certificate: Path,
        key: Path,
        chain: Path | None = None,
        source: str = "manual",
    ) -> TLSSourceSelection:
        """Return a manual TLS selection."""
        material = TLSMaterial(
            certificate=certificate,
            key=key,
            chain=chain,
        )
        return TLSSourceSelection(
            requested=source,
            resolved="custom" if source in {"custom", "manual"} else source,
            material=material,
            domain=None,
        )

    def resolve_for_instance(
        self,
        name: str,
        entry: Mapping[str, object],
        *,
        source_override: str | None = None,
        certificate: Path | None = None,
        key: Path | None = None,
        chain: Path | None = None,
    ) -> TLSSourceSelection:
        """Resolve TLS material for an instance registry entry."""
        tls_block_raw = entry.get("tls")
        tls_block = tls_block_raw if isinstance(tls_block_raw, Mapping) else {}
        recorded_source_raw = tls_block.get("source", "auto")
        recorded_source = str(recorded_source_raw).strip().lower()
        requested = (source_override or recorded_source or "auto").strip().lower() or "auto"
        if requested == "auto" and recorded_source in {"custom", "system"}:
            requested = recorded_source

        if certificate is not None and key is not None:
            # Explicit paths always take precedence and imply custom sourcing.
            return self.resolve_manual(
                certificate=certificate,
                key=key,
                chain=chain,
                source="custom",
            )

        domain = _extract_instance_domain(entry) or f"{name}.local"

        if requested == "custom":
            return self._resolve_custom(entry, tls_block, domain)
        if requested == "system":
            return self._resolve_system(domain)
        # auto detection
        le_selection = self._detect_lets_encrypt(domain)
        if le_selection is not None:
            return le_selection
        if recorded_source == "custom":
            # Fallback to stored custom paths when auto with legacy data.
            return self._resolve_custom(entry, tls_block, domain)
        return self._resolve_system(domain)

    def destination_for_instance(self, name: str) -> TLSMaterial:
        """Return destination paths for custom TLS assets for *name*."""
        key_dir = self._config.tls.system.key.parent
        cert_dir = self._config.tls.system.cert.parent
        safe = name.replace("/", "-")
        certificate = cert_dir / f"abssctl-{safe}.pem"
        key = key_dir / f"abssctl-{safe}.key"
        chain = cert_dir / f"abssctl-{safe}.chain.pem"
        return TLSMaterial(certificate=certificate, key=key, chain=chain)

    def _resolve_custom(
        self,
        entry: Mapping[str, object],
        tls_block: Mapping[str, object],
        domain: str,
    ) -> TLSSourceSelection:
        cert_raw = tls_block.get("cert")
        key_raw = tls_block.get("key")
        chain_raw = tls_block.get("chain")
        if not cert_raw or not key_raw:
            raise TLSConfigurationError(
                "Instance registry does not record custom TLS paths; provide --cert/--key."
            )
        material = TLSMaterial(
            certificate=Path(str(cert_raw)).expanduser(),
            key=Path(str(key_raw)).expanduser(),
            chain=Path(str(chain_raw)).expanduser() if chain_raw else None,
        )
        return TLSSourceSelection(
            requested="custom",
            resolved="custom",
            material=material,
            domain=domain,
        )

    def _resolve_system(self, domain: str) -> TLSSourceSelection:
        material = TLSMaterial(
            certificate=self._config.tls.system.cert.expanduser(),
            key=self._config.tls.system.key.expanduser(),
            chain=None,
        )
        return TLSSourceSelection(
            requested="system",
            resolved="system",
            material=material,
            domain=domain,
        )

    def _detect_lets_encrypt(self, domain: str) -> TLSSourceSelection | None:
        live_dir = self._config.tls.lets_encrypt.live_dir / domain
        cert_path = live_dir / "fullchain.pem"
        key_path = live_dir / "privkey.pem"
        chain_path = live_dir / "chain.pem"
        if cert_path.exists() and key_path.exists():
            chain = chain_path if chain_path.exists() else None
            material = TLSMaterial(
                certificate=cert_path,
                key=key_path,
                chain=chain,
            )
            return TLSSourceSelection(
                requested="auto",
                resolved="lets-encrypt",
                material=material,
                domain=domain,
            )
        return None


class TLSValidator:
    """Perform validation checks on TLS material."""

    def __init__(self, validation: TLSValidationConfig) -> None:
        """Capture validation policy (permissions, expiry thresholds)."""
        self._validation = validation

    def validate(
        self,
        selection: TLSSourceSelection,
        *,
        now: datetime | None = None,
    ) -> TLSValidationReport:
        """Validate *selection* and return a structured report."""
        now = now or datetime.now(UTC)
        findings: list[TLSValidationFinding] = []

        certificate = selection.material.certificate
        key = selection.material.key
        chain = selection.material.chain

        cert_exists = self._check_file(certificate, "certificate", findings)
        key_exists = self._check_file(key, "key", findings)
        chain_exists = chain and self._check_file(chain, "chain", findings)

        if cert_exists:
            self._check_permissions(
                certificate,
                "certificate",
                (self._validation.cert_permissions,),
                findings,
            )
        if chain_exists and chain is not None:
            self._check_permissions(
                chain,
                "chain",
                (self._validation.chain_permissions,),
                findings,
            )
        if key_exists:
            self._check_permissions(
                key,
                "key",
                self._validation.key_permissions,
                findings,
            )

        cert_obj: x509.Certificate | None = None
        key_obj: PrivateKeyProtocol | None = None
        not_before: datetime | None = None
        not_after: datetime | None = None

        if cert_exists and key_exists:
            try:
                cert_obj = _load_certificate(certificate)
                findings.append(
                    TLSValidationFinding(
                        scope="certificate",
                        check="parse",
                        severity=TLSValidationSeverity.OK,
                        message=f"Loaded certificate (serial {cert_obj.serial_number})",
                        path=certificate,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - surface parsing error
                findings.append(
                    TLSValidationFinding(
                        scope="certificate",
                        check="parse",
                        severity=TLSValidationSeverity.ERROR,
                        message=f"Failed to parse certificate: {exc}",
                        path=certificate,
                    )
                )

            try:
                key_obj = _load_private_key(key)
                findings.append(
                    TLSValidationFinding(
                        scope="key",
                        check="parse",
                        severity=TLSValidationSeverity.OK,
                        message="Loaded private key.",
                        path=key,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                findings.append(
                    TLSValidationFinding(
                        scope="key",
                        check="parse",
                        severity=TLSValidationSeverity.ERROR,
                        message=f"Failed to parse private key: {exc}",
                        path=key,
                    )
                )

            if cert_obj is not None and key_obj is not None:
                if _public_keys_match(cert_obj, key_obj):
                    findings.append(
                        TLSValidationFinding(
                            scope="certificate",
                            check="match",
                            severity=TLSValidationSeverity.OK,
                            message="Certificate and key match.",
                            path=certificate,
                        )
                    )
                else:
                    findings.append(
                        TLSValidationFinding(
                            scope="certificate",
                            check="match",
                            severity=TLSValidationSeverity.ERROR,
                            message="Certificate does not match the provided key.",
                            path=certificate,
                        )
                    )

        if cert_obj is not None:
            not_before_attr = getattr(cert_obj, "not_valid_before_utc", None)
            not_after_attr = getattr(cert_obj, "not_valid_after_utc", None)
            if isinstance(not_before_attr, datetime) and isinstance(not_after_attr, datetime):
                not_before = not_before_attr
                not_after = not_after_attr
            else:  # pragma: no cover - compatibility fallback
                not_before = _as_utc(cert_obj.not_valid_before)
                not_after = _as_utc(cert_obj.not_valid_after)
            if not_after <= now:
                findings.append(
                    TLSValidationFinding(
                        scope="certificate",
                        check="expiry",
                        severity=TLSValidationSeverity.ERROR,
                        message=f"Certificate expired on {not_after.isoformat()}",
                        path=certificate,
                    )
                )
            else:
                days_remaining = (not_after - now).days
                if days_remaining <= self._validation.warn_expiry_days:
                    findings.append(
                        TLSValidationFinding(
                            scope="certificate",
                            check="expiry",
                            severity=TLSValidationSeverity.WARNING,
                            message=(
                                "Certificate expires soon "
                                f"({not_after.isoformat()}, {days_remaining} day(s) remaining)"
                            ),
                            path=certificate,
                        )
                    )
                else:
                    findings.append(
                        TLSValidationFinding(
                            scope="certificate",
                            check="expiry",
                            severity=TLSValidationSeverity.OK,
                            message=f"Certificate valid until {not_after.isoformat()}",
                            path=certificate,
                        )
                    )

        return TLSValidationReport(
            selection=selection,
            findings=tuple(findings),
            not_valid_before=not_before,
            not_valid_after=not_after,
        )

    def _check_file(
        self,
        path: Path,
        scope: str,
        findings: list[TLSValidationFinding],
    ) -> bool:
        if not path.exists():
            findings.append(
                TLSValidationFinding(
                    scope=scope,
                    check="exists",
                    severity=TLSValidationSeverity.ERROR,
                    message="File does not exist.",
                    path=path,
                )
            )
            return False
        if not path.is_file():
            findings.append(
                TLSValidationFinding(
                    scope=scope,
                    check="type",
                    severity=TLSValidationSeverity.ERROR,
                    message="Path is not a regular file.",
                    path=path,
                )
            )
            return False
        if not os.access(path, os.R_OK):
            findings.append(
                TLSValidationFinding(
                    scope=scope,
                    check="readable",
                    severity=TLSValidationSeverity.ERROR,
                    message="File is not readable by the current user.",
                    path=path,
                )
            )
            return False
        findings.append(
            TLSValidationFinding(
                scope=scope,
                check="exists",
                severity=TLSValidationSeverity.OK,
                message="File present and readable.",
                path=path,
            )
        )
        return True

    def _check_permissions(
        self,
        path: Path,
        scope: str,
        expected: Iterable[TLSPermissionSpec],
        findings: list[TLSValidationFinding],
    ) -> None:
        actual_mode = stat.S_IMODE(path.stat().st_mode)
        try:
            import pwd

            owner_name = pwd.getpwuid(path.stat().st_uid).pw_name
        except Exception:  # noqa: BLE001 - fallback when resolution fails
            owner_name = str(path.stat().st_uid)
        try:
            import grp

            group_name = grp.getgrgid(path.stat().st_gid).gr_name
        except Exception:  # noqa: BLE001
            group_name = str(path.stat().st_gid)

        mode_str = f"{actual_mode:04o}"
        owner_group = f"{owner_name}:{group_name}"

        for spec in expected:
            if _permission_matches(spec, owner_name, group_name, actual_mode):
                findings.append(
                    TLSValidationFinding(
                        scope=scope,
                        check="permissions",
                        severity=TLSValidationSeverity.OK,
                        message=f"Permissions ok ({owner_group} {mode_str})",
                        path=path,
                    )
                )
                return

        allowed = ", ".join(
            f"{perm.owner}:{perm.group or '-'} {perm.mode:04o}" for perm in expected
        )
        findings.append(
            TLSValidationFinding(
                scope=scope,
                check="permissions",
                severity=TLSValidationSeverity.ERROR,
                message=f"Permissions {owner_group} {mode_str} not in allowed set ({allowed}).",
                path=path,
            )
        )


def _permission_matches(
    spec: TLSPermissionSpec,
    owner: str,
    group: str,
    mode: int,
) -> bool:
    owner_match = owner == spec.owner
    group_match = spec.group is None or group == spec.group
    return owner_match and group_match and mode == spec.mode


def _load_certificate(path: Path) -> x509.Certificate:
    data = path.read_bytes()
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def _load_private_key(path: Path) -> PrivateKeyProtocol:
    data = path.read_bytes()
    private_key = serialization.load_pem_private_key(data, password=None)
    return cast(PrivateKeyProtocol, private_key)


def _public_keys_match(cert: x509.Certificate, private_key: PrivateKeyProtocol) -> bool:
    cert_key = cert.public_key()
    try:
        key_public = private_key.public_key()
    except AttributeError:  # pragma: no cover - defensive
        return False
    cert_bytes = cert_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_bytes = key_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return cert_bytes == key_bytes


def _as_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def _extract_instance_domain(entry: Mapping[str, object]) -> str | None:
    domain_raw = entry.get("domain")
    if isinstance(domain_raw, str) and domain_raw.strip():
        return domain_raw.strip()
    metadata = entry.get("metadata")
    if isinstance(metadata, Mapping):
        meta_domain = metadata.get("domain")
        if isinstance(meta_domain, str) and meta_domain.strip():
            return meta_domain.strip()
    return None


__all__ = [
    "TLSConfigurationError",
    "TLSInspector",
    "TLSMaterial",
    "TLSSourceSelection",
    "TLSValidationFinding",
    "TLSValidationReport",
    "TLSValidationSeverity",
    "TLSValidator",
]
