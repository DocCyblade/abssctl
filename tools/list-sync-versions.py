#!/usr/bin/env python3
"""Populate docs/requirements/node-compat.yaml from npm metadata."""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception as exc:  # pragma: no cover - PyYAML is a dev dependency already
    sys.stderr.write(
        "ERROR: PyYAML is required; install with `pip install pyyaml`.\n"
    )
    raise SystemExit(2) from exc

DEFAULT_PACKAGE = "@actual-app/sync-server"
DEFAULT_LIMIT = 12
DEFAULT_OUTPUT = Path("docs/requirements/node-compat.yaml")
DEFAULT_RST = Path("docs/requirements/node-compatibility.rst")
NPM_REGISTRY = "https://registry.npmjs.org"
SCHEMA_VERSION = 1


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Refresh the Actual/Node compatibility YAML from npm metadata."
    )
    parser.add_argument(
        "--package",
        default=DEFAULT_PACKAGE,
        help=f"NPM package name (default: {DEFAULT_PACKAGE})",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="Maximum stable releases to keep (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Path to docs/requirements/node-compat.yaml",
    )
    parser.add_argument(
        "--rst-output",
        type=Path,
        default=DEFAULT_RST,
        help="Rendered compatibility doc destination (default: %(default)s)",
    )
    parser.add_argument(
        "--no-rst",
        action="store_true",
        help="Skip generating the RST compatibility document.",
    )
    parser.add_argument(
        "--include-pre",
        action="store_true",
        help="Allow pre-release (hyphenated) versions in the output.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS verification (not recommended).",
    )
    return parser.parse_args()


def _ssl_context(insecure: bool) -> ssl.SSLContext | None:
    if insecure:
        return ssl._create_unverified_context()  # type: ignore[attr-defined]

    candidates: list[str] = []

    env_override = os.environ.get("SSL_CERT_FILE")
    if env_override:
        candidates.append(env_override)

    try:  # pragma: no cover - optional dependency
        import certifi  # type: ignore
    except Exception:
        pass
    else:
        candidates.append(certifi.where())

    candidates.append("/etc/ssl/cert.pem")

    for candidate in candidates:
        path = Path(candidate)
        if path.is_file():
            return ssl.create_default_context(cafile=str(path))

    return ssl.create_default_context()


def _fetch_package_metadata(package: str, *, insecure: bool = False) -> dict[str, Any]:
    encoded = urllib.parse.quote(package, safe="")
    url = f"{NPM_REGISTRY}/{encoded}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    context = _ssl_context(insecure)
    try:
        with urllib.request.urlopen(req, timeout=30, context=context) as resp:
            payload = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:  # pragma: no cover - network failure path
        sys.stderr.write(f"ERROR: npm registry request failed: {exc}\n")
        raise SystemExit(2) from exc
    except urllib.error.URLError as exc:  # pragma: no cover - network failure path
        sys.stderr.write(f"ERROR: npm registry unreachable: {exc}\n")
        raise SystemExit(2) from exc
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        sys.stderr.write(f"ERROR: npm registry returned invalid JSON: {exc}\n")
        raise SystemExit(2) from exc


def _normalize_date(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw[:10]
    return dt.date().isoformat()


def _first_number(raw: str | None) -> int | None:
    if not raw:
        return None
    digits = ""
    for char in raw:
        if char.isdigit():
            digits += char
        elif digits:
            break
    return int(digits) if digits else None


def _default_node_versions() -> list[dict[str, Any]]:
    return [
        {
            "major": 18,
            "min_patch": "18.17.0",
            "status": "supported",
            "adr": "ADR-018",
            "notes": "TKL Node.js image ships Node 18; abssctl targets this baseline.",
        }
    ]


def _load_existing(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # pragma: no cover - defensive error path
        sys.stderr.write(f"ERROR: failed to parse existing YAML: {exc}\n")
        raise SystemExit(2) from exc
    if not isinstance(data, dict):
        sys.stderr.write("ERROR: node-compat.yaml must start with a mapping.\n")
        raise SystemExit(2)
    return data


def _build_version_rows(
    metadata: dict[str, Any],
    *,
    limit: int,
    include_pre: bool,
) -> list[dict[str, Any]]:
    versions = metadata.get("versions", {})
    time_map = metadata.get("time", {})
    if not isinstance(versions, dict):
        sys.stderr.write("ERROR: npm metadata missing versions.\n")
        raise SystemExit(2)
    if not isinstance(time_map, dict):
        time_map = {}

    tags = metadata.get("dist-tags", {}) or {}
    tag_lookup: dict[str, list[str]] = {}
    if isinstance(tags, dict):
        for tag_name, tagged_version in tags.items():
            tag_lookup.setdefault(str(tagged_version), []).append(str(tag_name))

    rows: list[dict[str, Any]] = []
    for version, info in versions.items():
        version_str = str(version)
        if not include_pre and "-" in version_str:
            continue
        release_date = _normalize_date(time_map.get(version_str))
        engines = info.get("engines") if isinstance(info, dict) else None
        if engines and not isinstance(engines, dict):
            engines = None
        node_constraint = (engines or {}).get("node")
        major = _first_number(node_constraint)
        rows.append(
            {
                "version": version_str,
                "release_date": release_date,
                "node_constraint": node_constraint,
                "node_major": major,
                "npm_dist_tags": sorted(tag_lookup.get(version_str, [])),
            }
        )

    rows.sort(key=lambda item: item.get("release_date") or "", reverse=True)
    if limit > 0:
        rows = rows[:limit]
    return rows


def _merge_existing(
    rows: list[dict[str, Any]],
    existing_versions: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    for row in rows:
        version = row["version"]
        stored = existing_versions.get(version, {})
        merged.append(
            {
                **row,
                "status": stored.get("status", "untested"),
                "tested_at": stored.get("tested_at"),
                "notes": stored.get("notes"),
            }
        )
    return merged


def _render_rst_document(data: dict[str, Any]) -> str:
    generated_at = data.get("generated_at", "")
    node_versions = data.get("node_versions") or []
    actual_versions = data.get("actual_versions") or []

    def fmt(value: object | None) -> str:
        if value is None:
            return "N/A"
        text = str(value)
        return text if text else "N/A"

    lines = [
        "=========================================",
        "Actual Node Compatibility Matrix",
        "=========================================",
        "",
        f".. note:: AUTO-GENERATED by ``tools/list-sync-versions.py`` on {generated_at}. "
        "Do not edit this file by hand.",
        "",
        "Source of Truth",
        "---------------",
        "",
        "* YAML: ``docs/requirements/node-compat.yaml``",
        "* Refresh command: ``python3 tools/list-sync-versions.py``",
        "",
        "Node Baseline",
        "-------------",
        "",
        ".. list-table:: Supported Node versions",
        "   :header-rows: 1",
        "   :widths: 8 12 12 14 54",
        "",
        "   * - Major",
        "     - Min patch",
        "     - Status",
        "     - ADR",
        "     - Notes",
    ]

    if node_versions:
        for entry in node_versions:
            lines.append(
                "   * - {major}\n"
                "     - {min_patch}\n"
                "     - {status}\n"
                "     - {adr}\n"
                "     - {notes}\n".format(
                    major=fmt(entry.get("major")),
                    min_patch=fmt(entry.get("min_patch")),
                    status=fmt(entry.get("status")),
                    adr=fmt(entry.get("adr")),
                    notes=fmt(entry.get("notes")),
                )
            )
    else:
        lines.append(
            "   * - N/A\n"
            "     - N/A\n"
            "     - N/A\n"
            "     - N/A\n"
            "     - Populate ``node_versions`` in the YAML.\n"
        )

    lines.extend(
        [
            "",
            "Actual Releases",
            "---------------",
            "",
            ".. list-table:: Latest ``@actual-app/sync-server`` releases",
            "   :header-rows: 1",
            "   :widths: 10 12 16 10 12 14 26",
            "",
            "   * - Version",
            "     - Release date",
            "     - Node constraint",
            "     - Node major",
            "     - Status",
            "     - Tested at",
            "     - Notes",
        ]
    )

    if actual_versions:
        for entry in actual_versions:
            notes = entry.get("notes")
            tags = entry.get("npm_dist_tags") or []
            tag_text = f"Tags: {', '.join(tags)}." if tags else ""
            combined_notes = " ".join(
                piece for piece in [tag_text, notes or ""] if piece
            ).strip()
            lines.append(
                "   * - {version}\n"
                "     - {release_date}\n"
                "     - {constraint}\n"
                "     - {node_major}\n"
                "     - {status}\n"
                "     - {tested_at}\n"
                "     - {notes}\n".format(
                    version=fmt(entry.get("version")),
                    release_date=fmt(entry.get("release_date")),
                    constraint=fmt(entry.get("node_constraint")),
                    node_major=fmt(entry.get("node_major")),
                    status=fmt(entry.get("status")),
                    tested_at=fmt(entry.get("tested_at")),
                    notes=combined_notes if combined_notes else "N/A",
                )
            )
    else:
        lines.append(
            "   * - N/A\n"
            "     - N/A\n"
            "     - N/A\n"
            "     - N/A\n"
            "     - N/A\n"
            "     - N/A\n"
            "     - Run the refresh script to populate releases.\n"
        )

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    """Entry point for refreshing the Node compatibility data + docs."""
    args = _parse_args()
    metadata = _fetch_package_metadata(args.package, insecure=args.insecure)
    rows = _build_version_rows(metadata, limit=args.limit, include_pre=args.include_pre)
    existing = _load_existing(args.output)

    existing_rows = {
        str(entry.get("version")): entry
        for entry in existing.get("actual_versions", []) or []
        if isinstance(entry, dict) and entry.get("version")
    }

    node_versions = existing.get("node_versions") or _default_node_versions()
    generated_at = datetime.now(UTC).isoformat()

    data = {
        "schema_version": existing.get("schema_version", SCHEMA_VERSION),
        "generated_at": generated_at,
        "package": args.package,
        "source": f"{NPM_REGISTRY}/{urllib.parse.quote(args.package, safe='')}",
        "limit": args.limit,
        "node_versions": node_versions,
        "actual_versions": _merge_existing(rows, existing_rows),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(
            data,
            handle,
            sort_keys=False,
            allow_unicode=False,
        )

    outputs = [f"Wrote {args.output} with {len(rows)} releases"]

    if not args.no_rst:
        rst_text = _render_rst_document(data)
        args.rst_output.parent.mkdir(parents=True, exist_ok=True)
        args.rst_output.write_text(rst_text, encoding="utf-8")
        outputs.append(f"{args.rst_output}")

    sys.stdout.write(" and ".join(outputs) + ".\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
