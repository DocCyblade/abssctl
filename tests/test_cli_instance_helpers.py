"""Unit tests for CLI helper functions that normalise instance metadata."""

from __future__ import annotations

from abssctl.cli import _normalize_instances


def test_normalize_instances_handles_strings_only() -> None:
    """String entries should expand into default dictionaries."""
    result = _normalize_instances(["alpha", "beta"])
    assert [entry["name"] for entry in result] == ["alpha", "beta"]
    assert all(entry["metadata"]["source"] == "registry" for entry in result)
    assert all(entry["status"] == "unknown" for entry in result)


def test_normalize_instances_handles_mapping_fields() -> None:
    """Mappings should retain canonical fields and stash extra keys in metadata."""
    result = _normalize_instances(
        [
            {
                "name": "alpha",
                "version": "v1",
                "domain": "alpha.example.com",
                "port": 5000,
                "status": "running",
                "path": "/srv/alpha",
                "notes": "primary",
                "extra": "value",
            }
        ]
    )
    assert len(result) == 1
    entry = result[0]
    assert entry["name"] == "alpha"
    assert entry["version"] == "v1"
    assert entry["domain"] == "alpha.example.com"
    assert entry["port"] == 5000
    assert entry["status"] == "running"
    assert entry["path"] == "/srv/alpha"
    assert entry["notes"] == "primary"
    assert entry["metadata"] == {"extra": "value", "source": "registry"}


def test_normalize_instances_derives_status_from_enabled_flag() -> None:
    """Enabled boolean should translate into enabled/disabled status strings."""
    result = _normalize_instances(
        [
            {"name": "alpha", "enabled": True},
            {"name": "beta", "enabled": False},
        ]
    )
    statuses = {item["name"]: item["status"] for item in result}
    assert statuses == {"alpha": "enabled", "beta": "disabled"}


def test_normalize_instances_handles_mixed_versions_domains() -> None:
    """version_binding/fqdn/data_dir fallbacks should populate canonical keys."""
    result = _normalize_instances(
        [
            {
                "name": "alpha",
                "version_binding": "v2",
                "fqdn": "alpha.internal",
                "data_dir": "/var/lib/alpha",
            }
        ]
    )
    entry = result[0]
    assert entry["version"] == "v2"
    assert entry["domain"] == "alpha.internal"
    assert entry["path"] == "/var/lib/alpha"


def test_normalize_instances_ignores_invalid_entries() -> None:
    """Non-string/mapping entries should be discarded safely."""
    result = _normalize_instances([None, 123, {"name": "alpha"}, "beta"])
    assert [entry["name"] for entry in result] == ["alpha", "beta"]
