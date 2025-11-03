"""Unit tests for bootstrap service account helpers."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from abssctl.bootstrap.service_accounts import ServiceAccountSpec, plan_service_account


def _raise_key_error(*args: object, **kwargs: object) -> None:
    raise KeyError


def test_plan_creates_group_and_user(monkeypatch: pytest.MonkeyPatch) -> None:
    """Plan should request group and user creation when missing."""
    from abssctl.bootstrap import service_accounts

    monkeypatch.setattr(service_accounts.pwd, "getpwnam", _raise_key_error)
    monkeypatch.setattr(service_accounts.grp, "getgrnam", _raise_key_error)
    monkeypatch.setattr(service_accounts.grp, "getgrgid", _raise_key_error)

    spec = ServiceAccountSpec(name="actual-sync", group="actual-sync")
    plan = plan_service_account(spec)

    kinds = [action.kind for action in plan.actions]
    assert kinds == ["ensure-group", "create-user"]
    assert plan.warnings == []


def test_plan_no_actions_when_account_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Plan should be empty when user and group already match expectations."""
    from abssctl.bootstrap import service_accounts

    pw_entry = SimpleNamespace(
        pw_uid=1234,
        pw_gid=5678,
        pw_dir="/srv/app",
        pw_shell="/usr/sbin/nologin",
    )
    group_entry = SimpleNamespace(gr_gid=5678, gr_name="actual-sync", gr_mem=[])

    monkeypatch.setattr(service_accounts.pwd, "getpwnam", lambda name: pw_entry)
    monkeypatch.setattr(service_accounts.grp, "getgrnam", lambda name: group_entry)
    monkeypatch.setattr(service_accounts.grp, "getgrgid", lambda gid: group_entry)

    spec = ServiceAccountSpec(
        name="actual-sync",
        group="actual-sync",
        home=None,
        shell="/usr/sbin/nologin",
    )
    plan = plan_service_account(spec)

    assert plan.actions == []
    assert plan.warnings == []


def test_plan_warns_on_mismatched_group(monkeypatch: pytest.MonkeyPatch) -> None:
    """Plan should warn if the existing account uses a different primary group."""
    from abssctl.bootstrap import service_accounts

    pw_entry = SimpleNamespace(
        pw_uid=1234,
        pw_gid=5678,
        pw_dir="/srv/app",
        pw_shell="/usr/sbin/nologin",
    )
    monkeypatch.setattr(service_accounts.pwd, "getpwnam", lambda name: pw_entry)
    monkeypatch.setattr(
        service_accounts.grp,
        "getgrnam",
        lambda name: SimpleNamespace(gr_gid=9012, gr_name=name, gr_mem=[]),
    )
    monkeypatch.setattr(
        service_accounts.grp,
        "getgrgid",
        lambda gid: SimpleNamespace(gr_gid=gid, gr_name="existing", gr_mem=[]),
    )

    spec = ServiceAccountSpec(
        name="actual-sync",
        group="actual-sync",
    )
    plan = plan_service_account(spec)

    assert plan.actions == []
    assert plan.warnings == [
        "User 'actual-sync' primary group is 'existing', expected 'actual-sync'."
    ]
