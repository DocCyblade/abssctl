"""Utilities for inspecting and planning service account provisioning."""
from __future__ import annotations

import grp
import pwd
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass(slots=True)
class ServiceAccountSpec:
    """Desired attributes for the abssctl runtime service account."""

    name: str
    group: str | None = None
    system: bool = True
    create_group: bool = True
    home: Path | None = None
    shell: str | None = None


@dataclass(slots=True)
class ServiceAccountStatus:
    """Current state of the service account on the host."""

    user_exists: bool
    group_exists: bool
    uid: int | None = None
    gid: int | None = None
    home: Path | None = None
    shell: str | None = None
    primary_group: str | None = None


@dataclass(slots=True)
class ServiceAccountAction:
    """Single remediation step required to satisfy the desired state."""

    kind: Literal["ensure-group", "create-user", "warn"]
    description: str
    command: list[str] | None = None


@dataclass(slots=True)
class ServiceAccountPlan:
    """Aggregated actions and warnings required to satisfy the spec."""

    spec: ServiceAccountSpec
    status: ServiceAccountStatus
    actions: list[ServiceAccountAction] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def inspect_service_account(spec: ServiceAccountSpec) -> ServiceAccountStatus:
    """Return the current status for *spec* from system passwd/group databases."""
    try:
        pw_entry = pwd.getpwnam(spec.name)
        user_exists = True
        uid = pw_entry.pw_uid
        gid = pw_entry.pw_gid
        home = Path(pw_entry.pw_dir)
        shell = pw_entry.pw_shell
        try:
            primary_group = grp.getgrgid(gid).gr_name
        except KeyError:
            primary_group = None
    except KeyError:
        user_exists = False
        uid = None
        gid = None
        home = None
        shell = None
        primary_group = None

    group_exists = False
    if spec.group:
        try:
            grp.getgrnam(spec.group)
        except KeyError:
            pass
        else:
            group_exists = True

    return ServiceAccountStatus(
        user_exists=user_exists,
        group_exists=group_exists,
        uid=uid,
        gid=gid,
        home=home,
        shell=shell,
        primary_group=primary_group,
    )


def plan_service_account(spec: ServiceAccountSpec) -> ServiceAccountPlan:
    """Return a plan describing how to satisfy *spec* on the current host."""
    status = inspect_service_account(spec)
    plan = ServiceAccountPlan(spec=spec, status=status)

    if spec.group and not status.group_exists:
        if spec.create_group:
            command = ["groupadd"]
            if spec.system:
                command.append("--system")
            command.append(spec.group)
            plan.actions.append(
                ServiceAccountAction(
                    kind="ensure-group",
                    description=f"Create group '{spec.group}'.",
                    command=command,
                )
            )
        else:
            plan.warnings.append(
                f"Group '{spec.group}' is missing and create_group is False."
            )

    if not status.user_exists:
        command = ["useradd"]
        if spec.system:
            command.append("--system")
        if spec.home:
            command.extend(["--home", str(spec.home)])
        else:
            command.append("--no-create-home")
        if spec.shell:
            command.extend(["--shell", str(spec.shell)])
        if spec.group:
            command.extend(["--gid", spec.group])
        command.append(spec.name)
        plan.actions.append(
            ServiceAccountAction(
                kind="create-user",
                description=f"Create service user '{spec.name}'.",
                command=command,
            )
        )
    else:
        if spec.group and status.primary_group and status.primary_group != spec.group:
            plan.warnings.append(
                "User "
                f"'{spec.name}' primary group is '{status.primary_group}', "
                f"expected '{spec.group}'."
            )
        if spec.home and status.home and status.home != spec.home:
            plan.warnings.append(
                f"User '{spec.name}' home '{status.home}' differs from desired '{spec.home}'."
            )
        if spec.shell and status.shell and str(status.shell) != str(spec.shell):
            plan.warnings.append(
                f"User '{spec.name}' shell '{status.shell}' differs from desired '{spec.shell}'."
            )

    return plan


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def apply_service_account_plan(
    plan: ServiceAccountPlan,
    *,
    runner: Runner | None = None,
    dry_run: bool = False,
) -> None:
    """Execute the commands described by *plan*."""
    if runner is None:
        runner = _default_runner

    for action in plan.actions:
        if action.command is None:
            continue
        if dry_run:
            continue
        runner(action.command)


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, capture_output=True, text=True)  # noqa: S603,S607


__all__ = [
    "ServiceAccountAction",
    "ServiceAccountPlan",
    "ServiceAccountSpec",
    "ServiceAccountStatus",
    "apply_service_account_plan",
    "inspect_service_account",
    "plan_service_account",
]
