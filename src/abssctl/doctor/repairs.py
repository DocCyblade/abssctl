"""Planning and execution helpers for ``abssctl doctor --fix``."""
from __future__ import annotations

import grp
import json
import os
import pwd
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..bootstrap.filesystem import (
    DirectoryAction,
    DirectorySpec,
    plan_directories,
)
from ..state.registry import StateRegistry

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..cli import RuntimeContext


CreationCallback = Callable[[], None]


@dataclass(slots=True)
class RepairAction:
    """Single repair that doctor --fix can apply."""

    step_id: str
    description: str
    detail: str
    apply: Callable[[], None]


def plan_repairs(runtime: RuntimeContext) -> list[RepairAction]:
    """Return all repairs that doctor --fix could apply for *runtime*."""
    actions: list[RepairAction] = []
    actions.extend(_plan_core_directories(runtime))
    actions.extend(_plan_registry_files(runtime))
    actions.extend(_plan_config_file(runtime))
    actions.extend(_plan_lock_cleanup(runtime))
    return actions


# ---------------------------------------------------------------------------
# Directory repairs
# ---------------------------------------------------------------------------


def _plan_core_directories(runtime: RuntimeContext) -> list[RepairAction]:
    config = runtime.config
    service_user = config.service_user
    service_group = _expected_group(service_user)

    specs: list[DirectorySpec] = []
    specs.extend(
        [
            DirectorySpec(
                path=config.state_dir,
                owner=service_user,
                group=service_group,
                mode=0o750,
            ),
            DirectorySpec(
                path=config.registry_dir,
                owner=service_user,
                group=service_group,
                mode=0o750,
            ),
            DirectorySpec(
                path=config.logs_dir,
                owner=service_user,
                group=service_group,
                mode=0o750,
            ),
            DirectorySpec(
                path=config.runtime_dir,
                owner=service_user,
                group=service_group,
                mode=0o750,
            ),
        ]
    )
    config_dir = config.config_file.parent
    if _is_etc_path(config_dir):
        specs.append(
            DirectorySpec(
                path=config_dir,
                owner="root",
                group="root",
                mode=0o750,
            )
        )

    unique: dict[Path, DirectorySpec] = {}
    for spec in specs:
        unique[spec.path] = spec

    plan = plan_directories(list(unique.values()))
    repairs: list[RepairAction] = []
    for action in plan.actions:
        repairs.append(_directory_action_to_repair(action))
    return repairs


def _directory_action_to_repair(action: DirectoryAction) -> RepairAction:
    if action.kind == "mkdir":
        description = f"Create directory {action.path}"

        def _apply_mkdir() -> None:
            action.path.mkdir(
                mode=action.mode or 0o755,
                parents=action.parents,
                exist_ok=True,
            )
            _maybe_chown(action.path, action.owner, action.group)
            if action.mode is not None:
                os.chmod(action.path, action.mode)

        detail = _format_detail(
            action.path,
            owner=action.owner,
            group=action.group,
            mode=action.mode,
        )
        return RepairAction(
            step_id="repair.dir.mkdir",
            description=description,
            detail=detail,
            apply=_apply_mkdir,
        )

    if action.kind == "chown":
        description = f"Set owner/group on {action.path}"

        def _apply_chown() -> None:
            _maybe_chown(action.path, action.owner, action.group)

        detail = _format_detail(
            action.path,
            owner=action.owner,
            group=action.group,
            mode=None,
        )
        return RepairAction(
            step_id="repair.dir.chown",
            description=description,
            detail=detail,
            apply=_apply_chown,
        )

    description = f"Update permissions for {action.path}"

    def _apply_chmod() -> None:
        if action.mode is not None:
            os.chmod(action.path, action.mode)

    detail = _format_detail(action.path, owner=None, group=None, mode=action.mode)
    return RepairAction(
        step_id="repair.dir.chmod",
        description=description,
        detail=detail,
        apply=_apply_chmod,
    )


# ---------------------------------------------------------------------------
# Registry/config file repairs
# ---------------------------------------------------------------------------


def _plan_registry_files(runtime: RuntimeContext) -> list[RepairAction]:
    registry = runtime.registry
    service_user = runtime.config.service_user
    service_group = _expected_group(service_user)
    actions: list[RepairAction] = []
    def _write_instances(registry: StateRegistry = registry) -> None:
        registry.write_instances([])

    def _write_ports(registry: StateRegistry = registry) -> None:
        registry.write_ports([])

    def _write_versions(registry: StateRegistry = registry) -> None:
        registry.write_versions([])

    creation_callbacks: dict[str, CreationCallback] = {
        "instances.yml": _write_instances,
        "ports.yml": _write_ports,
        "versions.yml": _write_versions,
    }
    for name, create_callback in creation_callbacks.items():
        path = registry.path_for(name)
        if not path.exists():
            description = f"Create {name} with default schema"

            def _apply_create(callback: CreationCallback = create_callback) -> None:
                callback()

            detail = f"path={path}"
            actions.append(
                RepairAction(
                    step_id="repair.registry.create",
                    description=description,
                    detail=detail,
                    apply=_apply_create,
                )
            )
            continue

        owner, group, mode = _stat_path(path)
        owner_mismatch = owner != service_user
        group_mismatch = service_group is not None and group != service_group
        if owner_mismatch or group_mismatch:

            def _apply_registry_owner(
                path: Path = path,
                user: str = service_user,
                grp_name: str | None = service_group,
            ) -> None:
                shutil.chown(path, user=user, group=grp_name)

            detail = _format_detail(path, owner=service_user, group=service_group, mode=None)
            actions.append(
                RepairAction(
                    step_id="repair.registry.owner",
                    description=f"Set owner/group on {path}",
                    detail=detail,
                    apply=_apply_registry_owner,
                )
            )
        if mode != 0o640:
            def _apply_registry_mode(path: Path = path) -> None:
                os.chmod(path, 0o640)

            detail = _format_detail(path, owner=None, group=None, mode=0o640)
            actions.append(
                RepairAction(
                    step_id="repair.registry.mode",
                    description=f"Set permissions on {path}",
                    detail=detail,
                    apply=_apply_registry_mode,
                )
            )
    return actions


def _plan_config_file(runtime: RuntimeContext) -> list[RepairAction]:
    config_file = runtime.config.config_file
    if not _is_etc_path(config_file):
        return []
    if not config_file.exists():
        return []
    owner, group, mode = _stat_path(config_file)
    actions: list[RepairAction] = []
    if owner != "root" or group != "root":
        def _apply(path: Path = config_file) -> None:
            shutil.chown(path, user="root", group="root")

        detail = _format_detail(config_file, owner="root", group="root", mode=None)
        actions.append(
            RepairAction(
                step_id="repair.config.owner",
                description=f"Set owner/group on {config_file}",
                detail=detail,
                apply=_apply,
            )
        )
    if mode != 0o640:
        def _apply(path: Path = config_file) -> None:
            os.chmod(path, 0o640)

        detail = _format_detail(config_file, owner=None, group=None, mode=0o640)
        actions.append(
            RepairAction(
                step_id="repair.config.mode",
                description=f"Set permissions on {config_file}",
                detail=detail,
                apply=_apply,
            )
        )
    return actions


# ---------------------------------------------------------------------------
# Lock cleanup
# ---------------------------------------------------------------------------


def _plan_lock_cleanup(runtime: RuntimeContext) -> list[RepairAction]:
    runtime_dir = runtime.config.runtime_dir
    timeout = max(runtime.locks.default_timeout * 2, 1.0)
    now = time.time()
    actions: list[RepairAction] = []
    for lock_path in _iter_lock_paths(runtime_dir):
        reason = _lock_cleanup_reason(lock_path, timeout, now)
        if not reason:
            continue

        def _apply(path: Path = lock_path) -> None:
            path.unlink(missing_ok=True)

        detail = f"path={lock_path} reason={reason}"
        actions.append(
            RepairAction(
                step_id="repair.locks.cleanup",
                description=f"Remove stale lock {lock_path}",
                detail=detail,
                apply=_apply,
            )
        )
    return actions


def _iter_lock_paths(runtime_dir: Path) -> list[Path]:
    paths: list[Path] = []
    candidates = list(runtime_dir.glob("*.lock"))
    versions_dir = runtime_dir / "versions"
    if versions_dir.exists():
        candidates.extend(versions_dir.glob("*.lock"))
    for candidate in candidates:
        if candidate.is_file():
            paths.append(candidate)
    return paths


def _lock_cleanup_reason(path: Path, threshold: float, now: float) -> str | None:
    try:
        info = path.stat()
    except FileNotFoundError:
        return None
    age = now - info.st_mtime
    if age < threshold:
        return None
    pid = _read_lock_pid(path)
    if pid is not None and _pid_is_running(pid):
        return None
    age_label = f"{int(age)}s"
    if pid is None:
        return f"age={age_label}, pid=unknown"
    return f"age={age_label}, pid={pid}"


def _read_lock_pid(path: Path) -> int | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    pid = payload.get("pid")
    if isinstance(pid, int):
        return pid if pid > 0 else None
    if isinstance(pid, str):
        try:
            value = int(pid)
        except ValueError:
            return None
        return value if value > 0 else None
    return None


def _pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _maybe_chown(path: Path, owner: str | None, group: str | None) -> None:
    kwargs: dict[str, str] = {}
    if owner:
        kwargs["user"] = owner
    if group:
        kwargs["group"] = group
    if kwargs:
        shutil.chown(path, **kwargs)


def _stat_path(path: Path) -> tuple[str | None, str | None, int | None]:
    try:
        info = path.stat()
    except FileNotFoundError:
        return None, None, None
    owner = _username(info.st_uid)
    group = _groupname(info.st_gid)
    mode = info.st_mode & 0o777
    return owner, group, mode


def _username(uid: int) -> str | None:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:  # pragma: no cover - depends on host passwd db
        return None


def _groupname(gid: int) -> str | None:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:  # pragma: no cover - depends on host group db
        return None


def _format_mode(mode: int | None) -> str:
    if mode is None:
        return "-"
    return f"0o{mode:03o}"


def _format_detail(path: Path, *, owner: str | None, group: str | None, mode: int | None) -> str:
    return (
        f"path={path} owner={owner or '-'} group={group or '-'} mode={_format_mode(mode)}"
    )


def _is_etc_path(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except FileNotFoundError:
        resolved = path
    return Path("/etc") in resolved.parents or resolved == Path("/etc")


def _expected_group(service_user: str) -> str | None:
    try:
        grp.getgrnam(service_user)
    except KeyError:  # pragma: no cover - depends on host group db
        return None
    return service_user


__all__ = ["RepairAction", "plan_repairs"]
