"""Helpers for enforcing the required Node.js runtime via ``n``."""
from __future__ import annotations

import logging
import shutil
import subprocess
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .logging import StructuredLogger

LOGGER = logging.getLogger(__name__)


class NodeRuntimeError(RuntimeError):
    """Raised when Node runtime management fails."""


@dataclass(slots=True)
class NodeVersionInfo:
    """Parsed Node version details."""

    raw: str
    version: str
    major: int
    minor: int
    patch: int


@dataclass(slots=True)
class NodeEnsureResult:
    """Outcome of ``node ensure`` operations."""

    version: str
    installed: bool
    installation_performed: bool
    env_file: Path
    env_changed: bool
    node_path: Path | None
    dry_run: bool


@dataclass(slots=True)
class NodeRuntimeManager:
    """Wrapper around ``n`` for installing and invoking Node."""

    logger: StructuredLogger | None = None
    env_file: Path = Path("/etc/default/abssctl-node")
    n_bin: str = "n"
    node_bin: str = "node"

    def detect_version(self) -> NodeVersionInfo | None:
        """Return the currently available Node version."""
        try:
            result = subprocess.run(  # noqa: S603,S607
                [self.node_bin, "--version"],
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return None
        output = (result.stdout or result.stderr or "").strip()
        if not output:
            return None
        version = output.lstrip("v").strip()
        major, minor, patch = _parse_semver(version)
        return NodeVersionInfo(raw=output, version=version, major=major, minor=minor, patch=patch)

    def ensure_version(
        self,
        version: str,
        *,
        dry_run: bool = False,
        update_env: bool = True,
    ) -> NodeEnsureResult:
        """Ensure *version* is installed via ``n`` and recorded in the env file."""
        normalized = version.strip().lstrip("v")
        if not normalized:
            raise NodeRuntimeError("Node version cannot be blank.")

        self._assert_n_available()
        node_path = self._which_version(normalized)
        installation_performed = False
        if node_path is None and not dry_run:
            self._run_n(["install", normalized])
            installation_performed = True
            node_path = self._which_version(normalized)
            if node_path is None:
                raise NodeRuntimeError(
                    f"n installed '{normalized}' but the binary could not be located."
                )

        env_changed = False
        if update_env:
            env_changed = self._write_env_file(normalized, dry_run=dry_run)

        self._log(
            f"Node ensure completed for {normalized}: "
            f"installed={node_path is not None} dry_run={dry_run}"
        )
        return NodeEnsureResult(
            version=normalized,
            installed=node_path is not None,
            installation_performed=installation_performed,
            env_file=self.env_file,
            env_changed=env_changed,
            node_path=node_path,
            dry_run=dry_run,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assert_n_available(self) -> None:
        resolved = shutil.which(self.n_bin) if not Path(self.n_bin).exists() else str(
            Path(self.n_bin)
        )
        if not resolved:
            raise NodeRuntimeError(
                f"'n' binary '{self.n_bin}' not found. Install n and ensure it is on PATH."
            )

    def _which_version(self, version: str) -> Path | None:
        args = [self.n_bin, "which", version]
        try:
            result = subprocess.run(  # noqa: S603,S607
                args,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            raise NodeRuntimeError(f"'n' binary '{self.n_bin}' not found.") from None
        if result.returncode != 0:
            return None
        path = (result.stdout or result.stderr or "").strip()
        return Path(path) if path else None

    def _run_n(self, args: Sequence[str]) -> None:
        command = [self.n_bin, *args]
        try:
            result = subprocess.run(  # noqa: S603,S607
                command,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise NodeRuntimeError(f"'n' binary '{self.n_bin}' not found: {exc}") from exc
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "").strip() or "unknown error"
            raise NodeRuntimeError(f"'n {' '.join(args)}' failed: {message}")

    def _write_env_file(self, version: str, *, dry_run: bool) -> bool:
        content = self._render_env_file(version)
        if self.env_file.exists() and self.env_file.read_text(encoding="utf-8") == content:
            return False
        if dry_run:
            return True
        self.env_file.parent.mkdir(parents=True, exist_ok=True)
        temp = self.env_file.with_name(f"{self.env_file.name}.tmp")
        temp.write_text(content, encoding="utf-8")
        temp.chmod(0o644)
        temp.replace(self.env_file)
        return True

    def _render_env_file(self, version: str) -> str:
        return textwrap.dedent(
            f"""\
            # Managed by abssctl node ensure. Manual edits may be overwritten.
            REQUIRED_NODE="{version}"
            """
        )

    def _log(self, message: str) -> None:
        LOGGER.debug(message)


def _parse_semver(value: str) -> tuple[int, int, int]:
    parts = [segment for segment in value.split(".") if segment]
    numbers: list[int] = []
    for segment in parts[:3]:
        try:
            numbers.append(int(segment))
        except ValueError:
            numbers.append(0)
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers)  # type: ignore[return-value]


__all__ = [
    "NodeEnsureResult",
    "NodeRuntimeError",
    "NodeRuntimeManager",
    "NodeVersionInfo",
]
