"""Archive helpers shared by backup and support bundle workflows."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

from .backups import BackupError


def detect_zstd_support() -> bool:
    """Return True when both tar and zstd binaries are available."""
    return shutil.which("tar") is not None and shutil.which("zstd") is not None


def compression_extension(algorithm: str) -> str:
    """Return the archive file extension for *algorithm*."""
    if algorithm == "gzip":
        return "tar.gz"
    if algorithm == "zstd":
        return "tar.zst"
    return "tar"


def create_archive(
    source_dir: Path,
    archive_path: Path,
    algorithm: str,
    compression_level: int | None,
) -> None:
    """Create an archive from *source_dir* at *archive_path*."""
    tar_bin = shutil.which("tar")
    if tar_bin is None:
        raise BackupError("The 'tar' command is required to create archives.")

    env = os.environ.copy()
    cmd: list[str] = [tar_bin]

    if algorithm == "gzip":
        cmd.extend(["-czf", str(archive_path)])
        if compression_level is not None:
            env["GZIP"] = f"-{compression_level}"
    elif algorithm == "zstd":
        cmd.extend(["--zstd", "-cf", str(archive_path)])
        if compression_level is not None:
            env["ZSTD_CLEVEL"] = str(compression_level)
    else:
        cmd.extend(["-cf", str(archive_path)])

    cmd.extend(["-C", str(source_dir.parent), source_dir.name])

    result = subprocess.run(  # noqa: S603, S607 - controlled command execution
        cmd,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr or result.stdout or "tar command failed"
        raise BackupError(message.strip())

    try:
        os.chmod(archive_path, 0o640)
    except OSError:
        pass


def compute_checksum(path: Path) -> str:
    """Return the SHA-256 checksum for *path*."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def write_checksum_file(archive_path: Path, checksum: str) -> Path:
    """Write ``<archive>.sha256`` and return the checksum path."""
    checksum_path = archive_path.with_name(f"{archive_path.name}.sha256")
    checksum_path.write_text(f"{checksum}  {archive_path.name}\n", encoding="utf-8")
    try:
        os.chmod(checksum_path, 0o640)
    except OSError:
        pass
    return checksum_path
