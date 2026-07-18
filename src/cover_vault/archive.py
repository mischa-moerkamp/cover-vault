from __future__ import annotations

import io
import os
import shutil
import tarfile
import tempfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from .errors import CoverVaultError

DEFAULT_EXCLUDES = {".DS_Store", "__pycache__", ".git", ".hg", ".svn"}
GIT_HISTORY_EXCLUDE = ".git"
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_TOTAL_BYTES = 10 * 1024 * 1024 * 1024
MAX_ARCHIVE_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_PATH_DEPTH = 64
MAX_ARCHIVE_PATH_CHARS = 4096


def _should_exclude(path: Path, root: Path, excludes: Iterable[str]) -> bool:
    exclude_set = set(excludes)
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return False
    return any(part in exclude_set for part in parts)


def make_archive(
    source: Path | str, excludes: Iterable[str] = DEFAULT_EXCLUDES
) -> tuple[bytes, int]:
    source_path = Path(source).expanduser().resolve()
    if not source_path.exists() or not source_path.is_dir():
        raise CoverVaultError(f"Source folder does not exist: {source_path}")

    buffer = io.BytesIO()
    files_added = 0
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
        for current, dirnames, filenames in os.walk(source_path):
            current_path = Path(current)
            dirnames[:] = [
                name
                for name in sorted(dirnames)
                if not _should_exclude(current_path / name, source_path, excludes)
            ]

            for dirname in dirnames:
                path = current_path / dirname
                if path.is_symlink():
                    continue
                rel = path.relative_to(source_path).as_posix()
                tar.add(path, arcname=rel, recursive=False)

            for filename in sorted(filenames):
                path = current_path / filename
                if _should_exclude(path, source_path, excludes) or path.is_symlink():
                    continue
                rel = path.relative_to(source_path).as_posix()
                tar.add(path, arcname=rel, recursive=False)
                files_added += 1

    return buffer.getvalue(), files_added


def _safe_member_path(destination: Path, member_name: str) -> Path:
    member_path = PurePosixPath(member_name)
    if member_path.is_absolute() or ".." in member_path.parts:
        raise CoverVaultError(f"Refusing unsafe archive path: {member_name}")
    if len(member_name) > MAX_ARCHIVE_PATH_CHARS:
        raise CoverVaultError(f"Archive path is too long: {member_name}")
    if len(member_path.parts) > MAX_ARCHIVE_PATH_DEPTH:
        raise CoverVaultError(f"Archive path is too deeply nested: {member_name}")

    target = (destination / Path(*member_path.parts)).resolve()
    destination_resolved = destination.resolve()
    if target != destination_resolved and destination_resolved not in target.parents:
        raise CoverVaultError(f"Refusing unsafe archive path: {member_name}")
    return target


def _validated_members(
    tar: tarfile.TarFile, validation_root: Path
) -> list[tarfile.TarInfo]:
    members = tar.getmembers()
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise CoverVaultError(f"Archive contains too many members ({len(members)}).")

    total_size = 0
    seen_names: set[str] = set()
    for member in members:
        _safe_member_path(validation_root, member.name)
        if member.name in seen_names:
            raise CoverVaultError(f"Archive contains a duplicate path: {member.name}")
        seen_names.add(member.name)

        if member.issym() or member.islnk():
            raise CoverVaultError(f"Refusing link in archive: {member.name}")
        if not member.isdir() and not member.isfile():
            raise CoverVaultError(f"Unsupported archive member type: {member.name}")
        if member.isfile():
            if member.size < 0 or member.size > MAX_ARCHIVE_FILE_BYTES:
                raise CoverVaultError(
                    f"Archive member is too large: {member.name} ({member.size} bytes)"
                )
            total_size += member.size
            if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                raise CoverVaultError(
                    "Archive expands beyond the configured total-size limit."
                )
    return members


def extract_archive(
    archive_bytes: bytes, destination: Path | str, overwrite: bool = False
) -> int:
    dest_path = Path(destination).expanduser().resolve()
    if dest_path.exists() and not overwrite:
        if not dest_path.is_dir() or any(dest_path.iterdir()):
            raise CoverVaultError(
                f"Destination already exists and is not empty: {dest_path}"
            )
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = Path(
        tempfile.mkdtemp(prefix=f".{dest_path.name}.restore-", dir=dest_path.parent)
    )

    try:
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
                members = _validated_members(tar, temporary_path)
                file_count = 0
                for member in members:
                    target = _safe_member_path(temporary_path, member.name)
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        source = tar.extractfile(member)
                        if source is None:
                            raise CoverVaultError(
                                f"Could not read archive member: {member.name}"
                            )
                        with source, target.open("wb") as output:
                            shutil.copyfileobj(source, output)
                        file_count += 1

                    try:
                        target.chmod(member.mode)
                    except OSError:
                        pass
                    try:
                        os.utime(target, (member.mtime, member.mtime))
                    except OSError:
                        pass
        except (tarfile.TarError, OSError) as exc:
            if isinstance(exc, CoverVaultError):
                raise
            raise CoverVaultError(
                "Could not read or restore the encrypted archive."
            ) from exc

        if dest_path.exists():
            if dest_path.is_dir():
                shutil.rmtree(dest_path)
            else:
                dest_path.unlink()
        os.replace(temporary_path, dest_path)
        return file_count
    finally:
        if temporary_path.exists():
            shutil.rmtree(temporary_path, ignore_errors=True)
