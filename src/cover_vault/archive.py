from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path
from typing import Iterable

from .errors import CoverVaultError

# Defaults intentionally exclude VCS internals. This captures the current
# filesystem state of the target folder, not its Git/SVN/Mercurial history.
DEFAULT_EXCLUDES = {".DS_Store", "__pycache__", ".git", ".hg", ".svn"}
GIT_HISTORY_EXCLUDE = ".git"


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


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
    target = (destination / member_name).resolve()
    destination_resolved = destination.resolve()
    if target != destination_resolved and destination_resolved not in target.parents:
        raise CoverVaultError(f"Refusing unsafe archive path: {member_name}")
    return target


def extract_archive(
    archive_bytes: bytes, destination: Path | str, overwrite: bool = False
) -> int:
    dest_path = Path(destination).expanduser().resolve()
    if dest_path.exists() and any(dest_path.iterdir()) and not overwrite:
        raise CoverVaultError(
            f"Destination already exists and is not empty: {dest_path}"
        )
    if overwrite and dest_path.exists():
        import shutil

        shutil.rmtree(dest_path)
    dest_path.mkdir(parents=True, exist_ok=True)

    file_count = 0
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            _safe_member_path(dest_path, member.name)
            if member.issym() or member.islnk():
                raise CoverVaultError(f"Refusing link in archive: {member.name}")
            if member.isfile():
                file_count += 1
        for member in members:
            target = _safe_member_path(dest_path, member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    raise CoverVaultError(
                        f"Could not read archive member: {member.name}"
                    )
                with source, target.open("wb") as out:
                    import shutil

                    shutil.copyfileobj(source, out)
            else:
                raise CoverVaultError(f"Unsupported archive member type: {member.name}")

            # Best-effort metadata restoration. File contents are the important
            # part; failures here should not make a valid vault unreadable.
            try:
                target.chmod(member.mode)
            except OSError:
                pass
            try:
                os.utime(target, (member.mtime, member.mtime))
            except OSError:
                pass
    return file_count
