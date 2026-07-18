from __future__ import annotations

import io
import os
import shutil
import stat
import tarfile
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .errors import CoverVaultError

DEFAULT_EXCLUDES = {".DS_Store", "__pycache__", ".git", ".hg", ".svn"}
GIT_HISTORY_EXCLUDE = ".git"
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_TOTAL_BYTES = 10 * 1024 * 1024 * 1024
MAX_ARCHIVE_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_PATH_DEPTH = 64
MAX_ARCHIVE_PATH_CHARS = 4096
# The archive and encrypted payload are currently processed in memory. Keep creation
# bounded rather than allowing the operating system to be exhausted unexpectedly.
MAX_IN_MEMORY_SOURCE_BYTES = 512 * 1024 * 1024
MAX_UNSUPPORTED_PATHS_IN_ERROR = 10


@dataclass(frozen=True)
class _SourceEntry:
    path: Path
    relative_name: str
    is_directory: bool


def _should_exclude(path: Path, root: Path, excludes: Iterable[str]) -> bool:
    exclude_set = set(excludes)
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return False
    return any(part in exclude_set for part in parts)


def _format_unsupported_paths(paths: list[Path], root: Path) -> str:
    shown = [
        path.relative_to(root).as_posix()
        for path in paths[:MAX_UNSUPPORTED_PATHS_IN_ERROR]
    ]
    suffix = (
        "" if len(paths) <= len(shown) else f" (and {len(paths) - len(shown)} more)"
    )
    return ", ".join(shown) + suffix


def _scan_source(
    source_path: Path, excludes: Iterable[str]
) -> tuple[list[_SourceEntry], int]:
    entries: list[_SourceEntry] = []
    unsupported: list[Path] = []
    total_file_bytes = 0
    exclude_set = tuple(excludes)

    try:
        for current, dirnames, filenames in os.walk(
            source_path, topdown=True, followlinks=False
        ):
            current_path = Path(current)
            included_dirs: list[str] = []
            for dirname in sorted(dirnames):
                path = current_path / dirname
                if _should_exclude(path, source_path, exclude_set):
                    continue
                try:
                    mode = path.lstat().st_mode
                except OSError as exc:
                    raise CoverVaultError(
                        f"Could not inspect source path: {path}"
                    ) from exc
                if stat.S_ISLNK(mode):
                    unsupported.append(path)
                    continue
                if not stat.S_ISDIR(mode):
                    unsupported.append(path)
                    continue
                included_dirs.append(dirname)
                entries.append(
                    _SourceEntry(path, path.relative_to(source_path).as_posix(), True)
                )
            dirnames[:] = included_dirs

            for filename in sorted(filenames):
                path = current_path / filename
                if _should_exclude(path, source_path, exclude_set):
                    continue
                try:
                    file_stat = path.lstat()
                except OSError as exc:
                    raise CoverVaultError(
                        f"Could not inspect source path: {path}"
                    ) from exc
                if not stat.S_ISREG(file_stat.st_mode):
                    unsupported.append(path)
                    continue
                if file_stat.st_size > MAX_ARCHIVE_FILE_BYTES:
                    raise CoverVaultError(
                        f"Source file is too large: {path} ({file_stat.st_size} bytes)."
                    )
                total_file_bytes += file_stat.st_size
                if total_file_bytes > MAX_IN_MEMORY_SOURCE_BYTES:
                    raise CoverVaultError(
                        "The selected folder contains more than "
                        f"{MAX_IN_MEMORY_SOURCE_BYTES} bytes of file data. "
                        "This release processes archives in memory; split the folder or add excludes."
                    )
                entries.append(
                    _SourceEntry(path, path.relative_to(source_path).as_posix(), False)
                )
    except OSError as exc:
        raise CoverVaultError(f"Could not scan source folder: {source_path}") from exc

    if unsupported:
        raise CoverVaultError(
            "The source contains unsupported symbolic links or special filesystem objects: "
            f"{_format_unsupported_paths(unsupported, source_path)}. "
            "Replace them with regular files/directories or exclude them before creating the vault."
        )
    if len(entries) > MAX_ARCHIVE_MEMBERS:
        raise CoverVaultError(
            f"Source contains too many archive members ({len(entries)})."
        )
    return entries, total_file_bytes


def make_archive(
    source: Path | str, excludes: Iterable[str] = DEFAULT_EXCLUDES
) -> tuple[bytes, int]:
    source_path = Path(source).expanduser().resolve()
    if not source_path.exists() or not source_path.is_dir():
        raise CoverVaultError(f"Source folder does not exist: {source_path}")

    entries, _total_file_bytes = _scan_source(source_path, excludes)
    buffer = io.BytesIO()
    files_added = 0
    try:
        with tarfile.open(
            fileobj=buffer,
            mode="w:gz",
            format=tarfile.PAX_FORMAT,
            dereference=True,
        ) as tar:
            for entry in entries:
                # Re-check immediately before reading. dereference=True makes hard-linked
                # files independent regular-file members that the extractor can restore.
                current_mode = entry.path.lstat().st_mode
                if entry.is_directory:
                    if not stat.S_ISDIR(current_mode) or stat.S_ISLNK(current_mode):
                        raise CoverVaultError(
                            f"Source path changed while archiving: {entry.path}"
                        )
                elif not stat.S_ISREG(current_mode) or stat.S_ISLNK(current_mode):
                    raise CoverVaultError(
                        f"Source path changed while archiving: {entry.path}"
                    )
                tar.add(entry.path, arcname=entry.relative_name, recursive=False)
                if not entry.is_directory:
                    files_added += 1
    except CoverVaultError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise CoverVaultError(
            "Could not create a stable archive from the selected folder. "
            "A file may have changed while it was being read."
        ) from exc

    archive_bytes = buffer.getvalue()
    if len(archive_bytes) > MAX_IN_MEMORY_SOURCE_BYTES:
        raise CoverVaultError(
            "The compressed archive exceeds the in-memory creation limit of "
            f"{MAX_IN_MEMORY_SOURCE_BYTES} bytes. Split the folder or add excludes."
        )
    return archive_bytes, files_added


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


def _is_same_or_ancestor(candidate: Path, child: Path) -> bool:
    return candidate == child or candidate in child.parents


def _validated_destination(
    destination: Path | str, protected_paths: Iterable[Path | str]
) -> Path:
    expanded = Path(destination).expanduser()
    if expanded.is_symlink():
        raise CoverVaultError("Refusing to restore over a symbolic-link destination.")
    destination_path = expanded.resolve(strict=False)

    root = Path(destination_path.anchor).resolve(strict=False)
    home = Path.home().resolve(strict=False)
    cwd = Path.cwd().resolve(strict=False)
    if destination_path == root:
        raise CoverVaultError("Refusing to restore over a filesystem root.")
    if destination_path == home:
        raise CoverVaultError("Refusing to restore over the user home directory.")
    if _is_same_or_ancestor(destination_path, cwd):
        raise CoverVaultError(
            "Refusing to restore over the current working directory or one of its parents."
        )

    for protected in protected_paths:
        protected_path = Path(protected).expanduser().resolve(strict=False)
        if _is_same_or_ancestor(destination_path, protected_path):
            raise CoverVaultError(
                "Refusing to restore into a destination that contains the vault or original cover file."
            )
    return destination_path


def _new_backup_path(destination: Path) -> Path:
    backup = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.backup-", dir=destination.parent)
    )
    backup.rmdir()
    return backup


def _install_restored_tree(temporary_path: Path, destination: Path) -> None:
    backup_path: Path | None = None
    try:
        if destination.exists():
            backup_path = _new_backup_path(destination)
            os.replace(destination, backup_path)
        try:
            os.replace(temporary_path, destination)
        except OSError:
            if (
                backup_path is not None
                and backup_path.exists()
                and not destination.exists()
            ):
                os.replace(backup_path, destination)
                backup_path = None
            raise
        if backup_path is not None:
            if backup_path.is_dir():
                shutil.rmtree(backup_path)
            else:
                backup_path.unlink()
    except OSError as exc:
        raise CoverVaultError(
            "Could not replace the restoration destination; the previous destination was preserved when possible."
        ) from exc


def extract_archive(
    archive_bytes: bytes,
    destination: Path | str,
    overwrite: bool = False,
    *,
    protected_paths: Iterable[Path | str] = (),
) -> int:
    dest_path = _validated_destination(destination, protected_paths)
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
                directories: list[tuple[Path, tarfile.TarInfo]] = []
                for member in members:
                    target = _safe_member_path(temporary_path, member.name)
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                        directories.append((target, member))
                        continue

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

                # Apply directory metadata after children are created, deepest first,
                # so read-only modes and timestamps do not interfere with extraction.
                for target, member in sorted(
                    directories, key=lambda item: len(item[0].parts), reverse=True
                ):
                    try:
                        target.chmod(member.mode)
                    except OSError:
                        pass
                    try:
                        os.utime(target, (member.mtime, member.mtime))
                    except OSError:
                        pass
        except CoverVaultError:
            raise
        except (tarfile.TarError, OSError) as exc:
            raise CoverVaultError(
                "Could not read or restore the encrypted archive."
            ) from exc

        _install_restored_tree(temporary_path, dest_path)
        return file_count
    finally:
        if temporary_path.exists():
            shutil.rmtree(temporary_path, ignore_errors=True)
