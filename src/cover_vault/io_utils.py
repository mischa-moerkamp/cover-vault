from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .errors import CoverVaultError


@contextmanager
def atomic_output_path(
    destination: Path | str, *, overwrite: bool = False
) -> Iterator[Path]:
    """Yield a temporary sibling path and atomically install it on success."""

    destination_path = Path(destination).expanduser()
    if destination_path.exists() and not overwrite:
        raise CoverVaultError(
            f"Output already exists: {destination_path}. Use the explicit overwrite option to replace it."
        )
    if destination_path.exists() and destination_path.is_dir():
        raise CoverVaultError(f"Output path is a directory: {destination_path}")

    destination_path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination_path.stem}.",
        suffix=destination_path.suffix,
        dir=destination_path.parent,
    )
    os.close(file_descriptor)
    temporary_path = Path(temporary_name)
    try:
        yield temporary_path
        if destination_path.exists() and not overwrite:
            raise CoverVaultError(
                f"Output appeared while the vault was being created: {destination_path}. "
                "It was not replaced."
            )
        os.replace(temporary_path, destination_path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def atomic_write_bytes(
    destination: Path | str, data: bytes, *, overwrite: bool = False
) -> None:
    with atomic_output_path(destination, overwrite=overwrite) as temporary_path:
        with temporary_path.open("wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
