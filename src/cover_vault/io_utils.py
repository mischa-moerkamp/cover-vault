from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def atomic_output_path(destination: Path | str) -> Iterator[Path]:
    """Yield a temporary sibling path and atomically replace on success."""

    destination_path = Path(destination).expanduser()
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
        os.replace(temporary_path, destination_path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def atomic_write_bytes(destination: Path | str, data: bytes) -> None:
    with atomic_output_path(destination) as temporary_path:
        with temporary_path.open("wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
