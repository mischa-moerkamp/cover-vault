from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class ProgressEvent:
    """A coarse-grained progress update emitted by hide/reveal operations."""

    fraction: float
    message: str


ProgressCallback = Callable[[ProgressEvent], None]


def report(callback: ProgressCallback | None, fraction: float, message: str) -> None:
    if callback is not None:
        callback(ProgressEvent(max(0.0, min(1.0, fraction)), message))
