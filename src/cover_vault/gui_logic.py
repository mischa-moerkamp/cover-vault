from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote, urlparse

from .archive import DEFAULT_EXCLUDES, GIT_HISTORY_EXCLUDE

MODES = ("auto", "image-lsb", "wav-lsb", "pdf-attachment")
_SUPPORTED_SUFFIXES = {".png", ".bmp", ".tif", ".tiff", ".wav", ".pdf"}


def build_excludes(include_git_history: bool, custom_text: str) -> tuple[str, ...]:
    defaults = set(DEFAULT_EXCLUDES)
    if include_git_history:
        defaults.discard(GIT_HISTORY_EXCLUDE)
    custom = {
        item.strip()
        for item in custom_text.replace(";", ",").split(",")
        if item.strip()
    }
    return tuple(sorted(defaults | custom))


def cover_suffix(cover_source: str) -> str:
    if not cover_source:
        return ""
    parsed = urlparse(cover_source)
    if parsed.scheme.lower() in {"http", "https"}:
        path = unquote(parsed.path)
        suffix = Path(path).suffix.lower()
        if suffix in _SUPPORTED_SUFFIXES:
            return suffix
        if "/pdf/" in f"{path.rstrip('/')}/":
            return ".pdf"
        return ""
    return Path(cover_source).expanduser().suffix


def suggested_output_filename(cover_source: str) -> str:
    if not cover_source:
        return ""
    parsed = urlparse(cover_source)
    if parsed.scheme.lower() in {"http", "https"}:
        path = unquote(parsed.path).rstrip("/")
        name = Path(path).name or "remote-cover"
        suffix = cover_suffix(cover_source)
        raw_suffix = Path(name).suffix.lower()
        stem = Path(name).stem if raw_suffix in _SUPPORTED_SUFFIXES else name
        if "/pdf/" in f"{path}/" and not stem.lower().startswith("arxiv-"):
            stem = f"arxiv-{stem}"
        return f"{stem}.vault{suffix or '.cover'}"
    path = Path(cover_source).expanduser()
    return f"{path.stem}.vault{path.suffix}"


def suggested_output_path(cover_source: str) -> str:
    if not cover_source:
        return ""
    parsed = urlparse(cover_source)
    filename = suggested_output_filename(cover_source)
    if parsed.scheme.lower() in {"http", "https"}:
        downloads = Path.home() / "Downloads"
        directory = downloads if downloads.is_dir() else Path.home()
        return str(directory / filename)
    path = Path(cover_source).expanduser()
    return str(path.with_name(filename))


def format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.2f} {unit}"
        amount /= 1024
    return f"{value} B"


def capacity_summary(plan: dict) -> str:
    status = (
        "Ready"
        if plan["fits_capacity"] and plan["fits_ratio_limit"]
        else "Does not fit"
    )
    return (
        f"{status} — {plan['files_to_encrypt']} files, "
        f"estimated payload {format_bytes(plan['estimated_payload_bytes'])}, "
        f"usage {plan['usage_percent']:.2f}% of {format_bytes(plan['capacity_bytes'])}."
    )
