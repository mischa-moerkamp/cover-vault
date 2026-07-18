from __future__ import annotations

from pathlib import Path

from .archive import DEFAULT_EXCLUDES, GIT_HISTORY_EXCLUDE

MODES = ("auto", "image-lsb", "wav-lsb", "pdf-append")


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


def suggested_output_path(cover_path: str) -> str:
    if not cover_path:
        return ""
    path = Path(cover_path).expanduser()
    suffix = path.suffix
    return str(path.with_name(f"{path.stem}.vault{suffix}"))


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
