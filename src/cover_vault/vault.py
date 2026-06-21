from __future__ import annotations

from pathlib import Path
from typing import Iterable, Literal

from .archive import DEFAULT_EXCLUDES, extract_archive, make_archive
from .cover import read_cover
from .crypto import (
    cover_hash_hex,
    decrypt_payload,
    encrypt_payload,
    encrypted_payload_size_for_plaintext,
)
from .errors import CoverVaultError
from .stego import (
    DEFAULT_MAX_USAGE_RATIO,
    embed_payload_image,
    embed_payload_wav,
    extract_payload_image,
    extract_payload_wav,
    image_capacity_bytes_from_bytes,
    position_seed,
    validate_capacity,
    wav_capacity_bytes_from_bytes,
)

CarrierMode = Literal["auto", "wav-lsb", "image-lsb"]
RevealMode = Literal["wav-lsb", "image-lsb", "auto"]


def _try_capacity(mode: str, cover_bytes: bytes) -> int | None:
    try:
        if mode == "wav-lsb":
            return wav_capacity_bytes_from_bytes(cover_bytes)
        if mode == "image-lsb":
            return image_capacity_bytes_from_bytes(cover_bytes)
    except CoverVaultError:
        return None
    return None


def _detect_hide_mode(cover_bytes: bytes, requested: CarrierMode) -> str:
    if requested != "auto":
        capacity = _try_capacity(requested, cover_bytes)
        if capacity is None:
            raise CoverVaultError(
                f"Cover file is not compatible with {requested} mode."
            )
        return requested

    # Prefer WAV when both parsers happen to accept the file because WAV output
    # preserves the same media family. Otherwise use lossless image LSB.
    if _try_capacity("wav-lsb", cover_bytes) is not None:
        return "wav-lsb"
    if _try_capacity("image-lsb", cover_bytes) is not None:
        return "image-lsb"
    raise CoverVaultError(
        "Could not identify a supported cover type. Use an uncompressed PCM WAV or an image readable by Pillow "
        "and write image output as PNG/BMP/TIFF."
    )


def _capacity_for_mode(mode: str, cover_bytes: bytes) -> int:
    capacity = _try_capacity(mode, cover_bytes)
    if capacity is None:
        raise CoverVaultError(f"Cover file is not compatible with {mode} mode.")
    return capacity


def _usage_result(payload_bytes: int, capacity_bytes: int) -> dict:
    ratio = 1.0 if capacity_bytes <= 0 else payload_bytes / capacity_bytes
    return {
        "payload_bytes": payload_bytes,
        "capacity_bytes": capacity_bytes,
        "usage_ratio": ratio,
        "usage_percent": ratio * 100,
        "usage_warning": ratio > 0.10,
    }


def hide_folder(
    source_folder: Path | str,
    cover_source: Path | str,
    output_file: Path | str,
    password: str,
    mode: CarrierMode = "auto",
    excludes: Iterable[str] = DEFAULT_EXCLUDES,
    max_usage_ratio: float = DEFAULT_MAX_USAGE_RATIO,
) -> dict:
    """Encrypt a folder and hide the encrypted payload in a cover file."""

    cover_bytes = read_cover(cover_source)
    detected_mode = _detect_hide_mode(cover_bytes, mode)
    archive_bytes, files_added = make_archive(source_folder, excludes=excludes)
    payload = encrypt_payload(archive_bytes, password=password, cover_bytes=cover_bytes)
    seed = position_seed(detected_mode, cover_bytes, password)

    if detected_mode == "wav-lsb":
        usage = embed_payload_wav(
            cover_bytes,
            output_file,
            payload,
            seed,
            max_usage_ratio=max_usage_ratio,
        )
    elif detected_mode == "image-lsb":
        usage = embed_payload_image(
            cover_bytes,
            output_file,
            payload,
            seed,
            max_usage_ratio=max_usage_ratio,
        )
    else:  # pragma: no cover - guarded by mode detection
        raise CoverVaultError(f"Unsupported carrier mode: {detected_mode}")

    return {
        "mode": detected_mode,
        "output": str(Path(output_file).expanduser()),
        "files_encrypted": files_added,
        "payload_bytes": len(payload),
        "capacity_bytes": usage["capacity_bytes"],
        "usage_ratio": usage["usage_ratio"],
        "usage_percent": usage["usage_percent"],
        "usage_warning": usage["warning"],
        "cover_sha256": cover_hash_hex(cover_bytes),
    }


def _extract_payload(
    stego_file: Path | str,
    mode: RevealMode,
    *,
    cover_bytes: bytes,
    password: str,
) -> tuple[bytes, str]:
    if mode == "wav-lsb":
        seed = position_seed("wav-lsb", cover_bytes, password)
        return extract_payload_wav(stego_file, seed), "wav-lsb"
    if mode == "image-lsb":
        seed = position_seed("image-lsb", cover_bytes, password)
        return extract_payload_image(stego_file, seed), "image-lsb"
    if mode == "auto":
        errors: list[str] = []
        for candidate in ("wav-lsb", "image-lsb"):
            try:
                return _extract_payload(
                    stego_file, candidate, cover_bytes=cover_bytes, password=password
                )  # type: ignore[arg-type]
            except CoverVaultError as exc:
                errors.append(f"{candidate}: {exc}")
        raise CoverVaultError(
            "Could not find a Cover Vault payload. Tried " + "; ".join(errors)
        )
    raise CoverVaultError(f"Unsupported reveal mode: {mode}")


def reveal_folder(
    stego_file: Path | str,
    cover_source: Path | str,
    destination_folder: Path | str,
    password: str,
    mode: RevealMode = "auto",
    overwrite: bool = False,
) -> dict:
    """Extract, decrypt, and restore a hidden folder payload."""

    cover_bytes = read_cover(cover_source)
    payload, detected_mode = _extract_payload(
        stego_file, mode, cover_bytes=cover_bytes, password=password
    )
    archive_bytes = decrypt_payload(payload, password=password, cover_bytes=cover_bytes)
    files_written = extract_archive(
        archive_bytes, destination_folder, overwrite=overwrite
    )
    return {
        "mode": detected_mode,
        "destination": str(Path(destination_folder).expanduser()),
        "files_decrypted": files_written,
        "cover_sha256": cover_hash_hex(cover_bytes),
    }


def cover_info(cover_source: Path | str) -> dict:
    cover_bytes = read_cover(cover_source)
    result: dict = {
        "cover_sha256": cover_hash_hex(cover_bytes),
        "cover_bytes": len(cover_bytes),
        "supported_modes": [],
        "capacities": {},
    }
    for mode in ("wav-lsb", "image-lsb"):
        capacity = _try_capacity(mode, cover_bytes)
        if capacity is not None:
            result["supported_modes"].append(mode)
            result["capacities"][mode] = capacity
    return result


def plan_folder(
    source_folder: Path | str,
    cover_source: Path | str,
    mode: CarrierMode = "auto",
    excludes: Iterable[str] = DEFAULT_EXCLUDES,
    max_usage_ratio: float = DEFAULT_MAX_USAGE_RATIO,
) -> dict:
    """Estimate whether a source folder fits into a cover before asking for a password."""

    cover_bytes = read_cover(cover_source)
    detected_mode = _detect_hide_mode(cover_bytes, mode)
    archive_bytes, files_added = make_archive(source_folder, excludes=excludes)
    estimated_payload_bytes = encrypted_payload_size_for_plaintext(len(archive_bytes))
    capacity_bytes = _capacity_for_mode(detected_mode, cover_bytes)
    usage = _usage_result(estimated_payload_bytes, capacity_bytes)
    fits_capacity = estimated_payload_bytes <= capacity_bytes
    fits_ratio = fits_capacity and usage["usage_ratio"] <= max_usage_ratio

    # Reuse the same validation message logic when the plan does not fit, but
    # keep plan_folder non-throwing so it can be used as advisory output.
    advisory: str | None = None
    try:
        validate_capacity(
            mode=detected_mode,
            payload_bytes=estimated_payload_bytes,
            capacity_bytes=capacity_bytes,
            max_usage_ratio=max_usage_ratio,
        )
    except CoverVaultError as exc:
        advisory = str(exc)

    return {
        "mode": detected_mode,
        "files_to_encrypt": files_added,
        "archive_bytes": len(archive_bytes),
        "estimated_payload_bytes": estimated_payload_bytes,
        "capacity_bytes": capacity_bytes,
        "usage_ratio": usage["usage_ratio"],
        "usage_percent": usage["usage_percent"],
        "usage_warning": usage["usage_warning"],
        "fits_capacity": fits_capacity,
        "fits_ratio_limit": fits_ratio,
        "max_usage_ratio": max_usage_ratio,
        "advisory": advisory,
        "cover_sha256": cover_hash_hex(cover_bytes),
    }
