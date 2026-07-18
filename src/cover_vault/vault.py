from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Literal

from .archive import DEFAULT_EXCLUDES, extract_archive, make_archive
from .cover import read_cover
from .crypto import (
    KdfParams,
    cover_hash_hex,
    decrypt_payload,
    derive_master_key,
    derive_placement_seed,
    encrypt_payload_with_context,
    encrypted_payload_size_for_plaintext,
)
from .errors import CoverVaultError
from .progress import ProgressCallback, report
from .stego import (
    DEFAULT_MAX_USAGE_RATIO,
    embed_payload_image,
    embed_payload_pdf,
    embed_payload_wav,
    extract_payload_image,
    extract_payload_pdf,
    extract_payload_wav,
    image_capacity_bytes_from_bytes,
    pdf_reference_capacity_bytes_from_bytes,
    read_image_kdf_params,
    read_wav_kdf_params,
    validate_capacity,
    wav_capacity_bytes_from_bytes,
)

CarrierMode = Literal["auto", "wav-lsb", "image-lsb", "pdf-attachment"]
RevealMode = Literal["wav-lsb", "image-lsb", "pdf-attachment", "auto"]


def _try_capacity(mode: str, cover_bytes: bytes) -> int | None:
    try:
        if mode == "wav-lsb":
            return wav_capacity_bytes_from_bytes(cover_bytes)
        if mode == "image-lsb":
            return image_capacity_bytes_from_bytes(cover_bytes)
        if mode == "pdf-attachment":
            return pdf_reference_capacity_bytes_from_bytes(cover_bytes)
    except CoverVaultError:
        return None
    return None


def _detect_hide_mode(cover_bytes: bytes, requested: CarrierMode) -> str:
    if requested != "auto":
        _capacity_for_mode(requested, cover_bytes)
        return requested

    if _try_capacity("wav-lsb", cover_bytes) is not None:
        return "wav-lsb"
    if _try_capacity("image-lsb", cover_bytes) is not None:
        return "image-lsb"
    if _try_capacity("pdf-attachment", cover_bytes) is not None:
        return "pdf-attachment"
    raise CoverVaultError(
        "Could not identify a supported cover type. Use an uncompressed PCM WAV, a lossless image readable by Pillow, or a PDF."
    )


def _capacity_for_mode(mode: str, cover_bytes: bytes) -> int:
    if mode == "wav-lsb":
        return wav_capacity_bytes_from_bytes(cover_bytes)
    if mode == "image-lsb":
        return image_capacity_bytes_from_bytes(cover_bytes)
    if mode == "pdf-attachment":
        return pdf_reference_capacity_bytes_from_bytes(cover_bytes)
    raise CoverVaultError(f"Unsupported carrier mode: {mode}")


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
    progress: ProgressCallback | None = None,
) -> dict:
    """Encrypt a folder and hide the encrypted payload in a cover file."""

    report(progress, 0.02, "Reading cover file")
    cover_bytes = read_cover(cover_source)
    detected_mode = _detect_hide_mode(cover_bytes, mode)
    report(progress, 0.12, f"Creating archive ({detected_mode})")
    archive_bytes, files_added = make_archive(source_folder, excludes=excludes)
    report(progress, 0.42, "Encrypting archive")
    encrypted = encrypt_payload_with_context(
        archive_bytes, password=password, cover_bytes=cover_bytes
    )
    report(progress, 0.66, "Embedding encrypted payload")

    if detected_mode == "wav-lsb":
        seed = derive_placement_seed(encrypted.master_key, detected_mode, cover_bytes)
        usage = embed_payload_wav(
            cover_bytes,
            output_file,
            encrypted.payload,
            seed,
            kdf_params=encrypted.kdf_params,
            max_usage_ratio=max_usage_ratio,
        )
    elif detected_mode == "image-lsb":
        seed = derive_placement_seed(encrypted.master_key, detected_mode, cover_bytes)
        usage = embed_payload_image(
            cover_bytes,
            output_file,
            encrypted.payload,
            seed,
            kdf_params=encrypted.kdf_params,
            max_usage_ratio=max_usage_ratio,
        )
    elif detected_mode == "pdf-attachment":
        usage = embed_payload_pdf(
            cover_bytes,
            output_file,
            encrypted.payload,
            max_usage_ratio=max_usage_ratio,
        )
    else:  # pragma: no cover - guarded by mode detection
        raise CoverVaultError(f"Unsupported carrier mode: {detected_mode}")

    report(progress, 1.0, "Vault created")
    return {
        "format_version": 2,
        "mode": detected_mode,
        "output": str(Path(output_file).expanduser()),
        "files_encrypted": files_added,
        "payload_bytes": len(encrypted.payload),
        "capacity_bytes": usage["capacity_bytes"],
        "usage_ratio": usage["usage_ratio"],
        "usage_percent": usage["usage_percent"],
        "usage_warning": usage["warning"],
        "cover_sha256": cover_hash_hex(cover_bytes),
    }


def _extract_lsb_payload(
    stego_file: Path | str,
    mode: Literal["wav-lsb", "image-lsb"],
    *,
    cover_bytes: bytes,
    password: str,
) -> tuple[bytes, bytes, KdfParams]:
    if mode == "wav-lsb":
        params = read_wav_kdf_params(stego_file)
        extractor = extract_payload_wav
    else:
        params = read_image_kdf_params(stego_file)
        extractor = extract_payload_image

    master_key = derive_master_key(password, params, cover_bytes)
    seed = derive_placement_seed(master_key, mode, cover_bytes)
    return extractor(stego_file, seed), master_key, params


def _extract_payload(
    stego_file: Path | str,
    mode: RevealMode,
    *,
    cover_bytes: bytes,
    password: str,
) -> tuple[bytes, str, bytes | None, KdfParams | None]:
    if mode == "wav-lsb":
        payload, master_key, params = _extract_lsb_payload(
            stego_file, "wav-lsb", cover_bytes=cover_bytes, password=password
        )
        return payload, "wav-lsb", master_key, params
    if mode == "image-lsb":
        payload, master_key, params = _extract_lsb_payload(
            stego_file, "image-lsb", cover_bytes=cover_bytes, password=password
        )
        return payload, "image-lsb", master_key, params
    if mode == "pdf-attachment":
        return extract_payload_pdf(stego_file), "pdf-attachment", None, None
    if mode == "auto":
        errors: list[str] = []
        for candidate in ("wav-lsb", "image-lsb", "pdf-attachment"):
            try:
                return _extract_payload(
                    stego_file,
                    candidate,  # type: ignore[arg-type]
                    cover_bytes=cover_bytes,
                    password=password,
                )
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
    progress: ProgressCallback | None = None,
) -> dict:
    """Extract, decrypt, and restore a hidden folder payload."""

    report(progress, 0.02, "Reading original cover")
    cover_bytes = read_cover(cover_source)
    report(progress, 0.18, "Extracting encrypted payload")
    payload, detected_mode, master_key, kdf_params = _extract_payload(
        stego_file, mode, cover_bytes=cover_bytes, password=password
    )
    report(progress, 0.50, "Decrypting archive")
    archive_bytes = decrypt_payload(
        payload,
        password=password,
        cover_bytes=cover_bytes,
        master_key=master_key,
        expected_kdf_params=kdf_params,
    )
    report(progress, 0.76, "Restoring files")
    files_written = extract_archive(
        archive_bytes, destination_folder, overwrite=overwrite
    )
    report(progress, 1.0, "Folder restored")
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
    for mode in ("wav-lsb", "image-lsb", "pdf-attachment"):
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
        "format_version": 2,
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
