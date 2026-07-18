from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import struct
import wave
from collections.abc import Iterable, Sequence
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.errors import PyPdfError

from .crypto import KdfParams
from .errors import CoverVaultError
from .io_utils import atomic_output_path

WAV_STEGO_MAGIC = b"CVWAV3\x00"
IMAGE_STEGO_MAGIC = b"CVIMG2\x00"
LSB_BOOTSTRAP_MAGIC = b"CVLSB2\x00"
MAX_LSB_BOOTSTRAP_BYTES = 4096
PDF_ATTACHMENT_NAME = "cover-vault.cvault"
LOSSLESS_IMAGE_OUTPUT_FORMATS = {
    ".png": "PNG",
    ".bmp": "BMP",
    ".tif": "TIFF",
    ".tiff": "TIFF",
}
HIGH_USAGE_WARNING_RATIO = 0.10
DEFAULT_MAX_USAGE_RATIO = 0.25


def _bytes_to_bits(data: bytes) -> Iterable[int]:
    for byte in data:
        for bit_index in range(7, -1, -1):
            yield (byte >> bit_index) & 1


def _bits_to_bytes(bits: Iterable[int], expected_bits: int) -> bytes:
    if expected_bits % 8 != 0:
        raise CoverVaultError("Bit stream length must be a multiple of 8.")
    output = bytearray(expected_bits // 8)
    for index, bit in enumerate(bits):
        output[index // 8] |= bit << (7 - (index % 8))
    return bytes(output)


def _container(magic: bytes, payload: bytes) -> bytes:
    return magic + struct.pack(">Q", len(payload)) + payload


def _usage_ratio(payload_bytes: int, capacity_bytes: int) -> float:
    if capacity_bytes <= 0:
        return 1.0
    return payload_bytes / capacity_bytes


def describe_usage(payload_bytes: int, capacity_bytes: int) -> dict:
    ratio = _usage_ratio(payload_bytes, capacity_bytes)
    return {
        "payload_bytes": payload_bytes,
        "capacity_bytes": capacity_bytes,
        "usage_ratio": ratio,
        "usage_percent": ratio * 100,
        "warning": ratio > HIGH_USAGE_WARNING_RATIO,
    }


def validate_capacity(
    *,
    mode: str,
    payload_bytes: int,
    capacity_bytes: int,
    max_usage_ratio: float = DEFAULT_MAX_USAGE_RATIO,
) -> None:
    if not 0 < max_usage_ratio <= 1:
        raise CoverVaultError("max_usage_ratio must be greater than 0 and at most 1.")
    if payload_bytes > capacity_bytes:
        raise CoverVaultError(
            f"Cover is too small for {mode}. Need {payload_bytes} bytes of payload capacity; "
            f"available capacity is {capacity_bytes} bytes."
        )
    ratio = _usage_ratio(payload_bytes, capacity_bytes)
    if ratio > max_usage_ratio:
        raise CoverVaultError(
            f"Cover usage would be {ratio:.2%}, above the configured limit of {max_usage_ratio:.2%}. "
            "Use a larger cover file, reduce the source folder, add excludes, or raise --max-usage-ratio."
        )


class _DeterministicHmacRng:
    """Small deterministic CSPRNG used by the partial Fisher-Yates shuffle."""

    def __init__(self, seed: bytes):
        self._key = hashlib.sha256(seed).digest()
        self._counter = 0

    def _block(self) -> bytes:
        block = hmac.new(
            self._key,
            self._counter.to_bytes(16, "big"),
            hashlib.sha256,
        ).digest()
        self._counter += 1
        return block

    def randbelow(self, upper_bound: int) -> int:
        if upper_bound <= 0:
            raise ValueError("upper_bound must be positive")
        byte_count = max(1, (upper_bound.bit_length() + 7) // 8)
        sample_space = 1 << (byte_count * 8)
        acceptance_limit = sample_space - (sample_space % upper_bound)
        while True:
            value = int.from_bytes(self._block()[:byte_count], "big")
            if value < acceptance_limit:
                return value % upper_bound


def _sampled_positions(count: int, take: int, seed: bytes) -> Iterable[int]:
    """Yield unique keyed positions using O(take), rather than O(count), memory."""

    if take < 0 or take > count:
        raise CoverVaultError("Carrier does not have enough positions.")
    rng = _DeterministicHmacRng(seed)
    swaps: dict[int, int] = {}
    for index in range(take):
        chosen = index + rng.randbelow(count - index)
        value_at_index = swaps.pop(index, index)
        if chosen == index:
            value_at_chosen = value_at_index
        else:
            value_at_chosen = swaps.pop(chosen, chosen)
            swaps[chosen] = value_at_index
        yield value_at_chosen


def _write_bits_spread(
    carrier: bytearray, byte_indices: Sequence[int], data: bytes, seed: bytes
) -> None:
    bit_count = len(data) * 8
    if bit_count > len(byte_indices):
        raise CoverVaultError("Carrier does not have enough writable positions.")
    positions = _sampled_positions(len(byte_indices), bit_count, seed)
    for position, bit in zip(positions, _bytes_to_bits(data), strict=True):
        carrier_index = byte_indices[position]
        carrier[carrier_index] = (carrier[carrier_index] & 0xFE) | bit


def _read_bytes_spread(
    carrier: bytearray, byte_indices: Sequence[int], byte_count: int, seed: bytes
) -> bytes:
    bit_count = byte_count * 8
    if bit_count > len(byte_indices):
        raise CoverVaultError("Carrier does not have enough readable positions.")
    positions = _sampled_positions(len(byte_indices), bit_count, seed)
    bits = (carrier[byte_indices[position]] & 1 for position in positions)
    return _bits_to_bytes(bits, bit_count)


def _write_bytes_linear(
    carrier: bytearray, byte_indices: Sequence[int], data: bytes
) -> None:
    bit_count = len(data) * 8
    if bit_count > len(byte_indices):
        raise CoverVaultError("Carrier does not have enough bootstrap capacity.")
    for carrier_index, bit in zip(
        byte_indices[:bit_count], _bytes_to_bits(data), strict=True
    ):
        carrier[carrier_index] = (carrier[carrier_index] & 0xFE) | bit


def _read_bytes_linear(
    carrier: bytearray, byte_indices: Sequence[int], byte_count: int
) -> bytes:
    bit_count = byte_count * 8
    if bit_count > len(byte_indices):
        raise CoverVaultError("Carrier does not have enough bootstrap capacity.")
    bits = (carrier[index] & 1 for index in byte_indices[:bit_count])
    return _bits_to_bytes(bits, bit_count)


def _lsb_bootstrap(params: KdfParams) -> bytes:
    header = json.dumps(
        {"version": 2, "kdf": params.to_dict()},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(header) > MAX_LSB_BOOTSTRAP_BYTES:
        raise CoverVaultError("LSB bootstrap metadata is too large.")
    return LSB_BOOTSTRAP_MAGIC + struct.pack(">I", len(header)) + header


def _estimated_lsb_bootstrap() -> bytes:
    return _lsb_bootstrap(KdfParams.predictable_for_estimate())


def _read_lsb_bootstrap(
    carrier: bytearray, byte_indices: Sequence[int]
) -> tuple[KdfParams, int]:
    prefix_bytes = len(LSB_BOOTSTRAP_MAGIC) + 4
    if len(byte_indices) < prefix_bytes * 8:
        raise CoverVaultError("No Cover Vault LSB bootstrap found.")
    prefix = _read_bytes_linear(carrier, byte_indices, prefix_bytes)
    if not prefix.startswith(LSB_BOOTSTRAP_MAGIC):
        raise CoverVaultError("No Cover Vault LSB bootstrap found.")
    header_len = struct.unpack(">I", prefix[-4:])[0]
    if header_len <= 0 or header_len > MAX_LSB_BOOTSTRAP_BYTES:
        raise CoverVaultError("LSB bootstrap metadata length is invalid.")
    total_bytes = prefix_bytes + header_len
    encoded = _read_bytes_linear(carrier, byte_indices, total_bytes)
    try:
        header = json.loads(encoded[prefix_bytes:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CoverVaultError("LSB bootstrap metadata is invalid.") from exc
    if not isinstance(header, dict) or header.get("version") != 2:
        raise CoverVaultError("Unsupported LSB bootstrap version.")
    return KdfParams.from_dict(header.get("kdf")), total_bytes * 8


def _sample_low_byte_indices(frame_bytes: bytearray, sample_width: int) -> list[int]:
    if sample_width not in {1, 2, 3, 4}:
        raise CoverVaultError(f"Unsupported WAV sample width: {sample_width} bytes")
    return list(range(0, len(frame_bytes), sample_width))


def _read_wav_frames(cover_bytes: bytes) -> tuple[wave._wave_params, int, bytearray]:
    try:
        with wave.open(io.BytesIO(cover_bytes), "rb") as wav:
            params = wav.getparams()
            sample_width = wav.getsampwidth()
            frames = bytearray(wav.readframes(wav.getnframes()))
    except wave.Error as exc:
        raise CoverVaultError(
            "WAV mode requires an uncompressed PCM WAV cover/stego file."
        ) from exc
    return params, sample_width, frames


def wav_capacity_bytes_from_bytes(cover_bytes: bytes) -> int:
    _, sample_width, frames = _read_wav_frames(cover_bytes)
    carrier_bits = len(_sample_low_byte_indices(frames, sample_width))
    overhead_bits = (len(_estimated_lsb_bootstrap()) + len(WAV_STEGO_MAGIC) + 8) * 8
    return max(0, (carrier_bits - overhead_bits) // 8)


def wav_capacity_bytes(cover_wav: Path | str) -> int:
    return wav_capacity_bytes_from_bytes(Path(cover_wav).expanduser().read_bytes())


def embed_payload_wav(
    cover_bytes: bytes,
    output_wav: Path | str,
    payload: bytes,
    seed: bytes,
    *,
    kdf_params: KdfParams,
    max_usage_ratio: float = DEFAULT_MAX_USAGE_RATIO,
) -> dict:
    output_path = Path(output_wav).expanduser()
    params, sample_width, frames = _read_wav_frames(cover_bytes)
    capacity = wav_capacity_bytes_from_bytes(cover_bytes)
    validate_capacity(
        mode="wav-lsb",
        payload_bytes=len(payload),
        capacity_bytes=capacity,
        max_usage_ratio=max_usage_ratio,
    )

    indices = _sample_low_byte_indices(frames, sample_width)
    bootstrap = _lsb_bootstrap(kdf_params)
    bootstrap_bits = len(bootstrap) * 8
    _write_bytes_linear(frames, indices, bootstrap)
    _write_bits_spread(
        frames,
        indices[bootstrap_bits:],
        _container(WAV_STEGO_MAGIC, payload),
        seed,
    )

    with atomic_output_path(output_path) as temporary_path:
        with wave.open(str(temporary_path), "wb") as output:
            output.setparams(params)
            output.writeframes(bytes(frames))
    return describe_usage(len(payload), capacity)


def read_wav_kdf_params(stego_file: Path | str) -> KdfParams:
    stego_bytes = Path(stego_file).expanduser().read_bytes()
    _, sample_width, frames = _read_wav_frames(stego_bytes)
    indices = _sample_low_byte_indices(frames, sample_width)
    params, _ = _read_lsb_bootstrap(frames, indices)
    return params


def extract_payload_wav(stego_file: Path | str, seed: bytes) -> bytes:
    stego_bytes = Path(stego_file).expanduser().read_bytes()
    _, sample_width, frames = _read_wav_frames(stego_bytes)
    indices = _sample_low_byte_indices(frames, sample_width)
    _, bootstrap_bits = _read_lsb_bootstrap(frames, indices)
    payload_indices = indices[bootstrap_bits:]

    header_bytes_needed = len(WAV_STEGO_MAGIC) + 8
    header = _read_bytes_spread(frames, payload_indices, header_bytes_needed, seed)
    if not header.startswith(WAV_STEGO_MAGIC):
        raise CoverVaultError("No Cover Vault WAV payload marker found.")
    payload_len = struct.unpack(">Q", header[len(WAV_STEGO_MAGIC) :])[0]
    if payload_len > (len(payload_indices) // 8) - header_bytes_needed:
        raise CoverVaultError("Stego WAV payload appears truncated.")
    container = _read_bytes_spread(
        frames, payload_indices, header_bytes_needed + payload_len, seed
    )
    return container[header_bytes_needed:]


def _load_rgba_image(image_bytes: bytes):
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError as exc:  # pragma: no cover - dependency declared in pyproject
        raise CoverVaultError(
            "Image mode requires Pillow. Install with: pip install pillow"
        ) from exc

    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.load()
    except UnidentifiedImageError as exc:
        raise CoverVaultError(
            "Image mode requires a readable image cover file."
        ) from exc
    return image.convert("RGBA")


def _rgb_channel_indices_rgba(pixel_bytes: bytearray) -> list[int]:
    indices: list[int] = []
    for base in range(0, len(pixel_bytes), 4):
        indices.extend((base, base + 1, base + 2))
    return indices


def image_capacity_bytes_from_bytes(image_bytes: bytes) -> int:
    image = _load_rgba_image(image_bytes)
    pixel_bytes = bytearray(image.tobytes())
    carrier_bits = len(_rgb_channel_indices_rgba(pixel_bytes))
    overhead_bits = (len(_estimated_lsb_bootstrap()) + len(IMAGE_STEGO_MAGIC) + 8) * 8
    return max(0, (carrier_bits - overhead_bits) // 8)


def image_capacity_bytes(image_file: Path | str) -> int:
    return image_capacity_bytes_from_bytes(Path(image_file).expanduser().read_bytes())


def _image_save_format(output_file: Path | str) -> str:
    suffix = Path(output_file).expanduser().suffix.lower()
    output_format = LOSSLESS_IMAGE_OUTPUT_FORMATS.get(suffix)
    if output_format is None:
        allowed = ", ".join(sorted(LOSSLESS_IMAGE_OUTPUT_FORMATS))
        raise CoverVaultError(
            f"Image mode must write a lossless output format ({allowed}). "
            "Do not use JPEG/WebP output because lossy encoders can destroy hidden bits."
        )
    return output_format


def embed_payload_image(
    cover_bytes: bytes,
    output_image: Path | str,
    payload: bytes,
    seed: bytes,
    *,
    kdf_params: KdfParams,
    max_usage_ratio: float = DEFAULT_MAX_USAGE_RATIO,
) -> dict:
    output_path = Path(output_image).expanduser()
    output_format = _image_save_format(output_path)
    image = _load_rgba_image(cover_bytes)
    pixel_bytes = bytearray(image.tobytes())
    indices = _rgb_channel_indices_rgba(pixel_bytes)
    capacity = image_capacity_bytes_from_bytes(cover_bytes)
    validate_capacity(
        mode="image-lsb",
        payload_bytes=len(payload),
        capacity_bytes=capacity,
        max_usage_ratio=max_usage_ratio,
    )

    bootstrap = _lsb_bootstrap(kdf_params)
    bootstrap_bits = len(bootstrap) * 8
    _write_bytes_linear(pixel_bytes, indices, bootstrap)
    _write_bits_spread(
        pixel_bytes,
        indices[bootstrap_bits:],
        _container(IMAGE_STEGO_MAGIC, payload),
        seed,
    )

    from PIL import Image

    stego = Image.frombytes("RGBA", image.size, bytes(pixel_bytes))
    with atomic_output_path(output_path) as temporary_path:
        if output_format == "BMP":
            stego.convert("RGB").save(temporary_path, format=output_format)
        elif output_format == "TIFF":
            stego.save(temporary_path, format=output_format, compression="raw")
        else:
            stego.save(temporary_path, format=output_format)
    return describe_usage(len(payload), capacity)


def read_image_kdf_params(stego_file: Path | str) -> KdfParams:
    stego_bytes = Path(stego_file).expanduser().read_bytes()
    image = _load_rgba_image(stego_bytes)
    pixel_bytes = bytearray(image.tobytes())
    indices = _rgb_channel_indices_rgba(pixel_bytes)
    params, _ = _read_lsb_bootstrap(pixel_bytes, indices)
    return params


def extract_payload_image(stego_file: Path | str, seed: bytes) -> bytes:
    stego_bytes = Path(stego_file).expanduser().read_bytes()
    image = _load_rgba_image(stego_bytes)
    pixel_bytes = bytearray(image.tobytes())
    indices = _rgb_channel_indices_rgba(pixel_bytes)
    _, bootstrap_bits = _read_lsb_bootstrap(pixel_bytes, indices)
    payload_indices = indices[bootstrap_bits:]

    header_bytes_needed = len(IMAGE_STEGO_MAGIC) + 8
    header = _read_bytes_spread(pixel_bytes, payload_indices, header_bytes_needed, seed)
    if not header.startswith(IMAGE_STEGO_MAGIC):
        raise CoverVaultError("No Cover Vault image payload marker found.")
    payload_len = struct.unpack(">Q", header[len(IMAGE_STEGO_MAGIC) :])[0]
    if payload_len > (len(payload_indices) // 8) - header_bytes_needed:
        raise CoverVaultError("Stego image payload appears truncated.")
    container = _read_bytes_spread(
        pixel_bytes, payload_indices, header_bytes_needed + payload_len, seed
    )
    return container[header_bytes_needed:]


def _pdf_reader(pdf_bytes: bytes, *, role: str) -> PdfReader:
    if not pdf_bytes.lstrip().startswith(b"%PDF-"):
        raise CoverVaultError(f"{role} must be a PDF file.")
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes), strict=False)
    except (PyPdfError, OSError, ValueError) as exc:
        raise CoverVaultError(f"{role} is not a readable PDF file.") from exc
    if reader.is_encrypted:
        raise CoverVaultError(
            f"{role} is encrypted. Password-protected PDF covers are not supported."
        )
    return reader


def pdf_reference_capacity_bytes_from_bytes(pdf_bytes: bytes) -> int:
    """Return the cover-size reference used for PDF attachment ratio guidance."""

    reader = _pdf_reader(pdf_bytes, role="PDF cover")
    try:
        has_reserved_attachment = PDF_ATTACHMENT_NAME in reader.attachments
    except (PyPdfError, OSError, ValueError) as exc:
        raise CoverVaultError("Could not inspect PDF cover attachments.") from exc
    if has_reserved_attachment:
        raise CoverVaultError(
            f"PDF cover already contains the reserved attachment {PDF_ATTACHMENT_NAME!r}."
        )
    return len(pdf_bytes)


def embed_payload_pdf(
    cover_bytes: bytes,
    output_pdf: Path | str,
    payload: bytes,
    *,
    max_usage_ratio: float = DEFAULT_MAX_USAGE_RATIO,
) -> dict:
    output_path = Path(output_pdf).expanduser()
    if output_path.suffix.lower() != ".pdf":
        raise CoverVaultError("PDF mode must write an output file ending in .pdf.")

    capacity = pdf_reference_capacity_bytes_from_bytes(cover_bytes)
    validate_capacity(
        mode="pdf-attachment",
        payload_bytes=len(payload),
        capacity_bytes=capacity,
        max_usage_ratio=max_usage_ratio,
    )

    try:
        writer = PdfWriter(clone_from=io.BytesIO(cover_bytes))
        writer.add_attachment(PDF_ATTACHMENT_NAME, payload)
        with atomic_output_path(output_path) as temporary_path:
            with temporary_path.open("wb") as output:
                writer.write(output)
                output.flush()
                os.fsync(output.fileno())
    except (PyPdfError, OSError, ValueError) as exc:
        raise CoverVaultError("Could not create the PDF attachment vault.") from exc
    return describe_usage(len(payload), capacity)


def extract_payload_pdf(stego_file: Path | str) -> bytes:
    path = Path(stego_file).expanduser()
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise CoverVaultError(f"Could not read PDF vault: {path}") from exc
    reader = _pdf_reader(data, role="PDF vault")
    try:
        attachments = reader.attachments.get(PDF_ATTACHMENT_NAME, [])
    except (PyPdfError, OSError, ValueError) as exc:
        raise CoverVaultError("Could not inspect PDF vault attachments.") from exc
    if len(attachments) != 1:
        if not attachments:
            raise CoverVaultError("No Cover Vault PDF attachment found.")
        raise CoverVaultError("PDF vault contains multiple reserved attachments.")
    return attachments[0]
