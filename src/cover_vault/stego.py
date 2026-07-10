from __future__ import annotations

import hashlib
import io
import random
import struct
import wave
from pathlib import Path
from typing import Sequence

from .errors import CoverVaultError

WAV_STEGO_MAGIC = b"CVWAV2\x00"
IMAGE_STEGO_MAGIC = b"CVIMG1\x00"
PDF_STEGO_MAGIC = b"CVPDF1\x00"
PDF_STEGO_FOOTER = b"CVPDFEND1\x00"
LOSSLESS_IMAGE_OUTPUT_FORMATS = {
    ".png": "PNG",
    ".bmp": "BMP",
    ".tif": "TIFF",
    ".tiff": "TIFF",
}
HIGH_USAGE_WARNING_RATIO = 0.10
DEFAULT_MAX_USAGE_RATIO = 0.25


def position_seed(mode: str, cover_bytes: bytes, password: str) -> bytes:
    if not password:
        raise CoverVaultError("Password cannot be empty.")
    return hashlib.sha256(
        b"cover-vault:stego-positions:v1\x00"
        + mode.encode("ascii")
        + b"\x00"
        + hashlib.sha256(cover_bytes).digest()
        + b"\x00"
        + password.encode("utf-8")
    ).digest()


def _bytes_to_bits(data: bytes):
    for byte in data:
        for bit_index in range(7, -1, -1):
            yield (byte >> bit_index) & 1


def _bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise CoverVaultError("Bit stream length must be a multiple of 8.")
    out = bytearray()
    for start in range(0, len(bits), 8):
        value = 0
        for bit in bits[start : start + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


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


def _permuted_indices(count: int, seed: bytes) -> list[int]:
    """Return a deterministic pseudorandom permutation of carrier positions.

    Spreading changes across the full carrier avoids concentrating all changed
    LSBs at the beginning of the audio/image stream. This is still a prototype
    and not an undetectability guarantee.
    """

    rng = random.Random(int.from_bytes(hashlib.sha256(seed).digest(), "big"))
    indices = list(range(count))
    rng.shuffle(indices)
    return indices


def _write_bits_spread(
    carrier: bytearray, byte_indices: Sequence[int], data: bytes, seed: bytes
) -> None:
    bits = list(_bytes_to_bits(data))
    if len(bits) > len(byte_indices):
        raise CoverVaultError("Carrier does not have enough writable positions.")
    positions = _permuted_indices(len(byte_indices), seed)[: len(bits)]
    for position, bit in zip(positions, bits):
        idx = byte_indices[position]
        carrier[idx] = (carrier[idx] & 0xFE) | bit


def _read_bits_spread(
    carrier: bytearray, byte_indices: Sequence[int], bit_count: int, seed: bytes
) -> list[int]:
    if bit_count > len(byte_indices):
        raise CoverVaultError("Carrier does not have enough readable positions.")
    positions = _permuted_indices(len(byte_indices), seed)[:bit_count]
    return [carrier[byte_indices[position]] & 1 for position in positions]


def _sample_low_byte_indices(frame_bytes: bytearray, sample_width: int) -> list[int]:
    if sample_width not in {1, 2, 3, 4}:
        raise CoverVaultError(f"Unsupported WAV sample width: {sample_width} bytes")
    # In PCM WAV, multi-byte samples are little-endian. Tweaking the low byte's
    # least significant bit changes the sample by the smallest possible amount.
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
    overhead_bits = (len(WAV_STEGO_MAGIC) + 8) * 8
    return max(0, (carrier_bits - overhead_bits) // 8)


def wav_capacity_bytes(cover_wav: Path | str) -> int:
    return wav_capacity_bytes_from_bytes(Path(cover_wav).expanduser().read_bytes())


def embed_payload_wav(
    cover_bytes: bytes,
    output_wav: Path | str,
    payload: bytes,
    seed: bytes,
    *,
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

    data = _container(WAV_STEGO_MAGIC, payload)
    indices = _sample_low_byte_indices(frames, sample_width)
    _write_bits_spread(frames, indices, data, seed)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(output_path), "wb") as out:
        out.setparams(params)
        out.writeframes(bytes(frames))
    return describe_usage(len(payload), capacity)


def extract_payload_wav(stego_file: Path | str, seed: bytes) -> bytes:
    stego_bytes = Path(stego_file).expanduser().read_bytes()
    _, sample_width, frames = _read_wav_frames(stego_bytes)
    indices = _sample_low_byte_indices(frames, sample_width)
    header_bits_needed = (len(WAV_STEGO_MAGIC) + 8) * 8
    if len(indices) < header_bits_needed:
        raise CoverVaultError(
            "Stego WAV is too small to contain a Cover Vault payload."
        )

    header_bits = _read_bits_spread(frames, indices, header_bits_needed, seed)
    header = _bits_to_bytes(header_bits)
    if not header.startswith(WAV_STEGO_MAGIC):
        raise CoverVaultError("No Cover Vault WAV payload marker found.")
    payload_len = struct.unpack(
        ">Q", header[len(WAV_STEGO_MAGIC) : len(WAV_STEGO_MAGIC) + 8]
    )[0]
    total_bits_needed = header_bits_needed + payload_len * 8
    if len(indices) < total_bits_needed:
        raise CoverVaultError("Stego WAV payload appears truncated.")

    payload_bits = _read_bits_spread(frames, indices, total_bits_needed, seed)[
        header_bits_needed:
    ]
    return _bits_to_bytes(payload_bits)


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
    overhead_bits = (len(IMAGE_STEGO_MAGIC) + 8) * 8
    return max(0, (carrier_bits - overhead_bits) // 8)


def image_capacity_bytes(image_file: Path | str) -> int:
    return image_capacity_bytes_from_bytes(Path(image_file).expanduser().read_bytes())


def _image_save_format(output_file: Path | str) -> str:
    suffix = Path(output_file).expanduser().suffix.lower()
    fmt = LOSSLESS_IMAGE_OUTPUT_FORMATS.get(suffix)
    if fmt is None:
        allowed = ", ".join(sorted(LOSSLESS_IMAGE_OUTPUT_FORMATS))
        raise CoverVaultError(
            f"Image mode must write a lossless output format ({allowed}). "
            "Do not use JPEG/WebP output because lossy encoders can destroy hidden bits."
        )
    return fmt


def embed_payload_image(
    cover_bytes: bytes,
    output_image: Path | str,
    payload: bytes,
    seed: bytes,
    *,
    max_usage_ratio: float = DEFAULT_MAX_USAGE_RATIO,
) -> dict:
    output_path = Path(output_image).expanduser()
    output_format = _image_save_format(output_path)
    image = _load_rgba_image(cover_bytes)
    pixel_bytes = bytearray(image.tobytes())
    indices = _rgb_channel_indices_rgba(pixel_bytes)
    capacity = max(0, (len(indices) - (len(IMAGE_STEGO_MAGIC) + 8) * 8) // 8)
    validate_capacity(
        mode="image-lsb",
        payload_bytes=len(payload),
        capacity_bytes=capacity,
        max_usage_ratio=max_usage_ratio,
    )

    data = _container(IMAGE_STEGO_MAGIC, payload)
    _write_bits_spread(pixel_bytes, indices, data, seed)

    from PIL import Image

    stego = Image.frombytes("RGBA", image.size, bytes(pixel_bytes))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "BMP":
        # BMP has no alpha in the common RGB output; PNG/TIFF preserve alpha.
        stego.convert("RGB").save(output_path, format=output_format)
    elif output_format == "TIFF":
        stego.save(output_path, format=output_format, compression="raw")
    else:
        stego.save(output_path, format=output_format)
    return describe_usage(len(payload), capacity)


def extract_payload_image(stego_file: Path | str, seed: bytes) -> bytes:
    stego_bytes = Path(stego_file).expanduser().read_bytes()
    image = _load_rgba_image(stego_bytes)
    pixel_bytes = bytearray(image.tobytes())
    indices = _rgb_channel_indices_rgba(pixel_bytes)
    header_bits_needed = (len(IMAGE_STEGO_MAGIC) + 8) * 8
    if len(indices) < header_bits_needed:
        raise CoverVaultError(
            "Stego image is too small to contain a Cover Vault payload."
        )

    header_bits = _read_bits_spread(pixel_bytes, indices, header_bits_needed, seed)
    header = _bits_to_bytes(header_bits)
    if not header.startswith(IMAGE_STEGO_MAGIC):
        raise CoverVaultError("No Cover Vault image payload marker found.")
    payload_len = struct.unpack(
        ">Q", header[len(IMAGE_STEGO_MAGIC) : len(IMAGE_STEGO_MAGIC) + 8]
    )[0]
    total_bits_needed = header_bits_needed + payload_len * 8
    if len(indices) < total_bits_needed:
        raise CoverVaultError("Stego image payload appears truncated.")

    payload_bits = _read_bits_spread(pixel_bytes, indices, total_bits_needed, seed)[
        header_bits_needed:
    ]
    return _bits_to_bytes(payload_bits)


def _validate_pdf_bytes(pdf_bytes: bytes) -> None:
    if not pdf_bytes.lstrip().startswith(b"%PDF-"):
        raise CoverVaultError("PDF mode requires a valid-looking PDF cover file.")
    if b"%%EOF" not in pdf_bytes[-4096:]:
        raise CoverVaultError("PDF cover does not contain a final %%EOF marker.")


def pdf_usage_capacity_bytes_from_bytes(pdf_bytes: bytes) -> int:
    """Return the reference capacity used for PDF cover-ratio guidance.

    PDF append mode is not physically bounded like LSB carriers, so the original
    PDF byte length is used as the denominator for the configurable usage guard.
    """
    _validate_pdf_bytes(pdf_bytes)
    return len(pdf_bytes)


def embed_payload_pdf(
    cover_bytes: bytes,
    output_pdf: Path | str,
    payload: bytes,
    *,
    max_usage_ratio: float = DEFAULT_MAX_USAGE_RATIO,
) -> dict:
    _validate_pdf_bytes(cover_bytes)
    output_path = Path(output_pdf).expanduser()
    if output_path.suffix.lower() != ".pdf":
        raise CoverVaultError("PDF mode must write an output file ending in .pdf.")

    capacity = pdf_usage_capacity_bytes_from_bytes(cover_bytes)
    validate_capacity(
        mode="pdf-append",
        payload_bytes=len(payload),
        capacity_bytes=capacity,
        max_usage_ratio=max_usage_ratio,
    )
    container = _container(PDF_STEGO_MAGIC, payload)
    footer = PDF_STEGO_FOOTER + struct.pack(">Q", len(container))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(cover_bytes + b"\n" + container + footer)
    return describe_usage(len(payload), capacity)


def extract_payload_pdf(stego_file: Path | str) -> bytes:
    data = Path(stego_file).expanduser().read_bytes()
    footer_len = len(PDF_STEGO_FOOTER) + 8
    if len(data) < footer_len or data[-footer_len:-8] != PDF_STEGO_FOOTER:
        raise CoverVaultError("No Cover Vault PDF payload marker found.")
    container_len = struct.unpack(">Q", data[-8:])[0]
    start = len(data) - footer_len - container_len
    if start < 0:
        raise CoverVaultError("Stego PDF payload appears truncated.")
    container = data[start : len(data) - footer_len]
    header_len = len(PDF_STEGO_MAGIC) + 8
    if len(container) < header_len or not container.startswith(PDF_STEGO_MAGIC):
        raise CoverVaultError("No Cover Vault PDF payload marker found.")
    payload_len = struct.unpack(
        ">Q", container[len(PDF_STEGO_MAGIC) : header_len]
    )[0]
    payload = container[header_len:]
    if len(payload) != payload_len:
        raise CoverVaultError("Stego PDF payload appears truncated.")
    return payload
