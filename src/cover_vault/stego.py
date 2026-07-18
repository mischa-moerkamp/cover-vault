from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import struct
import wave
from bisect import bisect_right
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.errors import PyPdfError

from .crypto import KdfParams, cover_digest
from .errors import CoverVaultError
from .io_utils import atomic_output_path

WAV_STEGO_MAGIC = b"CVWAV3\x00"
IMAGE_STEGO_MAGIC = b"CVIMG2\x00"
LEGACY_LSB_BOOTSTRAP_MAGIC = b"CVLSB2\x00"
LSB_BOOTSTRAP_VERSION = 3
MAX_LSB_BOOTSTRAP_BYTES = 4096
LSB_BOOTSTRAP_MAC_BYTES = 16
PDF_ATTACHMENT_NAME = "cover-vault.cvault"
LOSSLESS_IMAGE_OUTPUT_FORMATS = {
    ".png": "PNG",
    ".bmp": "BMP",
    ".tif": "TIFF",
    ".tiff": "TIFF",
}
HIGH_USAGE_WARNING_RATIO = 0.10
DEFAULT_MAX_USAGE_RATIO = 0.25
MAX_IMAGE_PIXELS = 50_000_000
MAX_DECODED_WAV_BYTES = 512 * 1024 * 1024
MAX_STEGO_FILE_BYTES = 512 * 1024 * 1024


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
    """Legacy deterministic CSPRNG retained only to read v2 LSB vaults."""

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


def _legacy_sampled_positions(count: int, take: int, seed: bytes) -> Iterable[int]:
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


def _rotate_left(value: int, shift: int, width: int, mask: int) -> int:
    if width <= 1:
        return value & mask
    shift %= width
    if shift == 0:
        return value & mask
    return ((value << shift) | (value >> (width - shift))) & mask


def _feistel_permute(
    value: int,
    half_bits: int,
    round_keys: tuple[int, ...],
    round_multipliers: tuple[int, ...],
) -> int:
    mask = (1 << half_bits) - 1
    left = value >> half_bits
    right = value & mask
    for round_index, (round_key, multiplier) in enumerate(
        zip(round_keys, round_multipliers, strict=True)
    ):
        mixed = (right + round_key) & mask
        mixed ^= _rotate_left(mixed, round_index * 3 + 1, half_bits, mask)
        mixed = (mixed * multiplier) & mask
        mixed ^= mixed >> max(1, half_bits // 2)
        left, right = right, left ^ (mixed & mask)
    return (left << half_bits) | right


def _permutation_parameters(
    seed: bytes, half_bits: int, rounds: int = 10
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    byte_count = max(1, (half_bits + 7) // 8)
    material = hashlib.shake_256(
        b"cover-vault:position-permutation:v3\x00" + seed + half_bits.to_bytes(2, "big")
    ).digest(rounds * byte_count * 2)
    mask = (1 << half_bits) - 1
    keys: list[int] = []
    multipliers: list[int] = []
    offset = 0
    for _ in range(rounds):
        keys.append(
            int.from_bytes(material[offset : offset + byte_count], "big") & mask
        )
        offset += byte_count
        multiplier = (
            int.from_bytes(material[offset : offset + byte_count], "big") & mask
        ) | 1
        offset += byte_count
        multipliers.append(multiplier)
    return tuple(keys), tuple(multipliers)


def _permuted_positions(count: int, take: int, seed: bytes) -> Iterator[int]:
    """Yield unique keyed positions with constant auxiliary memory."""

    if take < 0 or take > count:
        raise CoverVaultError("Carrier does not have enough positions.")
    if take == 0:
        return
    bits = max(2, (count - 1).bit_length())
    if bits % 2:
        bits += 1
    half_bits = bits // 2
    domain_size = 1 << bits
    round_keys, round_multipliers = _permutation_parameters(seed, half_bits)
    yielded = 0
    for input_value in range(domain_size):
        candidate = _feistel_permute(
            input_value, half_bits, round_keys, round_multipliers
        )
        if candidate >= count:
            continue
        yield candidate
        yielded += 1
        if yielded == take:
            return
    raise CoverVaultError("Could not generate enough carrier positions.")


class _RgbChannelIndices(Sequence[int]):
    def __init__(self, pixel_byte_count: int):
        self._length = (pixel_byte_count // 4) * 3

    def __len__(self) -> int:
        return self._length

    def __getitem__(self, index: int) -> int:
        if index < 0:
            index += self._length
        if index < 0 or index >= self._length:
            raise IndexError(index)
        pixel, channel = divmod(index, 3)
        return pixel * 4 + channel


class _OffsetIndexView(Sequence[int]):
    def __init__(self, base: Sequence[int], start: int):
        self._base = base
        self._start = start

    def __len__(self) -> int:
        return max(0, len(self._base) - self._start)

    def __getitem__(self, index: int) -> int:
        length = len(self)
        if index < 0:
            index += length
        if index < 0 or index >= length:
            raise IndexError(index)
        return self._base[self._start + index]


class _ExcludedIndexView(Sequence[int]):
    """View a base sequence while excluding logical positions without copying it."""

    def __init__(self, base: Sequence[int], excluded_positions: Iterable[int]):
        self._base = base
        self._excluded = tuple(sorted(set(excluded_positions)))
        if self._excluded and (
            self._excluded[0] < 0 or self._excluded[-1] >= len(base)
        ):
            raise ValueError("excluded position outside base sequence")

    def __len__(self) -> int:
        return len(self._base) - len(self._excluded)

    def __getitem__(self, index: int) -> int:
        length = len(self)
        if index < 0:
            index += length
        if index < 0 or index >= length:
            raise IndexError(index)
        physical = index
        while True:
            skipped = bisect_right(self._excluded, physical)
            candidate = index + skipped
            if candidate == physical:
                return self._base[physical]
            physical = candidate


def _write_bits_spread(
    carrier: bytearray,
    byte_indices: Sequence[int],
    data: bytes,
    seed: bytes,
    *,
    legacy: bool = False,
) -> None:
    bit_count = len(data) * 8
    if bit_count > len(byte_indices):
        raise CoverVaultError("Carrier does not have enough writable positions.")
    positions = (
        _legacy_sampled_positions(len(byte_indices), bit_count, seed)
        if legacy
        else _permuted_positions(len(byte_indices), bit_count, seed)
    )
    for position, bit in zip(positions, _bytes_to_bits(data), strict=True):
        carrier_index = byte_indices[position]
        carrier[carrier_index] = (carrier[carrier_index] & 0xFE) | bit


def _read_bytes_spread(
    carrier: bytearray,
    byte_indices: Sequence[int],
    byte_count: int,
    seed: bytes,
    *,
    legacy: bool = False,
) -> bytes:
    bit_count = byte_count * 8
    if bit_count > len(byte_indices):
        raise CoverVaultError("Carrier does not have enough readable positions.")
    positions = (
        _legacy_sampled_positions(len(byte_indices), bit_count, seed)
        if legacy
        else _permuted_positions(len(byte_indices), bit_count, seed)
    )
    bits = (carrier[byte_indices[position]] & 1 for position in positions)
    return _bits_to_bytes(bits, bit_count)


def _write_bytes_linear(
    carrier: bytearray, byte_indices: Sequence[int], data: bytes
) -> None:
    bit_count = len(data) * 8
    if bit_count > len(byte_indices):
        raise CoverVaultError("Carrier does not have enough bootstrap capacity.")
    for logical_index, bit in enumerate(_bytes_to_bits(data)):
        carrier_index = byte_indices[logical_index]
        carrier[carrier_index] = (carrier[carrier_index] & 0xFE) | bit


def _read_bytes_linear(
    carrier: bytearray, byte_indices: Sequence[int], byte_count: int
) -> bytes:
    bit_count = byte_count * 8
    if bit_count > len(byte_indices):
        raise CoverVaultError("Carrier does not have enough bootstrap capacity.")
    bits = (carrier[byte_indices[index]] & 1 for index in range(bit_count))
    return _bits_to_bytes(bits, bit_count)


def _hmac_stream(key: bytes, byte_count: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < byte_count:
        output.extend(
            hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha256).digest()
        )
        counter += 1
    return bytes(output[:byte_count])


def _xor_bytes(data: bytes, key_stream: bytes) -> bytes:
    return bytes(left ^ right for left, right in zip(data, key_stream, strict=True))


def _bootstrap_keys(cover_bytes: bytes, mode: str) -> tuple[bytes, bytes, bytes]:
    root = hashlib.sha256(
        b"cover-vault:lsb-bootstrap:v3\x00"
        + mode.encode("ascii")
        + b"\x00"
        + cover_digest(cover_bytes)
    ).digest()
    position_seed = hmac.new(root, b"positions", hashlib.sha256).digest()
    whitening_key = hmac.new(root, b"whitening", hashlib.sha256).digest()
    authentication_key = hmac.new(root, b"authentication", hashlib.sha256).digest()
    return position_seed, whitening_key, authentication_key


def _lsb_bootstrap_v3(params: KdfParams, cover_bytes: bytes, mode: str) -> bytes:
    header = json.dumps(
        {"version": LSB_BOOTSTRAP_VERSION, "kdf": params.to_dict()},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(header) > MAX_LSB_BOOTSTRAP_BYTES:
        raise CoverVaultError("LSB bootstrap metadata is too large.")
    _, whitening_key, authentication_key = _bootstrap_keys(cover_bytes, mode)
    tag = hmac.new(authentication_key, header, hashlib.sha256).digest()[
        :LSB_BOOTSTRAP_MAC_BYTES
    ]
    plaintext = struct.pack(">I", len(header)) + header + tag
    return _xor_bytes(plaintext, _hmac_stream(whitening_key, len(plaintext)))


def _estimated_lsb_bootstrap_size() -> int:
    header = json.dumps(
        {
            "version": LSB_BOOTSTRAP_VERSION,
            "kdf": KdfParams.predictable_for_estimate().to_dict(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return 4 + len(header) + LSB_BOOTSTRAP_MAC_BYTES


def _read_lsb_bootstrap_v3(
    carrier: bytearray,
    byte_indices: Sequence[int],
    cover_bytes: bytes,
    mode: str,
) -> tuple[KdfParams, Sequence[int]]:
    position_seed, whitening_key, authentication_key = _bootstrap_keys(
        cover_bytes, mode
    )
    encrypted_prefix = _read_bytes_spread(
        carrier, byte_indices, 4, position_seed, legacy=False
    )
    prefix = _xor_bytes(encrypted_prefix, _hmac_stream(whitening_key, 4))
    header_len = struct.unpack(">I", prefix)[0]
    if header_len <= 0 or header_len > MAX_LSB_BOOTSTRAP_BYTES:
        raise CoverVaultError("No Cover Vault v3 LSB bootstrap found.")
    total_bytes = 4 + header_len + LSB_BOOTSTRAP_MAC_BYTES
    encrypted = _read_bytes_spread(
        carrier, byte_indices, total_bytes, position_seed, legacy=False
    )
    decoded = _xor_bytes(encrypted, _hmac_stream(whitening_key, total_bytes))
    header = decoded[4 : 4 + header_len]
    supplied_tag = decoded[4 + header_len :]
    expected_tag = hmac.new(authentication_key, header, hashlib.sha256).digest()[
        :LSB_BOOTSTRAP_MAC_BYTES
    ]
    if not hmac.compare_digest(supplied_tag, expected_tag):
        raise CoverVaultError("No Cover Vault v3 LSB bootstrap found.")
    try:
        metadata = json.loads(header.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CoverVaultError("LSB bootstrap metadata is invalid.") from exc
    if (
        not isinstance(metadata, dict)
        or metadata.get("version") != LSB_BOOTSTRAP_VERSION
    ):
        raise CoverVaultError("Unsupported LSB bootstrap version.")
    params = KdfParams.from_dict(metadata.get("kdf"))
    bootstrap_positions = tuple(
        _permuted_positions(len(byte_indices), total_bytes * 8, position_seed)
    )
    return params, _ExcludedIndexView(byte_indices, bootstrap_positions)


def _read_legacy_lsb_bootstrap(
    carrier: bytearray, byte_indices: Sequence[int]
) -> tuple[KdfParams, Sequence[int]]:
    prefix_bytes = len(LEGACY_LSB_BOOTSTRAP_MAGIC) + 4
    if len(byte_indices) < prefix_bytes * 8:
        raise CoverVaultError("No Cover Vault LSB bootstrap found.")
    prefix = _read_bytes_linear(carrier, byte_indices, prefix_bytes)
    if not prefix.startswith(LEGACY_LSB_BOOTSTRAP_MAGIC):
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
    return KdfParams.from_dict(header.get("kdf")), _OffsetIndexView(
        byte_indices, total_bytes * 8
    )


def _read_lsb_bootstrap(
    carrier: bytearray,
    byte_indices: Sequence[int],
    *,
    cover_bytes: bytes | None,
    mode: str,
) -> tuple[KdfParams, Sequence[int], bool]:
    if cover_bytes is not None:
        try:
            params, payload_indices = _read_lsb_bootstrap_v3(
                carrier, byte_indices, cover_bytes, mode
            )
            return params, payload_indices, False
        except CoverVaultError:
            pass
    params, payload_indices = _read_legacy_lsb_bootstrap(carrier, byte_indices)
    return params, payload_indices, True


def _sample_low_byte_indices(frame_bytes: bytearray, sample_width: int) -> range:
    if sample_width not in {1, 2, 3, 4}:
        raise CoverVaultError(f"Unsupported WAV sample width: {sample_width} bytes")
    return range(0, len(frame_bytes), sample_width)


def _read_wav_frames(cover_bytes: bytes) -> tuple[wave._wave_params, int, bytearray]:
    try:
        with wave.open(io.BytesIO(cover_bytes), "rb") as wav:
            params = wav.getparams()
            if wav.getcomptype() != "NONE":
                raise CoverVaultError(
                    "WAV mode requires an uncompressed PCM WAV cover/stego file."
                )
            sample_width = wav.getsampwidth()
            expected_bytes = wav.getnframes() * wav.getnchannels() * sample_width
            if expected_bytes > MAX_DECODED_WAV_BYTES:
                raise CoverVaultError(
                    f"Decoded WAV data exceeds the {MAX_DECODED_WAV_BYTES}-byte processing limit."
                )
            frames = bytearray(wav.readframes(wav.getnframes()))
    except CoverVaultError:
        raise
    except (wave.Error, EOFError) as exc:
        raise CoverVaultError(
            "WAV mode requires an uncompressed PCM WAV cover/stego file."
        ) from exc
    return params, sample_width, frames


def wav_capacity_bytes_from_bytes(cover_bytes: bytes) -> int:
    _, sample_width, frames = _read_wav_frames(cover_bytes)
    carrier_bits = len(_sample_low_byte_indices(frames, sample_width))
    overhead_bits = (_estimated_lsb_bootstrap_size() + len(WAV_STEGO_MAGIC) + 8) * 8
    return max(0, (carrier_bits - overhead_bits) // 8)


def wav_capacity_bytes(cover_wav: Path | str) -> int:
    return wav_capacity_bytes_from_bytes(_read_bounded_file(cover_wav, "WAV cover"))


def _write_lsb_bootstrap_v3(
    carrier: bytearray,
    indices: Sequence[int],
    params: KdfParams,
    cover_bytes: bytes,
    mode: str,
) -> Sequence[int]:
    bootstrap = _lsb_bootstrap_v3(params, cover_bytes, mode)
    position_seed, _, _ = _bootstrap_keys(cover_bytes, mode)
    _write_bits_spread(carrier, indices, bootstrap, position_seed)
    positions = tuple(
        _permuted_positions(len(indices), len(bootstrap) * 8, position_seed)
    )
    return _ExcludedIndexView(indices, positions)


def embed_payload_wav(
    cover_bytes: bytes,
    output_wav: Path | str,
    payload: bytes,
    seed: bytes,
    *,
    kdf_params: KdfParams,
    max_usage_ratio: float = DEFAULT_MAX_USAGE_RATIO,
    overwrite: bool = False,
) -> dict:
    output_path = Path(output_wav).expanduser()
    params, sample_width, frames = _read_wav_frames(cover_bytes)
    indices = _sample_low_byte_indices(frames, sample_width)
    overhead_bits = (_estimated_lsb_bootstrap_size() + len(WAV_STEGO_MAGIC) + 8) * 8
    capacity = max(0, (len(indices) - overhead_bits) // 8)
    validate_capacity(
        mode="wav-lsb",
        payload_bytes=len(payload),
        capacity_bytes=capacity,
        max_usage_ratio=max_usage_ratio,
    )

    payload_indices = _write_lsb_bootstrap_v3(
        frames, indices, kdf_params, cover_bytes, "wav-lsb"
    )
    _write_bits_spread(
        frames,
        payload_indices,
        _container(WAV_STEGO_MAGIC, payload),
        seed,
    )

    with atomic_output_path(output_path, overwrite=overwrite) as temporary_path:
        with wave.open(str(temporary_path), "wb") as output:
            output.setparams(params)
            output.writeframes(bytes(frames))
    return describe_usage(len(payload), capacity)


def read_wav_kdf_params(
    stego_file: Path | str, cover_bytes: bytes | None = None
) -> KdfParams:
    stego_bytes = _read_bounded_file(stego_file, "WAV vault")
    _, sample_width, frames = _read_wav_frames(stego_bytes)
    indices = _sample_low_byte_indices(frames, sample_width)
    params, _, _ = _read_lsb_bootstrap(
        frames, indices, cover_bytes=cover_bytes, mode="wav-lsb"
    )
    return params


def extract_payload_wav(
    stego_file: Path | str, seed: bytes, cover_bytes: bytes | None = None
) -> bytes:
    stego_bytes = _read_bounded_file(stego_file, "WAV vault")
    _, sample_width, frames = _read_wav_frames(stego_bytes)
    indices = _sample_low_byte_indices(frames, sample_width)
    _, payload_indices, legacy = _read_lsb_bootstrap(
        frames, indices, cover_bytes=cover_bytes, mode="wav-lsb"
    )

    header_bytes_needed = len(WAV_STEGO_MAGIC) + 8
    header = _read_bytes_spread(
        frames, payload_indices, header_bytes_needed, seed, legacy=legacy
    )
    if not header.startswith(WAV_STEGO_MAGIC):
        raise CoverVaultError("No Cover Vault WAV payload marker found.")
    payload_len = struct.unpack(">Q", header[len(WAV_STEGO_MAGIC) :])[0]
    if payload_len > (len(payload_indices) // 8) - header_bytes_needed:
        raise CoverVaultError("Stego WAV payload appears truncated.")
    container = _read_bytes_spread(
        frames,
        payload_indices,
        header_bytes_needed + payload_len,
        seed,
        legacy=legacy,
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
        width, height = image.size
        if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
            raise CoverVaultError(
                f"Decoded image exceeds the {MAX_IMAGE_PIXELS}-pixel processing limit."
            )
        image.load()
    except CoverVaultError:
        raise
    except (
        UnidentifiedImageError,
        Image.DecompressionBombError,
        OSError,
        ValueError,
    ) as exc:
        raise CoverVaultError(
            "Image mode requires a readable image cover file."
        ) from exc
    return image.convert("RGBA")


def _rgb_channel_indices_rgba(pixel_bytes: bytearray) -> Sequence[int]:
    return _RgbChannelIndices(len(pixel_bytes))


def image_capacity_bytes_from_bytes(image_bytes: bytes) -> int:
    image = _load_rgba_image(image_bytes)
    pixel_bytes = bytearray(image.tobytes())
    carrier_bits = len(_rgb_channel_indices_rgba(pixel_bytes))
    overhead_bits = (_estimated_lsb_bootstrap_size() + len(IMAGE_STEGO_MAGIC) + 8) * 8
    return max(0, (carrier_bits - overhead_bits) // 8)


def image_capacity_bytes(image_file: Path | str) -> int:
    return image_capacity_bytes_from_bytes(
        _read_bounded_file(image_file, "image cover")
    )


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
    overwrite: bool = False,
) -> dict:
    output_path = Path(output_image).expanduser()
    output_format = _image_save_format(output_path)
    image = _load_rgba_image(cover_bytes)
    pixel_bytes = bytearray(image.tobytes())
    indices = _rgb_channel_indices_rgba(pixel_bytes)
    overhead_bits = (_estimated_lsb_bootstrap_size() + len(IMAGE_STEGO_MAGIC) + 8) * 8
    capacity = max(0, (len(indices) - overhead_bits) // 8)
    validate_capacity(
        mode="image-lsb",
        payload_bytes=len(payload),
        capacity_bytes=capacity,
        max_usage_ratio=max_usage_ratio,
    )

    payload_indices = _write_lsb_bootstrap_v3(
        pixel_bytes, indices, kdf_params, cover_bytes, "image-lsb"
    )
    _write_bits_spread(
        pixel_bytes,
        payload_indices,
        _container(IMAGE_STEGO_MAGIC, payload),
        seed,
    )

    from PIL import Image

    stego = Image.frombytes("RGBA", image.size, bytes(pixel_bytes))
    with atomic_output_path(output_path, overwrite=overwrite) as temporary_path:
        if output_format == "BMP":
            stego.convert("RGB").save(temporary_path, format=output_format)
        elif output_format == "TIFF":
            stego.save(temporary_path, format=output_format, compression="raw")
        else:
            stego.save(temporary_path, format=output_format)
    return describe_usage(len(payload), capacity)


def read_image_kdf_params(
    stego_file: Path | str, cover_bytes: bytes | None = None
) -> KdfParams:
    stego_bytes = _read_bounded_file(stego_file, "image vault")
    image = _load_rgba_image(stego_bytes)
    pixel_bytes = bytearray(image.tobytes())
    indices = _rgb_channel_indices_rgba(pixel_bytes)
    params, _, _ = _read_lsb_bootstrap(
        pixel_bytes, indices, cover_bytes=cover_bytes, mode="image-lsb"
    )
    return params


def extract_payload_image(
    stego_file: Path | str, seed: bytes, cover_bytes: bytes | None = None
) -> bytes:
    stego_bytes = _read_bounded_file(stego_file, "image vault")
    image = _load_rgba_image(stego_bytes)
    pixel_bytes = bytearray(image.tobytes())
    indices = _rgb_channel_indices_rgba(pixel_bytes)
    _, payload_indices, legacy = _read_lsb_bootstrap(
        pixel_bytes, indices, cover_bytes=cover_bytes, mode="image-lsb"
    )

    header_bytes_needed = len(IMAGE_STEGO_MAGIC) + 8
    header = _read_bytes_spread(
        pixel_bytes, payload_indices, header_bytes_needed, seed, legacy=legacy
    )
    if not header.startswith(IMAGE_STEGO_MAGIC):
        raise CoverVaultError("No Cover Vault image payload marker found.")
    payload_len = struct.unpack(">Q", header[len(IMAGE_STEGO_MAGIC) :])[0]
    if payload_len > (len(payload_indices) // 8) - header_bytes_needed:
        raise CoverVaultError("Stego image payload appears truncated.")
    container = _read_bytes_spread(
        pixel_bytes,
        payload_indices,
        header_bytes_needed + payload_len,
        seed,
        legacy=legacy,
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
    overwrite: bool = False,
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
        with atomic_output_path(output_path, overwrite=overwrite) as temporary_path:
            with temporary_path.open("wb") as output:
                writer.write(output)
                output.flush()
                os.fsync(output.fileno())
    except CoverVaultError:
        raise
    except (PyPdfError, OSError, ValueError) as exc:
        raise CoverVaultError("Could not create the PDF attachment vault.") from exc
    return describe_usage(len(payload), capacity)


def _read_bounded_file(path_value: Path | str, role: str) -> bytes:
    path = Path(path_value).expanduser()
    try:
        if not path.exists() or not path.is_file():
            raise CoverVaultError(f"{role} does not exist: {path}")
        size = path.stat().st_size
        if size > MAX_STEGO_FILE_BYTES:
            raise CoverVaultError(
                f"{role} exceeds the {MAX_STEGO_FILE_BYTES}-byte processing limit."
            )
        return path.read_bytes()
    except CoverVaultError:
        raise
    except OSError as exc:
        raise CoverVaultError(f"Could not read {role}: {path}") from exc


def extract_payload_pdf(stego_file: Path | str) -> bytes:
    data = _read_bounded_file(stego_file, "PDF vault")
    reader = _pdf_reader(data, role="PDF vault")
    try:
        attachments = reader.attachments.get(PDF_ATTACHMENT_NAME, [])
    except (PyPdfError, OSError, ValueError) as exc:
        raise CoverVaultError("Could not inspect PDF vault attachments.") from exc
    if len(attachments) != 1:
        if not attachments:
            raise CoverVaultError("No Cover Vault PDF attachment found.")
        raise CoverVaultError("PDF vault contains multiple reserved attachments.")
    payload = attachments[0]
    if len(payload) > MAX_STEGO_FILE_BYTES:
        raise CoverVaultError(
            "Embedded PDF vault payload exceeds the processing limit."
        )
    return payload
