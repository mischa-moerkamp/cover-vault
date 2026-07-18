from __future__ import annotations

import argparse
import math
import wave
from pathlib import Path

import pytest
from PIL import Image

from cover_vault.archive import DEFAULT_EXCLUDES, GIT_HISTORY_EXCLUDE
from cover_vault.cli import _excludes_from_args
from cover_vault.errors import CoverVaultError
from cover_vault.vault import cover_info, hide_folder, plan_folder, reveal_folder


def make_source_folder(path: Path) -> None:
    path.mkdir()
    (path / "main.py").write_text("print('hello')\n", encoding="utf-8")
    nested = path / "pkg"
    nested.mkdir()
    (nested / "module.py").write_text("VALUE = 42\n", encoding="utf-8")

    # Simulate Git history and refs. These should not be archived by default.
    git = path / ".git"
    (git / "objects" / "aa").mkdir(parents=True)
    (git / "objects" / "aa" / "fake-history-object").write_bytes(
        b"commit history bytes"
    )
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")


def make_wav(path: Path, seconds: float = 2.0, sample_rate: int = 44_100) -> None:
    frames = bytearray()
    total_samples = int(seconds * sample_rate)
    for i in range(total_samples):
        sample = int(12_000 * math.sin(2 * math.pi * 440 * i / sample_rate))
        frames.extend(sample.to_bytes(2, byteorder="little", signed=True))
    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)
        wav.writeframes(bytes(frames))


def make_png(path: Path, size: tuple[int, int] = (180, 180)) -> None:
    width, height = size
    image = Image.new("RGB", size)
    pixels = image.load()
    assert pixels is not None
    for y in range(height):
        for x in range(width):
            pixels[x, y] = (
                (x * 7 + y * 3) % 256,
                (x * 5 + y * 11) % 256,
                (x * 13 + y * 17) % 256,
            )
    image.save(path, format="PNG")


def make_pdf(path: Path, filler_bytes: int = 20_000) -> None:
    # Minimal one-page PDF followed by a large comment block. PDF readers ignore
    # comments, making this a deterministic, dependency-free test cover.
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n"
        b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n"
        b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>endobj\n"
        + b"%"
        + (b" cover-vault-test" * (filler_bytes // 17 + 1))[:filler_bytes]
        + b"\n"
        b"xref\n0 4\n0000000000 65535 f \n"
        b"trailer<< /Root 1 0 R /Size 4 >>\nstartxref\n0\n%%EOF\n"
    )
    path.write_bytes(body)


def assert_restored(restored: Path) -> None:
    assert (restored / "main.py").read_text(encoding="utf-8") == "print('hello')\n"
    assert (restored / "pkg" / "module.py").read_text(
        encoding="utf-8"
    ) == "VALUE = 42\n"
    assert not (restored / ".git").exists()


def assert_git_history_restored(restored: Path) -> None:
    assert (restored / ".git" / "HEAD").read_text(encoding="utf-8") == (
        "ref: refs/heads/main\n"
    )
    assert (
        restored / ".git" / "objects" / "aa" / "fake-history-object"
    ).read_bytes() == b"commit history bytes"


def test_include_git_history_option_keeps_other_default_excludes() -> None:
    args = argparse.Namespace(
        no_default_excludes=False, include_git_history=True, exclude=[]
    )

    excludes = _excludes_from_args(args)

    assert GIT_HISTORY_EXCLUDE not in excludes
    for default_exclude in DEFAULT_EXCLUDES - {GIT_HISTORY_EXCLUDE}:
        assert default_exclude in excludes


def test_wav_lsb_roundtrip_excludes_git_history_by_default(tmp_path: Path) -> None:
    source = tmp_path / "source"
    cover = tmp_path / "cover.wav"
    stego = tmp_path / "cover.stego.wav"
    restored = tmp_path / "restored"
    make_source_folder(source)
    make_wav(cover)

    result = hide_folder(source, cover, stego, "correct horse", mode="wav-lsb")
    assert result["files_encrypted"] == 2
    assert result["payload_bytes"] > 0
    assert result["usage_ratio"] < 0.25
    assert stego.exists()

    result = reveal_folder(stego, cover, restored, "correct horse")
    assert result["files_decrypted"] == 2
    assert_restored(restored)


def test_image_lsb_roundtrip(tmp_path: Path) -> None:
    source = tmp_path / "source"
    cover = tmp_path / "cover.png"
    stego = tmp_path / "cover.stego.png"
    restored = tmp_path / "restored"
    make_source_folder(source)
    make_png(cover)

    result = hide_folder(source, cover, stego, "password", mode="image-lsb")
    assert result["files_encrypted"] == 2
    assert result["capacity_bytes"] > result["payload_bytes"]

    result = reveal_folder(stego, cover, restored, "password", mode="image-lsb")
    assert result["files_decrypted"] == 2
    assert_restored(restored)


def test_image_lsb_roundtrip_can_include_git_history(tmp_path: Path) -> None:
    source = tmp_path / "source"
    cover = tmp_path / "cover.png"
    stego = tmp_path / "cover.stego.png"
    restored = tmp_path / "restored"
    make_source_folder(source)
    make_png(cover)
    excludes = tuple(name for name in DEFAULT_EXCLUDES if name != GIT_HISTORY_EXCLUDE)

    result = hide_folder(
        source, cover, stego, "password", mode="image-lsb", excludes=excludes
    )
    assert result["files_encrypted"] == 4

    result = reveal_folder(stego, cover, restored, "password", mode="image-lsb")
    assert result["files_decrypted"] == 4
    assert (restored / "main.py").exists()
    assert (restored / "pkg" / "module.py").exists()
    assert_git_history_restored(restored)


def test_auto_mode_detects_image(tmp_path: Path) -> None:
    source = tmp_path / "source"
    cover = tmp_path / "cover.png"
    stego = tmp_path / "cover.stego.png"
    restored = tmp_path / "restored"
    make_source_folder(source)
    make_png(cover)

    hidden = hide_folder(source, cover, stego, "password")
    assert hidden["mode"] == "image-lsb"
    revealed = reveal_folder(stego, cover, restored, "password")
    assert revealed["mode"] == "image-lsb"
    assert_restored(restored)


def test_wrong_password_or_cover_fails(tmp_path: Path) -> None:
    source = tmp_path / "source"
    cover = tmp_path / "cover.wav"
    wrong_cover = tmp_path / "wrong.wav"
    stego = tmp_path / "cover.stego.wav"
    make_source_folder(source)
    make_wav(cover)
    make_wav(wrong_cover, seconds=2.1)

    hide_folder(source, cover, stego, "right", mode="wav-lsb")

    with pytest.raises(CoverVaultError):
        reveal_folder(stego, cover, tmp_path / "bad-password", "wrong")

    with pytest.raises(CoverVaultError):
        reveal_folder(stego, wrong_cover, tmp_path / "bad-cover", "right")


def test_capacity_ratio_guard_rejects_tiny_cover(tmp_path: Path) -> None:
    source = tmp_path / "source"
    cover = tmp_path / "tiny.png"
    stego = tmp_path / "tiny.stego.png"
    make_source_folder(source)
    make_png(cover, size=(20, 20))

    with pytest.raises(CoverVaultError, match="too small|usage"):
        hide_folder(source, cover, stego, "password", mode="image-lsb")


def test_info_and_plan_report_capacity(tmp_path: Path) -> None:
    source = tmp_path / "source"
    cover = tmp_path / "cover.png"
    make_source_folder(source)
    make_png(cover)

    info = cover_info(cover)
    assert "image-lsb" in info["supported_modes"]
    assert info["capacities"]["image-lsb"] > 0

    plan = plan_folder(source, cover, mode="image-lsb")
    assert plan["files_to_encrypt"] == 2
    assert plan["fits_capacity"] is True
    assert plan["fits_ratio_limit"] is True


def test_pdf_append_roundtrip_and_auto_detection(tmp_path: Path) -> None:
    source = tmp_path / "source"
    cover = tmp_path / "cover.pdf"
    stego = tmp_path / "cover.stego.pdf"
    restored = tmp_path / "restored"
    make_source_folder(source)
    make_pdf(cover)

    result = hide_folder(source, cover, stego, "password")
    assert result["mode"] == "pdf-append"
    assert stego.read_bytes().startswith(cover.read_bytes())
    assert result["usage_ratio"] < 0.25

    revealed = reveal_folder(stego, cover, restored, "password")
    assert revealed["mode"] == "pdf-append"
    assert_restored(restored)


def test_pdf_info_and_plan(tmp_path: Path) -> None:
    source = tmp_path / "source"
    cover = tmp_path / "cover.pdf"
    make_source_folder(source)
    make_pdf(cover)

    info = cover_info(cover)
    assert info["supported_modes"] == ["pdf-append"]
    assert info["capacities"]["pdf-append"] == cover.stat().st_size

    plan = plan_folder(source, cover)
    assert plan["mode"] == "pdf-append"
    assert plan["fits_ratio_limit"] is True


def test_progress_callbacks_for_pdf_round_trip(tmp_path):
    from cover_vault.progress import ProgressEvent

    source = tmp_path / "source-progress"
    source.mkdir()
    (source / "hello.txt").write_text("progress test")
    cover = tmp_path / "cover-progress.pdf"
    make_pdf(cover, filler_bytes=5000)
    stego = tmp_path / "vault-progress.pdf"
    restored = tmp_path / "restored-progress"
    hide_events = []
    reveal_events = []

    hide_folder(
        source,
        cover,
        stego,
        "password",
        max_usage_ratio=1.0,
        progress=hide_events.append,
    )
    reveal_folder(stego, cover, restored, "password", progress=reveal_events.append)

    assert all(
        isinstance(event, ProgressEvent) for event in hide_events + reveal_events
    )
    assert hide_events[0].fraction > 0
    assert hide_events[-1].fraction == 1.0
    assert reveal_events[-1].fraction == 1.0
    assert (restored / "hello.txt").read_text() == "progress test"


def test_gui_logic_helpers(tmp_path):
    from cover_vault.gui_logic import build_excludes, suggested_output_path

    excludes = build_excludes(True, "node_modules, dist; .venv")
    assert ".git" not in excludes
    assert {"node_modules", "dist", ".venv"}.issubset(set(excludes))
    assert suggested_output_path(str(tmp_path / "photo.png")).endswith(
        "photo.vault.png"
    )


def _legacy_v1_payload(
    archive_bytes: bytes, password: str, cover_bytes: bytes
) -> bytes:
    import base64
    import json
    import os
    import struct

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from cover_vault.crypto import (
        CIPHER_NAME,
        KDF_NAME,
        LEGACY_AAD,
        PAYLOAD_MAGIC,
        KdfParams,
        derive_master_key,
    )

    params = KdfParams(
        name=KDF_NAME,
        salt=base64.urlsafe_b64encode(os.urandom(16)).decode("ascii"),
        n=2**15,
        r=8,
        p=1,
        length=32,
    )
    nonce = os.urandom(12)
    header = {
        "version": 1,
        "cipher": CIPHER_NAME,
        "kdf": params.to_dict(),
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "archive": "tar.gz",
        "aad": LEGACY_AAD.decode("ascii"),
    }
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    key = derive_master_key(password, params, cover_bytes)
    ciphertext = AESGCM(key).encrypt(nonce, archive_bytes, LEGACY_AAD)
    return (
        PAYLOAD_MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + ciphertext
    )


def _write_legacy_image_vault(
    cover: Path, output: Path, payload: bytes, password: str
) -> None:
    import struct

    from PIL import Image

    from cover_vault.stego import (
        LEGACY_IMAGE_STEGO_MAGIC,
        _rgb_channel_indices_rgba,
        _write_bits_spread,
        legacy_position_seed,
    )

    cover_bytes = cover.read_bytes()
    image = Image.open(cover).convert("RGBA")
    pixels = bytearray(image.tobytes())
    indices = _rgb_channel_indices_rgba(pixels)
    data = LEGACY_IMAGE_STEGO_MAGIC + struct.pack(">Q", len(payload)) + payload
    _write_bits_spread(
        pixels,
        indices,
        data,
        legacy_position_seed("image-lsb", cover_bytes, password),
    )
    Image.frombytes("RGBA", image.size, bytes(pixels)).save(output, format="PNG")


def test_legacy_v1_image_vault_remains_readable(tmp_path: Path) -> None:
    from cover_vault.archive import make_archive

    source = tmp_path / "source"
    cover = tmp_path / "cover.png"
    stego = tmp_path / "legacy.stego.png"
    restored = tmp_path / "restored"
    make_source_folder(source)
    make_png(cover)
    archive_bytes, _ = make_archive(source)
    payload = _legacy_v1_payload(archive_bytes, "legacy-password", cover.read_bytes())
    _write_legacy_image_vault(cover, stego, payload, "legacy-password")

    result = reveal_folder(stego, cover, restored, "legacy-password")

    assert result["mode"] == "image-lsb"
    assert_restored(restored)


def test_v2_payload_header_is_authenticated(tmp_path: Path) -> None:
    import json
    import struct

    from cover_vault.crypto import PAYLOAD_MAGIC, decrypt_payload, encrypt_payload

    cover_bytes = b"valid cover bytes"
    payload = encrypt_payload(b"secret archive", "password", cover_bytes)
    offset = len(PAYLOAD_MAGIC)
    header_len = struct.unpack(">I", payload[offset : offset + 4])[0]
    header_start = offset + 4
    header_end = header_start + header_len
    header = json.loads(payload[header_start:header_end].decode("utf-8"))
    header["untrusted_note"] = "changed"
    changed_header = json.dumps(header, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    tampered = (
        PAYLOAD_MAGIC
        + struct.pack(">I", len(changed_header))
        + changed_header
        + payload[header_end:]
    )

    with pytest.raises(CoverVaultError, match="Could not decrypt"):
        decrypt_payload(tampered, "password", cover_bytes)


def test_kdf_bounds_reject_excessive_work_factor() -> None:
    import base64

    from cover_vault.crypto import KDF_NAME, KdfParams, derive_master_key

    params = KdfParams(
        name=KDF_NAME,
        salt=base64.urlsafe_b64encode(b"0" * 16).decode("ascii"),
        n=2**30,
        r=8,
        p=1,
    )
    with pytest.raises(CoverVaultError, match="work factor"):
        derive_master_key("password", params, b"cover")


def test_v2_lsb_placement_rejects_legacy_fast_seed(tmp_path: Path) -> None:
    from cover_vault.stego import extract_payload_image, legacy_position_seed

    source = tmp_path / "source"
    cover = tmp_path / "cover.png"
    stego = tmp_path / "cover.stego.png"
    make_source_folder(source)
    make_png(cover)
    hide_folder(source, cover, stego, "password", mode="image-lsb")

    old_seed = legacy_position_seed("image-lsb", cover.read_bytes(), "password")
    with pytest.raises(CoverVaultError, match="payload marker"):
        extract_payload_image(stego, old_seed, use_v2=True)


def test_invalid_archive_does_not_destroy_existing_destination(tmp_path: Path) -> None:
    import io
    import tarfile

    from cover_vault.archive import extract_archive

    destination = tmp_path / "destination"
    destination.mkdir()
    sentinel = destination / "keep.txt"
    sentinel.write_text("keep me", encoding="utf-8")

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("../escape.txt")
        content = b"bad"
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))

    with pytest.raises(CoverVaultError, match="unsafe archive path"):
        extract_archive(buffer.getvalue(), destination, overwrite=True)

    assert sentinel.read_text(encoding="utf-8") == "keep me"
