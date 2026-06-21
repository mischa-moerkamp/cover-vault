from __future__ import annotations

import math
import wave
from pathlib import Path

import pytest
from PIL import Image

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


def assert_restored(restored: Path) -> None:
    assert (restored / "main.py").read_text(encoding="utf-8") == "print('hello')\n"
    assert (restored / "pkg" / "module.py").read_text(
        encoding="utf-8"
    ) == "VALUE = 42\n"
    assert not (restored / ".git").exists()


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
