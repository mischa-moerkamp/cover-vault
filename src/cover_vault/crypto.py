from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import CoverVaultError

PAYLOAD_MAGIC = b"CVLT1\x00"
KDF_NAME = "scrypt"
CIPHER_NAME = "AES-256-GCM"
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
AES_GCM_TAG_BYTES = 16
AAD = b"cover-vault:encrypted-folder-payload:v1"


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


@dataclass(frozen=True)
class KdfParams:
    name: str
    salt: str
    n: int
    r: int
    p: int
    length: int = KEY_BYTES

    @classmethod
    def fresh(cls) -> "KdfParams":
        return cls(
            name=KDF_NAME,
            salt=b64e(os.urandom(SALT_BYTES)),
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            length=KEY_BYTES,
        )

    @classmethod
    def predictable_for_estimate(cls) -> "KdfParams":
        return cls(
            name=KDF_NAME,
            salt=b64e(b"\x00" * SALT_BYTES),
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            length=KEY_BYTES,
        )

    @classmethod
    def from_dict(cls, data: dict) -> "KdfParams":
        return cls(
            name=data["name"],
            salt=data["salt"],
            n=int(data["n"]),
            r=int(data["r"]),
            p=int(data["p"]),
            length=int(data.get("length", KEY_BYTES)),
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "salt": self.salt,
            "n": self.n,
            "r": self.r,
            "p": self.p,
            "length": self.length,
        }


def cover_digest(cover_bytes: bytes) -> bytes:
    return hashlib.sha256(cover_bytes).digest()


def cover_hash_hex(cover_bytes: bytes) -> str:
    return hashlib.sha256(cover_bytes).hexdigest()


def derive_key(password: str, params: KdfParams, cover_bytes: bytes) -> bytes:
    """Derive the encryption key from the password and exact original cover bytes.

    The original cover file is intentionally part of the KDF salt material. A
    copied or re-encoded cover file will not unlock the payload, even when the
    password is correct.
    """

    if params.name != KDF_NAME:
        raise CoverVaultError(f"Unsupported KDF: {params.name}")
    if not password:
        raise CoverVaultError("Password cannot be empty.")
    if not cover_bytes:
        raise CoverVaultError("Cover file cannot be empty.")

    kdf_salt = b64d(params.salt) + b"\x00cover-vault\x00" + cover_digest(cover_bytes)
    kdf = Scrypt(
        salt=kdf_salt,
        length=params.length,
        n=params.n,
        r=params.r,
        p=params.p,
    )
    return kdf.derive(password.encode("utf-8"))


def _payload_header(params: KdfParams, nonce: bytes) -> bytes:
    header = {
        "version": 1,
        "cipher": CIPHER_NAME,
        "kdf": params.to_dict(),
        "nonce": b64e(nonce),
        "archive": "tar.gz",
        "aad": AAD.decode("ascii"),
    }
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(header_bytes) > 2**32 - 1:
        raise CoverVaultError("Payload header is too large.")
    return header_bytes


def encrypted_payload_size_for_plaintext(plaintext_size: int) -> int:
    """Return the exact payload size for a plaintext of this length.

    AES-GCM output is plaintext length plus a fixed tag, and the serialized
    header length is fixed because the random fields have fixed encoded sizes.
    """

    if plaintext_size < 0:
        raise CoverVaultError("Plaintext size cannot be negative.")
    header_bytes = _payload_header(
        KdfParams.predictable_for_estimate(), b"\x00" * NONCE_BYTES
    )
    return (
        len(PAYLOAD_MAGIC) + 4 + len(header_bytes) + plaintext_size + AES_GCM_TAG_BYTES
    )


def encrypt_payload(archive_bytes: bytes, password: str, cover_bytes: bytes) -> bytes:
    params = KdfParams.fresh()
    key = derive_key(password, params, cover_bytes)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, archive_bytes, AAD)

    header_bytes = _payload_header(params, nonce)
    return (
        PAYLOAD_MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + ciphertext
    )


def decrypt_payload(payload: bytes, password: str, cover_bytes: bytes) -> bytes:
    if not payload.startswith(PAYLOAD_MAGIC):
        raise CoverVaultError("Not a Cover Vault encrypted payload.")
    offset = len(PAYLOAD_MAGIC)
    if len(payload) < offset + 4:
        raise CoverVaultError("Payload is truncated.")
    header_len = struct.unpack(">I", payload[offset : offset + 4])[0]
    offset += 4
    if len(payload) < offset + header_len:
        raise CoverVaultError("Payload header is truncated.")
    header = json.loads(payload[offset : offset + header_len].decode("utf-8"))
    offset += header_len

    if header.get("version") != 1:
        raise CoverVaultError(f"Unsupported payload version: {header.get('version')}")
    if header.get("cipher") != CIPHER_NAME:
        raise CoverVaultError(f"Unsupported cipher: {header.get('cipher')}")

    key = derive_key(password, KdfParams.from_dict(header["kdf"]), cover_bytes)
    try:
        return AESGCM(key).decrypt(b64d(header["nonce"]), payload[offset:], AAD)
    except InvalidTag as exc:
        raise CoverVaultError(
            "Could not decrypt payload. The password, original cover file, or stego file may be wrong."
        ) from exc
