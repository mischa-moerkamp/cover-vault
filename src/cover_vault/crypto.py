from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import struct
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import CoverVaultError

PAYLOAD_MAGIC = b"CVLT1\x00"
KDF_NAME = "scrypt"
CIPHER_NAME = "AES-256-GCM"
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
AES_GCM_TAG_BYTES = 16
LEGACY_AAD = b"cover-vault:encrypted-folder-payload:v1"
MAX_PAYLOAD_HEADER_BYTES = 64 * 1024
MIN_SCRYPT_N = 2**14
MAX_SCRYPT_N = 2**20
MAX_SCRYPT_R = 32
MAX_SCRYPT_P = 16
MIN_SALT_BYTES = 16
MAX_SALT_BYTES = 64


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    try:
        return base64.b64decode(data.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise CoverVaultError("Invalid base64 value in vault metadata.") from exc


@dataclass(frozen=True)
class KdfParams:
    name: str
    salt: str
    n: int
    r: int
    p: int
    length: int = KEY_BYTES

    @classmethod
    def fresh(cls) -> KdfParams:
        return cls(
            name=KDF_NAME,
            salt=b64e(os.urandom(SALT_BYTES)),
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            length=KEY_BYTES,
        )

    @classmethod
    def predictable_for_estimate(cls) -> KdfParams:
        return cls(
            name=KDF_NAME,
            salt=b64e(b"\x00" * SALT_BYTES),
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            length=KEY_BYTES,
        )

    @classmethod
    def from_dict(cls, data: Any) -> KdfParams:
        if not isinstance(data, dict):
            raise CoverVaultError("Invalid KDF metadata in vault payload.")
        try:
            params = cls(
                name=str(data["name"]),
                salt=str(data["salt"]),
                n=int(data["n"]),
                r=int(data["r"]),
                p=int(data["p"]),
                length=int(data.get("length", KEY_BYTES)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CoverVaultError("Invalid KDF metadata in vault payload.") from exc
        params.validate()
        return params

    def validate(self) -> None:
        if self.name != KDF_NAME:
            raise CoverVaultError(f"Unsupported KDF: {self.name}")
        if self.length != KEY_BYTES:
            raise CoverVaultError("Unsupported derived-key length in vault metadata.")
        if self.n < MIN_SCRYPT_N or self.n > MAX_SCRYPT_N:
            raise CoverVaultError("scrypt work factor is outside the allowed range.")
        if self.n & (self.n - 1):
            raise CoverVaultError("scrypt work factor must be a power of two.")
        if not 1 <= self.r <= MAX_SCRYPT_R:
            raise CoverVaultError("scrypt block size is outside the allowed range.")
        if not 1 <= self.p <= MAX_SCRYPT_P:
            raise CoverVaultError("scrypt parallelism is outside the allowed range.")
        salt = b64d(self.salt)
        if not MIN_SALT_BYTES <= len(salt) <= MAX_SALT_BYTES:
            raise CoverVaultError("KDF salt length is outside the allowed range.")

    def to_dict(self) -> dict[str, int | str]:
        return {
            "name": self.name,
            "salt": self.salt,
            "n": self.n,
            "r": self.r,
            "p": self.p,
            "length": self.length,
        }


@dataclass(frozen=True)
class EncryptionContext:
    payload: bytes
    kdf_params: KdfParams
    master_key: bytes


def cover_digest(cover_bytes: bytes) -> bytes:
    return hashlib.sha256(cover_bytes).digest()


def cover_hash_hex(cover_bytes: bytes) -> str:
    return hashlib.sha256(cover_bytes).hexdigest()


def derive_master_key(password: str, params: KdfParams, cover_bytes: bytes) -> bytes:
    """Derive a cover-bound master key using validated scrypt parameters."""

    params.validate()
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


def derive_key(password: str, params: KdfParams, cover_bytes: bytes) -> bytes:
    """Backward-compatible alias for callers that used the version-1 API."""

    return derive_master_key(password, params, cover_bytes)


def _derive_subkey(master_key: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=None,
        info=info,
    ).derive(master_key)


def derive_placement_seed(master_key: bytes, mode: str, cover_bytes: bytes) -> bytes:
    if not master_key:
        raise CoverVaultError("Master key is required for stego placement.")
    return _derive_subkey(
        master_key,
        b"cover-vault:stego-placement:v2\x00"
        + mode.encode("ascii")
        + b"\x00"
        + cover_digest(cover_bytes),
    )


def _payload_header(params: KdfParams, nonce: bytes, *, version: int = 2) -> bytes:
    header: dict[str, Any] = {
        "version": version,
        "cipher": CIPHER_NAME,
        "kdf": params.to_dict(),
        "nonce": b64e(nonce),
        "archive": "tar.gz",
    }
    if version == 1:
        header["aad"] = LEGACY_AAD.decode("ascii")
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(header_bytes) > MAX_PAYLOAD_HEADER_BYTES:
        raise CoverVaultError("Payload header is too large.")
    return header_bytes


def _payload_prefix(header_bytes: bytes) -> bytes:
    return PAYLOAD_MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes


def encrypted_payload_size_for_plaintext(plaintext_size: int) -> int:
    """Return the exact version-2 payload size for a plaintext length."""

    if plaintext_size < 0:
        raise CoverVaultError("Plaintext size cannot be negative.")
    header_bytes = _payload_header(
        KdfParams.predictable_for_estimate(), b"\x00" * NONCE_BYTES
    )
    return len(_payload_prefix(header_bytes)) + plaintext_size + AES_GCM_TAG_BYTES


def encrypt_payload_with_context(
    archive_bytes: bytes, password: str, cover_bytes: bytes
) -> EncryptionContext:
    params = KdfParams.fresh()
    master_key = derive_master_key(password, params, cover_bytes)
    encryption_key = _derive_subkey(master_key, b"cover-vault:payload-encryption:v2")
    nonce = os.urandom(NONCE_BYTES)
    header_bytes = _payload_header(params, nonce, version=2)
    prefix = _payload_prefix(header_bytes)
    ciphertext = AESGCM(encryption_key).encrypt(nonce, archive_bytes, prefix)
    return EncryptionContext(
        payload=prefix + ciphertext,
        kdf_params=params,
        master_key=master_key,
    )


def encrypt_payload(archive_bytes: bytes, password: str, cover_bytes: bytes) -> bytes:
    return encrypt_payload_with_context(archive_bytes, password, cover_bytes).payload


def _parse_payload(payload: bytes) -> tuple[dict[str, Any], bytes, bytes]:
    if not payload.startswith(PAYLOAD_MAGIC):
        raise CoverVaultError("Not a Cover Vault encrypted payload.")
    offset = len(PAYLOAD_MAGIC)
    if len(payload) < offset + 4:
        raise CoverVaultError("Payload is truncated.")
    header_len = struct.unpack(">I", payload[offset : offset + 4])[0]
    offset += 4
    if header_len <= 0 or header_len > MAX_PAYLOAD_HEADER_BYTES:
        raise CoverVaultError("Payload header length is invalid.")
    if len(payload) < offset + header_len + AES_GCM_TAG_BYTES:
        raise CoverVaultError("Payload header or ciphertext is truncated.")
    header_bytes = payload[offset : offset + header_len]
    try:
        decoded = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CoverVaultError("Payload header is not valid JSON.") from exc
    if not isinstance(decoded, dict):
        raise CoverVaultError("Payload header must be a JSON object.")
    prefix = payload[: offset + header_len]
    return decoded, header_bytes, prefix


def decrypt_payload(
    payload: bytes,
    password: str,
    cover_bytes: bytes,
    *,
    master_key: bytes | None = None,
    expected_kdf_params: KdfParams | None = None,
) -> bytes:
    header, _header_bytes, prefix = _parse_payload(payload)
    version = header.get("version")
    if version not in {1, 2}:
        raise CoverVaultError(f"Unsupported payload version: {version}")
    if header.get("cipher") != CIPHER_NAME:
        raise CoverVaultError(f"Unsupported cipher: {header.get('cipher')}")
    if header.get("archive") != "tar.gz":
        raise CoverVaultError(f"Unsupported archive type: {header.get('archive')}")

    params = KdfParams.from_dict(header.get("kdf"))
    if expected_kdf_params is not None and params != expected_kdf_params:
        raise CoverVaultError(
            "Stego bootstrap and encrypted payload KDF metadata do not match."
        )
    nonce = b64d(str(header.get("nonce", "")))
    if len(nonce) != NONCE_BYTES:
        raise CoverVaultError("Invalid AES-GCM nonce length in vault metadata.")

    resolved_master_key = master_key or derive_master_key(password, params, cover_bytes)
    if version == 1:
        encryption_key = resolved_master_key
        aad = LEGACY_AAD
    else:
        encryption_key = _derive_subkey(
            resolved_master_key, b"cover-vault:payload-encryption:v2"
        )
        aad = prefix

    try:
        return AESGCM(encryption_key).decrypt(nonce, payload[len(prefix) :], aad)
    except InvalidTag as exc:
        raise CoverVaultError(
            "Could not decrypt payload. The password, original cover file, or stego file may be wrong."
        ) from exc
