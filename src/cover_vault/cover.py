from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

from .errors import CoverVaultError
from .progress import ProgressCallback, report

MAX_REMOTE_COVER_BYTES = 256 * 1024 * 1024
MAX_LOCAL_COVER_BYTES = 512 * 1024 * 1024
DOWNLOAD_CHUNK_BYTES = 1024 * 1024
REMOTE_USER_AGENT = "cover-vault/2.2"
_SUPPORTED_SUFFIXES = {".png", ".bmp", ".tif", ".tiff", ".wav", ".pdf"}
_CONTENT_TYPE_SUFFIXES = {
    "application/pdf": ".pdf",
    "audio/wav": ".wav",
    "audio/x-wav": ".wav",
    "image/png": ".png",
    "image/bmp": ".bmp",
    "image/tiff": ".tiff",
}


@dataclass(frozen=True)
class CachedRemoteCover:
    source_url: str
    final_url: str
    local_path: Path
    content_type: str | None
    size_bytes: int
    sha256: str
    retrieved_at: str


def is_remote_cover_source(source: Path | str) -> bool:
    return urlparse(str(source)).scheme.lower() in {"http", "https"}


def local_cover_path(source: Path | str) -> Path | None:
    """Return the normalized local cover path, or None for an HTTP(S) URL."""

    source_text = str(source)
    parsed = urlparse(source_text)
    if parsed.scheme.lower() in {"http", "https"}:
        return None
    if "://" in source_text:
        raise CoverVaultError("Only local paths and HTTP(S) cover URLs are supported.")
    return Path(source).expanduser().resolve(strict=False)


def default_cover_cache_dir() -> Path:
    """Return a platform-appropriate persistent cache directory."""

    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return root / "CoverVault" / "Cache" / "covers"
    if sys_platform() == "darwin":
        return Path.home() / "Library" / "Caches" / "CoverVault" / "covers"
    root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return root / "cover-vault" / "covers"


def sys_platform() -> str:
    # Kept as a small function so platform behavior can be tested without mutating
    # the imported sys module.
    import sys

    return sys.platform


def _validate_remote_url(source_text: str, *, allow_http: bool) -> None:
    parsed = urlparse(source_text)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise CoverVaultError("A valid HTTP(S) cover URL is required.")
    if parsed.username or parsed.password:
        raise CoverVaultError(
            "Cover URLs containing embedded credentials are rejected."
        )
    if parsed.scheme.lower() == "http" and not allow_http:
        raise CoverVaultError(
            "Plain HTTP can be changed in transit. Use HTTPS, or explicitly allow insecure HTTP."
        )


def _declared_content_length(headers) -> int | None:
    value = headers.get("Content-Length")
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _content_type(headers) -> str | None:
    value = headers.get("Content-Type")
    if not value:
        return None
    return value.split(";", 1)[0].strip().lower() or None


def _suffix_for_download(
    final_url: str, content_type: str | None, header: bytes
) -> str:
    path = unquote(urlparse(final_url).path)
    suffix = Path(path).suffix.lower()
    if suffix in _SUPPORTED_SUFFIXES:
        return suffix
    if path.rstrip("/").split("/")[-2:-1] == ["pdf"]:
        return ".pdf"
    if content_type in _CONTENT_TYPE_SUFFIXES:
        return _CONTENT_TYPE_SUFFIXES[content_type]
    if header.startswith(b"%PDF-"):
        return ".pdf"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if header.startswith(b"BM"):
        return ".bmp"
    if header.startswith((b"II*\x00", b"MM\x00*")):
        return ".tiff"
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WAVE":
        return ".wav"
    return ".cover"


def _remote_response(
    source_text: str,
    *,
    timeout: float,
):
    request = Request(source_text, headers={"User-Agent": REMOTE_USER_AGENT})
    return urlopen(request, timeout=timeout)


def _sha256_path(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(DOWNLOAD_CHUNK_BYTES):
            hasher.update(chunk)
    return hasher.hexdigest()


def read_cover(
    source: Path | str,
    *,
    max_remote_bytes: int = MAX_REMOTE_COVER_BYTES,
    max_local_bytes: int = MAX_LOCAL_COVER_BYTES,
) -> bytes:
    """Read exact cover bytes from a local path or a bounded HTTP(S) URL."""

    source_text = str(source)
    if is_remote_cover_source(source_text):
        if max_remote_bytes <= 0:
            raise CoverVaultError("Remote cover size limit must be positive.")
        _validate_remote_url(source_text, allow_http=True)
        try:
            with _remote_response(source_text, timeout=30) as response:
                final_url = response.geturl()
                if (
                    urlparse(source_text).scheme.lower() == "https"
                    and urlparse(final_url).scheme.lower() != "https"
                ):
                    raise CoverVaultError(
                        "Refusing an HTTPS-to-HTTP redirect downgrade."
                    )
                _validate_remote_url(final_url, allow_http=True)
                declared_size = _declared_content_length(response.headers)
                if declared_size is not None and declared_size > max_remote_bytes:
                    raise CoverVaultError(
                        f"Remote cover exceeds the {max_remote_bytes}-byte download limit."
                    )

                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = response.read(DOWNLOAD_CHUNK_BYTES)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_remote_bytes:
                        raise CoverVaultError(
                            f"Remote cover exceeds the {max_remote_bytes}-byte download limit."
                        )
                    chunks.append(chunk)
                return b"".join(chunks)
        except CoverVaultError:
            raise
        except Exception as exc:  # pragma: no cover - network-dependent
            raise CoverVaultError(
                f"Could not download cover file: {source_text}"
            ) from exc

    path = local_cover_path(source)
    assert path is not None
    if not path.exists() or not path.is_file():
        raise CoverVaultError(f"Cover file does not exist: {path}")
    try:
        size = path.stat().st_size
        if size > max_local_bytes:
            raise CoverVaultError(
                f"Cover file exceeds the {max_local_bytes}-byte local processing limit."
            )
        return path.read_bytes()
    except CoverVaultError:
        raise
    except OSError as exc:
        raise CoverVaultError(f"Could not read cover file: {path}") from exc


def cache_remote_cover(
    source_url: str,
    *,
    cache_dir: Path | None = None,
    max_remote_bytes: int = MAX_REMOTE_COVER_BYTES,
    allow_http: bool = False,
    timeout: float = 30,
    progress: ProgressCallback | None = None,
) -> CachedRemoteCover:
    """Download a remote cover once and retain the exact bytes in a local cache."""

    _validate_remote_url(source_url, allow_http=allow_http)
    if max_remote_bytes <= 0:
        raise CoverVaultError("Remote cover size limit must be positive.")

    target_dir = (cache_dir or default_cover_cache_dir()).expanduser()
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CoverVaultError(
            f"Could not create the cover cache: {target_dir}"
        ) from exc

    temporary_path: Path | None = None
    report(progress, 0.01, "Connecting to remote cover")
    try:
        with _remote_response(source_url, timeout=timeout) as response:
            final_url = response.geturl()
            if (
                urlparse(source_url).scheme.lower() == "https"
                and urlparse(final_url).scheme.lower() != "https"
            ):
                raise CoverVaultError("Refusing an HTTPS-to-HTTP redirect downgrade.")
            _validate_remote_url(final_url, allow_http=allow_http)

            declared_size = _declared_content_length(response.headers)
            if declared_size is not None and declared_size > max_remote_bytes:
                raise CoverVaultError(
                    f"Remote cover exceeds the {max_remote_bytes}-byte download limit."
                )
            content_type = _content_type(response.headers)
            hasher = hashlib.sha256()
            total = 0
            header = bytearray()
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix="cover-vault-",
                suffix=".download",
                dir=target_dir,
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                while True:
                    chunk = response.read(DOWNLOAD_CHUNK_BYTES)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_remote_bytes:
                        raise CoverVaultError(
                            f"Remote cover exceeds the {max_remote_bytes}-byte download limit."
                        )
                    if len(header) < 32:
                        header.extend(chunk[: 32 - len(header)])
                    hasher.update(chunk)
                    temporary.write(chunk)
                    if declared_size:
                        report(
                            progress,
                            min(0.98, total / declared_size),
                            f"Downloading remote cover ({total:,} of {declared_size:,} bytes)",
                        )
                    else:
                        report(
                            progress,
                            0.50,
                            f"Downloading remote cover ({total:,} bytes)",
                        )

        if total == 0:
            raise CoverVaultError("The remote cover response was empty.")
        digest = hasher.hexdigest()
        suffix = _suffix_for_download(final_url, content_type, bytes(header))
        cached_path = target_dir / f"remote-{digest[:20]}{suffix}"
        if cached_path.exists():
            if (
                cached_path.stat().st_size != total
                or _sha256_path(cached_path) != digest
            ):
                raise CoverVaultError(
                    f"A conflicting cached cover already exists: {cached_path}"
                )
            temporary_path.unlink(missing_ok=True)
        else:
            os.replace(temporary_path, cached_path)
        temporary_path = None

        retrieved_at = datetime.now(timezone.utc).isoformat()
        result = CachedRemoteCover(
            source_url=source_url,
            final_url=final_url,
            local_path=cached_path,
            content_type=content_type,
            size_bytes=total,
            sha256=digest,
            retrieved_at=retrieved_at,
        )
        metadata_path = cached_path.with_suffix(cached_path.suffix + ".json")
        metadata = asdict(result)
        metadata["local_path"] = str(cached_path)
        _atomic_write_json(metadata_path, metadata)
        report(progress, 1.0, f"Remote cover cached ({total:,} bytes)")
        return result
    except CoverVaultError:
        raise
    except Exception as exc:  # pragma: no cover - network-dependent
        raise CoverVaultError(f"Could not download cover file: {source_url}") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise CoverVaultError(f"Could not write metadata file: {path}") from exc


def preserve_cached_cover(
    cached: CachedRemoteCover,
    vault_output: Path | str,
) -> tuple[Path, Path]:
    """Copy an exact remote cover beside a vault and write a recovery receipt."""

    output = Path(vault_output).expanduser().resolve(strict=False)
    suffix = cached.local_path.suffix
    original_copy = output.with_name(
        f"{output.stem}.original-cover-{cached.sha256[:12]}{suffix}"
    )
    receipt = output.with_name(f"{output.stem}.cover-receipt.json")

    try:
        if not original_copy.exists():
            temporary = original_copy.with_name(
                f".{original_copy.name}.{os.getpid()}.tmp"
            )
            shutil.copyfile(cached.local_path, temporary)
            os.replace(temporary, original_copy)
        else:
            existing_hash = _sha256_path(original_copy)
            if existing_hash != cached.sha256:
                raise CoverVaultError(
                    f"Existing preserved cover has unexpected contents: {original_copy}"
                )
    except CoverVaultError:
        raise
    except OSError as exc:
        raise CoverVaultError(
            f"Could not preserve the downloaded original cover: {original_copy}"
        ) from exc

    receipt_data = {
        "format": "cover-vault-cover-receipt-v1",
        "vault_file": output.name,
        "original_cover_file": original_copy.name,
        "source_url": cached.source_url,
        "final_url": cached.final_url,
        "retrieved_at": cached.retrieved_at,
        "content_type": cached.content_type,
        "size_bytes": cached.size_bytes,
        "sha256": cached.sha256,
        "recovery_note": (
            "Use the preserved original_cover_file for recovery. The URL is only provenance; "
            "remote bytes can change or disappear."
        ),
    }
    _atomic_write_json(receipt, receipt_data)
    return original_copy, receipt
