from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .errors import CoverVaultError

MAX_REMOTE_COVER_BYTES = 256 * 1024 * 1024
MAX_LOCAL_COVER_BYTES = 512 * 1024 * 1024
DOWNLOAD_CHUNK_BYTES = 1024 * 1024


def local_cover_path(source: Path | str) -> Path | None:
    """Return the normalized local cover path, or None for an HTTP(S) URL."""

    source_text = str(source)
    parsed = urlparse(source_text)
    if parsed.scheme in {"http", "https"}:
        return None
    if "://" in source_text:
        raise CoverVaultError("Only local paths and HTTP(S) cover URLs are supported.")
    return Path(source).expanduser().resolve(strict=False)


def read_cover(
    source: Path | str,
    *,
    max_remote_bytes: int = MAX_REMOTE_COVER_BYTES,
    max_local_bytes: int = MAX_LOCAL_COVER_BYTES,
) -> bytes:
    """Read exact cover bytes from a local path or a bounded HTTP(S) URL."""

    source_text = str(source)
    parsed = urlparse(source_text)
    if parsed.scheme in {"http", "https"}:
        if max_remote_bytes <= 0:
            raise CoverVaultError("Remote cover size limit must be positive.")
        request = Request(source_text, headers={"User-Agent": "cover-vault/2.0"})
        try:
            with urlopen(request, timeout=30) as response:
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        declared_size = int(content_length)
                    except ValueError:
                        declared_size = 0
                    if declared_size > max_remote_bytes:
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
