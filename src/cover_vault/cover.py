from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .errors import CoverVaultError

MAX_REMOTE_COVER_BYTES = 256 * 1024 * 1024
DOWNLOAD_CHUNK_BYTES = 1024 * 1024


def read_cover(
    source: Path | str, *, max_remote_bytes: int = MAX_REMOTE_COVER_BYTES
) -> bytes:
    """Read exact cover bytes from a local path or a bounded HTTP(S) URL."""

    source_text = str(source)
    parsed = urlparse(source_text)
    if parsed.scheme in {"http", "https"}:
        if max_remote_bytes <= 0:
            raise CoverVaultError("Remote cover size limit must be positive.")
        request = Request(source_text, headers={"User-Agent": "cover-vault/1.1"})
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

    if "://" in source_text:
        raise CoverVaultError("Only local paths and HTTP(S) cover URLs are supported.")

    path = Path(source).expanduser()
    if not path.exists() or not path.is_file():
        raise CoverVaultError(f"Cover file does not exist: {path}")
    return path.read_bytes()
