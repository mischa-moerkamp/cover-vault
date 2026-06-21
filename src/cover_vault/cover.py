from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .errors import CoverVaultError


def read_cover(source: Path | str) -> bytes:
    """Read exact cover bytes from a local path or HTTP(S) URL."""

    source_text = str(source)
    parsed = urlparse(source_text)
    if parsed.scheme in {"http", "https"}:
        request = Request(source_text, headers={"User-Agent": "cover-vault/0.1"})
        try:
            with urlopen(request, timeout=30) as response:
                return response.read()
        except Exception as exc:  # pragma: no cover - network-dependent
            raise CoverVaultError(
                f"Could not download cover file: {source_text}"
            ) from exc

    path = Path(source).expanduser()
    if not path.exists() or not path.is_file():
        raise CoverVaultError(f"Cover file does not exist: {path}")
    return path.read_bytes()
