from __future__ import annotations

import re
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from .cover import MAX_REMOTE_COVER_BYTES, REMOTE_USER_AGENT
from .errors import CoverVaultError
from .progress import ProgressCallback, report

ARXIV_API_URL = "https://export.arxiv.org/api/query"
ARXIV_API_MAX_BYTES = 8 * 1024 * 1024
ARXIV_API_MIN_INTERVAL_SECONDS = 3.0
_ARXIV_HOSTS = {"arxiv.org", "www.arxiv.org", "export.arxiv.org"}
_ATOM = "{http://www.w3.org/2005/Atom}"
_ARXIV = "{http://arxiv.org/schemas/atom}"
_RATE_LOCK = threading.Lock()
_LAST_API_REQUEST = 0.0


@dataclass(frozen=True)
class ArxivPdfCandidate:
    arxiv_id: str
    title: str
    authors: tuple[str, ...]
    published: str
    pdf_url: str
    size_bytes: int
    license_url: str | None


def minimum_pdf_bytes_for_folder(payload_bytes: int, max_usage_ratio: float) -> int:
    """Return the smallest PDF reference size that satisfies the ratio limit."""

    import math

    if payload_bytes < 0:
        raise CoverVaultError("Payload size cannot be negative.")
    if not 0 < max_usage_ratio <= 1:
        raise CoverVaultError(
            "Maximum usage ratio must be greater than 0 and at most 1."
        )
    return math.ceil(payload_bytes / max_usage_ratio)


def _wait_for_arxiv_slot() -> None:
    global _LAST_API_REQUEST
    with _RATE_LOCK:
        now = time.monotonic()
        delay = ARXIV_API_MIN_INTERVAL_SECONDS - (now - _LAST_API_REQUEST)
        if delay > 0:
            time.sleep(delay)
        _LAST_API_REQUEST = time.monotonic()


def _read_bounded(response, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise CoverVaultError("The arXiv API response exceeded the safety limit.")
        chunks.append(chunk)
    return b"".join(chunks)


def _arxiv_host(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in _ARXIV_HOSTS


def _normalize_pdf_url(url: str) -> str:
    parsed = urlparse(url)
    if not _arxiv_host(url):
        raise CoverVaultError("arXiv returned a PDF link on an unexpected host.")
    return parsed._replace(scheme="https", netloc=parsed.netloc.lower()).geturl()


def _content_length(headers) -> int | None:
    value = headers.get("Content-Length")
    if value:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = -1
        if parsed >= 0:
            return parsed
    content_range = headers.get("Content-Range")
    if content_range:
        match = re.search(r"/(\d+)\s*$", content_range)
        if match:
            return int(match.group(1))
    return None


def probe_pdf_size(url: str, *, timeout: float = 20) -> int | None:
    """Return a remote arXiv PDF size without downloading the complete document."""

    normalized = _normalize_pdf_url(url)
    headers = {"User-Agent": REMOTE_USER_AGENT, "Accept": "application/pdf"}
    try:
        request = Request(normalized, headers=headers, method="HEAD")
        with urlopen(request, timeout=timeout) as response:
            final_url = response.geturl()
            if not _arxiv_host(final_url):
                raise CoverVaultError("arXiv redirected the PDF to an unexpected host.")
            size = _content_length(response.headers)
            if size is not None:
                return size
    except CoverVaultError:
        raise
    except Exception:
        pass

    try:
        range_headers = dict(headers)
        range_headers["Range"] = "bytes=0-0"
        request = Request(normalized, headers=range_headers)
        with urlopen(request, timeout=timeout) as response:
            final_url = response.geturl()
            if not _arxiv_host(final_url):
                raise CoverVaultError("arXiv redirected the PDF to an unexpected host.")
            return _content_length(response.headers)
    except CoverVaultError:
        raise
    except Exception:
        return None


def _search_expression(query: str) -> str:
    terms = [term.replace('"', "") for term in query.split() if term.replace('"', "")]
    if not terms:
        raise CoverVaultError("Enter at least one arXiv search term.")
    return " AND ".join(f'all:"{term}"' for term in terms)


def _parse_feed(data: bytes) -> list[dict]:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise CoverVaultError("arXiv returned an invalid API response.") from exc

    entries: list[dict] = []
    for entry in root.findall(f"{_ATOM}entry"):
        entry_url = (entry.findtext(f"{_ATOM}id") or "").strip()
        entry_path = urlparse(entry_url).path
        arxiv_id = (
            entry_path.split("/abs/", 1)[1]
            if "/abs/" in entry_path
            else entry_path.lstrip("/")
        )
        title = " ".join((entry.findtext(f"{_ATOM}title") or "").split())
        published = (entry.findtext(f"{_ATOM}published") or "").strip()
        authors = tuple(
            " ".join((author.findtext(f"{_ATOM}name") or "").split())
            for author in entry.findall(f"{_ATOM}author")
            if (author.findtext(f"{_ATOM}name") or "").strip()
        )
        pdf_url = ""
        for link in entry.findall(f"{_ATOM}link"):
            if (
                link.attrib.get("title") == "pdf"
                or link.attrib.get("type") == "application/pdf"
            ):
                pdf_url = link.attrib.get("href", "")
                break
        license_node = entry.find(f"{_ARXIV}license")
        license_url = None
        if license_node is not None:
            license_url = (
                license_node.attrib.get("href")
                or (license_node.text or "").strip()
                or None
            )
        if arxiv_id and title and pdf_url:
            entries.append(
                {
                    "arxiv_id": arxiv_id,
                    "title": title,
                    "authors": authors,
                    "published": published,
                    "pdf_url": _normalize_pdf_url(pdf_url),
                    "license_url": license_url,
                }
            )
    return entries


def search_arxiv_pdfs(
    query: str,
    *,
    minimum_bytes: int,
    max_results: int = 25,
    max_download_bytes: int = MAX_REMOTE_COVER_BYTES,
    timeout: float = 30,
    progress: ProgressCallback | None = None,
) -> list[ArxivPdfCandidate]:
    """Find arXiv PDFs that satisfy the requested size range."""

    if minimum_bytes <= 0:
        raise CoverVaultError("Minimum PDF size must be positive.")
    if max_download_bytes < minimum_bytes:
        return []
    if not 1 <= max_results <= 50:
        raise CoverVaultError("arXiv result count must be between 1 and 50.")

    params = urlencode(
        {
            "search_query": _search_expression(query),
            "start": 0,
            "max_results": max_results,
            "sortBy": "submittedDate",
            "sortOrder": "descending",
        }
    )
    request = Request(
        f"{ARXIV_API_URL}?{params}",
        headers={"User-Agent": REMOTE_USER_AGENT, "Accept": "application/atom+xml"},
    )
    report(progress, 0.02, "Searching arXiv metadata")
    _wait_for_arxiv_slot()
    try:
        with urlopen(request, timeout=timeout) as response:
            data = _read_bounded(response, ARXIV_API_MAX_BYTES)
    except CoverVaultError:
        raise
    except Exception as exc:  # pragma: no cover - network-dependent
        raise CoverVaultError("Could not search arXiv for PDF covers.") from exc

    entries = _parse_feed(data)
    candidates: list[ArxivPdfCandidate] = []
    total_entries = max(1, len(entries))
    for index, item in enumerate(entries, start=1):
        report(
            progress,
            0.10 + 0.85 * (index - 1) / total_entries,
            f"Checking arXiv PDF size ({index} of {len(entries)})",
        )
        size = probe_pdf_size(item["pdf_url"], timeout=timeout)
        if size is None or size < minimum_bytes or size > max_download_bytes:
            continue
        candidates.append(ArxivPdfCandidate(size_bytes=size, **item))

    candidates.sort(key=lambda candidate: (candidate.size_bytes, candidate.published))
    report(progress, 1.0, f"Found {len(candidates)} suitable arXiv PDFs")
    return candidates
