from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from cover_vault import arxiv, cover
from cover_vault.arxiv import minimum_pdf_bytes_for_folder, search_arxiv_pdfs
from cover_vault.cover import cache_remote_cover, preserve_cached_cover
from cover_vault.errors import CoverVaultError
from cover_vault.gui_logic import cover_suffix, suggested_output_filename


class FakeResponse:
    def __init__(
        self,
        data: bytes = b"",
        *,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._data = data
        self._offset = 0
        self._url = url
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._data) - self._offset
        chunk = self._data[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def geturl(self) -> str:
        return self._url


def test_cache_remote_cover_and_preserve_receipt(tmp_path: Path, monkeypatch) -> None:
    payload = b"%PDF-1.7\nremote test cover\n%%EOF\n"

    def fake_urlopen(request, timeout):
        assert request.full_url == "https://example.test/document"
        return FakeResponse(
            payload,
            url="https://cdn.example.test/document",
            headers={
                "Content-Length": str(len(payload)),
                "Content-Type": "application/pdf; charset=binary",
            },
        )

    monkeypatch.setattr(cover, "urlopen", fake_urlopen)
    events = []
    cached = cache_remote_cover(
        "https://example.test/document",
        cache_dir=tmp_path / "cache",
        progress=events.append,
    )

    assert cached.local_path.suffix == ".pdf"
    assert cached.local_path.read_bytes() == payload
    assert cached.sha256 == hashlib.sha256(payload).hexdigest()
    assert events[-1].fraction == 1.0

    vault = tmp_path / "paper.vault.pdf"
    vault.write_bytes(b"vault")
    original, receipt = preserve_cached_cover(cached, vault)
    assert original.read_bytes() == payload
    receipt_data = json.loads(receipt.read_text(encoding="utf-8"))
    assert receipt_data["sha256"] == cached.sha256
    assert receipt_data["original_cover_file"] == original.name
    assert receipt_data["source_url"] == "https://example.test/document"


def test_cache_remote_cover_rejects_plain_http_by_default(tmp_path: Path) -> None:
    with pytest.raises(CoverVaultError, match="Plain HTTP"):
        cache_remote_cover("http://example.test/cover.pdf", cache_dir=tmp_path)


def test_cache_remote_cover_rejects_https_downgrade(
    tmp_path: Path, monkeypatch
) -> None:
    def fake_urlopen(request, timeout):
        return FakeResponse(
            b"%PDF-1.7\n%%EOF\n",
            url="http://example.test/cover.pdf",
            headers={"Content-Type": "application/pdf"},
        )

    monkeypatch.setattr(cover, "urlopen", fake_urlopen)
    with pytest.raises(CoverVaultError, match="redirect downgrade"):
        cache_remote_cover("https://example.test/cover.pdf", cache_dir=tmp_path)


def test_url_output_helpers_handle_arxiv_pdf_links() -> None:
    url = "https://arxiv.org/pdf/2607.01234v2"
    assert cover_suffix(url) == ".pdf"
    assert suggested_output_filename(url) == "arxiv-2607.01234v2.vault.pdf"


def test_minimum_pdf_size_rounds_up() -> None:
    assert minimum_pdf_bytes_for_folder(101, 0.25) == 404
    with pytest.raises(CoverVaultError, match="at most 1"):
        minimum_pdf_bytes_for_folder(100, 1.1)


def test_search_arxiv_filters_by_probed_pdf_size(monkeypatch) -> None:
    feed = b"""<?xml version='1.0' encoding='UTF-8'?>
    <feed xmlns='http://www.w3.org/2005/Atom' xmlns:arxiv='http://arxiv.org/schemas/atom'>
      <entry>
        <id>http://arxiv.org/abs/2607.00001v2</id>
        <title>Large suitable paper</title>
        <published>2026-07-01T00:00:00Z</published>
        <author><name>Ada Example</name></author>
        <link title='pdf' href='http://arxiv.org/pdf/2607.00001v2' type='application/pdf'/>
        <arxiv:license href='https://creativecommons.org/licenses/by/4.0/'/>
      </entry>
      <entry>
        <id>http://arxiv.org/abs/2607.00002v1</id>
        <title>Too small paper</title>
        <published>2026-07-02T00:00:00Z</published>
        <author><name>Bob Example</name></author>
        <link title='pdf' href='http://arxiv.org/pdf/2607.00002v1' type='application/pdf'/>
      </entry>
    </feed>"""

    def fake_urlopen(request, timeout):
        if "api/query" in request.full_url:
            return FakeResponse(
                feed,
                url=request.full_url,
                headers={"Content-Type": "application/atom+xml"},
            )
        size = 2_000 if "00001" in request.full_url else 500
        return FakeResponse(
            b"",
            url=request.full_url,
            headers={"Content-Length": str(size), "Content-Type": "application/pdf"},
        )

    monkeypatch.setattr(arxiv, "urlopen", fake_urlopen)
    monkeypatch.setattr(arxiv, "_wait_for_arxiv_slot", lambda: None)

    candidates = search_arxiv_pdfs(
        "cryptography systems", minimum_bytes=1_000, max_results=10
    )

    assert [candidate.arxiv_id for candidate in candidates] == ["2607.00001v2"]
    assert candidates[0].pdf_url == "https://arxiv.org/pdf/2607.00001v2"
    assert candidates[0].size_bytes == 2_000
    assert candidates[0].license_url == "https://creativecommons.org/licenses/by/4.0/"


def test_remote_download_limits_apply_to_declared_and_streamed_bytes(
    tmp_path: Path, monkeypatch
) -> None:
    payload = b"%PDF-1.7\n0123456789\n%%EOF\n"

    def declared_urlopen(request, timeout):
        return FakeResponse(
            payload,
            url=request.full_url,
            headers={"Content-Length": "999", "Content-Type": "application/pdf"},
        )

    monkeypatch.setattr(cover, "urlopen", declared_urlopen)
    with pytest.raises(CoverVaultError, match="download limit"):
        cache_remote_cover(
            "https://example.test/declared.pdf",
            cache_dir=tmp_path / "declared",
            max_remote_bytes=100,
        )

    def streamed_urlopen(request, timeout):
        return FakeResponse(
            payload,
            url=request.full_url,
            headers={"Content-Type": "application/pdf"},
        )

    monkeypatch.setattr(cover, "urlopen", streamed_urlopen)
    with pytest.raises(CoverVaultError, match="download limit"):
        cache_remote_cover(
            "https://example.test/streamed.pdf",
            cache_dir=tmp_path / "streamed",
            max_remote_bytes=10,
        )


def test_read_cover_rejects_https_to_http_redirect(monkeypatch) -> None:
    def fake_urlopen(request, timeout):
        return FakeResponse(
            b"%PDF-1.7\n%%EOF\n",
            url="http://example.test/cover.pdf",
            headers={"Content-Type": "application/pdf"},
        )

    monkeypatch.setattr(cover, "urlopen", fake_urlopen)
    with pytest.raises(CoverVaultError, match="redirect downgrade"):
        cover.read_cover("https://example.test/cover.pdf")


def test_arxiv_parser_preserves_legacy_identifier_paths() -> None:
    feed = b"""<?xml version='1.0' encoding='UTF-8'?>
    <feed xmlns='http://www.w3.org/2005/Atom' xmlns:arxiv='http://arxiv.org/schemas/atom'>
      <entry>
        <id>http://arxiv.org/abs/hep-ex/0307015</id>
        <title>Legacy identifier paper</title>
        <published>2003-07-01T00:00:00Z</published>
        <author><name>Example Collaboration</name></author>
        <link title='pdf' href='http://arxiv.org/pdf/hep-ex/0307015' type='application/pdf'/>
        <arxiv:license>https://arxiv.org/licenses/nonexclusive-distrib/1.0/</arxiv:license>
      </entry>
    </feed>"""

    entries = arxiv._parse_feed(feed)

    assert entries[0]["arxiv_id"] == "hep-ex/0307015"
    assert entries[0]["pdf_url"] == "https://arxiv.org/pdf/hep-ex/0307015"
    assert entries[0]["license_url"].startswith("https://arxiv.org/licenses/")
