"""Tests for phishlens.reporting.generate (every export format)."""

from __future__ import annotations

import asyncio
import json
import re
import zipfile
from pathlib import Path

import pytest

from phishlens.models import AnalysisReport
from phishlens.pipeline import analyze_email
from phishlens.reporting import generate
from phishlens.reporting.generate import FORMATS, generate_report, pdf_available

FIXTURES = Path(__file__).parent / "fixtures"
ALLOWED_LINK_PREFIXES = ("https://attack.mitre.org/", "https://urlscan.io/")


@pytest.fixture(scope="module")
def report() -> AnalysisReport:
    return asyncio.run(
        analyze_email((FIXTURES / "link_mismatch.eml").read_bytes(), network=False)
    )


def test_every_format_is_created(report: AnalysisReport, tmp_path: Path) -> None:
    result = generate_report(report, list(FORMATS), tmp_path)
    expected = set(FORMATS) if pdf_available() else set(FORMATS) - {"pdf"}
    assert set(result.paths) == expected
    stem = f"{report.case_id}_malicious"
    assert result.paths["html"].name == f"{stem}.html"
    assert result.paths["stix"].name == f"{stem}.stix.json"
    assert json.loads(result.paths["json"].read_text())["case_id"] == report.case_id
    assert result.paths["csv"].read_text().startswith("type,value,defanged,verdict")
    with zipfile.ZipFile(result.paths["zip"]) as archive:
        members = sorted(archive.namelist())
    assert f"{stem}.html" in members and f"{stem}.json" in members
    assert (f"{stem}.pdf" in members) == pdf_available()
    if not pdf_available():
        assert "Pango" in result.skipped["pdf"]


def test_html_has_no_live_links_except_allowed(report: AnalysisReport, tmp_path: Path) -> None:
    html = generate_report(report, ["html"], tmp_path).paths["html"].read_text()
    links = re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', html)
    assert links, "expected MITRE links"
    for link in links:
        assert link.startswith(ALLOWED_LINK_PREFIXES), link
    assert not re.search(r"(?<![\w.])https?://(?!attack\.mitre\.org|urlscan\.io)", html)


@pytest.mark.skipif(not pdf_available(), reason="WeasyPrint libraries missing (SETUP_NOTES)")
def test_pdf_is_a_pdf(report: AnalysisReport, tmp_path: Path) -> None:
    pdf = generate_report(report, ["pdf"], tmp_path).paths["pdf"].read_bytes()
    assert pdf.startswith(b"%PDF")


def test_pdf_unavailable_is_reported(
    report: AnalysisReport, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(generate, "_weasyprint", lambda: ImportError("no pango"))
    result = generate_report(report, ["pdf", "json"], tmp_path)
    assert set(result.paths) == {"json"}
    assert "system libraries" in result.skipped["pdf"]


def test_pdf_renderer_never_fetches(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    class FakeHTML:
        def __init__(self, string: str, url_fetcher) -> None:
            captured["fetcher"] = url_fetcher

        def write_pdf(self) -> bytes:
            return b"%PDF-fake"

    monkeypatch.setattr(generate, "_weasyprint", lambda: type("W", (), {"HTML": FakeHTML}))
    assert generate.render_pdf("<p>x</p>") == b"%PDF-fake"
    with pytest.raises(ValueError, match="not loaded"):
        captured["fetcher"]("http://evil.test/pixel.gif")


def test_unknown_format(report: AnalysisReport, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown format"):
        generate_report(report, ["docx"], tmp_path)
