"""Tests for HTML report rendering (phishlens.reporting.html / view / safe)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

from phishlens.models import AnalysisReport, AnalyzerResult, CaseType, Finding, Verdict
from phishlens.pipeline import analyze_email, analyze_file
from phishlens.reporting.html import render_html
from phishlens.reporting.safe import Link, Plain, defang_text, finalize, is_allowed_link

FIXTURES = Path(__file__).parent / "fixtures"
ALLOWED = ("https://attack.mitre.org/", "https://urlscan.io/")


def _links(html: str) -> list[str]:
    return re.findall(r'(?:href|src)="([^"]+)"', html)


def _text(html: str) -> str:
    return BeautifulSoup(html, "html.parser").get_text(" ")


@pytest.fixture(scope="module")
def reports() -> dict[str, AnalysisReport]:
    import asyncio

    login = (
        b"<html><form action='https://collect.example.test/p'>"
        b"<input type=password></form></html>"
    )
    return {
        "clean": asyncio.run(
            analyze_email((FIXTURES / "clean_newsletter.eml").read_bytes(), network=False)
        ),
        "malicious": asyncio.run(
            analyze_email((FIXTURES / "link_mismatch.eml").read_bytes(), network=False)
        ),
        "file": asyncio.run(analyze_file(login, "login.html", network=False)),
    }


@pytest.mark.parametrize("case", ["clean", "malicious", "file"])
def test_renders_every_case(reports, case: str) -> None:
    html = render_html(reports[case], ["Summary sentence."], ["Do something."])
    assert html.startswith("<!DOCTYPE html>")
    text = _text(html)
    for section in ("Executive summary", "Indicators of compromise", "MITRE ATT&CK",
                    "Score breakdown", "Recommended actions"):
        assert section in text, section
    label = reports[case].verdict.label.value.upper()
    assert label in text
    assert "<script" not in html.lower()
    assert "Summary sentence." in text and "Do something." in text


def test_only_allowed_links_are_live(reports) -> None:
    for report in reports.values():
        html = render_html(report)
        for link in _links(html):
            assert link.startswith(ALLOWED), link


def test_malicious_values_are_defanged(reports) -> None:
    html = render_html(reports["malicious"], ["It links to paypal-secure-login.example."])
    for raw in ("paypal-secure-login.example", "http://paypal-secure-login", "203.0.113.12",
                "service@paypal-notice.example"):
        assert raw not in html, raw
    text = _text(html)
    assert "hxxp://paypal-secure-login[.]example/confirm" in text
    assert "203[.]0[.]113[.]12" in text
    assert "T1566.002" in text


def test_email_sections_for_email_cases(reports) -> None:
    text = _text(render_html(reports["malicious"]))
    for section in ("Email overview", "Header authentication", "Received chain",
                    "Sender and domain", "Body analysis", "Hidden artifacts"):
        assert section in text, section


def test_file_case_replaces_email_sections(reports) -> None:
    text = _text(render_html(reports["file"]))
    assert "File overview" in text and "standalone file case" in text
    for section in ("Email overview", "Received chain", "Body analysis", "Hidden artifacts"):
        assert section not in text, section
    assert "login.html" in text  # file names are shown as-is (Plain)


def test_empty_sections_say_no_findings(reports) -> None:
    text = _text(render_html(reports["clean"]))
    assert "No findings" in text
    assert "No action needed." in text  # no recommendations given
    assert "No summary available." in text


def test_html_escaping_of_attacker_text() -> None:
    finding = Finding(
        id="hidden_text", module="artifacts", title="<img src=x onerror=alert(1)>",
        description="</td><script>alert(1)</script>",
    )
    report = AnalysisReport(
        case_id="x", case_type=CaseType.EMAIL,
        results={"artifacts": AnalyzerResult(module="artifacts", findings=[finding])},
        verdict=Verdict(label="suspicious", total_score=40),
    )
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_safe_helpers() -> None:
    assert defang_text("see https://evil.test/a and 198.51.100.4") == (
        "see hxxps://evil[.]test/a and 198[.]51[.]100[.]4"
    )
    assert defang_text("version 1.2.3, ratio 0.75") == "version 1.2.3, ratio 0.75"
    assert is_allowed_link("https://attack.mitre.org/techniques/T1566")
    assert is_allowed_link("https://urlscan.io/screenshots/abc.png")
    assert not is_allowed_link("http://attack.mitre.org/")  # https only
    assert not is_allowed_link("https://attack.mitre.org.evil.test/")
    assert 'href="https://attack.mitre.org' in Link("https://attack.mitre.org/x", "T1").__html__()
    assert "href" not in Link("https://evil.test/", "evil.test").__html__()
    assert str(finalize(Plain("invoice.pdf.exe"))) == "invoice.pdf.exe"
    assert finalize("evil.test") == "evil[.]test"
    assert finalize(0.75) == 0.75 and finalize(None) == ""
