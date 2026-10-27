"""End-to-end tests for file cases (phishlens.pipeline.analyze_file / analyze_input), with all
network mocked."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import httpx
import pytest

from phishlens import pipeline
from phishlens.config import get_settings
from phishlens.enrichment import abusech
from phishlens.ingest.loader import InputTooLargeError
from phishlens.models import CaseType
from phishlens.parser import parse_email

FIXTURES = Path(__file__).parent / "fixtures"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _eicar_bytes() -> bytes:
    email = parse_email((FIXTURES / "eicar_attachment.eml").read_bytes())
    return email.attachments[0].data


def _double_extension_bytes() -> bytes:
    email = parse_email((FIXTURES / "double_extension.eml").read_bytes())
    return email.attachments[0].data


@pytest.fixture
def world(fake_dns, respx_mock, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-abusech")
    get_settings.cache_clear()
    fake_dns({})

    def malwarebazaar(request: httpx.Request) -> httpx.Response:
        if EICAR_SHA256 in request.content.decode():
            return httpx.Response(
                200,
                json={"query_status": "ok", "data": [{"sha256_hash": EICAR_SHA256}]},
            )
        return httpx.Response(200, json={"query_status": "hash_not_found"})

    respx_mock.post(abusech.MALWAREBAZAAR_API).mock(side_effect=malwarebazaar)
    respx_mock.post(abusech.URLHAUS_API).respond(200, json={"query_status": "no_results"})
    return respx_mock


async def test_harmless_text_file_is_clean(world) -> None:
    report = await pipeline.analyze_file(b"Meeting notes: agenda for Tuesday.\n", "notes.txt")
    assert report.case_type == CaseType.FILE
    assert report.verdict.label.value == "clean"
    assert report.email is None
    assert report.file_info.filename == "notes.txt"
    assert report.file_info.detected_type == "text/plain"
    for name in pipeline.FILE_SKIPPED_MODULES:
        assert report.results[name].skipped
        assert report.results[name].raw == {"skipped_reason": "not an email"}
    # Skipped analyzers do not lower confidence; only the two unconfigured key services do
    # (VirusTotal and Safe Browsing, 0.1 each).
    assert report.verdict.confidence == 0.8


async def test_eicar_with_mocked_reputation_is_malicious(world) -> None:
    report = await pipeline.analyze_file(_eicar_bytes(), "eicar.com")
    assert report.verdict.label.value == "malicious"
    assert "known_malicious_attachment" in report.verdict.overrides_applied
    assert any(i.value == EICAR_SHA256 and i.verdict == "malicious" for i in report.iocs)
    assert {"T1566.001", "T1204.002"} <= {t.id for t in report.mitre}


async def test_zip_with_double_extension_file(world) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("invoice.pdf.exe", _double_extension_bytes())
    report = await pipeline.analyze_file(buf.getvalue(), "invoice.zip")
    ids = {f.id for f in report.results["attachments"].findings}
    assert {"double_extension", "high_risk_file_type"} <= ids
    assert report.verdict.label.value == "malicious"  # 55 >= the file threshold of 50
    rows = report.results["attachments"].raw["attachments"]
    assert [(r["filename"], r["parent"]) for r in rows] == [
        ("invoice.zip", None),
        ("invoice.pdf.exe", "invoice.zip"),
    ]


async def test_urls_inside_a_file_are_analyzed(world) -> None:
    html = (
        b'<html><body><form action="https://collect.example.test/p">'
        b'<input type="password"></form></body></html>'
    )
    report = await pipeline.analyze_file(html, "login.html")
    rows = report.results["urls"].raw["urls"]
    assert [r["url"] for r in rows] == ["https://collect.example.test/p"]
    assert "credential_form_attachment" in {f.id for f in report.results["attachments"].findings}


async def test_email_uploaded_as_file_is_routed_to_the_email_pipeline(world) -> None:
    raw = (FIXTURES / "link_mismatch.eml").read_bytes()
    report = await pipeline.analyze_input(raw, "suspicious.bin")
    assert report.case_type == CaseType.EMAIL
    assert report.email is not None and report.email.subject
    file_report = await pipeline.analyze_input(b"plain text", "a.txt")
    assert file_report.case_type == CaseType.FILE


async def test_analyze_input_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAX_INPUT_SIZE_MB", "0.0001")
    get_settings.cache_clear()
    with pytest.raises(InputTooLargeError):
        await pipeline.analyze_input(b"x" * 1000, "big.bin")


async def test_file_case_offline_and_progress(world) -> None:
    events: list[tuple[str, str]] = []
    report = await pipeline.analyze_file(
        _eicar_bytes(), "eicar.com", lambda m, s: events.append((m, s)), network=False
    )
    assert world.calls.call_count == 0
    assert report.verdict.label.value != "malicious"  # no reputation offline
    assert ("header", "skipped") in events and ("attachments", "done") in events
    assert events[-1] == ("scoring", "done")
