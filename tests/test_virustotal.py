"""Tests for phishlens.enrichment.virustotal. HTTP is mocked with respx; the key is fake."""

from __future__ import annotations

import base64

import httpx
import pytest
import respx

from phishlens.config import get_settings
from phishlens.enrichment.virustotal import API_URL, GUI_URL, VirusTotalClient, url_id
from phishlens.models import EnrichmentStatus

KEY = "fake-vt-key"
SHA256 = "a" * 64


def _body(malicious: int = 0, suspicious: int = 0, harmless: int = 60, **attributes) -> dict:
    stats = {
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": 10,
        "harmless": harmless,
        "timeout": 0,
    }
    return {"data": {"attributes": {"last_analysis_stats": stats, "reputation": -5, **attributes}}}


@pytest.fixture(autouse=True)
def vt_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", KEY)
    monkeypatch.setenv("ENRICHMENT_RATE_LIMITS", "virustotal=1000/1")
    monkeypatch.delenv("UPLOAD_FILES_TO_VT", raising=False)
    get_settings.cache_clear()


def test_url_id_is_unpadded_base64url() -> None:
    url = "http://example.com/login?x=1"
    assert url_id(url) == base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    assert "=" not in url_id("http://a.test/")


@respx.mock
async def test_url_malicious() -> None:
    url = "http://phish.test/login"
    route = respx.get(f"{API_URL}/urls/{url_id(url)}").respond(
        200, json=_body(malicious=7, title="Sign in", last_final_url="http://phish.test/x")
    )
    async with VirusTotalClient() as vt:
        result = await vt.url(url)
    assert result.status == EnrichmentStatus.MALICIOUS
    assert (result.detections, result.total_engines) == (7, 77)
    assert result.details["title"] == "Sign in"
    assert result.details["last_final_url"] == "http://phish.test/x"
    assert result.link == f"{GUI_URL}/url/{url_id(url)}"
    assert route.calls.last.request.headers["x-apikey"] == KEY


@respx.mock
async def test_file_hash_clean_and_normalized() -> None:
    respx.get(f"{API_URL}/files/{SHA256}").respond(
        200, json=_body(meaningful_name="invoice.pdf", type_description="PDF")
    )
    async with VirusTotalClient() as vt:
        result = await vt.file(SHA256.upper())
    assert result.status == EnrichmentStatus.CLEAN
    assert result.query == SHA256
    assert result.details["meaningful_name"] == "invoice.pdf"
    assert result.link == f"{GUI_URL}/file/{SHA256}"


@respx.mock
async def test_domain_suspicious_below_threshold() -> None:
    respx.get(f"{API_URL}/domains/evil.test").respond(
        200, json=_body(malicious=1, categories={"x": "phishing"})
    )
    async with VirusTotalClient() as vt:
        result = await vt.domain("Evil.Test.")
    assert result.status == EnrichmentStatus.SUSPICIOUS
    assert result.details["categories"] == {"x": "phishing"}
    assert result.link == f"{GUI_URL}/domain/evil.test"


@respx.mock
async def test_ip_lookup_and_threshold_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VT_MALICIOUS_THRESHOLD", "1")
    get_settings.cache_clear()
    respx.get(f"{API_URL}/ip_addresses/203.0.113.5").respond(
        200, json=_body(malicious=1, country="NL", as_owner="Example AS")
    )
    async with VirusTotalClient() as vt:
        result = await vt.ip("203.0.113.5")
    assert result.status == EnrichmentStatus.MALICIOUS
    assert result.details["country"] == "NL"
    assert result.link == f"{GUI_URL}/ip-address/203.0.113.5"


@respx.mock
async def test_not_found_is_unknown_and_cached() -> None:
    route = respx.get(f"{API_URL}/domains/new.test").respond(404, json={"error": {}})
    async with VirusTotalClient() as vt:
        first = await vt.domain("new.test")
        second = await vt.domain("new.test")
    assert first.status == EnrichmentStatus.UNKNOWN
    assert first.details == {"found": False}
    assert second.cached and route.call_count == 1


@respx.mock
async def test_no_engine_results_is_unknown() -> None:
    respx.get(f"{API_URL}/domains/quiet.test").respond(200, json={"data": {"attributes": {}}})
    async with VirusTotalClient() as vt:
        assert (await vt.domain("quiet.test")).status == EnrichmentStatus.UNKNOWN


@respx.mock
async def test_429_is_retried(enrichment_env) -> None:
    route = respx.get(f"{API_URL}/domains/busy.test")
    route.side_effect = [httpx.Response(429), httpx.Response(200, json=_body())]
    async with VirusTotalClient() as vt:
        result = await vt.domain("busy.test")
    assert result.status == EnrichmentStatus.CLEAN
    assert route.call_count == 2 and len(enrichment_env) == 1


@respx.mock
async def test_quota_exhausted_is_error() -> None:
    respx.get(f"{API_URL}/domains/busy.test").respond(429)
    async with VirusTotalClient() as vt:
        result = await vt.domain("busy.test")
    assert result.status == EnrichmentStatus.ERROR
    assert result.error == "HTTP 429 (after 4 attempts)"


@respx.mock
async def test_bad_key_is_error_without_leaking_it() -> None:
    respx.get(f"{API_URL}/domains/x.test").respond(401)
    async with VirusTotalClient() as vt:
        result = await vt.domain("x.test")
    assert result.status == EnrichmentStatus.ERROR and result.error == "HTTP 401"
    assert KEY not in result.model_dump_json()


@pytest.mark.respx(assert_all_called=False)
async def test_not_configured(respx_mock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VIRUSTOTAL_API_KEY")
    get_settings.cache_clear()
    route = respx_mock.get(url__startswith=API_URL).respond(200, json=_body())
    async with VirusTotalClient() as vt:
        result = await vt.url("http://x.test/")
        upload = await vt.upload_file(b"data", "a.bin", SHA256)
    assert result.status == EnrichmentStatus.NOT_CONFIGURED
    assert upload.status == EnrichmentStatus.NOT_CONFIGURED
    assert route.call_count == 0


@pytest.mark.respx(assert_all_called=False)
async def test_upload_disabled_by_default_sends_nothing(respx_mock) -> None:
    route = respx_mock.post(f"{API_URL}/files").respond(200, json={"data": {"id": "x"}})
    async with VirusTotalClient() as vt:
        result = await vt.upload_file(b"MZ fake", "setup.exe", SHA256)
    assert result.status == EnrichmentStatus.NOT_CONFIGURED
    assert "UPLOAD_FILES_TO_VT" in result.details["reason"]
    assert route.call_count == 0


@respx.mock
async def test_upload_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UPLOAD_FILES_TO_VT", "true")
    get_settings.cache_clear()
    route = respx.post(f"{API_URL}/files").respond(200, json={"data": {"id": "analysis-1"}})
    async with VirusTotalClient() as vt:
        result = await vt.upload_file(b"harmless test bytes", "sample.bin", SHA256.upper())
    assert result.status == EnrichmentStatus.UNKNOWN
    assert result.details == {"uploaded": True, "analysis_id": "analysis-1"}
    assert result.link == f"{GUI_URL}/file/{SHA256}"
    request = route.calls.last.request
    assert request.headers["x-apikey"] == KEY
    assert b"harmless test bytes" in request.content


async def test_upload_too_large(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UPLOAD_FILES_TO_VT", "true")
    get_settings.cache_clear()
    monkeypatch.setattr("phishlens.enrichment.virustotal.MAX_UPLOAD_BYTES", 4)
    async with VirusTotalClient() as vt:
        result = await vt.upload_file(b"12345", "big.bin", SHA256)
    assert result.status == EnrichmentStatus.ERROR
