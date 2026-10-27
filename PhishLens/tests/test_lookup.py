"""Tests for phishlens.enrichment.lookup: query order and early stopping (all HTTP mocked)."""

from __future__ import annotations

import pytest

from phishlens.config import get_settings
from phishlens.enrichment import abusech, safebrowsing, virustotal
from phishlens.enrichment.lookup import hash_reputation, url_reputation
from phishlens.enrichment.virustotal import url_id
from phishlens.models import EnrichmentStatus

URL = "http://phish.test/login"
SHA256 = "a" * 64
VT_URL = f"{virustotal.API_URL}/urls/{url_id(URL)}"
VT_FILE = f"{virustotal.API_URL}/files/{SHA256}"
VT_STATS = {"data": {"attributes": {"last_analysis_stats": {"malicious": 9, "harmless": 50}}}}


@pytest.fixture(autouse=True)
def all_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "fake-gsb")
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-abusech")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-vt")
    monkeypatch.setenv("ENRICHMENT_RATE_LIMITS", "virustotal=100/1")
    get_settings.cache_clear()


def _gsb(router, hit: bool):
    body = {"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": URL}}]}
    return router.post(url__startswith=safebrowsing.API_URL).respond(200, json=body if hit else {})


def _urlhaus(router, hit: bool):
    body = {"query_status": "ok", "threat": "phishing"} if hit else {"query_status": "no_results"}
    return router.post(abusech.URLHAUS_API).respond(200, json=body)


def _services(results) -> list[tuple[str, str]]:
    return [(r.service, r.status) for r in results]


@pytest.mark.respx(assert_all_called=False)
async def test_url_stops_at_safe_browsing(respx_mock) -> None:
    _gsb(respx_mock, hit=True)
    urlhaus = _urlhaus(respx_mock, hit=True)
    vt = respx_mock.get(VT_URL).respond(200, json=VT_STATS)
    results = await url_reputation(URL)
    assert _services(results) == [("google_safebrowsing", "malicious")]
    assert urlhaus.call_count == 0 and vt.call_count == 0


@pytest.mark.respx(assert_all_called=False)
async def test_url_stops_at_urlhaus(respx_mock) -> None:
    _gsb(respx_mock, hit=False)
    _urlhaus(respx_mock, hit=True)
    vt = respx_mock.get(VT_URL).respond(200, json=VT_STATS)
    results = await url_reputation(URL)
    assert _services(results) == [
        ("google_safebrowsing", "unknown"),
        ("abusech", "malicious"),
    ]
    assert vt.call_count == 0


async def test_virustotal_only_when_earlier_services_are_unknown(respx_mock) -> None:
    _gsb(respx_mock, hit=False)
    _urlhaus(respx_mock, hit=False)
    vt = respx_mock.get(VT_URL).respond(200, json=VT_STATS)
    results = await url_reputation(URL)
    assert _services(results) == [
        ("google_safebrowsing", "unknown"),
        ("abusech", "unknown"),
        ("virustotal", "malicious"),
    ]
    assert vt.call_count == 1


@pytest.mark.respx(assert_all_called=False)
async def test_unconfigured_services_are_skipped_but_reported(respx_mock, monkeypatch) -> None:
    monkeypatch.delenv("GOOGLE_SAFEBROWSING_API_KEY")
    monkeypatch.delenv("ABUSECH_API_KEY")
    get_settings.cache_clear()
    gsb = _gsb(respx_mock, hit=True)
    respx_mock.get(VT_URL).respond(200, json=VT_STATS)
    results = await url_reputation(URL)
    assert _services(results) == [
        ("google_safebrowsing", "not_configured"),
        ("abusech", "not_configured"),
        ("virustotal", "malicious"),
    ]
    assert gsb.call_count == 0


async def test_error_does_not_stop_the_chain(respx_mock) -> None:
    respx_mock.post(url__startswith=safebrowsing.API_URL).respond(403)
    _urlhaus(respx_mock, hit=False)
    respx_mock.get(VT_URL).respond(404)
    results = await url_reputation(URL)
    assert [r.status for r in results] == ["error", "unknown", "unknown"]


@pytest.mark.respx(assert_all_called=False)
async def test_hash_stops_at_malwarebazaar(respx_mock) -> None:
    respx_mock.post(abusech.MALWAREBAZAAR_API).respond(
        200, json={"query_status": "ok", "data": [{"sha256_hash": SHA256}]}
    )
    vt = respx_mock.get(VT_FILE).respond(200, json=VT_STATS)
    results = await hash_reputation(SHA256)
    assert _services(results) == [("abusech", "malicious")]
    assert vt.call_count == 0


async def test_hash_falls_through_to_virustotal(respx_mock) -> None:
    respx_mock.post(abusech.MALWAREBAZAAR_API).respond(200, json={"query_status": "hash_not_found"})
    respx_mock.get(VT_FILE).respond(200, json=VT_STATS)
    results = await hash_reputation(SHA256)
    assert _services(results) == [("abusech", "unknown"), ("virustotal", "malicious")]
    assert results[1].status == EnrichmentStatus.MALICIOUS
