"""Tests for phishlens.enrichment.abusech. HTTP is mocked with respx; the key is fake."""

from __future__ import annotations

from urllib.parse import parse_qs

import pytest
import respx

from phishlens.config import get_settings
from phishlens.enrichment.abusech import (
    MALWAREBAZAAR_API,
    THREATFOX_API,
    URLHAUS_API,
    AbuseChClient,
)
from phishlens.models import EnrichmentStatus

KEY = "fake-abusech-key"
SHA256 = "b" * 64


@pytest.fixture(autouse=True)
def abusech_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSECH_API_KEY", KEY)
    get_settings.cache_clear()


def _form(request) -> dict[str, list[str]]:
    return parse_qs(request.content.decode())


@respx.mock
async def test_urlhaus_hit() -> None:
    route = respx.post(URLHAUS_API).respond(
        200,
        json={
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["exe"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
        },
    )
    async with AbuseChClient() as client:
        result = await client.urlhaus_url(" http://bad.test/a.exe ")
    assert result.status == EnrichmentStatus.MALICIOUS
    assert result.query == "http://bad.test/a.exe"
    assert result.details["threat"] == "malware_download"
    assert result.link == "https://urlhaus.abuse.ch/url/1/"
    request = route.calls.last.request
    assert request.headers["auth-key"] == KEY
    assert _form(request) == {"url": ["http://bad.test/a.exe"]}


@respx.mock
async def test_urlhaus_miss_is_unknown() -> None:
    respx.post(URLHAUS_API).respond(200, json={"query_status": "no_results"})
    async with AbuseChClient() as client:
        result = await client.urlhaus_url("http://fine.test/")
    assert result.status == EnrichmentStatus.UNKNOWN


@respx.mock
async def test_malwarebazaar_hit_and_miss() -> None:
    route = respx.post(MALWAREBAZAAR_API)
    route.respond(
        200,
        json={
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": SHA256,
                    "signature": "AgentTesla",
                    "file_type": "exe",
                    "tags": ["stealer"],
                }
            ],
        },
    )
    async with AbuseChClient() as client:
        hit = await client.malwarebazaar_hash(SHA256.upper())
        assert hit.status == EnrichmentStatus.MALICIOUS
        assert hit.details["signature"] == "AgentTesla"
        assert hit.link == f"https://bazaar.abuse.ch/sample/{SHA256}/"
        assert _form(route.calls.last.request) == {"query": ["get_info"], "hash": [SHA256]}

        route.respond(200, json={"query_status": "hash_not_found"})
        miss = await client.malwarebazaar_hash("c" * 64)
    assert miss.status == EnrichmentStatus.UNKNOWN


@respx.mock
async def test_threatfox_confidence_decides_status() -> None:
    route = respx.post(THREATFOX_API)
    route.respond(
        200,
        json={
            "query_status": "ok",
            "data": [
                {
                    "id": "42",
                    "threat_type": "botnet_cc",
                    "malware_printable": "Cobalt Strike",
                    "confidence_level": 90,
                    "tags": ["c2"],
                },
                {"id": "7", "threat_type": "payload_delivery", "confidence_level": 25},
            ],
        },
    )
    async with AbuseChClient() as client:
        high = await client.threatfox_ioc("bad.test")
        assert high.status == EnrichmentStatus.MALICIOUS
        assert high.detections == 2
        assert high.details["confidence"] == 90
        assert high.link == "https://threatfox.abuse.ch/ioc/42/"
        assert route.calls.last.request.read() == (
            b'{"query":"search_ioc","search_term":"bad.test"}'
        )

        low_entry = {"id": "1", "confidence_level": 30}
        route.respond(200, json={"query_status": "ok", "data": [low_entry]})
        low = await client.threatfox_ioc("maybe.test")
        assert low.status == EnrichmentStatus.SUSPICIOUS

        route.respond(200, json={"query_status": "no_result", "data": "Your search did not yield"})
        assert (await client.threatfox_ioc("none.test")).status == EnrichmentStatus.UNKNOWN


@respx.mock
async def test_bad_query_status_is_error() -> None:
    respx.post(URLHAUS_API).respond(200, json={"query_status": "unknown_auth_key"})
    async with AbuseChClient() as client:
        result = await client.urlhaus_url("http://x.test/")
    assert result.status == EnrichmentStatus.ERROR
    assert result.error == "urlhaus query_status unknown_auth_key"


@respx.mock
async def test_http_error() -> None:
    respx.post(MALWAREBAZAAR_API).respond(401)
    async with AbuseChClient() as client:
        result = await client.malwarebazaar_hash(SHA256)
    assert result.status == EnrichmentStatus.ERROR and result.error == "HTTP 401"


@respx.mock
async def test_results_are_cached_per_lookup_type() -> None:
    urlhaus = respx.post(URLHAUS_API).respond(200, json={"query_status": "no_results"})
    threatfox = respx.post(THREATFOX_API).respond(200, json={"query_status": "no_result"})
    async with AbuseChClient() as client:
        await client.urlhaus_url("http://x.test/")
        await client.urlhaus_url("http://x.test/")
        await client.threatfox_ioc("http://x.test/")
    assert urlhaus.call_count == 1 and threatfox.call_count == 1


@respx.mock(assert_all_called=False)
async def test_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ABUSECH_API_KEY")
    get_settings.cache_clear()
    route = respx.post(URLHAUS_API).respond(200, json={"query_status": "ok"})
    async with AbuseChClient() as client:
        result = await client.urlhaus_url("http://x.test/")
    assert result.status == EnrichmentStatus.NOT_CONFIGURED
    assert route.call_count == 0
