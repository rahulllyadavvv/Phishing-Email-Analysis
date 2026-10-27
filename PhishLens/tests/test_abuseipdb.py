"""Tests for phishlens.enrichment.abuseipdb. HTTP is mocked with respx; the key is fake."""

from __future__ import annotations

import pytest
import respx

from phishlens.config import get_settings
from phishlens.enrichment.abuseipdb import API_URL, AbuseIpdbClient
from phishlens.models import EnrichmentStatus

KEY = "fake-abuseipdb-key"
IP = "203.0.113.50"


@pytest.fixture(autouse=True)
def ipdb_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", KEY)
    get_settings.cache_clear()


def _data(score: int, whitelisted: bool = False) -> dict:
    return {
        "data": {
            "ipAddress": IP,
            "abuseConfidenceScore": score,
            "totalReports": 12,
            "isp": "Example Hosting",
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit",
            "domain": "hosting.test",
            "isWhitelisted": whitelisted,
        }
    }


@pytest.mark.parametrize(
    ("score", "whitelisted", "status"),
    [
        (100, False, EnrichmentStatus.MALICIOUS),
        (75, False, EnrichmentStatus.MALICIOUS),
        (40, False, EnrichmentStatus.SUSPICIOUS),
        (0, False, EnrichmentStatus.CLEAN),
        (90, True, EnrichmentStatus.CLEAN),
    ],
)
@respx.mock
async def test_status_from_score(score: int, whitelisted: bool, status: EnrichmentStatus) -> None:
    route = respx.get(API_URL).respond(200, json=_data(score, whitelisted))
    async with AbuseIpdbClient() as client:
        result = await client.ip(IP)
    assert result.status == status
    assert result.details["abuse_confidence_score"] == score
    assert result.details["isp"] == "Example Hosting"
    assert result.details["country"] == "US"
    assert result.details["usage_type"] == "Data Center/Web Hosting/Transit"
    assert result.link == f"https://www.abuseipdb.com/check/{IP}"
    request = route.calls.last.request
    assert request.headers["key"] == KEY
    assert request.url.params["ipAddress"] == IP
    assert request.url.params["maxAgeInDays"] == "90"


@respx.mock
async def test_error_status() -> None:
    respx.get(API_URL).respond(422)
    async with AbuseIpdbClient() as client:
        result = await client.ip("not-an-ip")
    assert result.status == EnrichmentStatus.ERROR and result.error == "HTTP 422"


@pytest.mark.respx(assert_all_called=False)
async def test_not_configured(respx_mock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY")
    get_settings.cache_clear()
    route = respx_mock.get(API_URL).respond(200, json=_data(100))
    async with AbuseIpdbClient() as client:
        assert (await client.ip(IP)).status == EnrichmentStatus.NOT_CONFIGURED
    assert route.call_count == 0
