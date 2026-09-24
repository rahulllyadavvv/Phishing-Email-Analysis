"""Tests for phishlens.enrichment.rdap. HTTP is mocked with respx; nothing leaves the machine."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest
import respx

from phishlens.config import get_settings
from phishlens.enrichment import rdap

URL = rdap.RDAP_BOOTSTRAP_URL + "zetatech.xyz"

RDAP_BODY = {
    "objectClassName": "domain",
    "ldhName": "ZETATECH.XYZ",
    "events": [
        {"eventAction": "registration", "eventDate": "2026-09-01T10:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-09-01T10:00:00Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "handle": "9999",
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "Reg Inc"]],
            ],
        }
    ],
}


@pytest.fixture(autouse=True)
def fresh(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("ENRICHMENT_CACHE_TTL", raising=False)
    get_settings.cache_clear()
    rdap.clear_cache()
    yield
    rdap.clear_cache()
    get_settings.cache_clear()


@respx.mock
async def test_registration_expiry_and_registrar() -> None:
    route = respx.get(URL).respond(200, json=RDAP_BODY)
    result = await rdap.lookup_domain("ZetaTech.xyz.")
    assert result.status == "ok"
    assert result.registered == datetime(2026, 9, 1, 10, tzinfo=UTC)
    assert result.expires == datetime(2027, 9, 1, 10, tzinfo=UTC)
    assert result.registrar == "Reg Inc"
    request = route.calls.last.request
    assert request.headers["accept"] == "application/rdap+json"
    assert request.headers["user-agent"].startswith("PhishLens/")
    assert result.to_dict()["registered"] == "2026-09-01T10:00:00+00:00"


@respx.mock
async def test_follows_bootstrap_redirect() -> None:
    registry = "https://rdap.registry.test/domain/zetatech.xyz"
    respx.get(URL).respond(302, headers={"Location": registry})
    respx.get(registry).respond(200, json=RDAP_BODY)
    assert (await rdap.lookup_domain("zetatech.xyz")).status == "ok"


@respx.mock
async def test_not_found_is_cached() -> None:
    route = respx.get(URL).respond(404)
    assert (await rdap.lookup_domain("zetatech.xyz")).status == "not_found"
    rdap.clear_cache()  # memory only: the SQLite cache still answers
    cached = await rdap.lookup_domain("zetatech.xyz")
    assert cached.status == "not_found" and cached.cached
    assert route.call_count == 1


@respx.mock
async def test_server_errors_are_retried_and_not_cached(
    enrichment_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ENRICHMENT_RATE_LIMITS", "rdap=100/1")  # only count backoff waits
    get_settings.cache_clear()
    route = respx.get(URL).respond(503)
    result = await rdap.lookup_domain("zetatech.xyz")
    assert result.status == "error"
    assert result.error == "HTTP 503 (after 4 attempts)"
    assert route.call_count == 4
    assert len(enrichment_env) == 3  # three backoff waits (sleeps are faked)
    for wait, base in zip(enrichment_env, (1, 2, 4), strict=True):
        assert base <= wait <= base + 0.5  # exponential backoff plus jitter
    await rdap.lookup_domain("zetatech.xyz")
    assert route.call_count == 8


@respx.mock
async def test_network_error_and_bad_json_are_errors() -> None:
    respx.get(URL).mock(side_effect=httpx.ConnectTimeout("slow"))
    result = await rdap.lookup_domain("zetatech.xyz")
    assert result.status == "error"
    assert result.error == "ConnectTimeout: slow (after 4 attempts)"

    respx.get(rdap.RDAP_BOOTSTRAP_URL + "bad.xyz").respond(200, content=b"not json")
    assert (await rdap.lookup_domain("bad.xyz")).status == "error"


@respx.mock
async def test_missing_events_give_no_dates() -> None:
    respx.get(URL).respond(200, json={"objectClassName": "domain"})
    result = await rdap.lookup_domain("zetatech.xyz")
    assert result.status == "ok" and result.registered is None and result.registrar is None


@respx.mock(assert_all_called=False)
async def test_reserved_names_are_never_looked_up() -> None:
    for name in ("company.example", "x.test", "example.com", "host.localhost", ""):
        assert (await rdap.lookup_domain(name)).status == "reserved"
    assert not respx.calls


@respx.mock
async def test_zero_ttl_disables_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENRICHMENT_CACHE_TTL", "rdap=0")
    get_settings.cache_clear()
    route = respx.get(URL).respond(200, json=RDAP_BODY)
    await rdap.lookup_domain("zetatech.xyz")
    await rdap.lookup_domain("zetatech.xyz")
    assert route.call_count == 2


@respx.mock
async def test_rdap_client_returns_normalized_result() -> None:
    respx.get(URL).respond(200, json=RDAP_BODY)
    async with rdap.RdapClient() as client:
        result = await client.domain("ZETATECH.xyz")
    assert result.service == "rdap"
    assert result.query == "zetatech.xyz"
    assert result.status == "unknown"
    assert result.details["registered"] == "2026-09-01T10:00:00+00:00"
    assert result.link == URL
