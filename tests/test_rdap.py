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
    monkeypatch.delenv("RDAP_CACHE_TTL_SECONDS", raising=False)
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
    assert route.calls.last.request.headers["accept"] == "application/rdap+json"
    assert result.to_dict()["registered"] == "2026-09-01T10:00:00+00:00"


@respx.mock
async def test_follows_bootstrap_redirect() -> None:
    registry = "https://rdap.registry.test/domain/zetatech.xyz"
    respx.get(URL).respond(302, headers={"Location": registry})
    respx.get(registry).respond(200, json=RDAP_BODY)
    assert (await rdap.lookup_domain("zetatech.xyz")).status == "ok"


@respx.mock
async def test_not_found_is_cached_but_errors_are_not() -> None:
    route = respx.get(URL).respond(404)
    assert (await rdap.lookup_domain("zetatech.xyz")).status == "not_found"
    cached = await rdap.lookup_domain("zetatech.xyz")
    assert cached.status == "not_found" and cached.cached
    assert route.call_count == 1

    rdap.clear_cache()
    route.respond(503)
    assert (await rdap.lookup_domain("zetatech.xyz")).error == "HTTP 503"
    await rdap.lookup_domain("zetatech.xyz")
    assert route.call_count == 3


@respx.mock
async def test_network_error_and_bad_json_are_errors() -> None:
    respx.get(URL).mock(side_effect=httpx.ConnectTimeout("slow"))
    result = await rdap.lookup_domain("zetatech.xyz")
    assert result.status == "error" and "ConnectTimeout" in result.error

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
    monkeypatch.setenv("RDAP_CACHE_TTL_SECONDS", "0")
    get_settings.cache_clear()
    route = respx.get(URL).respond(200, json=RDAP_BODY)
    await rdap.lookup_domain("zetatech.xyz")
    await rdap.lookup_domain("zetatech.xyz")
    assert route.call_count == 2
