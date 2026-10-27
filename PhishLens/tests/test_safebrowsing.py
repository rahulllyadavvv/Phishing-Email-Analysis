"""Tests for phishlens.enrichment.safebrowsing. HTTP is mocked with respx; the key is fake."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from phishlens.config import get_settings
from phishlens.enrichment import safebrowsing
from phishlens.enrichment.safebrowsing import API_URL, SafeBrowsingClient
from phishlens.models import EnrichmentStatus

KEY = "fake-gsb-key"


@pytest.fixture(autouse=True)
def gsb_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", KEY)
    get_settings.cache_clear()


def _matches(request: httpx.Request, bad: dict[str, str]) -> httpx.Response:
    entries = json.loads(request.content)["threatInfo"]["threatEntries"]
    matches = [
        {"threatType": bad[e["url"]], "platformType": "ANY_PLATFORM", "threat": {"url": e["url"]}}
        for e in entries
        if e["url"] in bad
    ]
    return httpx.Response(200, json={"matches": matches} if matches else {})


@respx.mock
async def test_single_hit_and_miss() -> None:
    route = respx.post(url__startswith=API_URL).mock(
        side_effect=lambda r: _matches(r, {"http://phish.test/": "SOCIAL_ENGINEERING"})
    )
    async with SafeBrowsingClient() as gsb:
        hit = await gsb.url("http://phish.test/")
        miss = await gsb.url("http://fine.test/")
    assert hit.status == EnrichmentStatus.MALICIOUS
    assert hit.details == {"threat_types": ["SOCIAL_ENGINEERING"]}
    assert hit.link.startswith("https://transparencyreport.google.com/safe-browsing/search?url=")
    assert miss.status == EnrichmentStatus.UNKNOWN
    request = route.calls.last.request
    assert request.url.params["key"] == KEY
    body = json.loads(request.content)
    assert body["client"]["clientId"] == "phishlens"
    assert "SOCIAL_ENGINEERING" in body["threatInfo"]["threatTypes"]


@respx.mock
async def test_batches_of_500_and_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    urls = [f"http://site{i}.test/" for i in range(1203)]
    bad = {urls[5]: "MALWARE", urls[900]: "SOCIAL_ENGINEERING"}
    route = respx.post(url__startswith=API_URL).mock(side_effect=lambda r: _matches(r, bad))
    async with SafeBrowsingClient() as gsb:
        results = await gsb.urls(urls)
        sizes = [
            len(json.loads(c.request.content)["threatInfo"]["threatEntries"]) for c in route.calls
        ]
        assert sizes == [500, 500, 203]
        assert results[urls[5]].status == EnrichmentStatus.MALICIOUS
        assert results[urls[900]].details["threat_types"] == ["SOCIAL_ENGINEERING"]
        assert results[urls[0]].status == EnrichmentStatus.UNKNOWN
        assert set(results) == set(urls)

        again = await gsb.urls([urls[5], urls[6], "http://new.test/"])
    assert again[urls[5]].cached and again[urls[6]].cached
    assert not again["http://new.test/"].cached
    assert route.call_count == 4  # only the new URL was sent
    assert json.loads(route.calls.last.request.content)["threatInfo"]["threatEntries"] == [
        {"url": "http://new.test/"}
    ]


@respx.mock
async def test_duplicates_are_sent_once() -> None:
    route = respx.post(url__startswith=API_URL).mock(side_effect=lambda r: _matches(r, {}))
    async with SafeBrowsingClient() as gsb:
        results = await gsb.urls(["http://a.test/", " http://a.test/"])
    assert len(results) == 2
    entries = json.loads(route.calls.last.request.content)["threatInfo"]["threatEntries"]
    assert entries == [{"url": "http://a.test/"}]


@respx.mock
async def test_failed_batch_marks_every_url_error_without_leaking_key(
    caplog: pytest.LogCaptureFixture,
) -> None:
    respx.post(url__startswith=API_URL).mock(
        side_effect=httpx.ConnectError(f"cannot reach {API_URL}?key={KEY}")
    )
    async with SafeBrowsingClient() as gsb:
        results = await gsb.urls(["http://a.test/", "http://b.test/"])
    for result in results.values():
        assert result.status == EnrichmentStatus.ERROR
        assert KEY not in result.error and "key=***" in result.error
    assert KEY not in caplog.text


@respx.mock
async def test_errors_are_not_cached() -> None:
    route = respx.post(url__startswith=API_URL)
    route.side_effect = [httpx.Response(400), httpx.Response(200, json={})]
    async with SafeBrowsingClient() as gsb:
        first = await gsb.url("http://a.test/")
        second = await gsb.url("http://a.test/")
    assert first.status == EnrichmentStatus.ERROR and first.error == "HTTP 400"
    assert second.status == EnrichmentStatus.UNKNOWN and not second.cached


@pytest.mark.respx(assert_all_called=False)
async def test_not_configured(respx_mock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOOGLE_SAFEBROWSING_API_KEY")
    get_settings.cache_clear()
    route = respx_mock.post(url__startswith=API_URL).respond(200, json={})
    async with SafeBrowsingClient() as gsb:
        results = await gsb.urls(["http://a.test/"])
    assert results["http://a.test/"].status == EnrichmentStatus.NOT_CONFIGURED
    assert route.call_count == 0


def test_batch_size_constant() -> None:
    assert safebrowsing.MAX_URLS_PER_REQUEST == 500
