"""Tests for phishlens.enrichment.base. HTTP is mocked with respx, sleeps are faked by the
``enrichment_env`` fixture (conftest), and only fake keys are used."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from phishlens.config import get_settings
from phishlens.enrichment import base
from phishlens.enrichment.base import BaseClient, EnrichmentError, RateLimiter
from phishlens.models import EnrichmentResult, EnrichmentStatus

API = "https://api.test/lookup"
SECRET = "vt-secret-123"


class DemoClient(BaseClient):
    """A client for a keyed service, using the VirusTotal settings slot."""

    service = "virustotal"

    def normalize(self, kind: str, query: str) -> str:
        return query.strip().lower()

    async def lookup(self, query: str) -> EnrichmentResult:
        return await self.cached_lookup("domain", query, self._fetch)

    async def _fetch(self, query: str) -> EnrichmentResult:
        response = await self.request("GET", API, params={"q": query, "key": SECRET})
        if response.status_code != 200:
            raise EnrichmentError(f"HTTP {response.status_code}")
        hits = response.json()["hits"]
        status = EnrichmentStatus.MALICIOUS if hits else EnrichmentStatus.CLEAN
        return self.result(query, status, detections=hits, total_engines=10)


@pytest.fixture
def keyed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", SECRET)
    monkeypatch.setenv("ENRICHMENT_RATE_LIMITS", "virustotal=1000/1")
    get_settings.cache_clear()


async def _lookup(query: str = "Evil.Test") -> EnrichmentResult:
    async with DemoClient() as client:
        return await client.lookup(query)


@pytest.mark.respx(assert_all_called=False)
async def test_missing_key_is_not_configured_without_network(respx_mock) -> None:
    route = respx_mock.get(API).respond(200, json={"hits": 1})
    result = await _lookup()
    assert result.status == EnrichmentStatus.NOT_CONFIGURED
    assert result.service == "virustotal" and result.query == "evil.test"
    assert route.call_count == 0


@respx.mock
async def test_result_is_cached_in_memory_and_sqlite(keyed) -> None:
    route = respx.get(API).respond(200, json={"hits": 3})
    first = await _lookup()
    assert (first.status, first.detections, first.cached) == ("malicious", 3, False)
    second = await _lookup("evil.test ")
    assert second.cached and second.detections == 3
    assert route.call_count == 1

    base.clear_cache()  # memory gone: the SQLite file answers
    third = await _lookup()
    assert third.cached and route.call_count == 1


@respx.mock
async def test_429_is_retried_with_retry_after(keyed, enrichment_env) -> None:
    route = respx.get(API)
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": "7"}),
        httpx.Response(200, json={"hits": 0}),
    ]
    result = await _lookup()
    assert result.status == EnrichmentStatus.CLEAN
    assert route.call_count == 2
    assert enrichment_env == [7.0]


@respx.mock
async def test_retry_after_is_capped(keyed, enrichment_env) -> None:
    respx.get(API).side_effect = [
        httpx.Response(503, headers={"Retry-After": "3600"}),
        httpx.Response(200, json={"hits": 0}),
    ]
    await _lookup()
    assert enrichment_env == [base.MAX_RETRY_AFTER_SECONDS]


@respx.mock
async def test_timeouts_are_retried_then_error_and_not_cached(keyed, enrichment_env) -> None:
    route = respx.get(API).mock(side_effect=httpx.ReadTimeout("timed out"))
    result = await _lookup()
    assert result.status == EnrichmentStatus.ERROR
    assert result.error == "ReadTimeout: timed out (after 4 attempts)"
    assert route.call_count == 4
    assert len(enrichment_env) == 3
    assert enrichment_env[0] < enrichment_env[1] < enrichment_env[2]  # exponential
    await _lookup()
    assert route.call_count == 8  # errors are not cached


@respx.mock
async def test_client_errors_are_not_retried(keyed) -> None:
    route = respx.get(API).respond(403)
    result = await _lookup()
    assert result.status == EnrichmentStatus.ERROR and result.error == "HTTP 403"
    assert route.call_count == 1


@respx.mock
async def test_max_retries_zero(keyed, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENRICHMENT_MAX_RETRIES", "0")
    get_settings.cache_clear()
    route = respx.get(API).respond(500)
    result = await _lookup()
    assert result.error == "HTTP 500 (after 1 attempts)"
    assert route.call_count == 1


@respx.mock
async def test_api_key_never_appears_in_errors(keyed, caplog: pytest.LogCaptureFixture) -> None:
    respx.get(API).mock(side_effect=httpx.ConnectError(f"cannot reach {API}?key={SECRET}"))
    result = await _lookup()
    assert SECRET not in result.error
    assert "key=***" in result.error
    assert SECRET not in caplog.text


async def test_unexpected_exception_becomes_redacted_error(keyed) -> None:
    async def broken(query: str) -> EnrichmentResult:
        raise ValueError(f"bad data for {SECRET}")

    async with DemoClient() as client:
        result = await client.cached_lookup("domain", "x.test", broken)
    assert result.status == EnrichmentStatus.ERROR
    assert result.error == "ValueError: bad data for ***"


@respx.mock
async def test_zero_ttl_disables_cache(keyed, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENRICHMENT_CACHE_TTL", "virustotal=0")
    get_settings.cache_clear()
    route = respx.get(API).respond(200, json={"hits": 0})
    await _lookup()
    await _lookup()
    assert route.call_count == 2


@respx.mock
async def test_broken_sqlite_file_does_not_break_lookups(
    keyed, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bad = tmp_path / "not-a-db.sqlite"
    bad.write_bytes(b"this is not sqlite")
    monkeypatch.setenv("ENRICHMENT_CACHE_PATH", str(bad))
    get_settings.cache_clear()
    respx.get(API).respond(200, json={"hits": 0})
    assert (await _lookup()).status == EnrichmentStatus.CLEAN
    assert (await _lookup()).cached  # the memory cache still works


async def test_rate_limiter_token_bucket(enrichment_env) -> None:
    now = [0.0]
    limiter = RateLimiter(2, 10.0, clock=lambda: now[0])
    assert await limiter.acquire() == 0.0
    assert await limiter.acquire() == 0.0
    assert await limiter.acquire() == pytest.approx(5.0)  # third request waits for a refill
    assert await limiter.acquire() == pytest.approx(10.0)  # queued behind the third
    now[0] = 100.0  # long idle: the bucket is full again (never above capacity)
    assert await limiter.acquire() == 0.0
    assert await limiter.acquire() == 0.0
    assert await limiter.acquire() == pytest.approx(5.0)
    assert enrichment_env == pytest.approx([5.0, 10.0, 5.0])


def test_limiters_are_shared_per_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENRICHMENT_RATE_LIMITS", "urlscan=30/60")
    get_settings.cache_clear()
    limiter = base.get_limiter("urlscan")
    assert limiter is base.get_limiter("urlscan")
    assert (limiter.capacity, limiter.rate) == (30, 0.5)
    assert base.get_limiter("virustotal").capacity == 4


@respx.mock
async def test_requests_wait_for_the_rate_limit(keyed, monkeypatch, enrichment_env) -> None:
    monkeypatch.setenv("ENRICHMENT_RATE_LIMITS", "virustotal=1/60")
    get_settings.cache_clear()
    respx.get(API).respond(200, json={"hits": 0})
    await _lookup("a.test")
    await _lookup("b.test")
    assert len(enrichment_env) == 1 and 59 < enrichment_env[0] <= 60


def test_redact(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ipdb-key")
    get_settings.cache_clear()
    assert base.redact("x ipdb-key y ipdb-key") == "x *** y ***"


@respx.mock
async def test_cache_only_answers_hits_and_skips_misses(keyed) -> None:
    from phishlens.enrichment.network import CACHE_ONLY_REASON, cache_only

    route = respx.get(API).respond(200, json={"hits": 3})
    await _lookup()  # fills the cache
    with cache_only():
        hit = await _lookup()
        miss = await _lookup("other.test")
        with pytest.raises(EnrichmentError, match="cache only"):
            await DemoClient().request("GET", API)
        batch = await DemoClient().batch_lookup(
            "domain", ["evil.test", "new.test"], lambda chunk: pytest.fail("fetched"), 10
        )
    assert hit.cached and hit.status == "malicious"
    assert miss.status == "not_configured" and miss.details["reason"] == CACHE_ONLY_REASON
    assert batch["evil.test"].cached and batch["new.test"].status == "not_configured"
    assert route.call_count == 1
    assert (await _lookup("other.test")).status == "malicious"  # switched off again
