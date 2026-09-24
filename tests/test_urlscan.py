"""Tests for phishlens.enrichment.urlscan. HTTP is mocked with respx, sleeps are faked by the
``enrichment_env`` fixture, and the key is fake."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from phishlens.config import get_settings
from phishlens.enrichment.urlscan import API_URL, SITE_URL, UrlscanClient
from phishlens.models import EnrichmentStatus

KEY = "fake-urlscan-key"
URL = "http://phish.test/login"
UUID = "0f0e0d0c-1111-2222-3333-444455556666"


def _result(malicious: bool = True, score: int = 100) -> dict:
    return {
        "task": {
            "uuid": UUID,
            "url": URL,
            "reportURL": f"{SITE_URL}/result/{UUID}/",
            "screenshotURL": f"{SITE_URL}/screenshots/{UUID}.png",
        },
        "page": {
            "url": "https://final.phish.test/signin",
            "title": "Sign in to your account",
            "ip": "203.0.113.7",
            "country": "NL",
        },
        "verdicts": {
            "overall": {
                "malicious": malicious,
                "score": score,
                "categories": ["phishing"] if malicious else [],
                "brands": ["Microsoft"] if malicious else [],
            }
        },
        "data": {
            "requests": [
                {
                    "requests": [
                        {"request": {"url": URL}},
                        {"request": {"url": "http://redirect.phish.test/r"}},
                        {"request": {"url": "https://final.phish.test/signin"}},
                    ]
                }
            ]
        },
    }


DOM_WITH_LOGIN = '<form><input name="u"><input type=password name="p"></form>'


@pytest.fixture(autouse=True)
def urlscan_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("URLSCAN_API_KEY", KEY)
    monkeypatch.setenv("ENRICHMENT_RATE_LIMITS", "urlscan=1000/1")
    for name in ("URLSCAN_VISIBILITY", "URLSCAN_MAX_WAIT_SECONDS", "URLSCAN_REUSE_DAYS"):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()


def _routes(router, search_results: list | None = None, dom: str | int = DOM_WITH_LOGIN):
    """Register the urlscan endpoints on ``router`` (the ``respx`` module or ``respx_mock``)."""
    search = router.get(f"{API_URL}/search/").respond(200, json={"results": search_results or []})
    submit = router.post(f"{API_URL}/scan/").respond(200, json={"uuid": UUID})
    result = router.get(f"{API_URL}/result/{UUID}/")
    if isinstance(dom, int):
        router.get(f"{SITE_URL}/dom/{UUID}/").respond(dom)
    else:
        router.get(f"{SITE_URL}/dom/{UUID}/").respond(200, text=dom)
    return search, submit, result


@pytest.mark.respx(assert_all_called=False)
async def test_existing_scan_is_reused(respx_mock, enrichment_env) -> None:
    search, submit, result = _routes(respx_mock, search_results=[{"task": {"uuid": UUID}}])
    result.respond(200, json=_result())
    async with UrlscanClient() as client:
        scan = await client.scan(URL)
    assert submit.call_count == 0
    query = search.calls.last.request.url.params["q"]
    assert query == f'task.url:"{URL}" AND date:>now-7d'
    assert search.calls.last.request.headers["api-key"] == KEY
    assert scan.status == EnrichmentStatus.MALICIOUS
    assert scan.details["reused_existing_scan"] is True
    assert enrichment_env == []  # no polling needed


@respx.mock
async def test_submit_and_poll_until_ready(enrichment_env) -> None:
    search, submit, result = _routes(respx)
    result.side_effect = [
        httpx.Response(404),
        httpx.Response(404),
        httpx.Response(200, json=_result()),
    ]
    async with UrlscanClient() as client:
        scan = await client.scan(URL)
    body = json.loads(submit.calls.last.request.content)
    assert body == {"url": URL, "visibility": "unlisted"}
    assert result.call_count == 3
    assert enrichment_env == [10.0, 15.0]  # growing poll intervals
    details = scan.details
    assert details["uuid"] == UUID and details["reused_existing_scan"] is False
    assert details["final_url"] == "https://final.phish.test/signin"
    assert details["redirect_chain"] == [
        URL,
        "http://redirect.phish.test/r",
        "https://final.phish.test/signin",
    ]
    assert details["page_title"] == "Sign in to your account"
    assert details["screenshot_url"] == f"{SITE_URL}/screenshots/{UUID}.png"
    assert details["login_form"] is True
    assert details["brands"] == ["Microsoft"]
    assert scan.link == f"{SITE_URL}/result/{UUID}/"


@respx.mock
async def test_poll_timeout_is_error_and_not_cached(
    enrichment_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("URLSCAN_MAX_WAIT_SECONDS", "20")
    get_settings.cache_clear()
    _, submit, result = _routes(respx)
    result.respond(404)
    async with UrlscanClient() as client:
        scan = await client.scan(URL)
        assert scan.status == EnrichmentStatus.ERROR
        assert f"scan {UUID} not finished after 20s" in scan.error
        assert enrichment_env == [10.0, 10.0]  # capped by the remaining wait
        await client.scan(URL)
    assert submit.call_count == 2


@pytest.mark.parametrize(
    ("malicious", "score", "status"),
    [
        (True, 100, EnrichmentStatus.MALICIOUS),
        (False, 30, EnrichmentStatus.SUSPICIOUS),
        (False, 0, EnrichmentStatus.UNKNOWN),
    ],
)
@respx.mock
async def test_verdict_mapping(malicious: bool, score: int, status: EnrichmentStatus) -> None:
    _, _, result = _routes(respx, search_results=[{"_id": UUID}])
    result.respond(200, json=_result(malicious=malicious, score=score))
    async with UrlscanClient() as client:
        assert (await client.scan(URL)).status == status


@respx.mock
async def test_login_form_unknown_when_dom_missing() -> None:
    _, _, result = _routes(respx, search_results=[{"_id": UUID}], dom=404)
    result.respond(200, json=_result())
    async with UrlscanClient() as client:
        assert (await client.scan(URL)).details["login_form"] is None


@respx.mock
async def test_no_login_form() -> None:
    _, _, result = _routes(respx, search_results=[{"_id": UUID}], dom="<p>Hello</p>")
    result.respond(200, json=_result())
    async with UrlscanClient() as client:
        assert (await client.scan(URL)).details["login_form"] is False


@pytest.mark.respx(assert_all_called=False)
async def test_reuse_disabled_and_visibility(respx_mock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("URLSCAN_REUSE_DAYS", "0")
    monkeypatch.setenv("URLSCAN_VISIBILITY", "private")
    get_settings.cache_clear()
    search, submit, result = _routes(respx_mock)
    result.respond(200, json=_result())
    async with UrlscanClient() as client:
        await client.scan(URL)
    assert search.call_count == 0
    assert json.loads(submit.calls.last.request.content)["visibility"] == "private"


@pytest.mark.respx(assert_all_called=False)
async def test_submit_refused(respx_mock) -> None:
    _routes(respx_mock)
    respx_mock.post(f"{API_URL}/scan/").respond(
        400, json={"message": "DNS Error - Could not resolve domain"}
    )
    async with UrlscanClient() as client:
        scan = await client.scan(URL)
    assert scan.status == EnrichmentStatus.ERROR
    assert scan.error == "submit failed: HTTP 400 (DNS Error - Could not resolve domain)"


@pytest.mark.respx(assert_all_called=False)
async def test_search_failure_falls_back_to_submit(respx_mock) -> None:
    _, submit, result = _routes(respx_mock)
    respx_mock.get(f"{API_URL}/search/").respond(400)
    result.respond(200, json=_result())
    async with UrlscanClient() as client:
        assert (await client.scan(URL)).status == EnrichmentStatus.MALICIOUS
    assert submit.call_count == 1


@pytest.mark.respx(assert_all_called=False)
async def test_result_is_cached(respx_mock) -> None:
    search, _, result = _routes(respx_mock, search_results=[{"_id": UUID}])
    result.respond(200, json=_result())
    async with UrlscanClient() as client:
        await client.scan(URL)
        again = await client.scan(URL)
    assert again.cached and search.call_count == 1


@pytest.mark.respx(assert_all_called=False)
async def test_not_configured(respx_mock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("URLSCAN_API_KEY")
    get_settings.cache_clear()
    search, submit, _ = _routes(respx_mock)
    async with UrlscanClient() as client:
        assert (await client.scan(URL)).status == EnrichmentStatus.NOT_CONFIGURED
    assert search.call_count == 0 and submit.call_count == 0
