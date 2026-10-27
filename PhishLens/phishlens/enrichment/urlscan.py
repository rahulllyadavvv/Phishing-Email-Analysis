"""urlscan.io client: reuse a recent scan of the URL, else submit one and poll for the result.

urlscan visits the URL in its own browser, so nothing is fetched on this host. Submissions use
``URLSCAN_VISIBILITY`` (default ``unlisted``). Before submitting, the search API is asked for a
scan of the same URL from the last ``URLSCAN_REUSE_DAYS`` days, which saves quota and avoids
tipping off the attacker with repeated visits.

The result gives urlscan's verdict, the final URL, the redirect chain, the page title and a
screenshot link. ``login_form`` comes from urlscan's stored copy of the rendered page
(``/dom/<uuid>/``): True when it contains a password field, None when the copy is unavailable.
Status: ``malicious`` when urlscan's overall verdict says so, ``suspicious`` when its score is
positive, otherwise ``unknown`` (no verdict is not proof of safety).
"""

from __future__ import annotations

import re
from typing import Any

from phishlens.enrichment import base
from phishlens.enrichment.base import BaseClient, EnrichmentError
from phishlens.models import EnrichmentResult, EnrichmentStatus

__all__ = ["API_URL", "POLL_FIRST_SECONDS", "UrlscanClient"]

API_URL = "https://urlscan.io/api/v1"
SITE_URL = "https://urlscan.io"
POLL_FIRST_SECONDS = 10.0  # urlscan asks clients to wait ~10 s before the first poll
POLL_FACTOR = 1.5
POLL_MAX_INTERVAL = 15.0
_PASSWORD_FIELD = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']?password", re.IGNORECASE)


def _search_quote(url: str) -> str:
    return '"' + url.replace("\\", "\\\\").replace('"', '\\"') + '"'


class UrlscanClient(BaseClient):
    service = "urlscan"

    def _headers(self) -> dict[str, str]:
        key = self.settings.urlscan_api_key
        return {"API-Key": key.get_secret_value() if key else ""}

    async def scan(self, url: str) -> EnrichmentResult:
        """Scan result for ``url`` (reused or new). Never raises."""
        return await self.cached_lookup("scan", url, self._scan)

    async def _scan(self, url: str) -> EnrichmentResult:
        uuid = await self._existing_scan(url)
        reused = uuid is not None
        if uuid is None:
            uuid = await self._submit(url)
        data = await self._poll(uuid)
        return await self._to_result(url, uuid, data, reused)

    async def _existing_scan(self, url: str) -> str | None:
        days = self.settings.urlscan_reuse_days
        if days <= 0:
            return None
        query = f"task.url:{_search_quote(url)} AND date:>now-{days}d"
        response = await self.request(
            "GET", f"{API_URL}/search/", params={"q": query, "size": 1}, headers=self._headers()
        )
        if response.status_code != 200:
            return None  # searching is an optimization; fall back to submitting
        for hit in response.json().get("results") or []:
            uuid = (hit.get("task") or {}).get("uuid") or hit.get("_id")
            if uuid:
                return str(uuid)
        return None

    async def _submit(self, url: str) -> str:
        response = await self.request(
            "POST",
            f"{API_URL}/scan/",
            headers=self._headers(),
            json={"url": url, "visibility": self.settings.urlscan_visibility},
        )
        if response.status_code != 200:
            try:
                reason = response.json().get("message") or response.json().get("description")
            except ValueError:
                reason = None
            raise EnrichmentError(f"submit failed: HTTP {response.status_code}" + (
                f" ({reason})" if reason else ""
            ))
        uuid = response.json().get("uuid")
        if not uuid:
            raise EnrichmentError("submit response had no uuid")
        return str(uuid)

    async def _poll(self, uuid: str) -> dict[str, Any]:
        """Wait for the result with growing intervals, up to ``URLSCAN_MAX_WAIT_SECONDS``."""
        deadline = self.settings.urlscan_max_wait_seconds
        waited = 0.0
        interval = POLL_FIRST_SECONDS
        while True:
            response = await self.request(
                "GET", f"{API_URL}/result/{uuid}/", headers=self._headers()
            )
            if response.status_code == 200:
                return response.json()
            if response.status_code != 404:  # 404 = not finished yet
                raise EnrichmentError(f"result failed: HTTP {response.status_code}")
            if waited >= deadline:
                raise EnrichmentError(
                    f"scan {uuid} not finished after {deadline:g}s "
                    f"(see {SITE_URL}/result/{uuid}/)"
                )
            pause = min(interval, deadline - waited)
            await base._sleep(pause)
            waited += pause
            interval = min(interval * POLL_FACTOR, POLL_MAX_INTERVAL)

    async def _login_form(self, uuid: str) -> bool | None:
        response = await self.request("GET", f"{SITE_URL}/dom/{uuid}/", headers=self._headers())
        if response.status_code != 200:
            return None
        return bool(_PASSWORD_FIELD.search(response.text))

    async def _to_result(
        self, url: str, uuid: str, data: dict[str, Any], reused: bool
    ) -> EnrichmentResult:
        task = data.get("task") or {}
        page = data.get("page") or {}
        overall = (data.get("verdicts") or {}).get("overall") or {}
        chain: list[str] = []
        for candidate in [task.get("url") or url, *_redirects(data), page.get("url")]:
            if candidate and candidate not in chain:
                chain.append(candidate)
        score = int(overall.get("score") or 0)
        if overall.get("malicious"):
            status = EnrichmentStatus.MALICIOUS
        elif score > 0:
            status = EnrichmentStatus.SUSPICIOUS
        else:
            status = EnrichmentStatus.UNKNOWN
        return self.result(
            url,
            status,
            details={
                "uuid": uuid,
                "reused_existing_scan": reused,
                "verdict_score": score,
                "categories": overall.get("categories") or [],
                "brands": overall.get("brands") or [],
                "final_url": page.get("url"),
                "redirect_chain": chain,
                "page_title": page.get("title"),
                "page_ip": page.get("ip"),
                "page_country": page.get("country"),
                "screenshot_url": task.get("screenshotURL") or f"{SITE_URL}/screenshots/{uuid}.png",
                "login_form": await self._login_form(uuid),
            },
            link=task.get("reportURL") or f"{SITE_URL}/result/{uuid}/",
        )


def _redirects(data: dict[str, Any]) -> list[str]:
    """URLs the main document was redirected through (from the first request's redirect hops)."""
    requests = (data.get("data") or {}).get("requests") or []
    if not requests or not isinstance(requests[0], dict):
        return []
    hops = requests[0].get("requests") or []
    urls = []
    for hop in hops:
        hop_url = ((hop or {}).get("request") or {}).get("url")
        if hop_url:
            urls.append(str(hop_url))
    return urls
