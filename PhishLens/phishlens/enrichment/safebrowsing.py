"""Google Safe Browsing v4 Lookup API (``threatMatches:find``), with batching.

Up to ``MAX_URLS_PER_REQUEST`` (500) URLs go in one request; each URL is cached on its own. The
API key travels as the ``key`` query parameter (Google's only option), so it is scrubbed from
every error message by the base client. A match is ``malicious``; no match is ``unknown``
(Safe Browsing is a blocklist, so absence does not prove a URL safe).
"""

from __future__ import annotations

from urllib.parse import quote

from phishlens import __version__
from phishlens.enrichment.base import BaseClient, EnrichmentError
from phishlens.models import EnrichmentResult, EnrichmentStatus

__all__ = ["API_URL", "MAX_URLS_PER_REQUEST", "THREAT_TYPES", "SafeBrowsingClient"]

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
MAX_URLS_PER_REQUEST = 500
THREAT_TYPES = (
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
)
REPORT_URL = "https://transparencyreport.google.com/safe-browsing/search?url="


class SafeBrowsingClient(BaseClient):
    service = "google_safebrowsing"

    async def url(self, url: str) -> EnrichmentResult:
        return (await self.urls([url]))[url]

    async def urls(self, urls: list[str]) -> dict[str, EnrichmentResult]:
        """Check many URLs; returns ``{url: result}`` for every URL given. Never raises."""
        return await self.batch_lookup("url", urls, self._fetch_batch, MAX_URLS_PER_REQUEST)

    async def _fetch_batch(self, urls: list[str]) -> dict[str, EnrichmentResult]:
        key = self.settings.google_safebrowsing_api_key
        body = {
            "client": {"clientId": "phishlens", "clientVersion": __version__},
            "threatInfo": {
                "threatTypes": list(THREAT_TYPES),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls],
            },
        }
        response = await self.request(
            "POST",
            API_URL,
            params={"key": key.get_secret_value() if key else ""},
            json=body,
        )
        if response.status_code != 200:
            raise EnrichmentError(f"HTTP {response.status_code}")
        matches: dict[str, set[str]] = {}
        for match in response.json().get("matches") or []:
            matched_url = (match.get("threat") or {}).get("url")
            if matched_url:
                matches.setdefault(matched_url, set()).add(str(match.get("threatType")))
        results = {}
        for u in urls:
            threats = sorted(matches.get(u, ()))
            results[u] = self.result(
                u,
                EnrichmentStatus.MALICIOUS if threats else EnrichmentStatus.UNKNOWN,
                detections=len(threats),
                details={"threat_types": threats},
                link=REPORT_URL + quote(u, safe=""),
            )
        return results
