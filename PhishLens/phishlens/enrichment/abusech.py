"""abuse.ch clients: URLhaus (URLs), MalwareBazaar (file hashes) and ThreatFox (any IOC).

All three use one ``ABUSECH_API_KEY``, sent as the ``Auth-Key`` header. They are blocklists:
a listed entry is ``malicious`` (ThreatFox: ``suspicious`` when its confidence is below
``THREATFOX_MALICIOUS_CONFIDENCE``), and "not listed" is ``unknown``, never ``clean``.
"""

from __future__ import annotations

from typing import Any

from phishlens.enrichment.base import BaseClient, EnrichmentError
from phishlens.models import EnrichmentResult, EnrichmentStatus

__all__ = [
    "MALWAREBAZAAR_API",
    "THREATFOX_API",
    "THREATFOX_MALICIOUS_CONFIDENCE",
    "URLHAUS_API",
    "AbuseChClient",
]

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_MALICIOUS_CONFIDENCE = 50

# query_status values meaning "looked up fine, nothing listed".
_NOT_LISTED = frozenset({"no_results", "no_result", "hash_not_found"})


class AbuseChClient(BaseClient):
    service = "abusech"

    def normalize(self, kind: str, query: str) -> str:
        query = query.strip()
        return query.lower() if kind == "hash" else query

    def _headers(self) -> dict[str, str]:
        key = self.settings.abusech_api_key
        return {"Auth-Key": key.get_secret_value() if key else ""}

    async def _post(self, url: str, **kwargs: Any) -> dict[str, Any]:
        response = await self.request("POST", url, headers=self._headers(), **kwargs)
        if response.status_code != 200:
            raise EnrichmentError(f"HTTP {response.status_code}")
        data = response.json()
        if not isinstance(data, dict):
            raise EnrichmentError("unexpected response")
        return data

    def _unlisted_or_error(self, query: str, data: dict[str, Any], source: str) -> EnrichmentResult:
        status = str(data.get("query_status"))
        if status in _NOT_LISTED:
            return self.result(query, EnrichmentStatus.UNKNOWN, details={"source": source})
        raise EnrichmentError(f"{source} query_status {status}")

    # -- URLhaus --

    async def urlhaus_url(self, url: str) -> EnrichmentResult:
        return await self.cached_lookup("urlhaus_url", url, self._fetch_urlhaus)

    async def _fetch_urlhaus(self, url: str) -> EnrichmentResult:
        data = await self._post(URLHAUS_API, data={"url": url})
        if data.get("query_status") != "ok":
            return self._unlisted_or_error(url, data, "urlhaus")
        return self.result(
            url,
            EnrichmentStatus.MALICIOUS,
            details={
                "source": "urlhaus",
                "url_status": data.get("url_status"),
                "threat": data.get("threat"),
                "tags": data.get("tags") or [],
                "date_added": data.get("date_added"),
            },
            link=data.get("urlhaus_reference"),
        )

    # -- MalwareBazaar --

    async def malwarebazaar_hash(self, file_hash: str) -> EnrichmentResult:
        return await self.cached_lookup("hash", file_hash, self._fetch_malwarebazaar)

    async def _fetch_malwarebazaar(self, file_hash: str) -> EnrichmentResult:
        data = await self._post(MALWAREBAZAAR_API, data={"query": "get_info", "hash": file_hash})
        entries = data.get("data")
        if data.get("query_status") != "ok" or not isinstance(entries, list) or not entries:
            return self._unlisted_or_error(file_hash, data, "malwarebazaar")
        entry = entries[0] if isinstance(entries[0], dict) else {}
        sha256 = entry.get("sha256_hash") or file_hash
        return self.result(
            file_hash,
            EnrichmentStatus.MALICIOUS,
            details={
                "source": "malwarebazaar",
                "sha256": sha256,
                "signature": entry.get("signature"),
                "file_type": entry.get("file_type"),
                "file_name": entry.get("file_name"),
                "tags": entry.get("tags") or [],
                "first_seen": entry.get("first_seen"),
            },
            link=f"https://bazaar.abuse.ch/sample/{sha256}/",
        )

    # -- ThreatFox --

    async def threatfox_ioc(self, ioc: str) -> EnrichmentResult:
        """Search any IOC (domain, IP:port, URL, hash)."""
        return await self.cached_lookup("threatfox_ioc", ioc, self._fetch_threatfox)

    async def _fetch_threatfox(self, ioc: str) -> EnrichmentResult:
        data = await self._post(THREATFOX_API, json={"query": "search_ioc", "search_term": ioc})
        entries = data.get("data")
        if data.get("query_status") != "ok" or not isinstance(entries, list) or not entries:
            return self._unlisted_or_error(ioc, data, "threatfox")
        entries = [e for e in entries if isinstance(e, dict)]
        confidence = max((int(e.get("confidence_level") or 0) for e in entries), default=0)
        best = max(entries, key=lambda e: int(e.get("confidence_level") or 0), default={})
        status = (
            EnrichmentStatus.MALICIOUS
            if confidence >= THREATFOX_MALICIOUS_CONFIDENCE
            else EnrichmentStatus.SUSPICIOUS
        )
        return self.result(
            ioc,
            status,
            detections=len(entries),
            details={
                "source": "threatfox",
                "confidence": confidence,
                "threat_types": sorted({str(e.get("threat_type")) for e in entries}),
                "malware": sorted({str(e.get("malware_printable")) for e in entries}),
                "tags": sorted({t for e in entries for t in (e.get("tags") or [])}),
            },
            link=f"https://threatfox.abuse.ch/ioc/{best.get('id')}/" if best.get("id") else None,
        )
