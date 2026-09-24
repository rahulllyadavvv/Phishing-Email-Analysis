"""VirusTotal API v3 client: URL, file hash, domain and IP reputation, and opt-in file upload.

Lookups are by identifier only (URL string, hash, domain, IP). A file is uploaded only when
``UPLOAD_FILES_TO_VT=true``; otherwise ``upload_file`` returns ``not_configured`` without any
network call.

``last_analysis_stats`` is mapped to the normalized status: ``malicious`` when at least
``VT_MALICIOUS_THRESHOLD`` engines say malicious, ``suspicious`` when any engine says malicious
or suspicious, ``clean`` when engines ran and none did, ``unknown`` when VirusTotal has no
record (HTTP 404) or no engine ran.
"""

from __future__ import annotations

import base64
from typing import Any

from phishlens.enrichment.base import BaseClient, EnrichmentError
from phishlens.models import EnrichmentResult, EnrichmentStatus

__all__ = ["API_URL", "GUI_URL", "MAX_UPLOAD_BYTES", "VirusTotalClient", "url_id"]

API_URL = "https://www.virustotal.com/api/v3"
GUI_URL = "https://www.virustotal.com/gui"
MAX_UPLOAD_BYTES = 32 * 1024 * 1024  # larger files need the separate upload_url endpoint

# kind -> (API collection, GUI path)
_PATHS = {
    "url": ("urls", "url"),
    "file": ("files", "file"),
    "domain": ("domains", "domain"),
    "ip": ("ip_addresses", "ip-address"),
}

# Attributes copied into ``details`` per kind, when present.
_DETAIL_FIELDS = {
    "url": ("last_final_url", "title", "categories", "tags"),
    "file": (
        "meaningful_name",
        "type_description",
        "size",
        "names",
        "tags",
        "popular_threat_classification",
    ),
    "domain": ("categories", "creation_date", "registrar", "tags"),
    "ip": ("country", "as_owner", "asn", "network", "tags"),
}


def url_id(url: str) -> str:
    """VirusTotal's identifier for a URL: unpadded base64url of the URL."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


class VirusTotalClient(BaseClient):
    service = "virustotal"

    def normalize(self, kind: str, query: str) -> str:
        query = query.strip()
        if kind in ("file", "domain"):
            return query.rstrip(".").lower()
        return query

    def _headers(self) -> dict[str, str]:
        key = self.settings.virustotal_api_key
        return {"x-apikey": key.get_secret_value() if key else "", "Accept": "application/json"}

    # -- lookups --

    async def url(self, url: str) -> EnrichmentResult:
        return await self.cached_lookup("url", url, lambda q: self._fetch("url", q, url_id(q)))

    async def file(self, file_hash: str) -> EnrichmentResult:
        """Look up a file by MD5, SHA-1 or SHA-256 (never uploads)."""
        return await self.cached_lookup("file", file_hash, lambda q: self._fetch("file", q, q))

    async def domain(self, domain: str) -> EnrichmentResult:
        return await self.cached_lookup("domain", domain, lambda q: self._fetch("domain", q, q))

    async def ip(self, ip: str) -> EnrichmentResult:
        return await self.cached_lookup("ip", ip, lambda q: self._fetch("ip", q, q))

    def _status(self, stats: dict[str, Any]) -> EnrichmentStatus:
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        if malicious >= self.settings.vt_malicious_threshold:
            return EnrichmentStatus.MALICIOUS
        if malicious or suspicious:
            return EnrichmentStatus.SUSPICIOUS
        if sum(int(v or 0) for v in stats.values() if isinstance(v, int | float)):
            return EnrichmentStatus.CLEAN
        return EnrichmentStatus.UNKNOWN

    async def _fetch(self, kind: str, query: str, identifier: str) -> EnrichmentResult:
        collection, gui_path = _PATHS[kind]
        link = f"{GUI_URL}/{gui_path}/{identifier}"
        response = await self.request(
            "GET", f"{API_URL}/{collection}/{identifier}", headers=self._headers()
        )
        if response.status_code == 404:
            return self.result(query, EnrichmentStatus.UNKNOWN, details={"found": False})
        if response.status_code != 200:
            raise EnrichmentError(f"HTTP {response.status_code}")
        attributes = (response.json().get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        details: dict[str, Any] = {
            "found": True,
            "stats": stats,
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }
        for name in _DETAIL_FIELDS[kind]:
            if name in attributes:
                details[name] = attributes[name]
        return self.result(
            query,
            self._status(stats),
            detections=int(stats.get("malicious") or 0),
            total_engines=sum(int(v) for v in stats.values() if isinstance(v, int)),
            details=details,
            link=link,
        )

    # -- upload --

    async def upload_file(self, data: bytes, filename: str, sha256: str) -> EnrichmentResult:
        """Submit a file for analysis, only when ``UPLOAD_FILES_TO_VT=true``. Never raises.

        Returns status ``unknown`` with the analysis id: the verdict comes later from ``file``.
        """
        sha256 = sha256.strip().lower()
        if not self.settings.upload_files_to_vt:
            return self.result(
                sha256,
                EnrichmentStatus.NOT_CONFIGURED,
                details={"reason": "uploads disabled (UPLOAD_FILES_TO_VT=false)"},
            )
        if not self.enabled:
            return self.result(sha256, EnrichmentStatus.NOT_CONFIGURED)
        if len(data) > MAX_UPLOAD_BYTES:
            return self.result(
                sha256, EnrichmentStatus.ERROR, error="file larger than 32 MB, not uploaded"
            )
        try:
            response = await self.request(
                "POST",
                f"{API_URL}/files",
                headers=self._headers(),
                files={"file": (filename or sha256, data)},
            )
            if response.status_code != 200:
                raise EnrichmentError(f"HTTP {response.status_code}")
            analysis_id = (response.json().get("data") or {}).get("id")
        except Exception as exc:
            message = str(exc) if isinstance(exc, EnrichmentError) else type(exc).__name__
            return self.result(sha256, EnrichmentStatus.ERROR, error=message)
        return self.result(
            sha256,
            EnrichmentStatus.UNKNOWN,
            details={"uploaded": True, "analysis_id": analysis_id},
            link=f"{GUI_URL}/file/{sha256}",
        )
