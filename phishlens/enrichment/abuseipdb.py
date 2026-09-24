"""AbuseIPDB v2 client: IP reputation (abuse confidence score, ISP, country, usage type).

Status from the abuse confidence score (0-100): ``malicious`` from ``MALICIOUS_SCORE``,
``suspicious`` from ``SUSPICIOUS_SCORE``, otherwise ``clean``. Whitelisted IPs are ``clean``.
"""

from __future__ import annotations

from phishlens.enrichment.base import BaseClient, EnrichmentError
from phishlens.models import EnrichmentResult, EnrichmentStatus

__all__ = ["API_URL", "MALICIOUS_SCORE", "MAX_AGE_DAYS", "SUSPICIOUS_SCORE", "AbuseIpdbClient"]

API_URL = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_DAYS = 90
MALICIOUS_SCORE = 75
SUSPICIOUS_SCORE = 25


class AbuseIpdbClient(BaseClient):
    service = "abuseipdb"

    async def ip(self, ip: str) -> EnrichmentResult:
        return await self.cached_lookup("ip", ip, self._fetch)

    async def _fetch(self, ip: str) -> EnrichmentResult:
        key = self.settings.abuseipdb_api_key
        response = await self.request(
            "GET",
            API_URL,
            params={"ipAddress": ip, "maxAgeInDays": MAX_AGE_DAYS},
            headers={"Key": key.get_secret_value() if key else "", "Accept": "application/json"},
        )
        if response.status_code != 200:
            raise EnrichmentError(f"HTTP {response.status_code}")
        data = response.json().get("data") or {}
        score = int(data.get("abuseConfidenceScore") or 0)
        if data.get("isWhitelisted"):
            status = EnrichmentStatus.CLEAN
        elif score >= MALICIOUS_SCORE:
            status = EnrichmentStatus.MALICIOUS
        elif score >= SUSPICIOUS_SCORE:
            status = EnrichmentStatus.SUSPICIOUS
        else:
            status = EnrichmentStatus.CLEAN
        return self.result(
            ip,
            status,
            details={
                "abuse_confidence_score": score,
                "total_reports": data.get("totalReports"),
                "isp": data.get("isp"),
                "country": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "domain": data.get("domain"),
                "is_whitelisted": data.get("isWhitelisted"),
                "last_reported_at": data.get("lastReportedAt"),
            },
            link=f"https://www.abuseipdb.com/check/{ip}",
        )
