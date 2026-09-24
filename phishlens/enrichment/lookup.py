"""Reputation lookups that query several services in a fixed order and stop early.

Free or generous services go first, VirusTotal (tight free quota) last:

- URLs: Google Safe Browsing -> URLhaus -> VirusTotal
- File hashes: MalwareBazaar -> VirusTotal

The chain stops at the first ``malicious`` result. Otherwise every service is asked, so
VirusTotal is only used when the earlier ones had nothing (unknown, error or not configured).
All results, including ``not_configured`` ones, are returned in query order so reports can show
what was checked.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from phishlens.enrichment.abusech import AbuseChClient
from phishlens.enrichment.safebrowsing import SafeBrowsingClient
from phishlens.enrichment.virustotal import VirusTotalClient
from phishlens.models import EnrichmentResult, EnrichmentStatus

__all__ = ["hash_reputation", "url_reputation"]

Step = Callable[[], Awaitable[EnrichmentResult]]


async def _chain(steps: list[Step]) -> list[EnrichmentResult]:
    results: list[EnrichmentResult] = []
    for step in steps:
        result = await step()
        results.append(result)
        if result.status == EnrichmentStatus.MALICIOUS:
            break
    return results


async def url_reputation(url: str) -> list[EnrichmentResult]:
    """Safe Browsing, then URLhaus, then VirusTotal; stops at the first malicious result."""
    async with SafeBrowsingClient() as gsb, AbuseChClient() as abusech, VirusTotalClient() as vt:
        return await _chain(
            [lambda: gsb.url(url), lambda: abusech.urlhaus_url(url), lambda: vt.url(url)]
        )


async def hash_reputation(sha256: str) -> list[EnrichmentResult]:
    """MalwareBazaar, then VirusTotal; stops at the first malicious result."""
    async with AbuseChClient() as abusech, VirusTotalClient() as vt:
        return await _chain([lambda: abusech.malwarebazaar_hash(sha256), lambda: vt.file(sha256)])
