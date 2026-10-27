"""RDAP client for domain registration dates (domain age), built on ``BaseClient``.

Queries go to the rdap.org bootstrap service, which redirects to the registry's own RDAP server.
Only the registered (organizational) domain is looked up. RDAP needs no API key; it still gets
the shared rate limiting, retries and cache (service name ``rdap``). Reserved names
(``.example``, ``.test``, ...) are never sent anywhere.

``RdapClient.domain`` returns a normalized ``EnrichmentResult`` (status ``unknown``: RDAP has
registration data, not a reputation verdict; the data is in ``details``). ``lookup_domain`` wraps
it in the ``RdapResult`` view used by the domain analyzer.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from phishlens.enrichment.base import BaseClient, EnrichmentError
from phishlens.enrichment.base import clear_cache as _clear_enrichment_cache
from phishlens.models import EnrichmentResult, EnrichmentStatus

__all__ = [
    "RDAP_BOOTSTRAP_URL",
    "RdapClient",
    "RdapResult",
    "clear_cache",
    "is_reserved",
    "lookup_domain",
]

RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/"

# RFC 2606 / RFC 6761 names that are never registered.
RESERVED_TLDS = frozenset({"example", "test", "invalid", "localhost", "local"})
RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org"})


@dataclass(frozen=True)
class RdapResult:
    """Registration data for one domain.

    ``status``: ``ok`` (record found), ``not_found`` (the registry has no such domain),
    ``reserved`` (a reserved name, not looked up), ``skipped`` (network disabled) or ``error``
    (``error`` says why).
    """

    domain: str
    status: str
    registered: datetime | None = None
    expires: datetime | None = None
    registrar: str | None = None
    error: str | None = None
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("registered", "expires"):
            data[key] = data[key].isoformat() if data[key] else None
        return data


def clear_cache() -> None:
    """Empty the in-memory enrichment cache (shared with the other clients)."""
    _clear_enrichment_cache()


def is_reserved(domain: str) -> bool:
    domain = domain.strip().rstrip(".").lower()
    return domain in RESERVED_DOMAINS or domain.rsplit(".", 1)[-1] in RESERVED_TLDS


def _parse_date(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _event(data: dict[str, Any], action: str) -> str | None:
    for event in data.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") == action:
            parsed = _parse_date(event.get("eventDate"))
            return parsed.isoformat() if parsed else None
    return None


def _registrar(data: dict[str, Any]) -> str | None:
    for entity in data.get("entities") or []:
        if not isinstance(entity, dict) or "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                    return str(item[3])
        return entity.get("handle")
    return None


class RdapClient(BaseClient):
    service = "rdap"
    requires_key = False

    def normalize(self, kind: str, query: str) -> str:
        return query.strip().rstrip(".").lower()

    async def domain(self, domain: str) -> EnrichmentResult:
        """Registration data for a registered domain. Never raises."""
        return await self.cached_lookup("domain", domain, self._fetch_domain)

    async def _fetch_domain(self, domain: str) -> EnrichmentResult:
        response = await self.request(
            "GET", RDAP_BOOTSTRAP_URL + domain, headers={"Accept": "application/rdap+json"}
        )
        if response.status_code == 404:
            return self.result(domain, EnrichmentStatus.UNKNOWN, details={"rdap": "not_found"})
        if response.status_code != 200:
            raise EnrichmentError(f"HTTP {response.status_code}")
        data = response.json()
        if not isinstance(data, dict):
            raise EnrichmentError("unexpected RDAP response")
        return self.result(
            domain,
            EnrichmentStatus.UNKNOWN,
            details={
                "rdap": "ok",
                "registered": _event(data, "registration"),
                "expires": _event(data, "expiration"),
                "registrar": _registrar(data),
            },
            link=str(response.url),
        )


async def lookup_domain(domain: str) -> RdapResult:
    """Look up the registration data of ``domain`` (a registered domain). Never raises."""
    domain = domain.strip().rstrip(".").lower()
    if not domain or is_reserved(domain):
        return RdapResult(domain, "reserved")
    async with RdapClient() as client:
        result = await client.domain(domain)
    if result.status == EnrichmentStatus.ERROR:
        return RdapResult(domain, "error", error=result.error)
    if result.status == EnrichmentStatus.NOT_CONFIGURED:
        return RdapResult(domain, "skipped")
    details = result.details
    if details.get("rdap") == "not_found":
        return RdapResult(domain, "not_found", cached=result.cached)
    return RdapResult(
        domain,
        "ok",
        registered=_parse_date(details.get("registered")),
        expires=_parse_date(details.get("expires")),
        registrar=details.get("registrar"),
        cached=result.cached,
    )
