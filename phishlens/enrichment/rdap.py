"""Minimal RDAP client for domain registration dates (domain age).

Queries go to the rdap.org bootstrap service, which redirects to the registry's own RDAP server.
Only the registered (organizational) domain is looked up. Results are cached in memory for
``RDAP_CACHE_TTL_SECONDS``; definitive answers (found / not found) are cached, errors are not.
Reserved names (``.example``, ``.test``, ...) are never sent anywhere.

Phase 4 will move this onto the shared base client (rate limiting, persistent cache).
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

import httpx

from phishlens.config import get_settings

__all__ = ["RDAP_BOOTSTRAP_URL", "RdapResult", "clear_cache", "is_reserved", "lookup_domain"]

RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/"
USER_AGENT = "PhishLens/0.1 (+phishing analysis; RDAP lookup)"

# RFC 2606 / RFC 6761 names that are never registered.
RESERVED_TLDS = frozenset({"example", "test", "invalid", "localhost", "local"})
RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org"})


@dataclass(frozen=True)
class RdapResult:
    """Registration data for one domain.

    ``status``: ``ok`` (record found), ``not_found`` (the registry has no such domain),
    ``reserved`` (a reserved name, not looked up) or ``error`` (``error`` says why).
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


# domain -> (expires_at, result)
_cache: dict[str, tuple[float, RdapResult]] = {}


def clear_cache() -> None:
    _cache.clear()


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


def _event(data: dict[str, Any], action: str) -> datetime | None:
    for event in data.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") == action:
            return _parse_date(event.get("eventDate"))
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


async def _fetch(domain: str, timeout: float) -> RdapResult:
    headers = {"Accept": "application/rdap+json", "User-Agent": USER_AGENT}
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        response = await client.get(RDAP_BOOTSTRAP_URL + domain, headers=headers)
    if response.status_code == 404:
        return RdapResult(domain, "not_found")
    if response.status_code != 200:
        return RdapResult(domain, "error", error=f"HTTP {response.status_code}")
    data = response.json()
    if not isinstance(data, dict):
        return RdapResult(domain, "error", error="unexpected RDAP response")
    return RdapResult(
        domain,
        "ok",
        registered=_event(data, "registration"),
        expires=_event(data, "expiration"),
        registrar=_registrar(data),
    )


async def lookup_domain(domain: str) -> RdapResult:
    """Look up the registration data of ``domain`` (a registered domain). Never raises."""
    domain = domain.strip().rstrip(".").lower()
    if not domain or is_reserved(domain):
        return RdapResult(domain, "reserved")
    now = time.time()
    hit = _cache.get(domain)
    if hit and hit[0] > now:
        return hit[1]
    settings = get_settings()
    try:
        result = await _fetch(domain, settings.rdap_timeout_seconds)
    except (httpx.HTTPError, ValueError) as exc:
        result = RdapResult(domain, "error", error=f"{type(exc).__name__}: {exc}")
    if result.status in ("ok", "not_found") and settings.rdap_cache_ttl_seconds > 0:
        cached = RdapResult(**{**asdict(result), "cached": True})
        _cache[domain] = (now + settings.rdap_cache_ttl_seconds, cached)
    return result
