"""Cached async DNS helper for TXT, MX, A, AAAA and PTR lookups.

All DNS lookups in PhishLens go through this module. Results are cached in memory and, when
``DNS_SQLITE_CACHE`` is on, in a SQLite file (``DNS_CACHE_PATH``) so repeated analyses do not hit
the network again. Lookups never raise: failures come back as ``DnsResult.error`` with one of
``nxdomain``, ``no_answer``, ``timeout``, ``no_nameservers``, ``unsupported_type`` or
``error: <details>``.

Only definitive answers (records, ``nxdomain``, ``no_answer``) are cached. Timeouts and other
errors are retried on the next call. Tests replace ``_query`` with ``monkeypatch``.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.resolver

from phishlens.config import get_settings

__all__ = [
    "DnsResult", "SUPPORTED_TYPES", "a", "aaaa", "clear_cache", "mx", "ptr", "resolve", "txt"
]

SUPPORTED_TYPES = frozenset({"TXT", "MX", "A", "AAAA", "PTR"})
CACHEABLE_ERRORS = frozenset({"nxdomain", "no_answer"})


@dataclass(frozen=True)
class DnsResult:
    """Answer for one ``(name, rdtype)`` lookup.

    ``records`` are strings: TXT records with their character-strings joined, MX records as
    ``"<preference> <exchange>"`` (sorted by preference), A/AAAA records as IP strings and PTR
    records as host names without the trailing dot.
    ``error`` is ``None`` on success. ``cached`` tells whether the answer came from the cache.
    """

    name: str
    rdtype: str
    records: list[str] = field(default_factory=list)
    error: str | None = None
    cached: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None


# (name, rdtype) -> (expires_at, result)
_memory: dict[tuple[str, str], tuple[float, DnsResult]] = {}


def clear_cache() -> None:
    """Empty the in-memory cache. The SQLite cache file is left as it is."""
    _memory.clear()


def _normalize(name: str) -> str:
    return name.strip().rstrip(".").lower()


async def _query(name: str, rdtype: str, timeout: float) -> list[str]:
    """Run the real lookup. Raises dnspython exceptions, which ``resolve`` turns into errors."""
    resolver = dns.asyncresolver.Resolver()
    answer = await resolver.resolve(name, rdtype, lifetime=timeout)
    if rdtype == "TXT":
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answer]
    if rdtype == "MX":
        mx_records = sorted(answer, key=lambda r: r.preference)
        return [f"{r.preference} {r.exchange.to_text(omit_final_dot=True)}" for r in mx_records]
    if rdtype == "PTR":
        return [r.target.to_text(omit_final_dot=True) for r in answer]
    return [r.to_text() for r in answer]


def _error_code(exc: Exception) -> str:
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return "nxdomain"
    if isinstance(exc, dns.resolver.NoAnswer):
        return "no_answer"
    if isinstance(exc, dns.exception.Timeout):
        return "timeout"
    if isinstance(exc, dns.resolver.NoNameservers):
        return "no_nameservers"
    return f"error: {type(exc).__name__}: {exc}"


def _sqlite_connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS dns_cache ("
        "name TEXT NOT NULL, rdtype TEXT NOT NULL, records TEXT NOT NULL, error TEXT, "
        "expires_at REAL NOT NULL, PRIMARY KEY (name, rdtype))"
    )
    return conn


def _sqlite_get(path: str, name: str, rdtype: str, now: float) -> DnsResult | None:
    try:
        with _sqlite_connect(path) as conn:
            row = conn.execute(
                "SELECT records, error, expires_at FROM dns_cache WHERE name = ? AND rdtype = ?",
                (name, rdtype),
            ).fetchone()
    except sqlite3.Error:
        return None
    if row is None or row[2] <= now:
        return None
    return DnsResult(name, rdtype, json.loads(row[0]), row[1], cached=True)


def _sqlite_put(path: str, result: DnsResult, expires_at: float) -> None:
    try:
        with _sqlite_connect(path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO dns_cache VALUES (?, ?, ?, ?, ?)",
                (result.name, result.rdtype, json.dumps(result.records), result.error, expires_at),
            )
    except sqlite3.Error:
        pass  # The cache is an optimization; a broken cache file must not break lookups.


async def resolve(name: str, rdtype: str) -> DnsResult:
    """Look up ``name`` for ``rdtype`` (see ``SUPPORTED_TYPES``), using the caches. Never raises."""
    name = _normalize(name)
    rdtype = rdtype.upper()
    if rdtype not in SUPPORTED_TYPES:
        return DnsResult(name, rdtype, error="unsupported_type")
    if not name:
        return DnsResult(name, rdtype, error="error: empty name")

    settings = get_settings()
    now = time.time()
    key = (name, rdtype)
    hit = _memory.get(key)
    if hit and hit[0] > now:
        return hit[1]
    sqlite_path = settings.dns_cache_path if settings.dns_sqlite_cache else None
    if sqlite_path:
        stored = _sqlite_get(sqlite_path, name, rdtype, now)
        if stored:
            _memory[key] = (now + settings.dns_cache_ttl_seconds, stored)
            return stored

    try:
        records = await _query(name, rdtype, settings.dns_timeout_seconds)
        result = DnsResult(name, rdtype, records)
    except Exception as exc:
        result = DnsResult(name, rdtype, error=_error_code(exc))

    if (result.ok or result.error in CACHEABLE_ERRORS) and settings.dns_cache_ttl_seconds > 0:
        expires_at = now + settings.dns_cache_ttl_seconds
        cached = DnsResult(name, rdtype, result.records, result.error, cached=True)
        _memory[key] = (expires_at, cached)
        if sqlite_path:
            _sqlite_put(sqlite_path, cached, expires_at)
    return result


async def txt(name: str) -> DnsResult:
    return await resolve(name, "TXT")


async def mx(name: str) -> DnsResult:
    return await resolve(name, "MX")


async def a(name: str) -> DnsResult:
    return await resolve(name, "A")


async def aaaa(name: str) -> DnsResult:
    return await resolve(name, "AAAA")


async def ptr(name: str) -> DnsResult:
    return await resolve(name, "PTR")
