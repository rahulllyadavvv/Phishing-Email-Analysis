"""Shared machinery for every external threat-intel / HTTP client.

``BaseClient`` gives each service:

- **Not configured → no network.** A service whose API key is missing returns an
  ``EnrichmentResult`` with status ``not_configured`` without sending anything.
- **Rate limiting.** A token bucket per service (``Settings.rate_limit``), shared by every client
  instance in the process. Callers wait for a token instead of failing.
- **Retries.** HTTP 429, 5xx, timeouts and connection errors are retried up to
  ``ENRICHMENT_MAX_RETRIES`` times with exponential backoff and jitter. ``Retry-After`` is
  honoured (capped at ``MAX_RETRY_AFTER_SECONDS``).
- **Caching.** Normalized results (never raw responses) are cached in memory and in a SQLite
  file (``ENRICHMENT_CACHE_PATH``) for ``Settings.cache_ttl(service)`` seconds. Errors and
  ``not_configured`` results are never cached.
- **Key safety.** Error messages are scrubbed of every configured secret before they are stored
  or logged; log lines never contain URLs.

A client subclass sets ``service`` (the name used by ``Settings.is_enabled``, rate limits and
cache TTLs) and implements lookups as ``await self.cached_lookup(kind, query, fetch)``, where
``fetch`` performs the request(s) with ``self.request`` and returns an ``EnrichmentResult``.
"""

from __future__ import annotations

import asyncio
import logging
import random
import sqlite3
import time
from collections.abc import Awaitable, Callable
from typing import Any, ClassVar

import httpx

from phishlens.config import Settings, get_settings
from phishlens.models import EnrichmentResult, EnrichmentStatus

__all__ = [
    "MAX_RETRY_AFTER_SECONDS",
    "USER_AGENT",
    "BaseClient",
    "EnrichmentError",
    "RateLimiter",
    "clear_cache",
    "get_limiter",
    "redact",
    "reset_limiters",
]

logger = logging.getLogger("phishlens.enrichment")

USER_AGENT = "PhishLens/0.1 (phishing email analysis)"
MAX_RETRY_AFTER_SECONDS = 60.0
BACKOFF_BASE_SECONDS = 1.0
UNCACHED = frozenset({EnrichmentStatus.ERROR, EnrichmentStatus.NOT_CONFIGURED})


async def _sleep(seconds: float) -> None:
    """Indirection so tests can replace every wait in this module."""
    await asyncio.sleep(seconds)


class EnrichmentError(Exception):
    """A lookup failed (after retries). The message must not contain secrets."""


def redact(text: str, settings: Settings | None = None) -> str:
    """Replace every configured secret in ``text`` with ``***``."""
    for secret in (settings or get_settings()).secret_values():
        text = text.replace(secret, "***")
    return text


# --- Rate limiting -------------------------------------------------------------------------------


class RateLimiter:
    """Token bucket: ``capacity`` requests per ``period`` seconds, starting full.

    ``acquire`` never holds a lock across an ``await``: it takes a token (letting the balance go
    negative to queue behind earlier callers) and then sleeps until that token has refilled.
    """

    def __init__(
        self, capacity: int, period: float, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.capacity = capacity
        self.rate = capacity / period
        self._clock = clock
        self._tokens = float(capacity)
        self._updated = clock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
        self._updated = now

    async def acquire(self) -> float:
        """Wait for one request slot. Returns the time waited in seconds."""
        self._refill()
        self._tokens -= 1
        if self._tokens >= 0:
            return 0.0
        wait = -self._tokens / self.rate
        await _sleep(wait)
        return wait


_limiters: dict[str, RateLimiter] = {}


def get_limiter(service: str) -> RateLimiter:
    """The process-wide limiter for ``service``, created from the settings on first use."""
    limiter = _limiters.get(service)
    if limiter is None:
        limiter = _limiters[service] = RateLimiter(*get_settings().rate_limit(service))
    return limiter


def reset_limiters() -> None:
    _limiters.clear()


# --- Cache ---------------------------------------------------------------------------------------

# key -> (expires_at, result json)
_memory: dict[str, tuple[float, str]] = {}


def clear_cache() -> None:
    """Empty the in-memory cache. The SQLite file is left as it is."""
    _memory.clear()


def _cache_key(service: str, kind: str, query: str) -> str:
    return f"{service}:{kind}:{query}"


def _sqlite(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS enrichment_cache ("
        "key TEXT PRIMARY KEY, result TEXT NOT NULL, expires_at REAL NOT NULL)"
    )
    return conn


def _cache_get(settings: Settings, key: str, now: float) -> EnrichmentResult | None:
    hit = _memory.get(key)
    if hit is None and settings.enrichment_cache:
        try:
            with _sqlite(settings.enrichment_cache_path) as conn:
                row = conn.execute(
                    "SELECT expires_at, result FROM enrichment_cache WHERE key = ?", (key,)
                ).fetchone()
        except sqlite3.Error:
            row = None
        if row is not None:
            hit = (row[0], row[1])
            _memory[key] = hit
    if hit is None or hit[0] <= now:
        return None
    try:
        result = EnrichmentResult.model_validate_json(hit[1])
    except ValueError:
        return None  # an entry from an older format: treat as a miss
    return result.model_copy(update={"cached": True})


def _cache_put(settings: Settings, key: str, result: EnrichmentResult, expires_at: float) -> None:
    data = result.model_copy(update={"cached": False}).model_dump_json()
    _memory[key] = (expires_at, data)
    if not settings.enrichment_cache:
        return
    try:
        with _sqlite(settings.enrichment_cache_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO enrichment_cache VALUES (?, ?, ?)",
                (key, data, expires_at),
            )
    except sqlite3.Error:
        pass  # the cache is an optimization; a broken file must not break lookups


# --- Client --------------------------------------------------------------------------------------


class BaseClient:
    """Base class for enrichment clients. Use as ``async with Client() as c: ...``."""

    service: ClassVar[str]
    requires_key: ClassVar[bool] = True

    def __init__(
        self,
        settings: Settings | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    # -- lifecycle --

    async def __aenter__(self) -> BaseClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.settings.enrichment_timeout_seconds,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
                transport=self._transport,
            )
        return self._client

    # -- configuration --

    @property
    def enabled(self) -> bool:
        return not self.requires_key or self.settings.is_enabled(self.service)

    def normalize(self, kind: str, query: str) -> str:
        """Normalize a query for caching. Override per service (e.g. lowercase domains)."""
        return query.strip()

    # -- HTTP --

    def _backoff(self, attempt: int, response: httpx.Response | None) -> float:
        if response is not None:
            retry_after = response.headers.get("Retry-After", "")
            if retry_after.strip().isdigit():
                return min(float(retry_after), MAX_RETRY_AFTER_SECONDS)
        return BACKOFF_BASE_SECONDS * 2**attempt + random.uniform(0, BACKOFF_BASE_SECONDS / 2)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Send a request with rate limiting and retries.

        Returns the response for any status other than 429/5xx (the caller interprets 4xx).
        Raises ``EnrichmentError`` (secret-free message) when every attempt failed.
        """
        attempts = self.settings.enrichment_max_retries + 1
        limiter = get_limiter(self.service)
        problem = ""
        for attempt in range(attempts):
            await limiter.acquire()
            response: httpx.Response | None = None
            try:
                response = await self._http().request(method, url, **kwargs)
            except httpx.TransportError as exc:  # timeouts, connection errors
                problem = f"{type(exc).__name__}: {redact(str(exc), self.settings)}"
            else:
                if response.status_code != 429 and response.status_code < 500:
                    return response
                problem = f"HTTP {response.status_code}"
            if attempt + 1 < attempts:
                delay = self._backoff(attempt, response)
                logger.info(
                    "%s: %s, retry %d/%d in %.1fs",
                    self.service,
                    problem,
                    attempt + 1,
                    attempts - 1,
                    delay,
                )
                await _sleep(delay)
        raise EnrichmentError(f"{problem} (after {attempts} attempts)")

    # -- lookups --

    def result(self, query: str, status: EnrichmentStatus, **fields: Any) -> EnrichmentResult:
        return EnrichmentResult(service=self.service, query=query, status=status, **fields)

    async def cached_lookup(
        self,
        kind: str,
        query: str,
        fetch: Callable[[str], Awaitable[EnrichmentResult]],
    ) -> EnrichmentResult:
        """Run ``fetch(normalized_query)`` behind the not-configured check and the cache.

        ``kind`` separates lookup types of one service in the cache (url, domain, hash, ...).
        Never raises: failures come back with status ``error`` and a secret-free message.
        """
        normalized = self.normalize(kind, query)
        if not self.enabled:
            return self.result(normalized, EnrichmentStatus.NOT_CONFIGURED)
        key = _cache_key(self.service, kind, normalized)
        now = time.time()
        cached = _cache_get(self.settings, key, now)
        if cached is not None:
            return cached
        try:
            result = await fetch(normalized)
        except Exception as exc:
            message = str(exc)
            if not isinstance(exc, EnrichmentError):
                message = f"{type(exc).__name__}: {message}"
            message = redact(message, self.settings)
            logger.warning("%s %s lookup failed: %s", self.service, kind, message)
            return self.result(normalized, EnrichmentStatus.ERROR, error=message)
        ttl = self.settings.cache_ttl(self.service)
        if result.status not in UNCACHED and ttl > 0:
            _cache_put(self.settings, key, result, now + ttl)
        return result

    async def batch_lookup(
        self,
        kind: str,
        queries: list[str],
        fetch_many: Callable[[list[str]], Awaitable[dict[str, EnrichmentResult]]],
        batch_size: int,
    ) -> dict[str, EnrichmentResult]:
        """Like ``cached_lookup`` for many queries: cached ones are answered from the cache, the
        rest are fetched ``batch_size`` at a time with ``fetch_many(normalized_queries)``, which
        returns a result per query. Keys of the returned dict are the queries as given.
        Never raises: a failed batch gives every query in it status ``error``.
        """
        normalized = {q: self.normalize(kind, q) for q in queries}
        if not self.enabled:
            return {
                q: self.result(n, EnrichmentStatus.NOT_CONFIGURED) for q, n in normalized.items()
            }
        now = time.time()
        found: dict[str, EnrichmentResult] = {}
        missing: list[str] = []
        for norm in dict.fromkeys(normalized.values()):
            cached = _cache_get(self.settings, _cache_key(self.service, kind, norm), now)
            if cached is not None:
                found[norm] = cached
            else:
                missing.append(norm)
        ttl = self.settings.cache_ttl(self.service)
        for start in range(0, len(missing), batch_size):
            chunk = missing[start : start + batch_size]
            try:
                results = await fetch_many(chunk)
            except Exception as exc:
                message = str(exc)
                if not isinstance(exc, EnrichmentError):
                    message = f"{type(exc).__name__}: {message}"
                message = redact(message, self.settings)
                logger.warning("%s %s batch lookup failed: %s", self.service, kind, message)
                results = {
                    n: self.result(n, EnrichmentStatus.ERROR, error=message) for n in chunk
                }
            for norm in chunk:
                result = results.get(norm) or self.result(
                    norm, EnrichmentStatus.ERROR, error="missing from batch response"
                )
                found[norm] = result
                if result.status not in UNCACHED and ttl > 0:
                    _cache_put(
                        self.settings, _cache_key(self.service, kind, norm), result, now + ttl
                    )
        return {q: found[n] for q, n in normalized.items()}
