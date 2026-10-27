"""API security: API-key authentication and a per-client upload rate limit.

- ``require_api_key``: every endpoint except ``/api/health`` needs the header
  ``X-API-Key: <PHISHLENS_API_KEY>`` (compared in constant time). When no key is configured,
  authentication is off (local use); ``/api/health`` says which mode is active.
- ``upload_limit``: at most ``UPLOAD_RATE_LIMIT`` uploads (``count/seconds``) per client IP, in
  a sliding window kept in memory (per API process). Over the limit: 429 with ``Retry-After``.
"""

from __future__ import annotations

import math
import secrets
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request
from fastapi.security import APIKeyHeader

from phishlens.config import get_settings

__all__ = [
    "API_KEY_HEADER",
    "OPEN_PATHS",
    "UploadRateLimiter",
    "auth_enabled",
    "require_api_key",
    "upload_limit",
    "upload_limiter",
]

API_KEY_HEADER = "X-API-Key"
OPEN_PATHS = frozenset({"/api/health"})
_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)


def auth_enabled() -> bool:
    key = get_settings().phishlens_api_key
    return bool(key and key.get_secret_value().strip())


async def require_api_key(request: Request) -> None:
    """FastAPI dependency: reject requests without the right X-API-Key (401)."""
    if request.url.path in OPEN_PATHS or not auth_enabled():
        return
    supplied = await _header(request) or ""
    expected = get_settings().phishlens_api_key.get_secret_value()  # type: ignore[union-attr]
    if not secrets.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(
            401, "missing or invalid API key", headers={"WWW-Authenticate": API_KEY_HEADER}
        )


class UploadRateLimiter:
    """Sliding-window counter per client, thread-safe."""

    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, client: str, count: int, seconds: int, cost: int = 1) -> float | None:
        """Record ``cost`` uploads; return None when allowed, else seconds to wait."""
        if count <= 0:
            return None
        now = self._clock()
        with self._lock:
            hits = self._hits[client]
            while hits and hits[0] <= now - seconds:
                hits.popleft()
            if len(hits) + cost > count:
                oldest = hits[0] if hits else now
                return max(1.0, oldest + seconds - now)
            hits.extend([now] * cost)
            return None

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


upload_limiter = UploadRateLimiter()


async def upload_limit(request: Request) -> None:
    """FastAPI dependency for upload endpoints (one upload request counts once)."""
    count, _, seconds = get_settings().upload_rate_limit.partition("/")
    client = request.client.host if request.client else "unknown"
    wait = upload_limiter.check(client, int(count), int(seconds))
    if wait is not None:
        raise HTTPException(
            429,
            f"too many uploads from this address; try again in {math.ceil(wait)} s",
            headers={"Retry-After": str(math.ceil(wait))},
        )
