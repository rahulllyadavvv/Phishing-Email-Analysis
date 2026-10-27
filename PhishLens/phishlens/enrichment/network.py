"""Global "no network" switch for offline analysis (CLI ``--no-network``, demos, tests).

Inside ``with offline():`` every DNS lookup and every enrichment/LLM/sandbox client skips its
network call: DNS returns the error ``offline`` and clients return ``not_configured``. The
switch is a context variable, so asyncio tasks and worker threads started inside the block
inherit it and concurrent analyses are not affected.

Inside ``with cache_only():`` enrichment clients answer only from their cache: a cache miss
comes back ``not_configured`` (reason ``cache only``) and no new API request, upload or sandbox
submission is made. DNS still works. The evaluation script uses it to re-run a dataset without
spending API quota.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

__all__ = [
    "CACHE_ONLY_REASON",
    "OFFLINE_REASON",
    "cache_only",
    "fetch_enabled",
    "network_enabled",
    "offline",
]

OFFLINE_REASON = "network disabled"
CACHE_ONLY_REASON = "cache only (no new API calls)"
_offline: ContextVar[bool] = ContextVar("phishlens_offline", default=False)
_cache_only: ContextVar[bool] = ContextVar("phishlens_cache_only", default=False)


def network_enabled() -> bool:
    return not _offline.get()


def fetch_enabled() -> bool:
    """New API requests are allowed (network on and not in cache-only mode)."""
    return network_enabled() and not _cache_only.get()


@contextmanager
def offline(enabled: bool = True) -> Iterator[None]:
    """Disable network access in this context (``enabled=False`` leaves it on)."""
    token = _offline.set(enabled or _offline.get())
    try:
        yield
    finally:
        _offline.reset(token)


@contextmanager
def cache_only(enabled: bool = True) -> Iterator[None]:
    """Answer enrichment lookups from the cache only in this context."""
    token = _cache_only.set(enabled or _cache_only.get())
    try:
        yield
    finally:
        _cache_only.reset(token)
