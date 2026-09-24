"""Global "no network" switch for offline analysis (CLI ``--no-network``, demos, tests).

Inside ``with offline():`` every DNS lookup and every enrichment/LLM/sandbox client skips its
network call: DNS returns the error ``offline`` and clients return ``not_configured``. The
switch is a context variable, so asyncio tasks and worker threads started inside the block
inherit it and concurrent analyses are not affected.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

__all__ = ["OFFLINE_REASON", "network_enabled", "offline"]

OFFLINE_REASON = "network disabled"
_offline: ContextVar[bool] = ContextVar("phishlens_offline", default=False)


def network_enabled() -> bool:
    return not _offline.get()


@contextmanager
def offline(enabled: bool = True) -> Iterator[None]:
    """Disable network access in this context (``enabled=False`` leaves it on)."""
    token = _offline.set(enabled or _offline.get())
    try:
        yield
    finally:
        _offline.reset(token)
