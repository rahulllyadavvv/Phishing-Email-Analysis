"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import dns.resolver
import pytest

from phishlens.config import get_settings
from phishlens.enrichment import dns as dns_helper


class FakeDns:
    """Stand-in for ``phishlens.enrichment.dns._query``: answers from a table, NXDOMAIN
    otherwise, and records every call. A table value may be an exception to raise."""

    def __init__(self, answers: dict[tuple[str, str], list[str] | Exception]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, name: str, rdtype: str, timeout: float) -> list[str]:
        self.calls.append((name, rdtype))
        answer = self.answers.get((name, rdtype), dns.resolver.NXDOMAIN())
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[dict], FakeDns]]:
    """Return a function that installs a ``FakeDns`` with the given answers.

    The DNS cache is emptied and the SQLite cache turned off, so answers never leak between tests.
    """
    monkeypatch.setenv("DNS_SQLITE_CACHE", "false")
    get_settings.cache_clear()
    dns_helper.clear_cache()

    def install(answers: dict) -> FakeDns:
        fake = FakeDns(answers)
        monkeypatch.setattr(dns_helper, "_query", fake)
        return fake

    yield install
    dns_helper.clear_cache()
    get_settings.cache_clear()
