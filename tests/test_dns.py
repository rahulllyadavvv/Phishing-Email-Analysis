"""Tests for phishlens.enrichment.dns. The real resolver is never used: ``_query`` is patched."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import dns.exception
import dns.resolver
import pytest

from phishlens.config import get_settings
from phishlens.enrichment import dns as dns_helper


class FakeDns:
    """Stand-in for ``_query``: answers from a table and counts calls."""

    def __init__(self, answers: dict[tuple[str, str], list[str] | Exception]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, name: str, rdtype: str, timeout: float) -> list[str]:
        self.calls.append((name, rdtype))
        answer = self.answers.get((name, rdtype), dns.resolver.NXDOMAIN())
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture(autouse=True)
def settings_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DNS_SQLITE_CACHE", "false")
    monkeypatch.setenv("DNS_CACHE_TTL_SECONDS", "3600")
    get_settings.cache_clear()
    dns_helper.clear_cache()
    yield
    get_settings.cache_clear()
    dns_helper.clear_cache()


def _install(monkeypatch: pytest.MonkeyPatch, answers: dict) -> FakeDns:
    fake = FakeDns(answers)
    monkeypatch.setattr(dns_helper, "_query", fake)
    return fake


async def test_txt_mx_a_records(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(
        monkeypatch,
        {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("example.com", "MX"): ["10 mx.example.com"],
            ("example.com", "A"): ["192.0.2.1"],
        },
    )
    assert (await dns_helper.txt("Example.COM.")).records == ["v=spf1 -all"]
    assert (await dns_helper.mx("example.com")).records == ["10 mx.example.com"]
    result = await dns_helper.a("example.com")
    assert result.ok and result.records == ["192.0.2.1"] and not result.cached


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (dns.resolver.NXDOMAIN(), "nxdomain"),
        (dns.resolver.NoAnswer(), "no_answer"),
        (dns.exception.Timeout(), "timeout"),
        (dns.resolver.NoNameservers(), "no_nameservers"),
        (RuntimeError("boom"), "error: RuntimeError: boom"),
    ],
)
async def test_errors_are_returned_not_raised(
    monkeypatch: pytest.MonkeyPatch, exc: Exception, code: str
) -> None:
    _install(monkeypatch, {("bad.test", "TXT"): exc})
    result = await dns_helper.txt("bad.test")
    assert not result.ok
    assert result.error == code
    assert result.records == []


async def test_unsupported_type_and_empty_name(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, {})
    assert (await dns_helper.resolve("example.com", "AAAA")).error == "unsupported_type"
    assert (await dns_helper.resolve("  ", "A")).error == "error: empty name"
    assert fake.calls == []


async def test_memory_cache_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, {("example.com", "TXT"): ["hello"]})
    await dns_helper.txt("example.com")
    second = await dns_helper.txt("EXAMPLE.com")
    assert second.cached and second.records == ["hello"]
    assert fake.calls == [("example.com", "TXT")]


async def test_nxdomain_cached_but_timeout_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(
        monkeypatch,
        {("gone.test", "A"): dns.resolver.NXDOMAIN(), ("slow.test", "A"): dns.exception.Timeout()},
    )
    for _ in range(2):
        await dns_helper.a("gone.test")
        await dns_helper.a("slow.test")
    assert fake.calls.count(("gone.test", "A")) == 1
    assert fake.calls.count(("slow.test", "A")) == 2


async def test_zero_ttl_disables_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DNS_CACHE_TTL_SECONDS", "0")
    get_settings.cache_clear()
    fake = _install(monkeypatch, {("example.com", "A"): ["192.0.2.1"]})
    await dns_helper.a("example.com")
    await dns_helper.a("example.com")
    assert len(fake.calls) == 2


async def test_expired_entry_is_refetched(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, {("example.com", "A"): ["192.0.2.1"]})
    now = 1_000_000.0
    monkeypatch.setattr(dns_helper.time, "time", lambda: now)
    await dns_helper.a("example.com")
    now += 3601
    await dns_helper.a("example.com")
    assert len(fake.calls) == 2


async def test_sqlite_cache_survives_memory_clear(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cache_file = tmp_path / "dns.sqlite"
    monkeypatch.setenv("DNS_SQLITE_CACHE", "true")
    monkeypatch.setenv("DNS_CACHE_PATH", str(cache_file))
    get_settings.cache_clear()
    fake = _install(monkeypatch, {("example.com", "MX"): ["10 mx.example.com"]})

    await dns_helper.mx("example.com")
    dns_helper.clear_cache()
    again = await dns_helper.mx("example.com")

    assert cache_file.exists()
    assert again.cached and again.records == ["10 mx.example.com"]
    assert len(fake.calls) == 1


async def test_broken_sqlite_file_does_not_break_lookups(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bad = tmp_path / "not-a-db.sqlite"
    bad.write_bytes(b"this is not a sqlite database" * 10)
    monkeypatch.setenv("DNS_SQLITE_CACHE", "true")
    monkeypatch.setenv("DNS_CACHE_PATH", str(bad))
    get_settings.cache_clear()
    _install(monkeypatch, {("example.com", "A"): ["192.0.2.1"]})
    result = await dns_helper.a("example.com")
    assert result.ok and result.records == ["192.0.2.1"]
