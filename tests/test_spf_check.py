"""Tests for phishlens.enrichment.spf_check. All DNS answers come from the ``fake_dns`` fixture."""

from __future__ import annotations

import dns.exception
import pytest
import spf

from phishlens.enrichment import spf_check
from phishlens.enrichment.spf_check import check_spf

IP = "203.0.113.45"


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("v=spf1 ip4:203.0.113.0/24 -all", "pass"),
        ("v=spf1 ip4:192.0.2.1 -all", "fail"),
        ("v=spf1 ip4:192.0.2.1 ~all", "softfail"),
        ("v=spf1 ?all", "neutral"),
        ("v=spf1 ip4:203.0.113.45 bogus:mechanism -all", "permerror"),
    ],
)
async def test_results_from_record(fake_dns, record: str, expected: str) -> None:
    fake_dns({("sender.test", "TXT"): ["some-verification=abc", record]})
    check = await check_spf(IP, "bounce@sender.test", "mail.sender.test")
    assert check.result == expected
    assert check.identity == "mailfrom"
    assert check.domain == "sender.test"
    assert check.ip == IP


async def test_include_a_and_mx_mechanisms_use_the_helper(fake_dns) -> None:
    fake = fake_dns(
        {
            ("sender.test", "TXT"): ["v=spf1 include:_spf.esp.test a mx -all"],
            ("_spf.esp.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
            ("sender.test", "A"): ["198.51.100.7"],
            ("sender.test", "MX"): ["10 mx.sender.test"],
            ("mx.sender.test", "A"): [IP],
        }
    )
    check = await check_spf(IP, "bounce@sender.test", "")
    assert check.result == "pass"
    assert ("_spf.esp.test", "TXT") in fake.calls
    assert ("mx.sender.test", "A") in fake.calls


async def test_ipv6_sender_uses_aaaa(fake_dns) -> None:
    fake_dns(
        {
            ("sender.test", "TXT"): ["v=spf1 a -all"],
            ("sender.test", "AAAA"): ["2001:db8::25"],
        }
    )
    assert (await check_spf("2001:db8::25", "x@sender.test", "")).result == "pass"


async def test_no_record_is_none(fake_dns) -> None:
    fake_dns({})
    check = await check_spf(IP, "bounce@nothing.test", "")
    assert check.result == "none"


async def test_dns_timeout_is_temperror(fake_dns) -> None:
    fake_dns({("slow.test", "TXT"): dns.exception.Timeout()})
    check = await check_spf(IP, "bounce@slow.test", "")
    assert check.result == "temperror"
    assert "timeout" in check.explanation


async def test_helo_identity_when_no_mail_from(fake_dns) -> None:
    fake_dns({("mail.sender.test", "TXT"): ["v=spf1 ip4:203.0.113.45 -all"]})
    check = await check_spf(IP, "", "Mail.Sender.Test.")
    assert check.result == "pass"
    assert check.identity == "helo"
    assert check.domain == "mail.sender.test"
    assert check.to_dict()["helo"] == "mail.sender.test"


async def test_unexpected_error_is_temperror(fake_dns, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object) -> tuple[str, str]:
        raise RuntimeError("thread exploded")

    monkeypatch.setattr(spf_check, "_run_query", boom)
    check = await check_spf(IP, "bounce@sender.test", "")
    assert check.result == "temperror"
    assert "thread exploded" in check.explanation


def test_lookup_outside_check_spf_uses_pyspf_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        spf_check, "_original_lookup", lambda name, qtype, *a: calls.append((name, qtype)) or []
    )
    assert spf.DNSLookup is spf_check._lookup
    assert spf.DNSLookup("example.test", "TXT") == []
    assert calls == [("example.test", "TXT")]
