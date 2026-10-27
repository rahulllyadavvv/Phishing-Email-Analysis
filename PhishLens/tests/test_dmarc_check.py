"""Tests for phishlens.enrichment.dmarc_check. DNS answers come from the ``fake_dns`` fixture."""

from __future__ import annotations

import dns.exception

from phishlens.enrichment.dmarc_check import fetch_dmarc, parse_dmarc


async def test_record_at_from_domain(fake_dns) -> None:
    fake_dns(
        {
            ("_dmarc.signer.test", "TXT"): [
                "some-other-txt",
                "v=DMARC1; p=reject; adkim=s; aspf=r; pct=50; rua=mailto:d@signer.test",
            ]
        }
    )
    record = await fetch_dmarc("signer.test", "signer.test")
    assert record.found and record.error is None
    assert (record.p, record.sp, record.policy) == ("reject", None, "reject")
    assert (record.adkim, record.aspf, record.pct) == ("s", "r", 50)
    assert record.record_domain == "signer.test"
    assert record.tags["rua"] == "mailto:d@signer.test"


async def test_subdomain_falls_back_to_org_domain_and_uses_sp(fake_dns) -> None:
    fake = fake_dns({("_dmarc.signer.test", "TXT"): ["v=DMARC1; p=reject; sp=quarantine"]})
    record = await fetch_dmarc("News.Signer.Test", "signer.test")
    assert record.domain == "news.signer.test"
    assert record.record_domain == "signer.test"
    assert record.policy == "quarantine"
    assert fake.calls == [("_dmarc.news.signer.test", "TXT"), ("_dmarc.signer.test", "TXT")]


async def test_org_record_without_sp_uses_p(fake_dns) -> None:
    fake_dns({("_dmarc.signer.test", "TXT"): ["v=DMARC1; p=quarantine"]})
    assert (await fetch_dmarc("a.signer.test", "signer.test")).policy == "quarantine"


async def test_no_record(fake_dns) -> None:
    fake_dns({})
    record = await fetch_dmarc("nothing.test", "nothing.test")
    assert not record.found and record.error is None and record.policy is None


async def test_dns_error_is_reported(fake_dns) -> None:
    fake_dns({("_dmarc.slow.test", "TXT"): dns.exception.Timeout()})
    record = await fetch_dmarc("slow.test", "slow.test")
    assert not record.found
    assert record.error == "DNS timeout for _dmarc.slow.test"


async def test_multiple_records_mean_no_policy(fake_dns) -> None:
    fake_dns({("_dmarc.two.test", "TXT"): ["v=DMARC1; p=reject", "v=DMARC1; p=none"]})
    record = await fetch_dmarc("two.test", "two.test")
    assert not record.found
    assert "2 DMARC records" in record.warnings[0]


async def test_invalid_values_fall_back_with_warnings(fake_dns) -> None:
    fake_dns({("_dmarc.odd.test", "TXT"): ["v=DMARC1; p=block; sp=maybe; adkim=x; pct=250"]})
    record = await fetch_dmarc("odd.test", "odd.test")
    assert (record.p, record.sp, record.adkim, record.pct) == ("none", None, "r", 100)
    assert record.policy == "none"
    assert len(record.warnings) == 4


def test_parse_dmarc() -> None:
    tags, warnings = parse_dmarc("v=DMARC1;  P = Reject ; junk; ;pct=10")
    assert tags == {"v": "DMARC1", "p": "Reject", "pct": "10"}
    assert warnings == ["ignored malformed tag: junk"]
