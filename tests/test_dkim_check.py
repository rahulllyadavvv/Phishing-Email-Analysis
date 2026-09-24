"""Tests for phishlens.enrichment.dkim_check. Messages are signed in the test with a throwaway
key (``dkim_key``) and the key record is served by ``fake_dns``."""

from __future__ import annotations

import dns.exception
import pytest

from phishlens.enrichment import dkim_check
from phishlens.enrichment.dkim_check import verify_dkim

KEY_NAME = ("sel._domainkey.signer.test", "TXT")

MESSAGE = (
    b"From: Alice <alice@signer.test>\r\n"
    b"To: bob@recipient.test\r\n"
    b"Subject: Quarterly report\r\n"
    b"Date: Thu, 24 Sep 2026 10:00:00 +0000\r\n"
    b"Message-ID: <1@signer.test>\r\n"
    b"\r\n"
    b"Hello Bob,\r\nthe report is ready.\r\n"
)


@pytest.fixture
def key_in_dns(fake_dns, dkim_key):
    return fake_dns({KEY_NAME: ["unrelated=txt", dkim_key.dns_record]})


async def test_valid_signature_passes(key_in_dns, dkim_key) -> None:
    [sig] = await verify_dkim(dkim_key.sign(MESSAGE))
    assert sig.status == "pass" and sig.valid and sig.error is None
    assert (sig.domain, sig.selector, sig.algorithm) == ("signer.test", "sel", "rsa-sha256")
    assert sig.signed_headers == ["from", "to", "subject", "date"]
    assert sig.body_length is None and sig.expiration is None
    assert isinstance(sig.timestamp, int)
    assert sig.to_dict()["valid"] is True
    assert key_in_dns.calls == [KEY_NAME]


async def test_tampered_body_fails(key_in_dns, dkim_key) -> None:
    signed = dkim_key.sign(MESSAGE).replace(b"report is ready", b"invoice is overdue")
    [sig] = await verify_dkim(signed)
    assert sig.status == "fail" and not sig.valid
    assert "body hash mismatch" in sig.error


async def test_tampered_signed_header_fails(key_in_dns, dkim_key) -> None:
    signed = dkim_key.sign(MESSAGE).replace(b"Quarterly report", b"Urgent: reset password")
    [sig] = await verify_dkim(signed)
    assert sig.status == "fail"
    assert sig.error == "signature does not verify"


async def test_body_length_tag_is_recorded(key_in_dns, dkim_key) -> None:
    signed = dkim_key.sign(MESSAGE, length=True) + b"Appended by someone else.\r\n"
    [sig] = await verify_dkim(signed)
    assert sig.status == "pass"
    assert sig.body_length == len(b"Hello Bob,\r\nthe report is ready.\r\n")


async def test_missing_key_is_permerror(fake_dns, dkim_key) -> None:
    fake_dns({})
    [sig] = await verify_dkim(dkim_key.sign(MESSAGE))
    assert sig.status == "permerror"
    assert sig.error == "no key record at sel._domainkey.signer.test"


async def test_dns_timeout_is_temperror(fake_dns, dkim_key) -> None:
    fake_dns({KEY_NAME: dns.exception.Timeout()})
    [sig] = await verify_dkim(dkim_key.sign(MESSAGE))
    assert sig.status == "temperror"
    assert "timeout" in sig.error


async def test_bad_key_record_is_permerror(fake_dns, dkim_key) -> None:
    fake_dns({KEY_NAME: ["v=DKIM1; k=rsa; p=bm90IGEga2V5"]})
    [sig] = await verify_dkim(dkim_key.sign(MESSAGE))
    assert sig.status == "permerror"
    assert sig.error.startswith("bad key record")


async def test_expired_signature(fake_dns) -> None:
    fake_dns({})
    header = (
        b"DKIM-Signature: v=1; a=rsa-sha256; d=signer.test; s=sel; h=from:to:subject;\r\n"
        b" t=1000; x=2000; bh=AAAA; b=AAAA\r\n"
    )
    [sig] = await verify_dkim(header + MESSAGE)
    assert sig.status == "expired"
    assert (sig.timestamp, sig.expiration) == (1000, 2000)


async def test_malformed_signature_is_permerror(fake_dns) -> None:
    fake_dns({})
    [sig] = await verify_dkim(b"DKIM-Signature: this is not a tag list\r\n" + MESSAGE)
    assert sig.status == "permerror"
    assert sig.error


async def test_multiple_signatures_verified_separately(key_in_dns, dkim_key) -> None:
    signed = dkim_key.sign(MESSAGE)
    signed = dkim_key.sign(signed, domain="other.test", selector="s2")
    sigs = await verify_dkim(signed)
    assert [(s.domain, s.status) for s in sigs] == [
        ("other.test", "permerror"),
        ("signer.test", "pass"),
    ]


async def test_no_signatures(fake_dns) -> None:
    fake_dns({})
    assert await verify_dkim(MESSAGE) == []


def test_pick_key_prefers_record_with_p_tag() -> None:
    assert dkim_check._pick_key(["google-site-verification=x", "v=DKIM1; p=abc"]) == (
        "v=DKIM1; p=abc"
    )
    assert dkim_check._pick_key([]) is None
