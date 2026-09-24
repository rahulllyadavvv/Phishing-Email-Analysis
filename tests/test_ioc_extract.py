"""Tests for phishlens.ioc.extract (fixtures 2, 5 and 14 plus synthetic results)."""

from __future__ import annotations

from pathlib import Path

import pytest

from phishlens.analyzers import artifacts, attachments, header, urls
from phishlens.ioc.extract import canonical_url, extract_iocs
from phishlens.models import AnalyzerResult, EnrichmentResult, IOCType, ParsedEmail, UrlRef
from phishlens.parser import parse_email

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> ParsedEmail:
    return parse_email((FIXTURES / name).read_bytes())


async def _results(email: ParsedEmail) -> dict[str, AnalyzerResult]:
    return {
        "header": await header.analyze(email),
        "urls": await urls.analyze(email, reputation=False),
        "attachments": await attachments.analyze(email, reputation=False, sandbox=False),
        "artifacts": await artifacts.analyze(email),
    }


def _by(iocs, kind: IOCType) -> dict:
    return {i.value: i for i in iocs if i.type == kind}


def _check_invariants(iocs) -> None:
    keys = [(i.type, i.value) for i in iocs]
    assert len(keys) == len(set(keys)), "IOCs must be deduplicated"
    for ioc in iocs:
        assert ioc.defanged, ioc
        if ioc.type in (IOCType.URL, IOCType.DOMAIN, IOCType.IP, IOCType.EMAIL):
            assert ioc.defanged != ioc.value or ":" in ioc.value, ioc  # IPv6 has no dots
            assert "http://" not in ioc.defanged and "https://" not in ioc.defanged
        assert ioc.verdict in ("malicious", "suspicious", "clean", "unknown")


async def test_fixture_2_spoofed_sender(fake_dns) -> None:
    fake_dns({("zetatech.xyz", "TXT"): ["v=spf1 ip4:203.0.113.0/24 -all"]})
    email = _fixture("spoof_unaligned.eml")
    iocs = extract_iocs(email, await _results(email))
    _check_invariants(iocs)
    emails = _by(iocs, IOCType.EMAIL)
    assert emails["account-security@microsoft.com"].defanged == "account-security[@]microsoft[.]com"
    assert emails["account-security@microsoft.com"].context == "From address"
    domains = _by(iocs, IOCType.DOMAIN)
    assert domains["zetatech.xyz"].verdict == "suspicious"  # authenticated, unaligned with From
    assert "authenticated domain unaligned with From" in domains["zetatech.xyz"].context
    ip = _by(iocs, IOCType.IP)["203.0.113.45"]
    assert ip.context == "originating IP (Received)" and ip.defanged == "203[.]0[.]113[.]45"
    url = _by(iocs, IOCType.URL)["http://account-review.zetatech.example/verify"]
    assert url.defanged == "hxxp://account-review[.]zetatech[.]example/verify"
    assert set(url.source_module.split(", ")) == {"email", "urls", "text"}


async def test_fixture_5_link_mismatch() -> None:
    email = _fixture("link_mismatch.eml")
    iocs = extract_iocs(email, await _results(email))
    _check_invariants(iocs)
    url_iocs = _by(iocs, IOCType.URL)
    assert set(url_iocs) == {
        "http://paypal-secure-login.example/confirm",
        "https://www.paypal.com/",  # "https://www.paypal.com" from the text merged into it
    }
    assert url_iocs["http://paypal-secure-login.example/confirm"].verdict == "suspicious"
    assert _by(iocs, IOCType.DOMAIN)["paypal-secure-login.example"].verdict == "suspicious"
    assert url_iocs["https://www.paypal.com/"].verdict == "unknown"


async def test_fixture_14_eicar_with_malicious_reputation(monkeypatch) -> None:
    async def fake(sha256: str) -> list[EnrichmentResult]:
        return [EnrichmentResult(service="abusech", query=sha256, status="malicious")]

    monkeypatch.setattr(attachments, "hash_reputation", fake)
    email = _fixture("eicar_attachment.eml")
    results = await _results(email)
    results["attachments"] = await attachments.analyze(email, sandbox=False)
    iocs = extract_iocs(email, results)
    _check_invariants(iocs)
    sha256 = _by(iocs, IOCType.SHA256)
    eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert sha256[eicar].verdict == "malicious"
    assert _by(iocs, IOCType.MD5)["44d88612fea8a8f36de82e1278abb02f"].verdict == "malicious"
    assert _by(iocs, IOCType.FILENAME)["eicar.com"].context == "attachment"


def test_sandbox_iocs_tracking_and_extracted_urls() -> None:
    attachment_result = AnalyzerResult(
        module="attachments",
        raw={
            "attachments": [
                {
                    "filename": "doc.exe", "safe_name": "doc.exe", "parent": "a.zip",
                    "size": 10, "md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64,
                    "flags": [], "reputation_verdict": None, "inline": False,
                    "sandbox": {
                        "status": "done", "verdict": "malicious",
                        "network_domains": ["c2.bad.test"], "network_ips": ["203.0.113.66"],
                        "network_urls": ["http://c2.bad.test/gate"],
                        "dropped_hashes": ["D" * 64],
                    },
                },
                {
                    "filename": "logo.png", "safe_name": "logo.png", "parent": None,
                    "size": 5, "md5": "e" * 32, "sha1": "f" * 40, "sha256": "0" * 64,
                    "flags": [], "inline": True,
                },
            ]
        },
        extracted_urls=[UrlRef(url="https://qr.example.test/p", source="qr_code")],
    )
    artifact_result = AnalyzerResult(
        module="artifacts", raw={"tracking_domains": ["track[.]mailer[.]test"]}
    )
    iocs = extract_iocs(None, {"attachments": attachment_result, "artifacts": artifact_result})
    _check_invariants(iocs)
    assert _by(iocs, IOCType.FILENAME)["doc.exe"].verdict == "malicious"
    assert _by(iocs, IOCType.FILENAME)["doc.exe"].context == "attachment inside a.zip"
    assert "logo.png" not in _by(iocs, IOCType.FILENAME)  # inline images are skipped
    assert _by(iocs, IOCType.DOMAIN)["c2.bad.test"].verdict == "malicious"
    assert _by(iocs, IOCType.IP)["203.0.113.66"].context == "sandbox network IP"
    assert _by(iocs, IOCType.SHA256)["d" * 64].context == "file dropped in sandbox"
    assert _by(iocs, IOCType.URL)["https://qr.example.test/p"].context == "QR code"
    assert _by(iocs, IOCType.DOMAIN)["track.mailer.test"].context == "tracking pixel domain"


def test_private_and_trusted_received_ips_are_skipped(monkeypatch) -> None:
    from phishlens.config import get_settings
    from phishlens.models import ReceivedHop

    monkeypatch.setenv("TRUSTED_INTERNAL_HOSTS", "198.51.100.0/24")
    get_settings.cache_clear()
    email = ParsedEmail(
        received_chain=[
            ReceivedHop(ip="203.0.113.5"),
            ReceivedHop(ip="198.51.100.9"),
            ReceivedHop(ip="10.0.0.2"),
        ]
    )
    ips = _by(extract_iocs(email, {}), IOCType.IP)
    assert set(ips) == {"203.0.113.5"}
    assert ips["203.0.113.5"].context == "originating IP (Received)"


def test_worst_verdict_wins_and_contexts_merge() -> None:
    result = AnalyzerResult(
        module="urls",
        raw={
            "urls": [
                {
                    "url": "http://x.test/a", "sources": ["html_href"], "flags": [],
                    "reputation_verdict": "clean",
                },
                {
                    "url": "HTTP://X.TEST/a", "sources": ["text_body"], "flags": [],
                    "reputation_verdict": "malicious",
                },
            ]
        },
    )
    [url] = [i for i in extract_iocs(None, {"urls": result}) if i.type == IOCType.URL]
    assert url.value == "http://x.test/a" and url.verdict == "malicious"
    assert url.context == "link (html_href); link (text_body)"


def test_safety_net_finds_defanged_text_urls() -> None:
    email = ParsedEmail(
        text_body="Report: hxxp://evil[.]example[.]test/drop seen from 203.0.113.77"
    )
    iocs = extract_iocs(email, {})
    assert "http://evil.example.test/drop" in _by(iocs, IOCType.URL)
    assert _by(iocs, IOCType.IP)["203.0.113.77"].source_module == "text"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("HTTPS://WWW.PayPal.com", "https://www.paypal.com/"),
        ("http://user@Host.TEST:8080/Path?Q=1#F", "http://user@host.test:8080/Path?Q=1#F"),
        ("http://[2001:DB8::1]", "http://[2001:db8::1]/"),
    ],
)
def test_canonical_url(url: str, expected: str) -> None:
    assert canonical_url(url) == expected
