"""Tests for phishlens.analyzers.domain."""

from __future__ import annotations

from pathlib import Path

import pytest

from phishlens import data_loader
from phishlens.analyzers import domain
from phishlens.analyzers.domain import find_brand_mentions
from phishlens.models import Severity
from phishlens.parser import parse_email

FIXTURES = Path(__file__).parent / "fixtures"
ALL_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.eml"))


def _email(headers: str):
    raw = headers.strip().replace("\n", "\r\n") + "\r\nSubject: hi\r\n\r\nbody\r\n"
    return parse_email(raw.encode())


def _ids(result) -> dict:
    return {f.id: f for f in result.findings}


async def _analyze(headers: str):
    return await domain.analyze(_email(headers))


# --- Display-name brand spoofing -----------------------------------------------------------------


async def test_paypal_security_from_gmail_is_flagged() -> None:
    result = await _analyze('From: "PayPal Security" <x@gmail.com>')
    finding = _ids(result)["display_name_brand_spoof"]
    assert finding.severity == Severity.HIGH
    assert finding.evidence["brand"] == "PayPal"
    assert finding.evidence["free_webmail"] is True
    assert "paypal.com" in finding.evidence["legitimate_domains"]


async def test_brand_from_unrelated_domain_is_flagged() -> None:
    result = await _analyze("From: Microsoft Support <security@micros0ft-support.example>")
    finding = _ids(result)["display_name_brand_spoof"]
    assert finding.evidence["brand"] == "Microsoft"
    assert finding.evidence["free_webmail"] is False


@pytest.mark.parametrize(
    "from_header",
    [
        "From: PayPal <service@paypal.com>",
        "From: PayPal <service@mail.paypal.com>",
        "From: Google <no-reply@accounts.google.com>",
        "From: Alice Smith <alice@gmail.com>",
        "From: Upstairs Groups <team@company.example>",
    ],
)
async def test_no_display_name_spoof(from_header: str) -> None:
    assert "display_name_brand_spoof" not in _ids(await _analyze(from_header))


async def test_brand_domain_that_is_free_webmail_is_still_spoof() -> None:
    """outlook.com belongs to Microsoft, but anyone can register an address there."""
    result = await _analyze("From: Microsoft Account Team <helpdesk@outlook.com>")
    assert _ids(result)["display_name_brand_spoof"].evidence["free_webmail"] is True


def test_find_brand_mentions_whole_words_and_phrases() -> None:
    assert [m.brand.name for m in find_brand_mentions("Your PayPal account")] == ["PayPal"]
    assert [m.keyword for m in find_brand_mentions("Office-365 alert")] == ["office 365"]
    assert [m.brand.name for m in find_brand_mentions("STATE BANK OF INDIA")] == [
        "State Bank of India"
    ]
    assert find_brand_mentions("groups and startups") == []
    assert find_brand_mentions("") == []


def test_organization_counts_as_a_brand(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "brand_registry.yaml").write_text(
        "organization:\n  name: Acme Corp\n  domains: [acme.test]\n"
        "brands:\n  - name: PayPal\n    keywords: [paypal]\n    legitimate_domains: [paypal.com]\n"
    )
    monkeypatch.setattr(data_loader, "DATA_DIR", tmp_path)
    data_loader.clear_cache()
    try:
        [mention] = find_brand_mentions("Acme Corp IT desk")
        assert mention.brand.name == "Acme Corp"
        assert mention.brand.legitimate_domains == ("acme.test",)
    finally:
        data_loader.clear_cache()


# --- Domain consistency --------------------------------------------------------------------------


async def test_replyto_mismatch_and_free_webmail_from_corporate_domain() -> None:
    result = await _analyze(
        "From: CFO <cfo@company.example>\nReply-To: cfo.company@gmail.com"
    )
    findings = _ids(result)
    assert findings["replyto_mismatch"].severity == Severity.MEDIUM
    free = findings["replyto_free_webmail"]
    assert free.severity == Severity.HIGH
    assert free.evidence["reply_to"] == "cfo.company@gmail.com"
    assert free.evidence["from_is_free_webmail"] is False


async def test_replyto_free_webmail_is_medium_when_from_is_webmail() -> None:
    result = await _analyze("From: a@yahoo.com\nReply-To: b@gmail.com")
    assert _ids(result)["replyto_free_webmail"].severity == Severity.MEDIUM


@pytest.mark.parametrize(
    "headers",
    [
        "From: a@company.example\nReply-To: support@help.company.example",
        "From: a@gmail.com\nReply-To: a@gmail.com",
        "From: a@company.example",
    ],
)
async def test_no_replyto_findings(headers: str) -> None:
    findings = _ids(await _analyze(headers))
    assert "replyto_mismatch" not in findings
    assert "replyto_free_webmail" not in findings


async def test_returnpath_mismatch() -> None:
    result = await domain.analyze(parse_email((FIXTURES / "spoof_unaligned.eml").read_bytes()))
    finding = _ids(result)["returnpath_mismatch"]
    assert finding.severity == Severity.LOW
    assert finding.evidence["return_path_domain"] == "zetatech.xyz"
    assert finding.evidence["from_domain"] == "microsoft.com"


async def test_returnpath_on_esp_is_info() -> None:
    result = await _analyze(
        "Return-Path: <bounce-123@em.sendgrid.net>\nFrom: News <news@company.example>"
    )
    finding = _ids(result)["returnpath_mismatch"]
    assert finding.severity == Severity.INFO
    assert finding.evidence["esp"] == "SendGrid"


async def test_same_org_return_path_is_fine() -> None:
    result = await _analyze(
        "Return-Path: <bounce@mail.company.example>\nFrom: a@company.example"
    )
    assert "returnpath_mismatch" not in _ids(result)


async def test_domain_table() -> None:
    result = await _analyze(
        "Return-Path: <b@zetatech.xyz>\nFrom: PayPal <x@gmail.com>\n"
        "Reply-To: r@paypal.com\nSender: s@gmail.com"
    )
    rows = {r["role"]: r for r in result.raw["domain_table"]}
    assert set(rows) == {"from", "return_path", "reply_to", "sender"}
    assert rows["from"]["free_webmail"] is True and rows["from"]["matches_from"] is True
    assert rows["return_path"]["risky_tld"] is True
    assert rows["return_path"]["matches_from"] is False
    assert rows["reply_to"]["brand"] == "PayPal"
    assert rows["sender"]["matches_from"] is True


async def test_no_from() -> None:
    result = await domain.analyze(parse_email(b"Subject: x\r\n\r\nbody"))
    assert result.findings == [] and result.errors == []
    assert result.raw["domain_table"] == []


async def test_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object) -> None:
        raise RuntimeError("data exploded")

    monkeypatch.setattr(domain, "find_brand_mentions", boom)
    result = await _analyze('From: "PayPal" <x@gmail.com>')
    assert result.errors == ["display_name: RuntimeError: data exploded"]


@pytest.mark.parametrize("name", ALL_FIXTURES)
async def test_every_fixture(name: str) -> None:
    result = await domain.analyze(parse_email((FIXTURES / name).read_bytes()))
    assert result.errors == []


# --- Lookalike domains ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "brand", "kind"),
    [
        ("micros0ft.com", "Microsoft", "homoglyph"),
        ("paypa1.com", "PayPal", "homoglyph"),
        ("xn--pple-43d.com", "Apple", "homoglyph"),  # Cyrillic "а" + "pple"
        ("xn--80ak6aa92e.com", "Apple", "homoglyph"),  # fully Cyrillic "аррӏе"
        ("rnicrosoft.com", "Microsoft", "homoglyph"),
        ("paypal-secure-login.net", "PayPal", "combosquat"),
        ("microsoft-support-login.example", "Microsoft", "combosquat"),
        ("micros0ft-support.example", "Microsoft", "combosquat"),
        ("paypalsecure.com", "PayPal", "combosquat"),
        ("gooogle.com", "Google", "typosquat"),
        ("netflx.com", "Netflix", "typosquat"),
        ("paypal.net", "PayPal", "tld_swap"),
        ("paypal.com.account-check.example", "PayPal", "brand_in_subdomain"),
        ("0ffice.com", "Microsoft", "homoglyph"),
    ],
)
def test_check_lookalike_detects(candidate: str, brand: str, kind: str) -> None:
    matches = domain.check_lookalike(candidate)
    assert [(m.brand, m.kind) for m in matches][:1] == [(brand, kind)]
    assert matches[0].legitimate_domain


def test_idn_is_decoded() -> None:
    [match] = domain.check_lookalike("xn--pple-43d.com")
    assert match.decoded == "аpple.com"
    assert match.legitimate_domain == "apple.com"
    assert domain.check_lookalike("аpple.com")[0].domain == "xn--pple-43d.com"


@pytest.mark.parametrize(
    "candidate",
    [
        "microsoft.com",
        "login.microsoftonline.com",
        "mail.paypal.com",
        "apple.com",
        "example.com",
        "company.example",
        "purchase.com",  # contains "chase"
        "pineapple.com",  # contains "apple"
        "home-office.co.uk",  # "office" is a generic label
        "live-events.com",
        "apply.com",  # one edit from "apple", but too short for typo matching
        "groups.com",
        "localhost",
        "",
    ],
)
def test_check_lookalike_ignores(candidate: str) -> None:
    assert domain.check_lookalike(candidate) == []


def test_one_match_per_brand_strongest_kind() -> None:
    matches = domain.check_lookalike("paypa1-paypal.com")
    assert [(m.brand, m.kind) for m in matches] == [("PayPal", "combosquat")]
    assert all(m.brand != "PayPal" or m.kind == "combosquat" for m in matches)


def test_skeleton_and_decode_idn() -> None:
    assert domain.skeleton("PayPa1") == domain.skeleton("paypal")
    assert domain.skeleton("rnicros0ft") == domain.skeleton("microsoft")
    assert domain.decode_idn("xn--pple-43d.com") == "аpple.com"
    assert domain.decode_idn("xn--invalid-.com") == "xn--invalid-.com"


async def test_fixture_6_lookalike_finding() -> None:
    result = await domain.analyze(parse_email((FIXTURES / "lookalike_domain.eml").read_bytes()))
    finding = _ids(result)["lookalike_domain"]
    assert finding.severity == Severity.HIGH
    assert finding.evidence["domain"] == "micros0ft-support.example"
    assert set(finding.evidence["roles"]) == {"from", "return_path"}
    assert finding.evidence["matches"][0]["brand"] == "Microsoft"
    assert "micros0ft-support.example" in result.raw["lookalikes"]


async def test_punycode_domain_findings() -> None:
    result = await _analyze("From: Apple <id@xn--pple-43d.com>\nReply-To: a@xn--mnchen-3ya.test")
    punycode = [f for f in result.findings if f.id == "punycode_domain"]
    severities = {f.evidence["domain"]: f.severity for f in punycode}
    assert severities == {"xn--pple-43d.com": Severity.HIGH, "xn--mnchen-3ya.test": Severity.MEDIUM}
    assert _ids(result)["lookalike_domain"].evidence["decoded"] == "аpple.com"


async def test_no_lookalike_for_genuine_sender() -> None:
    result = await _analyze("From: Microsoft <no-reply@accountprotection.microsoft.com>")
    assert result.findings == []
    assert result.raw["lookalikes"] == {}
