"""Tests for phishlens.analyzers.tone (rule layer)."""

from __future__ import annotations

from pathlib import Path

import pytest

from phishlens.analyzers import tone
from phishlens.analyzers.tone import match_lexicons, normalize_text
from phishlens.models import Address, AnalyzerResult, ParsedEmail, Severity
from phishlens.parser import parse_email

FIXTURES = Path(__file__).parent / "fixtures"
ALL_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.eml"))


def _ids(result) -> dict:
    return {f.id: f for f in result.findings}


async def _text(body: str, subject: str = "") -> dict:
    return _ids(await tone.analyze(ParsedEmail(subject=subject, text_body=body)))


async def test_fixture_6_urgency_and_credential_request() -> None:
    result = await tone.analyze(parse_email((FIXTURES / "lookalike_domain.eml").read_bytes()))
    findings = _ids(result)
    urgency = findings["tone_urgency"]
    assert urgency.severity == Severity.MEDIUM
    assert {"urgent", "action required", "immediately"} <= {
        m["phrase"] for m in urgency.evidence["matches"]
    }
    credential = findings["credential_request"]
    assert credential.severity == Severity.HIGH
    assert "reset your password" in {m["phrase"] for m in credential.evidence["matches"]}
    assert "tone_fear" in findings
    text = result.raw["normalized_text"]
    for _category, phrase, start, end in result.raw["highlights"]:
        assert " ".join(text[start:end].split()) == phrase


def test_normalize_text() -> None:
    raw = "URGENT​:  Verify\tYOUR account\n\n\n  Now  "
    assert normalize_text(raw) == "urgent: verify your account\nnow"


@pytest.mark.parametrize(
    ("body", "finding_id"),
    [
        ("Please act now, this offer expires today.", "tone_urgency"),
        ("Your mailbox has been suspended due to unusual activity.", "tone_fear"),
        ("Congratulations! You have won a cash reward of $1,000,000.", "tone_greed"),
        ("This notice comes from the IT Department helpdesk.", "tone_authority"),
        ("Click here to verify your account and enter your password.", "credential_request"),
        ("Please wire transfer the amount to our updated bank details.", "payment_request"),
        ("I need a quick favour. Keep this confidential, I am in a meeting.", "secrecy_request"),
        ("Dear Customer,\nyour statement is ready.", "generic_greeting"),
        ("Please buy 5 gift cards and send me the codes.", "payment_request"),
    ],
)
async def test_categories(body: str, finding_id: str) -> None:
    assert finding_id in await _text(body)


@pytest.mark.parametrize(
    ("body", "finding_id"),
    [
        ("Aapka khata band ho jayega, turant KYC update karein.", "tone_fear"),
        ("Aapka khata band ho jayega, turant KYC update karein.", "tone_urgency"),
        ("Aapka khata band ho jayega, turant KYC update karein.", "credential_request"),
        ("प्रिय ग्राहक, आपका खाता बंद हो जाएगा। तुरंत पासवर्ड अपडेट करें।", "generic_greeting"),
        ("प्रिय ग्राहक, आपका खाता बंद हो जाएगा। तुरंत पासवर्ड अपडेट करें।", "tone_urgency"),
        ("प्रिय ग्राहक, आपका खाता बंद हो जाएगा। तुरंत पासवर्ड अपडेट करें।", "credential_request"),
        ("Kisi ko na batayein, UPI id par paisa bhejein.", "secrecy_request"),
        ("Kisi ko na batayein, UPI id par paisa bhejein.", "payment_request"),
    ],
)
async def test_hindi_and_hinglish(body: str, finding_id: str) -> None:
    assert finding_id in await _text(body)


async def test_clean_text_has_no_findings() -> None:
    findings = await _text(
        "Hi Priya,\nthe minutes from Tuesday's planning meeting are attached.\nThanks, Arun"
    )
    assert findings == {}


def test_whole_word_matching() -> None:
    assert "urgency" not in match_lexicons("the insurgent group")  # not "urgent"
    assert "credential_request" not in match_lexicons("botpress logs")  # not "otp"
    assert "urgency" in match_lexicons("urgent!")


def test_longest_overlapping_match_wins() -> None:
    [(phrase, _, _)] = match_lexicons("your account will be suspended")["fear"]
    assert phrase == "account will be suspended"


async def test_cap_and_counts() -> None:
    body = "urgent. immediately. act now. asap. final notice. last chance. deadline. right away."
    urgency = (await _text(body))["tone_urgency"]
    assert urgency.evidence["count"] == 8
    assert urgency.evidence["counted"] == 5 and urgency.evidence["cap"] == 5


async def test_snippets_are_defanged() -> None:
    result = await _text("Verify your account now at https://evil.example.test/login please.")
    snippet = result["credential_request"].evidence["matches"][0]["snippet"]
    assert "hxxps://evil[.]example[.]test/login" in snippet
    assert "https://" not in snippet


async def test_html_only_body_uses_visible_text() -> None:
    email = ParsedEmail(html_body="<p>Dear user,</p><p>Please <b>verify your account</b></p>")
    findings = _ids(await tone.analyze(email))
    assert {"generic_greeting", "credential_request"} <= set(findings)


# --- Brand mentions and identity binding --------------------------------------------------------


def _sender(domain: str) -> list[Address]:
    return [Address(address=f"x@{domain}", domain=domain, org_domain=domain)]


def _header_context(aligned: bool) -> AnalyzerResult:
    summary = [{"mechanism": "dmarc", "result": "pass", "domain": "x", "aligned": aligned}]
    return AnalyzerResult(module="header", raw={"auth_summary": summary})


async def test_body_brand_from_unrelated_sender_is_impersonation() -> None:
    email = ParsedEmail(
        from_addrs=_sender("billing-center.test"),
        text_body="Your PayPal account needs attention.",
    )
    result = await tone.analyze(email, {"header": _header_context(True)})
    finding = _ids(result)["brand_impersonation"]
    assert finding.module == "tone"
    assert finding.severity == Severity.MEDIUM  # body-only claims are weak
    assert finding.evidence["claimed_in"] == ["body"]
    assert result.raw["body_brands"] == ["PayPal"]


async def test_brand_already_claimed_by_domain_analyzer_is_skipped() -> None:
    domain_result = AnalyzerResult(
        module="domain",
        raw={"identity": {"claimed_brands": {"PayPal": ["display_name"]}}, "lookalikes": {}},
    )
    email = ParsedEmail(
        from_addrs=_sender("billing-center.test"),
        subject="PayPal notice",
        text_body="Your PayPal account needs attention.",
    )
    result = await tone.analyze(email, {"domain": domain_result})
    assert "brand_impersonation" not in _ids(result)


async def test_genuine_brand_sender_is_fine() -> None:
    email = ParsedEmail(
        from_addrs=_sender("paypal.com"), text_body="Your PayPal receipt is attached."
    )
    result = await tone.analyze(email, {"header": _header_context(True)})
    assert "brand_impersonation" not in _ids(result)


async def test_new_domain_from_domain_context_makes_it_critical() -> None:
    domain_result = AnalyzerResult(
        module="domain",
        raw={"identity": {"claimed_brands": {}}, "lookalikes": {}, "new_domains": ["fresh.test"]},
    )
    email = ParsedEmail(from_addrs=_sender("fresh.test"), text_body="Netflix: update billing.")
    result = await tone.analyze(email, {"domain": domain_result})
    assert _ids(result)["brand_impersonation"].severity == Severity.CRITICAL


async def test_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(text: str) -> dict:
        raise RuntimeError("lexicon exploded")

    monkeypatch.setattr(tone, "match_lexicons", boom)
    result = await tone.analyze(ParsedEmail(text_body="urgent"))
    assert result.errors == ["rules: RuntimeError: lexicon exploded"]


@pytest.mark.parametrize("name", ALL_FIXTURES)
async def test_every_fixture(name: str) -> None:
    result = await tone.analyze(parse_email((FIXTURES / name).read_bytes()))
    assert result.errors == []
