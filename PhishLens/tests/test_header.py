"""Tests for phishlens.analyzers.header (Authentication-Results trust checks and SPF).

DNS is always faked: every test starts with an empty ``fake_dns`` table (all NXDOMAIN)."""

from __future__ import annotations

import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path

import dkim
import dns.exception
import pytest

from phishlens.analyzers import header
from phishlens.config import get_settings
from phishlens.models import ParsedEmail, ReceivedHop, Severity
from phishlens.parser import parse_email

FIXTURES = Path(__file__).parent / "fixtures"
ALL_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.eml"))


@pytest.fixture(autouse=True)
def settings_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fake_dns) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("TRUSTED_AUTHSERV_IDS", raising=False)
    monkeypatch.delenv("TRUSTED_INTERNAL_HOSTS", raising=False)
    monkeypatch.delenv("TRUSTED_ARC_SEALERS", raising=False)
    monkeypatch.delenv("DKIM_MAX_AGE_DAYS", raising=False)
    get_settings.cache_clear()
    fake_dns({})
    yield
    get_settings.cache_clear()


def _trust(monkeypatch: pytest.MonkeyPatch, ids: str) -> None:
    monkeypatch.setenv("TRUSTED_AUTHSERV_IDS", ids)
    get_settings.cache_clear()


def _fixture(name: str) -> ParsedEmail:
    return parse_email((FIXTURES / name).read_bytes())


def _forged(result) -> list:
    return [f for f in result.findings if f.id == "forged_auth_results_header"]


async def test_fixture_2_untrusted_authserv_id_is_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    _trust(monkeypatch, "mx.ourcompany.example")
    result = await header.analyze(_fixture("spoof_unaligned.eml"))

    assert result.errors == []
    [finding] = _forged(result)
    assert finding.severity == Severity.MEDIUM
    assert finding.module == "header"
    assert finding.evidence["authserv_id"] == "mx.recipient.example"
    assert "dmarc=fail" in finding.evidence["header"]
    assert result.raw["trusted_auth_results"] == []


async def test_fixture_2_trusted_authserv_id_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    _trust(monkeypatch, "MX.Recipient.Example")
    result = await header.analyze(_fixture("spoof_unaligned.eml"))

    assert _forged(result) == []
    [entry] = result.raw["auth_results"]
    assert entry["trusted"] is True
    methods = {r["method"]: r for r in result.raw["trusted_auth_results"]}
    assert methods["spf"]["result"] == "pass"
    assert methods["spf"]["properties"] == {"smtp.mailfrom": "zetatech.xyz"}
    assert methods["dmarc"]["result"] == "fail"
    assert methods["dmarc"]["properties"] == {"header.from": "microsoft.com"}


async def test_empty_trust_list_skips_forgery_check() -> None:
    result = await header.analyze(_fixture("spoof_unaligned.eml"))
    assert _forged(result) == []
    assert result.raw["trusted_authserv_ids_configured"] is False
    assert result.raw["auth_results"][0]["trusted"] is False
    assert result.raw["trusted_auth_results"] == []


async def test_only_untrusted_headers_are_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    _trust(monkeypatch, "mx.trusted.test")
    email = ParsedEmail(
        auth_results_headers=[
            "mx.trusted.test; spf=fail smtp.mailfrom=bad.test",
            "attacker.test; spf=pass smtp.mailfrom=bad.test; dkim=pass header.d=bank.test",
        ]
    )
    result = await header.analyze(email)
    [finding] = _forged(result)
    assert finding.evidence["authserv_id"] == "attacker.test"
    assert [r["result"] for r in result.raw["trusted_auth_results"]] == ["fail"]


async def test_unparseable_header_is_untrusted(monkeypatch: pytest.MonkeyPatch) -> None:
    _trust(monkeypatch, "mx.trusted.test")
    result = await header.analyze(ParsedEmail(auth_results_headers=["garbage;;"]))
    [entry] = result.raw["auth_results"]
    assert entry["parse_error"] and entry["authserv_id"] is None
    [finding] = _forged(result)
    assert finding.evidence["header"] == "garbage;;"
    assert result.errors == []


async def test_no_headers() -> None:
    result = await header.analyze(ParsedEmail())
    assert [f.id for f in result.findings] == ["dkim_none"] and result.errors == []
    assert result.raw["auth_results"] == []


async def test_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> None:
        raise RuntimeError("settings exploded")

    monkeypatch.setattr(header, "get_settings", boom)
    result = await header.analyze(_fixture("spoof_unaligned.eml"))
    assert result.errors and "settings exploded" in result.errors[0]


@pytest.mark.parametrize("name", ALL_FIXTURES)
async def test_every_fixture_analyzes_without_errors(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    _trust(monkeypatch, "mx.recipient.example")
    result = await header.analyze(_fixture(name))
    assert result.errors == []
    assert result.raw["auth_results"]
    assert "spf" in result.raw


# --- SPF -----------------------------------------------------------------------------------------

SPOOF_IP = "203.0.113.45"


SPF_RESULT_IDS = {"spf_fail", "spf_softfail", "spf_none", "spf_error"}


def _spf(result) -> list:
    return [f for f in result.findings if f.id in SPF_RESULT_IDS]


@pytest.mark.parametrize(
    ("record", "expected", "finding_id", "severity"),
    [
        ("v=spf1 ip4:203.0.113.45 -all", "pass", None, None),
        ("v=spf1 ip4:192.0.2.1 -all", "fail", "spf_fail", Severity.HIGH),
        ("v=spf1 ip4:192.0.2.1 ~all", "softfail", "spf_softfail", Severity.MEDIUM),
        ("v=spf1 ?all", "neutral", None, None),
        ("v=spf1 ip4:192.0.2.1 bad:mech -all", "permerror", "spf_error", Severity.LOW),
    ],
)
async def test_fixture_2_spf_results(
    fake_dns, record: str, expected: str, finding_id: str | None, severity: Severity | None
) -> None:
    fake_dns({("zetatech.xyz", "TXT"): [record]})
    result = await header.analyze(_fixture("spoof_unaligned.eml"))

    assert result.errors == []
    spf = result.raw["spf"]
    assert spf["result"] == expected
    assert spf["domain"] == "zetatech.xyz"
    assert spf["identity"] == "mailfrom"
    assert spf["ip"] == SPOOF_IP
    assert spf["helo"] == "mail.zetatech.xyz"
    findings = _spf(result)
    if finding_id is None:
        assert findings == []
    else:
        [finding] = findings
        assert (finding.id, finding.severity) == (finding_id, severity)
        assert finding.evidence["domain"] == "zetatech.xyz"
        assert finding.evidence["ip"] == SPOOF_IP


async def test_spf_none_when_no_record() -> None:
    result = await header.analyze(_fixture("spoof_unaligned.eml"))
    assert result.raw["spf"]["result"] == "none"
    [finding] = _spf(result)
    assert finding.id == "spf_none" and finding.severity == Severity.LOW


async def test_spf_temperror_is_spf_error(fake_dns) -> None:
    fake_dns({("zetatech.xyz", "TXT"): dns.exception.Timeout()})
    result = await header.analyze(_fixture("spoof_unaligned.eml"))
    assert result.raw["spf"]["result"] == "temperror"
    [finding] = _spf(result)
    assert finding.id == "spf_error"


async def test_spf_falls_back_to_helo_without_return_path(fake_dns) -> None:
    fake_dns({("mail.zetatech.xyz", "TXT"): ["v=spf1 ip4:203.0.113.45 -all"]})
    email = _fixture("spoof_unaligned.eml").model_copy(update={"return_path": None})
    result = await header.analyze(email)
    spf = result.raw["spf"]
    assert (spf["result"], spf["identity"], spf["domain"]) == ("pass", "helo", "mail.zetatech.xyz")


async def test_spf_uses_ip_behind_trusted_internal_hosts(
    monkeypatch: pytest.MonkeyPatch, fake_dns
) -> None:
    monkeypatch.setenv("TRUSTED_INTERNAL_HOSTS", "203.0.113.0/24")
    get_settings.cache_clear()
    result = await header.analyze(_fixture("spoof_unaligned.eml"))
    assert result.raw["spf"] == {"result": None, "skipped_reason": "no_originating_ip"}
    assert _spf(result) == []


async def test_spf_skipped_without_identity() -> None:
    email = ParsedEmail(received_chain=[ReceivedHop(from_host="[203.0.113.45]", ip=SPOOF_IP)])
    result = await header.analyze(email)
    assert result.raw["spf"] == {"result": None, "ip": SPOOF_IP, "skipped_reason": "no_identity"}
    assert _spf(result) == []


# --- DKIM ----------------------------------------------------------------------------------------

DKIM_KEY_NAME = ("sel._domainkey.signer.test", "TXT")


def _message(
    received_at: datetime | None = None, return_path: str | None = None
) -> bytes:
    received_at = received_at or datetime.now(UTC)
    rp = f"Return-Path: <{return_path}>\r\n".encode() if return_path else b""
    return (
        rp
        + b"Received: from mail.signer.test ([198.51.100.20]) by mx.recipient.test; "
        + format_datetime(received_at).encode()
        + b"\r\nFrom: Alice <alice@signer.test>\r\n"
        b"To: bob@recipient.test\r\n"
        b"Subject: Quarterly report\r\n"
        b"Message-ID: <1@signer.test>\r\n"
        b"\r\n"
        b"Hello Bob,\r\nthe report is ready.\r\n"
    )


def _dkim(result) -> dict:
    return {f.id: f for f in result.findings if f.id.startswith("dkim_")}


@pytest.fixture
def dkim_dns(fake_dns, dkim_key):
    return fake_dns({DKIM_KEY_NAME: [dkim_key.dns_record]})


async def test_dkim_valid_signature_has_no_findings(dkim_dns, dkim_key) -> None:
    result = await header.analyze(parse_email(dkim_key.sign(_message())))
    assert result.errors == []
    assert _dkim(result) == {}
    [sig] = result.raw["dkim"]["signatures"]
    assert (sig["domain"], sig["status"], sig["valid"]) == ("signer.test", "pass", True)


async def test_dkim_tampered_body_is_invalid(dkim_dns, dkim_key) -> None:
    signed = dkim_key.sign(_message()).replace(b"report is ready", b"account is locked")
    findings = _dkim(await header.analyze(parse_email(signed)))
    assert list(findings) == ["dkim_invalid"]
    finding = findings["dkim_invalid"]
    assert finding.severity == Severity.MEDIUM
    [sig] = finding.evidence["signatures"]
    assert (sig["domain"], sig["status"]) == ("signer.test", "fail")


async def test_dkim_invalid_is_low_when_another_signature_passes(dkim_dns, dkim_key) -> None:
    signed = dkim_key.sign(dkim_key.sign(_message()), domain="nokey.test")
    findings = _dkim(await header.analyze(parse_email(signed)))
    assert findings["dkim_invalid"].severity == Severity.LOW
    assert findings["dkim_invalid"].evidence["signatures"][0]["domain"] == "nokey.test"


async def test_dkim_body_length_tag(dkim_dns, dkim_key) -> None:
    signed = dkim_key.sign(_message(), length=True) + b"Click here: http://evil.test/\r\n"
    findings = _dkim(await header.analyze(parse_email(signed)))
    assert list(findings) == ["dkim_body_length_tag"]
    assert findings["dkim_body_length_tag"].severity == Severity.MEDIUM
    assert findings["dkim_body_length_tag"].evidence["signatures"][0]["body_length"] > 0


async def test_dkim_unsigned_critical_headers(dkim_dns, dkim_key) -> None:
    signed = dkim_key.sign(_message(), include_headers=[b"from", b"message-id"])
    findings = _dkim(await header.analyze(parse_email(signed)))
    [sig] = findings["dkim_unsigned_critical_headers"].evidence["signatures"]
    assert sig["missing"] == ["subject", "to"]


async def test_dkim_old_signature_is_flagged(
    dkim_dns, dkim_key, monkeypatch: pytest.MonkeyPatch
) -> None:
    signed_at = time.time() - 30 * 86400
    with monkeypatch.context() as m:
        m.setattr(dkim.time, "time", lambda: signed_at)
        signed = dkim_key.sign(_message())
    email = parse_email(signed)

    findings = _dkim(await header.analyze(email))
    [sig] = findings["dkim_expired_or_old"].evidence["signatures"]
    assert sig["reason"] == "old"
    assert 29.9 < sig["age_days"] < 30.1

    monkeypatch.setenv("DKIM_MAX_AGE_DAYS", "60")
    get_settings.cache_clear()
    assert "dkim_expired_or_old" not in _dkim(await header.analyze(email))


async def test_dkim_age_uses_delivery_time(dkim_dns, dkim_key) -> None:
    """An old message analyzed today is not a replay: age is measured at delivery."""
    delivered = datetime.now(UTC) - timedelta(days=365)
    signed = dkim_key.sign(_message(received_at=delivered))
    # Signed "now", delivered a year ago: negative age, so not old.
    assert "dkim_expired_or_old" not in _dkim(await header.analyze(parse_email(signed)))


async def test_dkim_expired_signature(fake_dns) -> None:
    header_line = (
        b"DKIM-Signature: v=1; a=rsa-sha256; d=signer.test; s=sel; h=from:to:subject;\r\n"
        b" t=1000; x=2000; bh=AAAA; b=AAAA\r\n"
    )
    findings = _dkim(await header.analyze(parse_email(header_line + _message())))
    assert list(findings) == ["dkim_expired_or_old"]
    assert findings["dkim_expired_or_old"].evidence["signatures"][0]["reason"] == "expired"


async def test_dkim_none_on_unsigned_fixture() -> None:
    result = await header.analyze(_fixture("spoof_unaligned.eml"))
    assert _dkim(result)["dkim_none"].severity == Severity.LOW
    assert result.raw["dkim"]["signatures"] == []


async def test_dkim_skipped_without_raw_bytes() -> None:
    email = ParsedEmail(headers=[("DKIM-Signature", "v=1; d=signer.test")])
    result = await header.analyze(email)
    assert result.raw["dkim"]["skipped_reason"] == "no_raw_message"
    assert _dkim(result) == {}


# --- DMARC and alignment -------------------------------------------------------------------------

ALIGNMENT_IDS = {
    "spf_pass_unaligned",
    "dkim_pass_unaligned",
    "auth_but_unaligned",
    "dmarc_fail",
    "dmarc_none_record",
    "dmarc_policy_none",
}


def _dmarc(result) -> dict:
    return {f.id: f for f in result.findings if f.id in ALIGNMENT_IDS}


async def test_fixture_2_zetatech_spoofing_microsoft_is_critical(fake_dns) -> None:
    fake_dns(
        {
            ("zetatech.xyz", "TXT"): ["v=spf1 ip4:203.0.113.0/24 -all"],
            ("_dmarc.microsoft.com", "TXT"): ["v=DMARC1; p=reject"],
        }
    )
    result = await header.analyze(_fixture("spoof_unaligned.eml"))

    assert result.errors == []
    findings = _dmarc(result)
    assert set(findings) == {"spf_pass_unaligned", "auth_but_unaligned", "dmarc_fail"}
    assert findings["auth_but_unaligned"].severity == Severity.CRITICAL
    assert findings["auth_but_unaligned"].evidence["spf_domain"] == "zetatech.xyz"
    assert findings["spf_pass_unaligned"].severity == Severity.HIGH
    assert findings["dmarc_fail"].evidence["policy"] == "reject"

    dmarc = result.raw["dmarc"]
    assert (dmarc["result"], dmarc["spf_aligned"], dmarc["auth_but_unaligned"]) == (
        "fail",
        False,
        True,
    )
    assert result.raw["auth_summary"] == [
        {"mechanism": "spf", "result": "pass", "domain": "zetatech.xyz", "aligned": False},
        {"mechanism": "dkim", "result": "none", "domain": None, "aligned": False},
        {"mechanism": "dmarc", "result": "fail", "domain": "microsoft.com", "aligned": False},
    ]


async def test_auth_but_unaligned_even_without_dmarc_record(fake_dns) -> None:
    fake_dns({("zetatech.xyz", "TXT"): ["v=spf1 ip4:203.0.113.0/24 -all"]})
    findings = _dmarc(await header.analyze(_fixture("spoof_unaligned.eml")))
    assert set(findings) == {"spf_pass_unaligned", "auth_but_unaligned", "dmarc_none_record"}


async def test_fully_aligned_pass(fake_dns, dkim_key) -> None:
    fake_dns(
        {
            DKIM_KEY_NAME: [dkim_key.dns_record],
            ("signer.test", "TXT"): ["v=spf1 ip4:198.51.100.20 -all"],
            ("_dmarc.signer.test", "TXT"): ["v=DMARC1; p=reject"],
        }
    )
    signed = dkim_key.sign(_message(return_path="bounce@signer.test"))
    result = await header.analyze(parse_email(signed))

    assert _dmarc(result) == {}
    dmarc = result.raw["dmarc"]
    assert dmarc["result"] == "pass"
    assert dmarc["spf_aligned"] and dmarc["dkim_aligned"] and dmarc["dmarc_pass"]
    assert all(row["aligned"] for row in result.raw["auth_summary"])


async def test_esp_spf_unaligned_but_dkim_aligned_passes(fake_dns, dkim_key) -> None:
    """Normal ESP mail: SPF passes for the ESP bounce domain, DKIM aligns with From."""
    fake_dns(
        {
            DKIM_KEY_NAME: [dkim_key.dns_record],
            ("esp.test", "TXT"): ["v=spf1 ip4:198.51.100.0/24 -all"],
            ("_dmarc.signer.test", "TXT"): ["v=DMARC1; p=reject"],
        }
    )
    signed = dkim_key.sign(_message(return_path="bounces+123@esp.test"))
    result = await header.analyze(parse_email(signed))

    assert _dmarc(result) == {}
    assert result.raw["dmarc"]["result"] == "pass"
    spf_row = result.raw["auth_summary"][0]
    assert (spf_row["result"], spf_row["domain"], spf_row["aligned"]) == (
        "pass",
        "esp.test",
        False,
    )


async def test_p_none_spoof(fake_dns) -> None:
    fake_dns(
        {
            ("signer.test", "TXT"): ["v=spf1 ip4:192.0.2.1 -all"],
            ("_dmarc.signer.test", "TXT"): ["v=DMARC1; p=none"],
        }
    )
    result = await header.analyze(parse_email(_message(return_path="bounce@signer.test")))
    findings = _dmarc(result)
    assert set(findings) == {"dmarc_fail", "dmarc_policy_none"}
    assert findings["dmarc_policy_none"].severity == Severity.LOW
    assert result.raw["dmarc"]["policy"] == "none"
    assert result.raw["spf"]["result"] == "fail"


@pytest.mark.parametrize(("adkim", "aligned"), [("s", False), ("r", True)])
async def test_strict_alignment_with_subdomain(
    fake_dns, dkim_key, adkim: str, aligned: bool
) -> None:
    fake_dns(
        {
            ("sel._domainkey.mail.signer.test", "TXT"): [dkim_key.dns_record],
            ("_dmarc.signer.test", "TXT"): [f"v=DMARC1; p=reject; adkim={adkim}"],
        }
    )
    signed = dkim_key.sign(_message(), domain="mail.signer.test")
    result = await header.analyze(parse_email(signed))

    assert result.raw["dmarc"]["dkim_aligned"] is aligned
    findings = _dmarc(result)
    if aligned:
        assert findings == {}
    else:
        assert set(findings) == {"dkim_pass_unaligned", "auth_but_unaligned", "dmarc_fail"}
        assert findings["dkim_pass_unaligned"].evidence["dkim_domains"] == ["mail.signer.test"]


async def test_dmarc_dns_error_gives_temperror_without_policy_findings(fake_dns) -> None:
    fake_dns({("_dmarc.microsoft.com", "TXT"): dns.exception.Timeout()})
    result = await header.analyze(_fixture("spoof_unaligned.eml"))
    assert result.raw["dmarc"]["result"] == "temperror"
    assert _dmarc(result) == {}


async def test_dmarc_skipped_without_from() -> None:
    result = await header.analyze(ParsedEmail())
    assert result.raw["dmarc"] == {"result": None, "skipped_reason": "no_from_domain"}
    assert "auth_summary" not in result.raw


# --- ESP, ARC, parser warnings and header verdict -------------------------------------------------


def _ids(result) -> dict:
    return {f.id: f for f in result.findings}


def _verdict(result) -> str:
    return result.raw["header_verdict"]["verdict"]


async def test_esp_unaligned_names_the_esp(fake_dns) -> None:
    fake_dns(
        {
            ("sendgrid.net", "TXT"): ["v=spf1 ip4:198.51.100.0/24 -all"],
            ("_dmarc.signer.test", "TXT"): ["v=DMARC1; p=reject"],
        }
    )
    result = await header.analyze(parse_email(_message(return_path="bounces@sendgrid.net")))
    finding = _ids(result)["esp_unaligned"]
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["esps"] == ["SendGrid"]
    assert finding.evidence["domains"] == ["sendgrid.net"]
    assert _verdict(result) == "spoofing"


async def test_no_esp_finding_for_non_esp_domain(fake_dns) -> None:
    fake_dns({("zetatech.xyz", "TXT"): ["v=spf1 ip4:203.0.113.0/24 -all"]})
    result = await header.analyze(_fixture("spoof_unaligned.eml"))
    assert "esp_unaligned" not in _ids(result)


async def test_no_esp_finding_when_dmarc_passes(fake_dns, dkim_key) -> None:
    fake_dns(
        {
            DKIM_KEY_NAME: [dkim_key.dns_record],
            ("sendgrid.net", "TXT"): ["v=spf1 ip4:198.51.100.0/24 -all"],
        }
    )
    signed = dkim_key.sign(_message(return_path="bounces@sendgrid.net"))
    result = await header.analyze(parse_email(signed))
    assert "esp_unaligned" not in _ids(result)
    assert _verdict(result) == "ok"


def _forwarded(dkim_key, aar_dmarc: str = "pass") -> bytes:
    """signer.test signs, a list at fwd.test adds a footer (breaking DKIM), rewrites the envelope
    sender to its own domain (SPF passes for fwd.test) and ARC-seals what it received."""
    original = dkim_key.sign(_message(return_path="bounce@fwd.test"))
    modified = original + b"-- \r\nSent via the fwd.test list\r\n"
    ar = (
        b"Authentication-Results: lists.fwd.test; dkim=pass header.d=signer.test;\r\n"
        b" dmarc=" + aar_dmarc.encode() + b" header.from=signer.test\r\n"
    )
    return dkim_key.arc_sign(ar + modified, "fwd.test", "lists.fwd.test")


@pytest.fixture
def forward_dns(fake_dns, dkim_key):
    return fake_dns(
        {
            DKIM_KEY_NAME: [dkim_key.dns_record],
            ("arc._domainkey.fwd.test", "TXT"): [dkim_key.dns_record],
            ("fwd.test", "TXT"): ["v=spf1 ip4:198.51.100.0/24 -all"],
            ("_dmarc.signer.test", "TXT"): ["v=DMARC1; p=reject"],
        }
    )


def _trust_sealers(monkeypatch: pytest.MonkeyPatch, sealers: str) -> None:
    monkeypatch.setenv("TRUSTED_ARC_SEALERS", sealers)
    get_settings.cache_clear()


async def test_trusted_arc_forward_downgrades_findings(
    forward_dns, dkim_key, monkeypatch: pytest.MonkeyPatch
) -> None:
    _trust_sealers(monkeypatch, "fwd.test")
    result = await header.analyze(parse_email(_forwarded(dkim_key)))

    assert result.errors == []
    arc = result.raw["arc"]
    assert (arc["chain"], arc["sealer"], arc["trusted"]) == ("pass", "fwd.test", True)
    assert arc["original_dmarc"] == "pass"
    findings = _ids(result)
    for fid in ("dkim_invalid", "dmarc_fail", "spf_pass_unaligned", "auth_but_unaligned"):
        assert findings[fid].severity == Severity.LOW, fid
        assert findings[fid].evidence["downgraded_by"] == "arc_trusted_forward"
    forward = findings["arc_trusted_forward"]
    assert forward.severity == Severity.INFO
    assert set(forward.evidence["downgraded"]) >= {"dkim_invalid", "auth_but_unaligned"}
    assert _verdict(result) == "likely_forward"


async def test_untrusted_arc_sealer_changes_nothing(forward_dns, dkim_key) -> None:
    result = await header.analyze(parse_email(_forwarded(dkim_key)))
    assert result.raw["arc"]["chain"] == "pass"
    assert result.raw["arc"]["trusted"] is False
    findings = _ids(result)
    assert findings["auth_but_unaligned"].severity == Severity.CRITICAL
    assert "arc_trusted_forward" not in findings
    assert _verdict(result) == "spoofing"


async def test_trusted_arc_without_original_dmarc_pass_keeps_spoofing(
    forward_dns, dkim_key, monkeypatch: pytest.MonkeyPatch
) -> None:
    _trust_sealers(monkeypatch, "fwd.test")
    result = await header.analyze(parse_email(_forwarded(dkim_key, aar_dmarc="fail")))
    findings = _ids(result)
    assert findings["dkim_invalid"].severity == Severity.LOW
    assert findings["auth_but_unaligned"].severity == Severity.CRITICAL
    assert _verdict(result) == "spoofing"


async def test_broken_arc_chain_is_not_trusted(
    forward_dns, dkim_key, monkeypatch: pytest.MonkeyPatch
) -> None:
    _trust_sealers(monkeypatch, "fwd.test")
    tampered = _forwarded(dkim_key).replace(b"the report is ready", b"wire the money")
    result = await header.analyze(parse_email(tampered))
    assert result.raw["arc"]["chain"] == "fail"
    assert result.raw["arc"]["trusted"] is False
    assert "arc_trusted_forward" not in _ids(result)


async def test_multiple_from_headers_finding() -> None:
    finding = _ids(await header.analyze(_fixture("duplicate_from.eml")))["multiple_from_headers"]
    assert finding.severity == Severity.HIGH
    assert finding.evidence["warnings"] == ["multiple_from_headers: 2 From headers found"]


async def test_display_name_contains_address_finding() -> None:
    result = await header.analyze(_fixture("display_name_trick.eml"))
    finding = _ids(result)["display_name_contains_address"]
    assert finding.severity == Severity.MEDIUM
    assert "ceo@company.com" in finding.evidence["warnings"][0]


async def test_received_chain_anomaly_finding() -> None:
    raw = (
        b"Received: from b.test ([198.51.100.2]) by mx.test; Mon, 07 Sep 2026 08:00:00 +0000\r\n"
        b"Received: from a.test ([198.51.100.1]) by b.test; Mon, 07 Sep 2026 09:00:00 +0000\r\n"
        b"From: x@a.test\r\nSubject: hi\r\n\r\nbody\r\n"
    )
    finding = _ids(await header.analyze(parse_email(raw)))["received_chain_anomaly"]
    assert finding.severity == Severity.LOW
    assert finding.evidence["warnings"][0].startswith("received_out_of_order")


async def test_verdict_fail_with_enforced_policy(fake_dns) -> None:
    fake_dns(
        {
            ("signer.test", "TXT"): ["v=spf1 ip4:192.0.2.1 -all"],
            ("_dmarc.signer.test", "TXT"): ["v=DMARC1; p=reject"],
        }
    )
    result = await header.analyze(parse_email(_message(return_path="bounce@signer.test")))
    assert result.raw["header_verdict"] == {
        "verdict": "fail",
        "risk": "high",
        "reason": "authentication failed (DMARC policy reject)",
    }


@pytest.mark.parametrize("record", [None, "v=DMARC1; p=none"])
async def test_verdict_fail_policy_none(fake_dns, record: str | None) -> None:
    answers = {("signer.test", "TXT"): ["v=spf1 ip4:192.0.2.1 -all"]}
    if record:
        answers[("_dmarc.signer.test", "TXT")] = [record]
    fake_dns(answers)
    result = await header.analyze(parse_email(_message(return_path="bounce@signer.test")))
    assert _verdict(result) == "fail_policy_none"
    assert result.raw["header_verdict"]["risk"] == "critical"


async def test_verdict_spoofing_on_fixture_2(fake_dns) -> None:
    fake_dns({("zetatech.xyz", "TXT"): ["v=spf1 ip4:203.0.113.0/24 -all"]})
    result = await header.analyze(_fixture("spoof_unaligned.eml"))
    assert result.raw["header_verdict"]["verdict"] == "spoofing"
    assert result.raw["header_verdict"]["risk"] == "critical"


async def test_verdict_unknown(fake_dns) -> None:
    assert _verdict(await header.analyze(ParsedEmail())) == "unknown"
    fake_dns({("_dmarc.signer.test", "TXT"): dns.exception.Timeout()})
    result = await header.analyze(parse_email(_message()))
    assert result.raw["header_verdict"] == {
        "verdict": "unknown",
        "risk": "unknown",
        "reason": "DMARC record lookup failed",
    }


@pytest.mark.parametrize("name", ALL_FIXTURES)
async def test_every_fixture_gets_a_verdict_and_never_raises(name: str) -> None:
    result = await header.analyze(_fixture(name))
    assert result.errors == []
    assert result.raw["header_verdict"]["verdict"] in {
        "ok",
        "spoofing",
        "fail",
        "fail_policy_none",
        "likely_forward",
        "unknown",
    }
    assert result.raw["arc"]["chain"] == "none"
