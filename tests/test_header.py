"""Tests for phishlens.analyzers.header (Authentication-Results trust checks and SPF).

DNS is always faked: every test starts with an empty ``fake_dns`` table (all NXDOMAIN)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

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
    assert result.findings == [] and result.errors == []
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


def _spf(result) -> list:
    return [f for f in result.findings if f.id.startswith("spf_")]


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
