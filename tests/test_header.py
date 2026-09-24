"""Tests for phishlens.analyzers.header (Authentication-Results trust checks)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from phishlens.analyzers import header
from phishlens.config import get_settings
from phishlens.models import ParsedEmail, Severity
from phishlens.parser import parse_email

FIXTURES = Path(__file__).parent / "fixtures"
ALL_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.eml"))


@pytest.fixture(autouse=True)
def settings_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("TRUSTED_AUTHSERV_IDS", raising=False)
    get_settings.cache_clear()
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
