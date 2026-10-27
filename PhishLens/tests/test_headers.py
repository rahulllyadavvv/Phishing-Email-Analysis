"""Tests for phishlens.parser.headers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from phishlens.ingest.loader import MSG_NO_TRANSPORT_HEADERS, PARSE_WARNING_HEADER
from phishlens.parser.headers import make_address, org_domain, parse_headers

FIXTURES = Path(__file__).parent / "fixtures"


def _codes(warnings: list[str]) -> list[str]:
    return [w.split(":", 1)[0] for w in warnings]


def _fixture(name: str):
    return parse_headers((FIXTURES / name).read_bytes())


# --- fixture 2: spoof_unaligned ---


def test_spoof_unaligned_addresses() -> None:
    parsed = _fixture("spoof_unaligned.eml")
    assert parsed.parse_warnings == []
    [sender] = parsed.from_addrs
    assert sender.display_name == "Microsoft Account Team"
    assert sender.address == "account-security@microsoft.com"
    assert sender.org_domain == "microsoft.com"
    assert parsed.return_path is not None
    assert parsed.return_path.address == "mailer@zetatech.xyz"
    assert parsed.return_path.org_domain == "zetatech.xyz"
    assert [a.address for a in parsed.to] == ["victim@recipient.example"]
    assert parsed.subject == "Unusual sign-in activity on your account"
    assert parsed.date == datetime(2026, 9, 7, 9, 0, tzinfo=UTC)
    assert parsed.message_id == "<spoof-unaligned-0002@phishlens.test>"
    assert len(parsed.sha256) == 64


def test_spoof_unaligned_keeps_header_order_and_unfolds() -> None:
    parsed = _fixture("spoof_unaligned.eml")
    names = [n for n, _ in parsed.headers]
    assert names[:4] == ["Return-Path", "Received", "Authentication-Results", "From"]
    received = dict(parsed.headers)["Received"]
    assert "\n" not in received
    assert "203.0.113.45" in received


# --- fixture 3: display_name_trick ---


def test_display_name_trick_warns() -> None:
    parsed = _fixture("display_name_trick.eml")
    assert "display_name_contains_email" in _codes(parsed.parse_warnings)
    [sender] = parsed.from_addrs
    assert sender.display_name == "ceo@company.com"
    assert sender.address == "attacker@evil-example.net"
    assert sender.domain == "evil-example.net"
    assert sender.org_domain == "evil-example.net"


# --- fixture 4: duplicate_from ---


def test_duplicate_from_warns_and_keeps_both() -> None:
    parsed = _fixture("duplicate_from.eml")
    assert "multiple_from_headers" in _codes(parsed.parse_warnings)
    assert [a.address for a in parsed.from_addrs] == [
        "billing@invoices.example",
        "helpdesk@recipient.example",
    ]
    from_headers = [v for n, v in parsed.headers if n.lower() == "from"]
    assert from_headers == [
        "Billing <billing@invoices.example>",
        "IT Helpdesk <helpdesk@recipient.example>",
    ]
    assert parsed.from_addrs[0].org_domain == "invoices.example"


# --- other warnings and edge cases ---


def test_multiple_addresses_in_one_from() -> None:
    parsed = parse_headers(b"From: a@one.example, b@two.example\nSubject: x\n\nbody\n")
    assert "multiple_from_addresses" in _codes(parsed.parse_warnings)
    assert "multiple_from_headers" not in _codes(parsed.parse_warnings)
    assert len(parsed.from_addrs) == 2


def test_missing_from() -> None:
    parsed = parse_headers(b"Subject: hi\nTo: x@y.example\n\nbody\n")
    assert _codes(parsed.parse_warnings) == ["missing_from"]
    assert parsed.from_addrs == []


def test_empty_from() -> None:
    parsed = parse_headers(b"From: \nSubject: hi\n\nbody\n")
    assert "empty_from" in _codes(parsed.parse_warnings)


def test_display_name_equal_to_address_is_not_flagged() -> None:
    parsed = parse_headers(b'From: "bob@example.com" <Bob@example.com>\n\nbody\n')
    assert "display_name_contains_email" not in _codes(parsed.parse_warnings)


def test_display_name_trick_in_reply_to() -> None:
    parsed = parse_headers(
        b"From: a@example.com\nReply-To: \"help@bank.example\" <x@evil.example>\n\nb\n"
    )
    assert any(
        w.startswith("display_name_contains_email: Reply-To") for w in parsed.parse_warnings
    )


def test_encoded_words_are_decoded() -> None:
    raw = (
        b"From: =?utf-8?B?SsO8cmdlbg==?= <j@example.com>\n"
        b"Subject: =?utf-8?Q?Caf=C3=A9_order?=\n\nbody\n"
    )
    parsed = parse_headers(raw)
    assert parsed.subject == "Café order"
    assert parsed.from_addrs[0].display_name == "Jürgen"
    assert parsed.parse_warnings == []


@pytest.mark.parametrize(
    "raw",
    [
        b"From: =?x-bogus?Q?abc?= <a@example.com>\nSubject: s\n\nb\n",
        b"From: a@example.com\nSubject: =?utf-8?B?!!!bad?=\n\nb\n",
        b"From: a@example.com\nSubject: caf\xff\xfe\n\nb\n",
    ],
)
def test_bad_encoding_never_crashes(raw: bytes) -> None:
    parsed = parse_headers(raw)
    assert any(
        w.startswith(("header_decode_error", "header_defect")) for w in parsed.parse_warnings
    )
    assert parsed.from_addrs[0].address == "a@example.com"


def test_garbage_input_never_crashes() -> None:
    parsed = parse_headers(b"\x00\xff\xfe not an email at all")
    assert "missing_from" in _codes(parsed.parse_warnings)


def test_sender_cc_and_null_return_path() -> None:
    raw = (
        b"Return-Path: <>\nFrom: a@example.com\nSender: Bot <bot@mail.example.co.uk>\n"
        b"Cc: c1@example.org, C Two <c2@example.org>\n\nb\n"
    )
    parsed = parse_headers(raw)
    assert parsed.return_path is None
    assert parsed.sender is not None
    assert parsed.sender.org_domain == "example.co.uk"
    assert [a.address for a in parsed.cc] == ["c1@example.org", "c2@example.org"]


def test_loader_warning_header_becomes_parse_warning() -> None:
    raw = f"{PARSE_WARNING_HEADER}: {MSG_NO_TRANSPORT_HEADERS}\nFrom: a@example.com\n\nb\n"
    parsed = parse_headers(raw.encode())
    assert parsed.parse_warnings == [MSG_NO_TRANSPORT_HEADERS]
    assert all(n != PARSE_WARNING_HEADER for n, _ in parsed.headers)


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("mail.example.co.uk", "example.co.uk"),
        ("Evil-Example.NET", "evil-example.net"),
        ("mx.recipient.example", "recipient.example"),
        ("phishlens.test", "phishlens.test"),
        ("[192.0.2.1]", "[192.0.2.1]"),
        ("192.0.2.1", "192.0.2.1"),
        ("", ""),
    ],
)
def test_org_domain(domain: str, expected: str) -> None:
    assert org_domain(domain) == expected


def test_make_address_without_at() -> None:
    addr = make_address("", "undisclosed-recipients")
    assert addr.domain == ""
    assert addr.org_domain == ""
