"""Tests for phishlens.parser.received."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from phishlens.models import ReceivedHop
from phishlens.parser.headers import parse_headers
from phishlens.parser.received import (
    is_internal_ip,
    originating_external_ip,
    parse_received,
    parse_received_chain,
    received_chain_from_headers,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _codes(warnings: list[str]) -> list[str]:
    return [w.split(":", 1)[0] for w in warnings]


# Header order (newest first), as in an email.
# Sender laptop (private) -> attacker relay -> our MX -> our internal filter -> our mailbox.
CHAIN_PRIVATE = [
    "from filter.recipient.example (filter.recipient.example [10.1.2.3]) by "
    "mbox.recipient.example with LMTP id mbox01; Mon, 07 Sep 2026 09:00:05 +0000",
    "from mx.recipient.example (mx.recipient.example [198.51.100.5]) by "
    "filter.recipient.example with ESMTP id filt01; Mon, 07 Sep 2026 09:00:03 +0000",
    "from mail.evil-example.test (mail.evil-example.test [203.0.113.60]) by "
    "mx.recipient.example with ESMTPS id mx0001 for <victim@recipient.example>; "
    "Mon, 07 Sep 2026 09:00:01 +0000",
    "from [192.168.1.20] (unknown [192.168.1.20]) by mail.evil-example.test with ESMTPSA "
    "id sub001; Mon, 07 Sep 2026 08:59:58 +0000 (UTC)",
]

# IPv6 chain: sender connects over IPv6, then an internal IPv6 hop (ULA).
CHAIN_IPV6 = [
    "from mx.recipient.example ([IPv6:fd00:10::5]) by mbox.recipient.example with LMTP; "
    "Tue, 08 Sep 2026 10:00:02 +0000",
    "from mail.sender.test (mail.sender.test [IPv6:2001:db8:abcd::25]) by "
    "mx.recipient.example with ESMTPS id v6hop1; Tue, 08 Sep 2026 10:00:01 +0000",
]


# --- single hop parsing ---


def test_parse_single_hop_fields() -> None:
    hop = parse_received(CHAIN_PRIVATE[2])
    assert hop.from_host == "mail.evil-example.test"
    assert hop.by_host == "mx.recipient.example"
    assert hop.ip == "203.0.113.60"
    assert hop.timestamp == datetime(2026, 9, 7, 9, 0, 1, tzinfo=UTC)
    assert hop.raw == CHAIN_PRIVATE[2]


def test_parse_ipv6_bracketed() -> None:
    hop = parse_received(CHAIN_IPV6[1])
    assert hop.ip == "2001:db8:abcd::25"
    assert hop.from_host == "mail.sender.test"


def test_parse_bracketed_helo_gives_no_host() -> None:
    hop = parse_received(CHAIN_PRIVATE[3])
    assert hop.from_host is None
    assert hop.ip == "192.168.1.20"
    assert hop.by_host == "mail.evil-example.test"
    assert hop.timestamp == datetime(2026, 9, 7, 8, 59, 58, tzinfo=UTC)


def test_parse_folded_header_and_timezone() -> None:
    hop = parse_received(
        "from relay.example.test\n (relay.example.test [198.51.100.9])\n\tby mx.example.test"
        " with SMTP;\n Mon, 7 Sep 2026 02:00:00 -0700 (PDT)"
    )
    assert hop.ip == "198.51.100.9"
    assert hop.by_host == "mx.example.test"
    assert hop.timestamp == datetime(2026, 9, 7, 2, 0, tzinfo=timezone(timedelta(hours=-7)))


def test_parse_unbracketed_ip_and_mapped_ipv6() -> None:
    assert parse_received("from 198.51.100.33 by mx.example.test; x").ip == "198.51.100.33"
    hop = parse_received("from host.example.test ([IPv6:::ffff:203.0.113.7]) by mx.example.test")
    assert hop.ip == "203.0.113.7"
    hop = parse_received("from host.example.test (2001:db8::99) by mx.example.test")
    assert hop.ip == "2001:db8::99"


def test_ip_in_by_clause_is_ignored() -> None:
    hop = parse_received("by mx.example.test ([198.51.100.1]) with LMTP; Mon, 07 Sep 2026 09:00:00")
    assert hop.from_host is None
    assert hop.ip is None
    assert hop.by_host == "mx.example.test"
    assert hop.timestamp == datetime(2026, 9, 7, 9, 0, tzinfo=UTC)


def test_by_inside_comment_does_not_start_clause() -> None:
    hop = parse_received(
        "from a.example.test (Authenticated by sender [198.51.100.2]) by b.example.test; "
        "Mon, 07 Sep 2026 09:00:00 +0000"
    )
    assert hop.by_host == "b.example.test"
    assert hop.ip == "198.51.100.2"


@pytest.mark.parametrize("value", ["", "garbage", ";;;", "from", "from [999.1.1.1] by ; bad"])
def test_parse_garbage_never_raises(value: str) -> None:
    hop = parse_received(value)
    assert hop.raw == value
    assert hop.ip is None


# --- chain parsing ---


def test_chain_is_oldest_first() -> None:
    chain, warnings = parse_received_chain(CHAIN_PRIVATE)
    assert [h.ip for h in chain] == ["192.168.1.20", "203.0.113.60", "198.51.100.5", "10.1.2.3"]
    assert warnings == []


def test_out_of_order_warning() -> None:
    values = [
        "from b.example.test ([198.51.100.2]) by c.example.test; Mon, 07 Sep 2026 08:00:00 +0000",
        "from a.example.test ([198.51.100.1]) by b.example.test; Mon, 07 Sep 2026 09:00:00 +0000",
    ]
    _, warnings = parse_received_chain(values)
    assert _codes(warnings) == ["received_out_of_order"]
    assert "hop 2" in warnings[0]


def test_out_of_order_across_timezones_is_fine() -> None:
    values = [
        "from b.example.test ([198.51.100.2]) by c; Mon, 07 Sep 2026 02:00:01 -0700",
        "from a.example.test ([198.51.100.1]) by b; Mon, 07 Sep 2026 09:00:00 +0000",
    ]
    assert parse_received_chain(values)[1] == []


def test_no_ip_warning() -> None:
    values = [
        "from b.example.test ([198.51.100.2]) by c.example.test; Mon, 07 Sep 2026 09:00:01 +0000",
        "by b.example.test with local; Mon, 07 Sep 2026 09:00:00 +0000",
    ]
    chain, warnings = parse_received_chain(values)
    assert chain[0].ip is None
    assert _codes(warnings) == ["received_no_ip"]
    assert "hop 1" in warnings[0]


def test_chain_from_headers_and_fixture() -> None:
    parsed = parse_headers((FIXTURES / "spoof_unaligned.eml").read_bytes())
    chain, warnings = received_chain_from_headers(parsed.headers)
    assert len(chain) == 1
    assert chain[0].ip == "203.0.113.45"
    assert chain[0].from_host == "mail.zetatech.xyz"
    assert warnings == []
    assert originating_external_ip(chain, ["recipient.example"]) == "203.0.113.45"


# --- IP classification ---


@pytest.mark.parametrize(
    ("ip", "internal"),
    [
        ("10.0.0.1", True),
        ("172.16.5.4", True),
        ("192.168.0.1", True),
        ("127.0.0.1", True),
        ("169.254.1.1", True),
        ("100.64.0.1", True),
        ("0.0.0.0", True),
        ("240.0.0.1", True),
        ("fd00::1", True),
        ("fe80::1", True),
        ("::1", True),
        ("not-an-ip", True),
        ("198.51.100.1", False),
        ("203.0.113.1", False),
        ("192.0.2.1", False),
        ("2001:db8::1", False),
        ("8.8.8.8", False),
    ],
)
def test_is_internal_ip(ip: str, internal: bool) -> None:
    assert is_internal_ip(ip) is internal


# --- originating external IP ---


@pytest.mark.parametrize(
    ("values", "trusted", "expected"),
    [
        # Private internal hop is skipped; our MX (public IP) is trusted by domain.
        (CHAIN_PRIVATE, ["recipient.example"], "203.0.113.60"),
        # Trusted by CIDR instead of domain.
        (CHAIN_PRIVATE, ["198.51.100.0/24"], "203.0.113.60"),
        # Trusted by exact IP.
        (CHAIN_PRIVATE, ["198.51.100.5"], "203.0.113.60"),
        # Without trust config our own MX's public IP is the first external hop.
        (CHAIN_PRIVATE, [], "198.51.100.5"),
        # IPv6: ULA internal hop skipped, public IPv6 returned.
        (CHAIN_IPV6, [], "2001:db8:abcd::25"),
        (CHAIN_IPV6, ["recipient.example"], "2001:db8:abcd::25"),
        # Everything trusted or private -> nothing external.
        (CHAIN_PRIVATE, ["recipient.example", "evil-example.test"], None),
        # Only private hops.
        ([CHAIN_PRIVATE[0], CHAIN_PRIVATE[3]], [], None),
    ],
)
def test_originating_external_ip(
    values: list[str], trusted: list[str], expected: str | None
) -> None:
    chain, _ = parse_received_chain(values)
    assert originating_external_ip(chain, trusted) == expected


def test_originating_skips_hops_without_ip() -> None:
    chain = [
        ReceivedHop(from_host="a.example.test", ip="203.0.113.9"),
        ReceivedHop(from_host="b.example.test", ip=None),
    ]
    assert originating_external_ip(chain) == "203.0.113.9"


def test_originating_empty_chain() -> None:
    assert originating_external_ip([]) is None


def test_trusted_domain_does_not_match_lookalike() -> None:
    chain = [ReceivedHop(from_host="mail.evilrecipient.example", ip="203.0.113.9")]
    assert originating_external_ip(chain, ["recipient.example"]) == "203.0.113.9"
