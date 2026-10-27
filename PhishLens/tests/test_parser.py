"""Tests for phishlens.parser.parse_email."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from phishlens.models import ParsedEmail
from phishlens.parser import MAX_NESTED_DEPTH, parse_email

FIXTURES = Path(__file__).parent / "fixtures"
ALL_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.eml"))


def _parse(name: str) -> ParsedEmail:
    return parse_email((FIXTURES / name).read_bytes())


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_every_fixture_parses_completely(name: str):
    raw = (FIXTURES / name).read_bytes()
    parsed = parse_email(raw)
    errors = [w for w in parsed.parse_warnings if "error" in w.split(":")[0]]
    assert errors == []
    assert parsed.sha256 == hashlib.sha256(raw).hexdigest()
    assert parsed.raw_bytes == raw
    assert parsed.headers and parsed.from_addrs and parsed.subject
    assert parsed.message_id
    assert parsed.received_chain
    assert parsed.auth_results_headers
    assert parsed.text_body.strip()
    # Serializes without raw bytes.
    dumped = parsed.model_dump_json()
    assert "raw_bytes" not in dumped


def test_fixture_7_zip_attachment():
    parsed = _parse("zip_attachment.eml")
    assert [a.filename for a in parsed.attachments] == ["notes.zip"]
    assert parsed.attachments[0].sha256
    assert parsed.inline_images == [] and parsed.nested_emails == []
    assert "meeting notes are attached" in parsed.text_body


def test_fixture_12_qr_code():
    parsed = _parse("qr_code.eml")
    assert parsed.attachments == []
    assert [i.filename for i in parsed.inline_images] == ["qrcode.png"]
    assert 'src="cid:qrcode@phishlens.test"' in parsed.html_body


def test_fixture_13_forwarded_nested():
    parsed = _parse("forwarded_nested.eml")
    assert parsed.subject.startswith("Fwd:")
    assert parsed.attachments == []
    assert len(parsed.nested_emails) == 1
    inner = parsed.nested_emails[0]
    assert inner.from_addrs[0].address == "account-security@microsoft.com"
    assert inner.return_path is not None and inner.return_path.domain == "zetatech.xyz"
    assert inner.received_chain[0].ip == "203.0.113.45"
    assert len(inner.auth_results_headers) == 1
    assert "dmarc=fail header.from=microsoft.com" in inner.auth_results_headers[0]
    assert [u.url for u in inner.urls] == ["http://account-review.zetatech.example/verify"]
    assert inner.sha256 == hashlib.sha256(inner.raw_bytes).hexdigest()
    # The outer body does not contain the forwarded message's text.
    assert "unusual sign-in" not in parsed.text_body.lower()
    assert parsed.urls == []


def test_fixture_14_eicar():
    parsed = _parse("eicar_attachment.eml")
    assert [a.filename for a in parsed.attachments] == ["eicar.com"]
    assert parsed.attachments[0].sha256 == (
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    )


def _wrap(inner: bytes, level: int) -> bytes:
    head = (
        f"From: l{level}@example.com\r\nTo: b@example.com\r\nSubject: level {level}\r\n"
        f'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="B{level}"\r\n\r\n'
        f"--B{level}\r\nContent-Type: text/plain\r\n\r\nwrapper\r\n"
        f"--B{level}\r\nContent-Type: message/rfc822\r\n\r\n"
    ).encode()
    return head + inner + f"\r\n--B{level}--\r\n".encode()


def test_nested_depth_limited():
    raw = b"From: l5@example.com\r\nTo: b@example.com\r\nSubject: level 5\r\n\r\ndeepest\r\n"
    for level in range(4, -1, -1):
        raw = _wrap(raw, level)
    parsed = parse_email(raw)
    node = parsed
    for depth in range(1, MAX_NESTED_DEPTH + 1):
        assert len(node.nested_emails) == 1
        node = node.nested_emails[0]
        assert node.subject == f"level {depth}"
    # Level 4 is deeper than the limit: kept as a plain attachment with a warning.
    assert node.nested_emails == []
    assert [a.declared_type for a in node.attachments] == ["message/rfc822"]
    assert any(w.startswith("nested_depth_exceeded") for w in node.parse_warnings)


def test_garbage_never_raises():
    for raw in (b"", b"\x00\xff\xfe garbage", b"Subject: x\r\n\r\n"):
        parsed = parse_email(raw)
        assert parsed.sha256 == hashlib.sha256(raw).hexdigest()
