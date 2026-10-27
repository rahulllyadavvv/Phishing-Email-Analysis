"""Tests for phishlens.ingest.loader."""

from __future__ import annotations

import email
import email.policy
import os
from email.message import EmailMessage
from pathlib import Path

import pytest

from phishlens.config import get_settings
from phishlens.ingest import loader
from phishlens.ingest.loader import (
    MSG_NO_TRANSPORT_HEADERS,
    OLE_SIGNATURE,
    PARSE_WARNING_HEADER,
    InputTooLargeError,
    MsgConversionError,
    load_input,
    looks_like_rfc822,
)

FIXTURES = Path(__file__).parent / "fixtures"
EML_FIXTURES = sorted(FIXTURES.glob("*.eml"))


@pytest.fixture(autouse=True)
def _fresh_settings(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MAX_INPUT_SIZE_MB", raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class FakeMsg:
    """Stand-in for an extract-msg ``Message``."""

    def __init__(self, message: EmailMessage, header_text: str | None) -> None:
        self._message = message
        self.headerText = header_text
        self.closed = False

    def asEmailMessage(self) -> EmailMessage:  # noqa: N802 - mirrors extract-msg API
        return self._message

    def close(self) -> None:
        self.closed = True


def _converted_message() -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = "Sender <sender@example.com>"
    msg["To"] = "user@example.test"
    msg["Subject"] = "Converted from msg"
    msg.set_content("plain body")
    msg.add_alternative("<p>html body</p>", subtype="html")
    msg.add_attachment(b"harmless", maintype="text", subtype="plain", filename="note.txt")
    return msg


def _fake_msg_bytes() -> bytes:
    return OLE_SIGNATURE + b"\x00" * 1024


@pytest.mark.parametrize("path", EML_FIXTURES, ids=lambda p: p.name)
def test_every_fixture_loads_as_email(path: Path) -> None:
    kind, data = load_input(path)
    assert kind == "email"
    assert data == path.read_bytes()


def test_fixtures_exist() -> None:
    assert len(EML_FIXTURES) >= 10


def test_fixture_bytes_load_as_email() -> None:
    raw = (FIXTURES / "clean_newsletter.eml").read_bytes()
    assert load_input(raw, filename="upload.bin") == ("email", raw)


def test_random_binary_loads_as_file() -> None:
    data = os.urandom(4096)
    assert load_input(data) == ("file", data)


def test_random_binary_path_loads_as_file(tmp_path: Path) -> None:
    data = os.urandom(4096)
    path = tmp_path / "sample.eml"  # extension is not trusted
    path.write_bytes(data)
    assert load_input(path) == ("file", data)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"%PDF-1.7\n1 0 obj\n",
        b"PK\x03\x04rest-of-zip",
        b"MZ\x90\x00\x03\x00",
        b"Hello there,\nthis is plain text.\n",
        b"key: value\nother: thing\n",  # colon lines but no mail header
        b"Subject: only one header\n\nbody",  # a single field is not enough
        b"From: a@example.com\nSubject: x\x00\n",  # NUL byte
    ],
)
def test_non_email_content_is_file(data: bytes) -> None:
    assert load_input(data) == ("file", data)


@pytest.mark.parametrize(
    "data",
    [
        b"From: a@example.com\r\nSubject: hi\r\n\r\nbody",
        b"\xef\xbb\xbfFrom: a@example.com\nTo: b@example.test\n\nbody",
        b"From sender@example.com Mon Sep  7 09:00:00 2026\nFrom: a@example.com\nSubject: x\n\n",
        b"Received: from a.example\n by b.example; Mon, 7 Sep 2026\nMessage-ID: <1@example>\n",
    ],
)
def test_header_variants_detected(data: bytes) -> None:
    assert looks_like_rfc822(data)


def test_continuation_before_first_field_is_not_email() -> None:
    assert not looks_like_rfc822(b" folded\nFrom: a@example.com\nSubject: x\n")


def test_msg_with_transport_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeMsg(_converted_message(), "Received: from mx.example.com\nFrom: x@example.com\n")
    seen: list[bytes] = []

    def fake_open(data: bytes) -> FakeMsg:
        seen.append(data)
        return fake

    monkeypatch.setattr(loader.extract_msg, "openMsg", fake_open)
    raw_msg = _fake_msg_bytes()
    kind, data = load_input(raw_msg, filename="mail.msg")

    assert kind == "email"
    assert seen == [raw_msg]
    assert fake.closed
    parsed = email.message_from_bytes(data, policy=email.policy.default)
    assert parsed["Subject"] == "Converted from msg"
    assert parsed[PARSE_WARNING_HEADER] is None
    assert parsed.get_body(("plain",)).get_content().strip() == "plain body"
    assert parsed.get_body(("html",)).get_content().strip() == "<p>html body</p>"
    attachments = list(parsed.iter_attachments())
    assert [a.get_filename() for a in attachments] == ["note.txt"]
    assert attachments[0].get_content() == "harmless"
    assert looks_like_rfc822(data)


def test_msg_without_transport_headers_adds_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeMsg(_converted_message(), None)
    monkeypatch.setattr(loader.extract_msg, "openMsg", lambda data: fake)
    kind, data = load_input(_fake_msg_bytes())
    assert kind == "email"
    parsed = email.message_from_bytes(data, policy=email.policy.default)
    assert parsed[PARSE_WARNING_HEADER] == MSG_NO_TRANSPORT_HEADERS


def test_msg_conversion_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenMsg(FakeMsg):
        def asEmailMessage(self) -> EmailMessage:  # noqa: N802
            raise RuntimeError("bad attachment")

    broken = BrokenMsg(EmailMessage(), None)
    monkeypatch.setattr(loader.extract_msg, "openMsg", lambda data: broken)
    with pytest.raises(MsgConversionError, match="bad attachment"):
        load_input(_fake_msg_bytes(), filename="mail.msg")
    assert broken.closed


def test_ole_non_message_is_file(monkeypatch: pytest.MonkeyPatch) -> None:
    class NotAMessage:
        def close(self) -> None:
            pass

    monkeypatch.setattr(loader.extract_msg, "openMsg", lambda data: NotAMessage())
    data = _fake_msg_bytes()
    assert load_input(data) == ("file", data)


def test_corrupt_ole_is_file() -> None:
    # Real extract-msg: an OLE signature followed by junk cannot be opened as a message.
    data = _fake_msg_bytes()
    assert load_input(data) == ("file", data)


def test_default_max_size_is_25_mb() -> None:
    assert loader.max_input_bytes() == 25 * 1024 * 1024


def test_too_large_bytes_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAX_INPUT_SIZE_MB", "0.001")  # 1048 bytes
    get_settings.cache_clear()
    with pytest.raises(InputTooLargeError, match="big.bin"):
        load_input(b"x" * 2000, filename="big.bin")
    assert load_input(b"x" * 1000) == ("file", b"x" * 1000)


def test_too_large_path_rejected_before_reading(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("MAX_INPUT_SIZE_MB", "0.001")
    get_settings.cache_clear()
    path = tmp_path / "big.eml"
    path.write_bytes(b"x" * 2000)

    def fail_read(self: Path) -> bytes:
        raise AssertionError("file should not be read")

    monkeypatch.setattr(Path, "read_bytes", fail_read)
    with pytest.raises(InputTooLargeError, match="big.eml"):
        load_input(path)
