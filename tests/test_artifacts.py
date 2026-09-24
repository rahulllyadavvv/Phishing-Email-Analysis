"""Tests for phishlens.analyzers.artifacts (hidden content, tracking, obfuscation, headers)."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from phishlens.analyzers import artifacts
from phishlens.models import Address, ParsedEmail, ReceivedHop, Severity
from phishlens.parser import parse_email
from phishlens.parser.attachments import make_attachment

FIXTURES = Path(__file__).parent / "fixtures"
ALL_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.eml"))
DELIVERED = datetime(2026, 9, 7, 9, 0, tzinfo=UTC)


def _ids(result) -> dict:
    return {f.id: f for f in result.findings}


async def _html(html: str, text: str = "") -> dict:
    return _ids(await artifacts.analyze(ParsedEmail(html_body=html, text_body=text)))


async def test_fixture_11_tracking_pixel_and_hidden_text() -> None:
    result = await artifacts.analyze(parse_email((FIXTURES / "tracking_pixel.eml").read_bytes()))
    findings = _ids(result)
    pixel = findings["tracking_pixel"]
    assert pixel.severity == Severity.LOW
    assert pixel.evidence["images"][0]["url"] == (
        "hxxp://track[.]promo-offers[.]example/open.gif?id=abc123"
    )
    assert result.raw["tracking_domains"] == ["track[.]promo-offers[.]example"]
    hidden = findings["hidden_text"]
    assert hidden.severity == Severity.MEDIUM
    assert [b["reason"] for b in hidden.evidence["blocks"]] == ["display:none", "font-size:0px"]
    assert hidden.evidence["total_chars"] == 96


@pytest.mark.parametrize(
    "img",
    [
        '<img src="https://t.example.test/o.gif" style="display:none">',
        '<div style="visibility:hidden"><img src="https://t.example.test/o.gif"></div>',
        '<img src="https://t.example.test/o.gif" width="0" height="0">',
        '<img src="https://t.example.test/o.png?uid=a8f3e2c1b9d04e7f9a1b" '
        'width="1px" height="1px">',
    ],
)
async def test_tracking_pixel_variants(img: str) -> None:
    assert "tracking_pixel" in await _html(img)


async def test_normal_images_are_not_trackers() -> None:
    html = (
        '<img src="https://cdn.example.test/logo.png?v=a8f3e2c1b9d04e7f9a1b" width="200">'
        '<img src="cid:logo123" width="1" height="1">'
    )
    assert "tracking_pixel" not in await _html(html)


@pytest.mark.parametrize(
    ("style", "reason"),
    [
        ("display: none", "display: none"),
        ("visibility:hidden", "visibility:hidden"),
        ("font-size:0", "font-size:0"),
        ("opacity:0", "opacity:0"),
        ("max-height:0px;overflow:hidden", "max-height:0px"),
        ("color:#ffffff", "text colour #ffffff on the same background"),
        ("color:#123456;background-color:#123456", "text colour #123456 on the same background"),
    ],
)
async def test_hidden_text_styles(style: str, reason: str) -> None:
    findings = await _html(f'<p>Visible</p><div style="{style}">secret filter-bait words</div>')
    assert findings["hidden_text"].evidence["blocks"][0]["reason"] == reason


async def test_short_or_visible_text_is_fine() -> None:
    findings = await _html(
        '<div style="display:none">x</div><p style="color:#333">Normal visible paragraph</p>'
    )
    assert "hidden_text" not in findings


async def test_nested_hidden_blocks_counted_once() -> None:
    html = '<div style="display:none">outer words here <span style="font-size:0">inner</span></div>'
    blocks = (await _html(html))["hidden_text"].evidence["blocks"]
    assert len(blocks) == 1


async def test_hidden_filler_text() -> None:
    filler = " ".join(f"word{i}" for i in range(120))
    findings = await _html(f'<p>Pay now</p><div style="display:none">{filler}</div>')
    assert findings["hidden_filler_text"].evidence["total_chars"] >= 500


async def test_zero_width_characters() -> None:
    findings = await _html("<p>Pa​y​Pal acc‍ount ver﻿ify</p>")
    zw = findings["zero_width_characters"]
    assert zw.evidence["count"] == 4
    assert zw.evidence["characters"] == ["U+200B", "U+200D", "U+FEFF"]


async def test_text_html_mismatch() -> None:
    findings = await _html(
        "<p>Your mailbox is full, verify your password immediately to avoid suspension</p>",
        text="Weekly gardening newsletter tomatoes roses compost watering tips",
    )
    assert findings["text_html_mismatch"].evidence["overlap"] < 0.2
    same = await _html(
        "<p>Hello team, the meeting notes are attached for review</p>",
        text="Hello team, the meeting notes are attached for review",
    )
    assert "text_html_mismatch" not in same


async def test_encoded_links() -> None:
    target = base64.b64encode(b"https://hidden.example.test/login").decode()
    html = (
        f'<a href="https://redir.example.test/r?u={target}">Open</a>'
        '<a href="&#104;ttps://entity.example.test/">x</a>'
    )
    result = await artifacts.analyze(ParsedEmail(html_body=html))
    links = _ids(result)["encoded_link"].evidence["links"]
    techniques = [link["technique"] for link in links]
    assert techniques == ["html_entities_in_href", "base64_url_parameter"]
    assert links[1]["decoded"] == "hxxps://hidden[.]example[.]test/login"
    assert [(u.url, u.source.value) for u in result.extracted_urls] == [
        ("https://hidden.example.test/login", "artifact")
    ]


async def test_script_and_meta_refresh() -> None:
    html = (
        '<meta http-equiv="refresh" content="0; url=https://go.example.test/x">'
        '<script src="https://kit.example.test/k.js"></script><p>hi</p>'
    )
    result = await artifacts.analyze(ParsedEmail(html_body=html))
    findings = _ids(result)
    assert findings["script_in_body"].severity == Severity.HIGH
    assert findings["script_in_body"].evidence["sources"] == ["hxxps://kit[.]example[.]test/k.js"]
    assert findings["meta_refresh"].evidence["targets"] == ["hxxps://go[.]example[.]test/x"]
    assert ("https://go.example.test/x", "meta_refresh") in [
        (u.url, u.source.value) for u in result.extracted_urls
    ]


# --- Headers -------------------------------------------------------------------------------------


def _email(**fields) -> ParsedEmail:
    defaults = {
        "headers": [("From", "a@shop.test")],
        "from_addrs": [Address(address="a@shop.test", domain="shop.test", org_domain="shop.test")],
        "message_id": "<1@mail.shop.test>",
        "date": DELIVERED,
        "received_chain": [ReceivedHop(ip="198.51.100.1", timestamp=DELIVERED)],
    }
    return ParsedEmail(**{**defaults, **fields})


async def test_clean_headers() -> None:
    assert (await artifacts.analyze(_email())).findings == []


async def test_missing_message_id_and_date() -> None:
    findings = _ids(await artifacts.analyze(_email(message_id=None, date=None)))
    assert {"missing_message_id", "missing_date"} <= set(findings)


async def test_date_in_future_and_too_old() -> None:
    future = _ids(await artifacts.analyze(_email(date=DELIVERED + timedelta(days=3))))
    assert future["date_in_future"].severity == Severity.MEDIUM
    old = _ids(await artifacts.analyze(_email(date=DELIVERED - timedelta(days=45))))
    assert old["date_too_old"].evidence["days"] == 45
    no_received = _ids(
        await artifacts.analyze(_email(date=DELIVERED - timedelta(days=45), received_chain=[]))
    )
    assert "date_too_old" not in no_received  # nothing to compare with


async def test_message_id_domain() -> None:
    mismatch = _ids(await artifacts.analyze(_email(message_id="<x@bulk.other.test>")))
    assert mismatch["message_id_domain_mismatch"].evidence["message_id_domain"] == (
        "bulk[.]other[.]test"
    )
    esp = _ids(await artifacts.analyze(_email(message_id="<x@ismtpd0001.sendgrid.net>")))
    assert "message_id_domain_mismatch" not in esp


async def test_suspicious_mailer() -> None:
    email = _email(headers=[("From", "a@shop.test"), ("X-Mailer", "Leaf PHPMailer 2.7")])
    finding = _ids(await artifacts.analyze(email))["suspicious_mailer"]
    assert finding.evidence["matches"] == [
        {"tool": "Leaf PHPMailer", "header": "Leaf PHPMailer 2.7"}
    ]
    normal = _email(headers=[("From", "a@shop.test"), ("X-Mailer", "Apple Mail (2.3774)")])
    assert "suspicious_mailer" not in _ids(await artifacts.analyze(normal))


# --- Inline QR -----------------------------------------------------------------------------------


async def test_inline_qr_goes_to_extracted_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(artifacts, "qr_available", lambda: True)
    monkeypatch.setattr(artifacts, "decode_qr", lambda data: ["https://qr.example.test/p"])
    email = ParsedEmail(inline_images=[make_attachment("qr.png", b"\x89PNG fake")])
    result = await artifacts.analyze(email)
    assert [(u.url, u.source.value) for u in result.extracted_urls] == [
        ("https://qr.example.test/p", "qr_code")
    ]
    assert result.raw["inline_qr"] == [{"image": "qr.png", "url": "hxxps://qr[.]example[.]test/p"}]
    assert result.findings == []  # the attachment analyzer owns qr_code_url


async def test_inline_qr_without_zbar(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(artifacts, "qr_available", lambda: False)
    result = await artifacts.analyze(parse_email((FIXTURES / "qr_code.eml").read_bytes()))
    assert result.raw["inline_qr"] == "unavailable (zbar not installed)"


async def test_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object) -> None:
        raise RuntimeError("style exploded")

    monkeypatch.setattr(artifacts, "_invisible", boom)
    result = await artifacts.analyze(ParsedEmail(html_body="<div>x</div>"))
    assert any(e.startswith("hidden_text: RuntimeError") for e in result.errors)


@pytest.mark.parametrize("name", ALL_FIXTURES)
async def test_every_fixture(name: str) -> None:
    result = await artifacts.analyze(parse_email((FIXTURES / name).read_bytes()))
    assert result.errors == []
