"""Tests for phishlens.parser.body."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from phishlens.models import UrlSource
from phishlens.parser.body import (
    extract_urls,
    html_to_text,
    normalize_url,
    parse_bodies,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _mime(body_parts: str, boundary: str = "BOUND") -> bytes:
    head = (
        "From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n"
        f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n\r\n'
    )
    return (head + body_parts + f"--{boundary}--\r\n").encode("latin-1")


# --- fixture 1: clean newsletter -------------------------------------------------------


def test_clean_newsletter_bodies_decoded():
    parts = parse_bodies(_fixture("clean_newsletter.eml"))
    assert parts.warnings == []
    # Quoted-printable soft line breaks are joined.
    assert "the library\nextended its hours" in parts.text_body
    assert "lib=" not in parts.text_body
    assert '<a href="https://www.newsletter.example/september">' in parts.html_body


def test_clean_newsletter_url_keeps_both_sources():
    urls = parse_bodies(_fixture("clean_newsletter.eml")).urls
    assert {u.url for u in urls} == {"https://www.newsletter.example/september"}
    assert {u.source for u in urls} == {UrlSource.TEXT_BODY, UrlSource.HTML_HREF}
    href = next(u for u in urls if u.source == UrlSource.HTML_HREF)
    assert href.visible_text == "https://www.newsletter.example/september"


# --- fixture 5: link mismatch ----------------------------------------------------------


def test_link_mismatch_keeps_visible_text_and_href():
    urls = parse_bodies(_fixture("link_mismatch.eml")).urls
    links = [u for u in urls if u.visible_text and "paypal.com" in u.visible_text]
    assert len(links) == 1
    link = links[0]
    assert link.url == "http://paypal-secure-login.example/confirm"
    assert link.visible_text == "https://www.paypal.com"
    assert link.source == UrlSource.HTML_HREF


def test_link_mismatch_text_body_url():
    urls = parse_bodies(_fixture("link_mismatch.eml")).urls
    text_urls = [u for u in urls if u.source == UrlSource.TEXT_BODY]
    assert [u.url for u in text_urls] == ["https://www.paypal.com/"]
    assert text_urls[0].visible_text is None


# --- bodies ----------------------------------------------------------------------------


def test_base64_and_charset_decoding():
    html = "<p>Grüße <a href='https://example.com/ü'>hier</a></p>".encode("iso-8859-1")
    raw = _mime(
        "--BOUND\r\nContent-Type: text/html; charset=iso-8859-1\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n"
        f"{base64.b64encode(html).decode()}\r\n"
    )
    parts = parse_bodies(raw)
    assert "Grüße" in parts.html_body
    # Only HTML exists, so the text body is derived from it.
    assert parts.text_body == "Grüße\nhier"
    assert parts.urls[0].url == "https://example.com/ü"


def test_nested_alternative_inside_mixed_and_attachment_skipped():
    raw = _mime(
        "--BOUND\r\n"
        'Content-Type: multipart/alternative; boundary="ALT"\r\n\r\n'
        "--ALT\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nplain part\r\n"
        "--ALT\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<b>html part</b>\r\n"
        "--ALT--\r\n"
        "--BOUND\r\nContent-Type: text/plain\r\n"
        'Content-Disposition: attachment; filename="notes.txt"\r\n\r\n'
        "attached http://attached.example/\r\n"
        "--BOUND\r\nContent-Type: message/rfc822\r\n\r\n"
        "Subject: inner\r\nContent-Type: text/plain\r\n\r\ninner http://inner.example/\r\n"
    )
    parts = parse_bodies(raw)
    assert parts.text_body.strip() == "plain part"
    assert parts.html_body.strip() == "<b>html part</b>"
    assert parts.urls == []


def test_unknown_charset_and_bad_bytes_warn():
    raw = _mime(
        "--BOUND\r\nContent-Type: text/plain; charset=x-made-up\r\n\r\nhello\r\n"
        "--BOUND\r\nContent-Type: text/html; charset=utf-8\r\n"
        "Content-Transfer-Encoding: 8bit\r\n\r\n<p>caf\xe9</p>\r\n"
    )
    parts = parse_bodies(raw)
    codes = [w.split(":", 1)[0] for w in parts.warnings]
    assert "unknown_charset" in codes
    assert "charset_decode_error" in codes
    assert "hello" in parts.text_body
    assert "caf�" in parts.html_body


def test_single_part_plain_message():
    raw = b"From: a@example.com\r\nSubject: s\r\n\r\nSee www.example.com/path, thanks.\r\n"
    parts = parse_bodies(raw)
    assert parts.html_body == ""
    assert [u.url for u in parts.urls] == ["http://www.example.com/path"]


def test_parse_bodies_never_raises_on_garbage():
    parts = parse_bodies(b"\x00\xff\xfe not an email")
    assert isinstance(parts.text_body, str)


def test_html_to_text_drops_scripts_and_styles():
    html = (
        "<html><head><title>T</title><style>p{}</style></head>"
        "<body><p>Hello</p><script>alert(1)</script><p>World</p></body></html>"
    )
    assert html_to_text(html) == "Hello\nWorld"


# --- URL extraction --------------------------------------------------------------------


def test_html_sources():
    html = """
    <html><head><meta http-equiv="Refresh" content="0; URL='https://redirect.example/go'">
    </head><body>
    <a href="https://link.example/a">Click  <b>here</b></a>
    <a href="mailto:x@example.com">mail</a>
    <a href="/relative">rel</a>
    <img src="http://img.example/p.gif">
    <script src="https://cdn.example/x.js"></script>
    <form action="https://collect.example/post"><input></form>
    <a href="https://link.example/a">Click here</a>
    <a href="https://link.example/a"><img src="http://img.example/p.gif"></a>
    </body></html>
    """
    urls = extract_urls("", html)
    got = [(u.url, u.source, u.visible_text) for u in urls]
    assert got == [
        ("https://redirect.example/go", UrlSource.META_REFRESH, None),
        ("https://link.example/a", UrlSource.HTML_HREF, "Click here"),
        ("http://img.example/p.gif", UrlSource.HTML_SRC, None),
        ("https://cdn.example/x.js", UrlSource.HTML_SRC, None),
        ("https://collect.example/post", UrlSource.FORM_ACTION, None),
        ("https://link.example/a", UrlSource.HTML_HREF, None),
    ]


def test_text_urls_trailing_punctuation_and_dedup():
    text = (
        "Visit https://a.example/x. Or (see https://b.example/wiki_(page)). "
        "Again https://a.example/x, and HTTPS://A.EXAMPLE/x!"
    )
    urls = extract_urls(text, "")
    assert [u.url for u in urls] == [
        "https://a.example/x",
        "https://b.example/wiki_(page)",
    ]
    assert all(u.source == UrlSource.TEXT_BODY for u in urls)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTP://Example.COM", "http://example.com/"),
        ("https://example.com:443/a?b=1#c", "https://example.com/a?b=1#c"),
        ("http://example.com:8080/a", "http://example.com:8080/a"),
        ("  http://exa\nmple.com/a\t", "http://example.com/a"),
        ("www.example.com", "http://www.example.com/"),
        ("http://user:Pw@Example.com/", "http://user:Pw@example.com/"),
        ("http://[2001:DB8::1]/", "http://[2001:db8::1]/"),
        ("javascript:alert(1)", None),
        ("mailto:a@example.com", None),
        ("/relative/path", None),
        ("http://", None),
        ("http://[bad/", None),
        ("", None),
    ],
)
def test_normalize_url(raw: str, expected: str | None):
    assert normalize_url(raw) == expected
