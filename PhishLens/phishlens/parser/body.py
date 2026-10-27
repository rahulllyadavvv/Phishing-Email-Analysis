"""Extract the text and HTML bodies of an email and the URLs they contain.

Bodies are collected from every ``text/plain`` and ``text/html`` leaf part across
``multipart/alternative`` and ``multipart/mixed`` trees. Parts with ``Content-Disposition:
attachment`` and nested ``message/*`` parts are skipped (they are handled by the attachment
parser). Transfer encodings (quoted-printable, base64) are decoded and the declared charset is
applied; unknown or wrong charsets fall back to UTF-8 with replacement characters.

If a message has HTML but no plain text, the text body is derived from the HTML with
BeautifulSoup. HTML is only parsed, never rendered, and nothing it references is fetched.

URLs are taken from the text body (regex) and from the HTML (``a``/``area`` href with the
visible link text, ``img``/``script``/``iframe`` src, ``form`` action and ``meta`` refresh).
They are normalized and deduplicated per ``(url, source, visible_text)``, so a URL found in
several places keeps one ``UrlRef`` per source.

Parsing never raises on bad input. Problems are returned as ``"<code>: <detail>"`` warnings.
"""

from __future__ import annotations

import codecs
import email
import re
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from urllib.parse import urlsplit, urlunsplit

from bs4 import BeautifulSoup

from phishlens.models import UrlRef, UrlSource

_POLICY = policy.default
_ALLOWED_SCHEMES = frozenset({"http", "https", "ftp"})
_DEFAULT_PORTS = {"http": "80", "https": "443", "ftp": "21"}
_TEXT_URL_RE = re.compile(r"""(?:\b(?:https?|ftp)://|\bwww\.)[^\s<>"'`]+""", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?'\"*"
_BRACKETS = {")": "(", "]": "[", "}": "{"}
_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")
_WS_RE = re.compile(r"\s+")
_META_URL_RE = re.compile(r"""url\s*=\s*['"]?\s*([^'"]+?)\s*['"]?\s*$""", re.IGNORECASE)
_NON_TEXT_TAGS = ("script", "style", "noscript", "template", "head")
_SRC_TAGS = frozenset({"img", "script", "iframe"})


@dataclass
class BodyParts:
    """Bodies and URLs extracted from one message."""

    text_body: str = ""
    html_body: str = ""
    urls: list[UrlRef] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _decode_part(part: Message, warnings: list[str]) -> str:
    """Decode the transfer encoding and charset of one leaf part."""
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return ""
    content_type = part.get_content_type()
    charset = part.get_content_charset() or "utf-8"
    try:
        codecs.lookup(charset)
    except LookupError:
        warnings.append(f"unknown_charset: {content_type} declares {charset!r}; used utf-8")
        charset = "utf-8"
    try:
        return payload.decode(charset)
    except UnicodeDecodeError:
        warnings.append(
            f"charset_decode_error: {content_type} is not valid {charset}; "
            "undecodable bytes replaced"
        )
        return payload.decode(charset, errors="replace")


def _collect(
    part: Message, texts: list[str], htmls: list[str], warnings: list[str], top: bool
) -> None:
    for defect in getattr(part, "defects", ()):
        warnings.append(f"mime_defect: {part.get_content_type()}: {type(defect).__name__}")
    if not top and part.get_content_maintype() == "message":
        return
    if part.is_multipart():
        payload = part.get_payload()
        for sub in payload if isinstance(payload, list) else []:
            _collect(sub, texts, htmls, warnings, top=False)
        return
    if part.get_content_disposition() == "attachment":
        return
    content_type = part.get_content_type()
    if content_type == "text/plain":
        texts.append(_decode_part(part, warnings))
    elif content_type == "text/html":
        htmls.append(_decode_part(part, warnings))


def extract_bodies(msg: Message) -> tuple[str, str, list[str]]:
    """Return ``(text_body, html_body, warnings)`` for a parsed message.

    Several parts of the same type are joined with a newline. When there is HTML but no
    plain text, the text body is derived from the HTML.
    """
    texts: list[str] = []
    htmls: list[str] = []
    warnings: list[str] = []
    _collect(msg, texts, htmls, warnings, top=True)
    text = "\n".join(t for t in texts if t)
    html = "\n".join(h for h in htmls if h)
    if not text.strip() and html:
        text = html_to_text(html)
    return text, html, warnings


def html_to_text(html: str) -> str:
    """Derive readable text from HTML without rendering it (scripts and styles dropped)."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(_NON_TEXT_TAGS):
        tag.decompose()
    lines = (_WS_RE.sub(" ", line).strip() for line in soup.get_text("\n").splitlines())
    return "\n".join(line for line in lines if line)


def _strip_trailing(url: str) -> str:
    """Remove punctuation that ends a sentence rather than the URL, and unbalanced brackets."""
    while url:
        last = url[-1]
        if last in _TRAILING_PUNCT:
            url = url[:-1]
        elif last in _BRACKETS and url.count(last) > url.count(_BRACKETS[last]):
            url = url[:-1]
        else:
            break
    return url


def normalize_url(url: str) -> str | None:
    """Normalize a URL string, or return ``None`` if it is not an absolute web URL.

    Whitespace and control characters are removed, ``www.`` links get ``http://``, the
    scheme and host are lowercased, default ports are dropped and an empty path becomes
    ``/``. Only ``http``, ``https`` and ``ftp`` URLs are kept.
    """
    url = _CONTROL_RE.sub("", url)
    if not url:
        return None
    if url.lower().startswith("www."):
        url = "http://" + url
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            return None
        host = (parts.hostname or "").rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None
    userinfo, _, _ = parts.netloc.rpartition("@")
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{userinfo}@{host}" if userinfo else host
    if port is not None and str(port) != _DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))


def _text_urls(text: str) -> list[UrlRef]:
    refs: list[UrlRef] = []
    for match in _TEXT_URL_RE.finditer(text):
        url = normalize_url(_strip_trailing(match.group(0)))
        if url:
            refs.append(UrlRef(url=url, source=UrlSource.TEXT_BODY))
    return refs


def _meta_refresh_url(content: str) -> str | None:
    match = _META_URL_RE.search(content)
    return match.group(1) if match else None


def _attr(tag: object, name: str) -> str | None:
    value = tag.get(name)  # type: ignore[attr-defined]
    if isinstance(value, list):
        value = " ".join(value)
    return value if isinstance(value, str) else None


def _html_urls(html: str) -> list[UrlRef]:
    refs: list[UrlRef] = []
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(True):
        name = tag.name.lower()
        raw: str | None = None
        visible: str | None = None
        if name in ("a", "area"):
            raw, source = _attr(tag, "href"), UrlSource.HTML_HREF
            visible = _WS_RE.sub(" ", tag.get_text(" ")).strip() or None
        elif name in _SRC_TAGS:
            raw, source = _attr(tag, "src"), UrlSource.HTML_SRC
        elif name == "form":
            raw, source = _attr(tag, "action"), UrlSource.FORM_ACTION
        elif name == "meta" and (_attr(tag, "http-equiv") or "").lower() == "refresh":
            raw, source = _meta_refresh_url(_attr(tag, "content") or ""), UrlSource.META_REFRESH
        if not raw:
            continue
        url = normalize_url(raw)
        if url:
            refs.append(UrlRef(url=url, visible_text=visible, source=source))
    return refs


def extract_urls(text: str, html: str) -> list[UrlRef]:
    """Extract URLs from the text and HTML bodies, deduplicated per source and link text.

    Order is: text body URLs first, then HTML URLs in document order.
    """
    seen: set[tuple[str, UrlSource, str | None]] = set()
    result: list[UrlRef] = []
    for ref in _text_urls(text) + (_html_urls(html) if html else []):
        key = (ref.url, ref.source, ref.visible_text)
        if key not in seen:
            seen.add(key)
            result.append(ref)
    return result


def parse_bodies(raw: bytes) -> BodyParts:
    """Parse a raw RFC 822 message and return its bodies, URLs and warnings. Never raises."""
    parts = BodyParts()
    try:
        msg = email.message_from_bytes(raw, policy=_POLICY)
        parts.text_body, parts.html_body, parts.warnings = extract_bodies(msg)
    except Exception as exc:
        parts.warnings.append(f"body_parse_error: {type(exc).__name__}: {exc}")
    try:
        parts.urls = extract_urls(parts.text_body, parts.html_body)
    except Exception as exc:
        parts.warnings.append(f"url_extract_error: {type(exc).__name__}: {exc}")
    return parts
