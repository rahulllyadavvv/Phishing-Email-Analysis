"""Hidden artifacts analyzer: tracking, hidden text, obfuscation and malformed headers.

The HTML body is parsed with BeautifulSoup (never rendered, no remote content is loaded).

- Tracking pixels: images of at most 1x1, hidden images, and remote images whose URL carries a
  long unique ID. Tracking domains are recorded in ``raw["tracking_domains"]``.
- Hidden text and filter evasion: text inside elements styled invisible (display:none,
  visibility:hidden, font-size:0, opacity:0, zero height, text colour equal to the background),
  zero-width characters, large hidden filler blocks, and a text/plain part that has little in
  common with the HTML part.
- Obfuscation: links hidden behind HTML entities or base64, script tags in the body, and meta
  refresh redirects.
- Malformed headers: missing Message-ID or Date, a Date far from the delivery time, a Message-ID
  domain unrelated to the From domain, and X-Mailer values of mass-mailing tools
  (``data/suspicious_mailers.yaml``).
- QR codes in inline images are decoded into ``extracted_urls`` (the attachment analyzer owns
  the ``qr_code_url`` finding for them, so none is added here).
"""

from __future__ import annotations

import base64
import binascii
import re
import time
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from bs4 import BeautifulSoup, Tag

from phishlens.analyzers.binaries import defang_text
from phishlens.analyzers.qr import decode_qr, qr_available
from phishlens.data_loader import esp_for_domain, suspicious_mailers
from phishlens.ioc.defang import defang_domain, defang_url
from phishlens.models import AnalyzerResult, Finding, ParsedEmail, Severity, UrlRef, UrlSource
from phishlens.parser.headers import org_domain

MODULE = "artifacts"

__all__ = ["MODULE", "analyze"]

MIN_HIDDEN_CHARS = 10
FILLER_CHARS = 500
MIN_ZERO_WIDTH = 3
UNIQUE_ID_MIN = 16
MAX_DATE_AGE_DAYS = 30
FUTURE_TOLERANCE = timedelta(days=1)
SNIPPET = 200

ZERO_WIDTH = frozenset("​‌‍⁠﻿­᠎")
_ZERO_WIDTH_RE = re.compile("[" + "".join(ZERO_WIDTH) + "]")
_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|%)?\s*(?:;|$)"
    r"|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|(?:max-)?height\s*:\s*0(?:px)?\s*(?:;|$)",
    re.IGNORECASE,
)
_COLOR_RE = re.compile(r"(?<![-\w])color\s*:\s*([^;]+)", re.IGNORECASE)
_BG_RE = re.compile(r"background(?:-color)?\s*:\s*([^;]+)", re.IGNORECASE)
_ENTITY_IN_HREF_RE = re.compile(r"""href\s*=\s*["']?[^"'>\s]*&#x?[0-9a-f]+;""", re.IGNORECASE)
_B64_VALUE_RE = re.compile(r"^[A-Za-z0-9+/_-]{16,}={0,2}$")
_ID_VALUE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_META_REFRESH_RE = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-z0-9]{2,}")
_WHITE = {"#fff", "#ffffff", "white", "rgb(255,255,255)"}

FINDINGS: dict[str, tuple[Severity, str, str]] = {
    "tracking_pixel": (
        Severity.LOW,
        "Tracking pixel",
        "A tiny or hidden remote image reports when and where the message was opened.",
    ),
    "hidden_text": (
        Severity.MEDIUM,
        "Hidden text in the message",
        "Text is present but made invisible, a trick to fool spam filters with harmless words.",
    ),
    "hidden_filler_text": (
        Severity.MEDIUM,
        "Large block of hidden filler text",
        "A lot of invisible text is padded into the message to dilute the phishing content.",
    ),
    "zero_width_characters": (
        Severity.MEDIUM,
        "Zero-width characters in the text",
        "Invisible characters split words so filters no longer recognise them.",
    ),
    "text_html_mismatch": (
        Severity.LOW,
        "Plain-text and HTML versions differ",
        "The plain-text part says something different from the HTML part, so filters and "
        "people may see different messages.",
    ),
    "encoded_link": (
        Severity.MEDIUM,
        "Link hidden behind encoding",
        "A link is written with HTML entities or carries a base64-encoded URL to hide its "
        "destination from filters.",
    ),
    "script_in_body": (
        Severity.HIGH,
        "Script in the message body",
        "Mail clients do not run scripts, so a script in the body only makes sense as an "
        "attack on webmail or a leftover of a phishing kit.",
    ),
    "meta_refresh": (
        Severity.MEDIUM,
        "Automatic redirect in the message",
        "A meta refresh tag redirects to another page when the HTML is opened.",
    ),
    "missing_message_id": (
        Severity.LOW,
        "No Message-ID header",
        "Every standard mail server adds a Message-ID; its absence suggests a script sent it.",
    ),
    "missing_date": (
        Severity.LOW,
        "No Date header",
        "Every standard mail client adds a Date header.",
    ),
    "date_in_future": (
        Severity.MEDIUM,
        "Date header is in the future",
        "The Date is later than the delivery time, a sign of a forged or careless sender.",
    ),
    "date_too_old": (
        Severity.LOW,
        "Date header is much older than delivery",
        "The Date is more than 30 days before delivery: the message may be replayed or the "
        "date forged.",
    ),
    "message_id_domain_mismatch": (
        Severity.LOW,
        "Message-ID domain differs from the sender",
        "The Message-ID was created by a domain unrelated to the From domain.",
    ),
    "suspicious_mailer": (
        Severity.MEDIUM,
        "Sent with a mass-mailing tool",
        "The X-Mailer or User-Agent names a bulk-mailing or spam tool.",
    ),
}


def _finding(finding_id: str, evidence: dict[str, Any]) -> Finding:
    severity, title, description = FINDINGS[finding_id]
    return Finding(
        id=finding_id,
        module=MODULE,
        title=title,
        description=description,
        severity=severity,
        evidence=evidence,
    )


def _snippet(text: str) -> str:
    text = " ".join(text.split())
    return defang_text(text[:SNIPPET] + ("..." if len(text) > SNIPPET else ""))


def _norm_color(value: str) -> str:
    return re.sub(r"\s+", "", value.strip().lower().replace("!important", ""))


def _invisible(tag: Tag) -> str | None:
    """Why ``tag`` is invisible, or None."""
    style = str(tag.get("style") or "")
    if tag.has_attr("hidden"):
        return "hidden attribute"
    match = _HIDDEN_STYLE_RE.search(style)
    if match:
        return match.group(0).strip().rstrip(";")
    color = _COLOR_RE.search(style)
    if color:
        text_color = _norm_color(color.group(1))
        background = _BG_RE.search(style)
        bg_color = _norm_color(background.group(1)) if background else None
        if (bg_color and text_color == bg_color) or (bg_color is None and text_color in _WHITE):
            return f"text colour {text_color} on the same background"
    return None


# --- Body checks ---------------------------------------------------------------------------------


def _tracking(soup: BeautifulSoup, result: AnalyzerResult) -> None:
    pixels: list[dict[str, Any]] = []
    domains: list[str] = []
    for img in soup.find_all("img"):
        src = str(img.get("src") or "")
        if not src.lower().startswith(("http://", "https://")):
            continue
        reasons = []
        size = [
            str(img.get(a) or "").strip().lower().removesuffix("px") for a in ("width", "height")
        ]
        if all(v.isdigit() and int(v) <= 1 for v in size):
            reasons.append("1x1 or smaller")
        style = str(img.get("style") or "")
        if _HIDDEN_STYLE_RE.search(style) or any(
            isinstance(parent, Tag) and _invisible(parent) for parent in img.parents
        ):
            reasons.append("hidden")
        ids = [
            name for name, value in parse_qsl(urlsplit(src).query)
            if len(value) >= UNIQUE_ID_MIN and _ID_VALUE_RE.match(value)
        ]
        if ids and reasons:
            reasons.append("unique id parameter")
        if not reasons:
            continue
        host = (urlsplit(src).hostname or "").lower()
        if host and host not in domains:
            domains.append(host)
        pixels.append({"url": defang_url(src), "reasons": reasons, "id_parameters": ids})
    result.raw["tracking_domains"] = [defang_domain(d) for d in domains]
    if pixels:
        result.findings.append(_finding("tracking_pixel", {"images": pixels}))


def _hidden_text(soup: BeautifulSoup, email: ParsedEmail, result: AnalyzerResult) -> None:
    blocks: list[dict[str, Any]] = []
    counted: set[int] = set()
    for tag in soup.find_all(True):
        if tag.name in ("script", "style", "head", "title", "meta"):
            continue
        reason = _invisible(tag)
        if not reason or any(id(p) in counted for p in tag.parents):
            continue
        text = tag.get_text(" ", strip=True)
        if len(text) >= MIN_HIDDEN_CHARS:
            counted.add(id(tag))
            blocks.append({"reason": reason, "chars": len(text), "text": _snippet(text)})
    total = sum(b["chars"] for b in blocks)
    result.raw["hidden_text_chars"] = total
    if blocks:
        result.findings.append(_finding("hidden_text", {"blocks": blocks, "total_chars": total}))
    if total >= FILLER_CHARS:
        result.findings.append(_finding("hidden_filler_text", {"total_chars": total}))

    body = email.text_body + " " + soup.get_text(" ")
    zero_width = len(_ZERO_WIDTH_RE.findall(body))
    if zero_width >= MIN_ZERO_WIDTH:
        kinds = sorted({f"U+{ord(c):04X}" for c in _ZERO_WIDTH_RE.findall(body)})
        result.findings.append(
            _finding("zero_width_characters", {"count": zero_width, "characters": kinds})
        )

    if email.text_body.strip() and email.html_body.strip():
        visible = soup.get_text(" ")
        text_words = set(_WORD_RE.findall(email.text_body.lower()))
        html_words = set(_WORD_RE.findall(visible.lower()))
        if len(text_words) >= 5 and len(html_words) >= 5:
            overlap = len(text_words & html_words) / len(text_words | html_words)
            result.raw["text_html_overlap"] = round(overlap, 2)
            if overlap < 0.2:
                result.findings.append(
                    _finding(
                        "text_html_mismatch",
                        {
                            "overlap": round(overlap, 2),
                            "text_part": _snippet(email.text_body),
                            "html_part": _snippet(visible),
                        },
                    )
                )


def _decoded_url(value: str) -> str | None:
    if not _B64_VALUE_RE.match(value):
        return None
    padded = value + "=" * (-len(value) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            text = decoder(padded).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if text.lower().startswith(("http://", "https://")):
            return text
    return None


def _obfuscation(soup: BeautifulSoup, html: str, result: AnalyzerResult) -> None:
    encoded: list[dict[str, Any]] = []
    if _ENTITY_IN_HREF_RE.search(html):
        encoded.append({"technique": "html_entities_in_href"})
    for link in soup.find_all("a"):
        href = str(link.get("href") or "")
        for name, value in parse_qsl(urlsplit(href).query):
            target = _decoded_url(value)
            if target:
                encoded.append(
                    {
                        "technique": "base64_url_parameter",
                        "link": defang_url(href),
                        "parameter": name,
                        "decoded": defang_url(target),
                    }
                )
                result.extracted_urls.append(UrlRef(url=target, source=UrlSource.ARTIFACT))
    if encoded:
        result.findings.append(_finding("encoded_link", {"links": encoded}))

    scripts = soup.find_all("script")
    if scripts:
        result.findings.append(
            _finding(
                "script_in_body",
                {
                    "count": len(scripts),
                    "sources": [defang_url(str(s["src"])) for s in scripts if s.get("src")],
                },
            )
        )

    targets = []
    for meta in soup.find_all("meta"):
        if str(meta.get("http-equiv", "")).lower() != "refresh":
            continue
        match = _META_REFRESH_RE.search(str(meta.get("content", "")))
        if match:
            url = match.group(1).strip()
            targets.append(defang_url(url))
            if url.lower().startswith(("http://", "https://")):
                result.extracted_urls.append(UrlRef(url=url, source=UrlSource.META_REFRESH))
    if targets:
        result.findings.append(_finding("meta_refresh", {"targets": targets}))


# --- Header checks -------------------------------------------------------------------------------


def _header(email: ParsedEmail, *names: str) -> list[str]:
    wanted = {n.lower() for n in names}
    return [v for n, v in email.headers if n.lower() in wanted]


def _headers(email: ParsedEmail, result: AnalyzerResult) -> None:
    if not email.headers:
        return
    if not email.message_id:
        result.findings.append(_finding("missing_message_id", {}))
    if email.date is None:
        result.findings.append(_finding("missing_date", {}))

    received = [h.timestamp for h in email.received_chain if h.timestamp is not None]
    if email.date is not None and received:
        delivered = received[-1]
        if email.date > delivered + FUTURE_TOLERANCE:
            result.findings.append(
                _finding(
                    "date_in_future",
                    {"date": email.date.isoformat(), "delivered": delivered.isoformat()},
                )
            )
        elif delivered - email.date > timedelta(days=MAX_DATE_AGE_DAYS):
            result.findings.append(
                _finding(
                    "date_too_old",
                    {
                        "date": email.date.isoformat(),
                        "delivered": delivered.isoformat(),
                        "days": (delivered - email.date).days,
                    },
                )
            )

    from_domain = email.from_addrs[0].org_domain if email.from_addrs else ""
    match = re.search(r"@([^>\s]+)>?\s*$", email.message_id or "")
    if match and from_domain:
        mid_domain = match.group(1).lower().rstrip(".")
        mid_org = org_domain(mid_domain) or mid_domain
        if mid_org != from_domain and esp_for_domain(mid_domain) is None:
            result.findings.append(
                _finding(
                    "message_id_domain_mismatch",
                    {
                        "message_id_domain": defang_domain(mid_domain),
                        "from_domain": defang_domain(from_domain),
                    },
                )
            )

    mailer_headers = _header(email, "X-Mailer", "User-Agent", "X-MimeOLE")
    hits = [
        {"tool": m.name, "header": value[:120]}
        for value in mailer_headers
        for m in suspicious_mailers()
        if re.search(m.pattern, value, re.IGNORECASE)
    ]
    if hits:
        result.findings.append(_finding("suspicious_mailer", {"matches": hits}))


def _inline_qr(email: ParsedEmail, result: AnalyzerResult) -> None:
    if not email.inline_images:
        return
    if not qr_available():
        result.raw["inline_qr"] = "unavailable (zbar not installed)"
        return
    found = []
    for image in email.inline_images:
        for text in decode_qr(image.data):
            if text.lower().startswith(("http://", "https://")):
                found.append({"image": image.filename, "url": defang_url(text)})
                result.extracted_urls.append(UrlRef(url=text, source=UrlSource.QR_CODE))
    result.raw["inline_qr"] = found


async def analyze(
    email: ParsedEmail, context: dict[str, AnalyzerResult] | None = None
) -> AnalyzerResult:
    """Look for hidden artifacts. Never raises; errors go into ``errors``."""
    start = time.perf_counter()
    result = AnalyzerResult(module=MODULE)
    soup = BeautifulSoup(email.html_body or "", "html.parser")
    checks = (
        ("tracking", lambda: _tracking(soup, result)),
        ("hidden_text", lambda: _hidden_text(soup, email, result)),
        ("obfuscation", lambda: _obfuscation(soup, email.html_body, result)),
        ("headers", lambda: _headers(email, result)),
        ("inline_qr", lambda: _inline_qr(email, result)),
    )
    for name, check in checks:
        try:
            check()
        except Exception as exc:
            result.errors.append(f"{name}: {type(exc).__name__}: {exc}")
    result.duration_ms = int((time.perf_counter() - start) * 1000)
    return result
