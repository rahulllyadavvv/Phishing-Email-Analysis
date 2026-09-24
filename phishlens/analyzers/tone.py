"""Body tone analyzer (rule layer): pressure, fear, greed, authority and sensitive requests.

The subject and body (text part, or the visible text of the HTML part when there is no text
part) are normalized: lowercased, zero-width characters removed, spaces collapsed (line breaks
kept). Each lexicon in ``data/lexicons/`` (phrases matched as whole words, plus regular
expressions) produces one finding per category with the matched phrases and a short context
snippet. A category counts at most ``cap`` distinct matches (``evidence.counted``), which the
scorer uses so a long rant cannot outweigh everything else.

``raw["highlights"]`` lists ``(category, phrase, start, end)`` offsets into
``raw["normalized_text"]`` for UI highlighting.

Brands named in the body are checked with ``domain.bind_identity``: claiming to be a brand the
sender did not authenticate as is ``brand_impersonation``. Brands already claimed in the display
name, a lookalike domain or the subject are handled by the domain analyzer and skipped here.
"""

from __future__ import annotations

import re
import time
from functools import cache
from typing import Any

from bs4 import BeautifulSoup

from phishlens.analyzers.binaries import defang_text
from phishlens.analyzers.domain import (
    ClaimedBrand,
    bind_identity,
    find_brand_mentions,
    sender_identity,
)
from phishlens.data_loader import Lexicon, lexicons
from phishlens.models import AnalyzerResult, Finding, ParsedEmail, Severity

MODULE = "tone"

__all__ = ["MODULE", "analyze", "match_lexicons", "normalize_text"]

MAX_TEXT = 20_000  # characters of normalized text kept in raw for highlighting
CONTEXT = 40
_WORD = r"\wऀ-ॿ"  # Devanagari vowel signs are not \w in Python's re
_ZERO_WIDTH_RE = re.compile("[​‌‍⁠﻿­᠎]")
_SPACES_RE = re.compile(r"[ \t\r\f\v ]+")
_BLANK_LINES_RE = re.compile(r"\n\s*\n+")

TEXTS: dict[str, tuple[str, str]] = {
    "tone_urgency": (
        "Urgent, pressuring language",
        "The message pushes the reader to act immediately, a classic way to stop them thinking.",
    ),
    "tone_fear": (
        "Threatening language",
        "The message threatens loss, lock-out or trouble if the reader does not act.",
    ),
    "tone_greed": (
        "Promise of money or prizes",
        "The message dangles prizes, refunds or unexpected money.",
    ),
    "tone_authority": (
        "Appeal to authority",
        "The message leans on management, IT, a bank or the government to force compliance.",
    ),
    "credential_request": (
        "Asks for credentials or verification",
        "The message asks the reader to log in, verify an account or share a password or code.",
    ),
    "payment_request": (
        "Asks for a payment",
        "The message asks for a transfer, an invoice payment, gift cards or new bank details.",
    ),
    "secrecy_request": (
        "Asks for secrecy",
        "The message asks the reader to keep the request private or away from normal "
        "channels, typical of CEO fraud.",
    ),
    "generic_greeting": (
        "Generic greeting",
        "The message does not use the recipient's name (\"Dear customer\"), typical of mass "
        "phishing.",
    ),
}


def normalize_text(text: str) -> str:
    """Lowercase, remove zero-width characters, collapse spaces (keeping line breaks)."""
    text = _ZERO_WIDTH_RE.sub("", text).lower()
    lines = [_SPACES_RE.sub(" ", line).strip() for line in text.splitlines()]
    return _BLANK_LINES_RE.sub("\n", "\n".join(lines)).strip()


def _body_text(email: ParsedEmail) -> str:
    if email.text_body.strip():
        return email.text_body
    if email.html_body.strip():
        return BeautifulSoup(email.html_body, "html.parser").get_text("\n")
    return ""


@cache
def _compiled(lexicon: Lexicon) -> tuple[re.Pattern[str], ...]:
    patterns = [
        re.compile(
            rf"(?<![{_WORD}])"
            + r"\s+".join(re.escape(w) for w in phrase.split())
            + rf"(?![{_WORD}])"
        )
        for phrase in lexicon.phrases
    ]
    patterns += [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in lexicon.patterns]
    return tuple(patterns)


def match_lexicons(text: str) -> dict[str, list[tuple[str, int, int]]]:
    """Category -> non-overlapping matches ``(matched text, start, end)`` in ``text``.

    Where matches of one category overlap, the longest wins ("account will be suspended"
    rather than just "suspended").
    """
    found: dict[str, list[tuple[str, int, int]]] = {}
    for category, lexicon in lexicons().items():
        candidates = [
            match.span()
            for pattern in _compiled(lexicon)
            for match in pattern.finditer(text)
            if match.end() > match.start()
        ]
        spans: list[tuple[str, int, int]] = []
        for start, end in sorted(set(candidates), key=lambda s: (s[0] - s[1], s[0])):
            if not any(s < end and start < e for _, s, e in spans):
                spans.append((" ".join(text[start:end].split()), start, end))
        if spans:
            found[category] = sorted(spans, key=lambda m: m[1])
    return found


def _snippet(text: str, start: int, end: int) -> str:
    left = max(0, start - CONTEXT)
    right = min(len(text), end + CONTEXT)
    piece = defang_text(text[left:right].replace("\n", " "))
    return ("..." if left else "") + piece + ("..." if right < len(text) else "")


def _tone_findings(text: str, result: AnalyzerResult) -> None:
    matches = match_lexicons(text)
    highlights = []
    all_lexicons = lexicons()
    for category, spans in matches.items():
        lexicon = all_lexicons[category]
        distinct: list[str] = []
        entries = []
        for phrase, start, end in spans:
            highlights.append((category, phrase, start, end))
            if phrase not in distinct:
                distinct.append(phrase)
                entries.append(
                    {"phrase": defang_text(phrase), "snippet": _snippet(text, start, end)}
                )
        title, description = TEXTS.get(lexicon.finding_id, (category, ""))
        result.findings.append(
            Finding(
                id=lexicon.finding_id,
                module=MODULE,
                title=title,
                description=description,
                severity=Severity(lexicon.severity),
                evidence={
                    "matches": entries,
                    "count": len(distinct),
                    "counted": min(len(distinct), lexicon.cap),
                    "cap": lexicon.cap,
                },
            )
        )
    result.raw["highlights"] = sorted(highlights, key=lambda h: h[2])
    result.raw["categories"] = {c: len(s) for c, s in matches.items()}


def _brand_claims(
    email: ParsedEmail, body: str, context: dict[str, AnalyzerResult] | None, result: AnalyzerResult
) -> None:
    domain_result = (context or {}).get("domain")
    already = set()
    claims: dict[str, tuple[Any, list[str]]] = {}
    if domain_result is not None:
        already = set((domain_result.raw.get("identity") or {}).get("claimed_brands", {}))
    else:
        for mention in find_brand_mentions(email.subject):
            claims.setdefault(mention.brand.name, (mention.brand, []))[1].append("subject")
    for mention in find_brand_mentions(body):
        entry = claims.setdefault(mention.brand.name, (mention.brand, []))
        if "body" not in entry[1]:
            entry[1].append("body")
    claimed = [
        ClaimedBrand(brand, tuple(sources))
        for name, (brand, sources) in claims.items()
        if name not in already
    ]
    result.raw["body_brands"] = sorted(claims)
    identity = sender_identity(email, context)
    if identity is None or not claimed:
        return
    domain_raw = domain_result.raw if domain_result is not None else {}
    findings = bind_identity(
        claimed,
        identity,
        lookalike_domains=frozenset(domain_raw.get("lookalikes", {})),
        new_domains=frozenset(domain_raw.get("new_domains", [])),
    )
    result.findings.extend(f.model_copy(update={"module": MODULE}) for f in findings)


async def analyze(
    email: ParsedEmail, context: dict[str, AnalyzerResult] | None = None
) -> AnalyzerResult:
    """Analyze the tone of the subject and body. Never raises."""
    start = time.perf_counter()
    result = AnalyzerResult(module=MODULE)
    body = ""
    try:
        body = _body_text(email)
        text = normalize_text(f"{email.subject}\n{body}")
        result.raw["normalized_text"] = text[:MAX_TEXT]
        _tone_findings(text[:MAX_TEXT], result)
    except Exception as exc:
        result.errors.append(f"rules: {type(exc).__name__}: {exc}")
    try:
        _brand_claims(email, body, context, result)
    except Exception as exc:
        result.errors.append(f"brands: {type(exc).__name__}: {exc}")
    result.duration_ms = int((time.perf_counter() - start) * 1000)
    return result
