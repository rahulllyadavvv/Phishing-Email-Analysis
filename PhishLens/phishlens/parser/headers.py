"""Parse the header block of an email into a ``ParsedEmail``.

Only headers are handled here: every header is kept in original order (duplicates included),
encoded words are decoded, and the address headers (From, Reply-To, Sender, Return-Path, To,
Cc) are turned into ``Address`` objects. Bodies, Received hops and attachments are filled in by
other parser modules.

Parsing never raises on bad input. Problems are recorded in ``ParsedEmail.parse_warnings`` as
``"<code>: <detail>"`` strings.
"""

from __future__ import annotations

import email
import hashlib
import re
from datetime import datetime
from email import policy
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from functools import lru_cache

import tldextract

from phishlens.ingest.loader import PARSE_WARNING_HEADER
from phishlens.models import Address, ParsedEmail

_POLICY = policy.default
_EMAIL_IN_TEXT_RE = re.compile(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")
_FOLD_RE = re.compile(r"\r?\n[ \t]*")
# Headers whose display names are checked for an embedded email address.
_DISPLAY_NAME_CHECKED = ("From", "Sender", "Reply-To")


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    # Offline: use the public suffix snapshot bundled with tldextract, never fetch it.
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def org_domain(domain: str) -> str:
    """Return the organizational (registered) domain for ``domain``.

    Domains without a known public suffix (reserved TLDs such as ``.example`` / ``.test``,
    single labels) fall back to the last two labels. IP literals are returned unchanged.
    """
    domain = domain.strip().strip(".").lower()
    if not domain:
        return ""
    if domain.startswith("["):
        return domain
    result = _extractor()(domain)
    if result.suffix:
        return result.top_domain_under_public_suffix or domain
    if result.domain.replace(".", "").isdigit():
        return domain
    return ".".join(domain.split(".")[-2:])


def make_address(display_name: str, addr: str) -> Address:
    """Build an ``Address`` with lowercased ``domain`` and its ``org_domain``."""
    addr = addr.strip()
    domain = addr.rpartition("@")[2].lower() if "@" in addr else ""
    return Address(
        display_name=display_name.strip(),
        address=addr,
        domain=domain,
        org_domain=org_domain(domain),
    )


def _unfold(value: str) -> str:
    return _FOLD_RE.sub(" ", value).strip()


def _fallback_decode(value: str) -> str:
    try:
        return str(make_header(decode_header(_unfold(value))))
    except Exception:
        return _unfold(value)


def _decode(name: str, raw: str, warnings: list[str]) -> tuple[str, object | None]:
    """Decode one raw header value. Returns the text and the policy header object (if any)."""
    try:
        header = _POLICY.header_fetch_parse(name, raw)
        text = str(header)
    except Exception as exc:
        warnings.append(f"header_decode_error: {name}: {type(exc).__name__}")
        return _fallback_decode(raw), None
    for defect in getattr(header, "defects", ()):
        warnings.append(f"header_defect: {name}: {defect}")
    if "�" in text:
        warnings.append(f"header_decode_error: {name}: undecodable bytes replaced")
    return text, header


def _addresses_from(name: str, raw: str, header: object | None) -> list[Address]:
    """Turn one address header into ``Address`` objects, with a lenient fallback."""
    if name.lower() == "return-path":
        _, addr = parseaddr(_fallback_decode(raw))
        return [make_address("", addr)] if addr else []
    parsed = getattr(header, "addresses", None)
    if parsed is not None:
        try:
            return [
                make_address(a.display_name, a.addr_spec)
                for a in parsed
                if a.addr_spec and a.addr_spec != "<>"
            ]
        except Exception:
            pass
    return [
        make_address(display, addr)
        for display, addr in getaddresses([_fallback_decode(raw)])
        if addr
    ]


def _parse_date(value: str) -> datetime | None:
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None


def parse_headers(raw: bytes) -> ParsedEmail:
    """Parse the headers of a raw RFC 822 message.

    The returned ``ParsedEmail`` has ``headers``, the address fields, ``subject``, ``date``,
    ``message_id``, ``raw_bytes`` and ``parse_warnings`` set. Other fields stay empty.
    """
    warnings: list[str] = []
    try:
        msg = email.message_from_bytes(raw, policy=_POLICY)
        raw_items = list(msg.raw_items())
    except Exception as exc:
        warnings.append(f"message_parse_error: {type(exc).__name__}: {exc}")
        raw_items = []

    headers: list[tuple[str, str]] = []
    addresses: dict[str, list[list[Address]]] = {}
    for name, raw_value in raw_items:
        text, header = _decode(name, raw_value, warnings)
        if name.lower() == PARSE_WARNING_HEADER.lower():
            warnings.append(text)
            continue
        headers.append((name, text))
        key = name.lower()
        if key in {"from", "reply-to", "sender", "return-path", "to", "cc"}:
            addresses.setdefault(key, []).append(_addresses_from(name, raw_value, header))

    def first(name: str) -> str | None:
        return next((v for n, v in headers if n.lower() == name), None)

    def flat(key: str) -> list[Address]:
        return [a for group in addresses.get(key, []) for a in group]

    from_groups = addresses.get("from", [])
    from_addrs = flat("from")
    if not from_groups:
        warnings.append("missing_from: no From header")
    elif not from_addrs:
        warnings.append("empty_from: the From header has no address")
    if len(from_groups) > 1:
        warnings.append(f"multiple_from_headers: {len(from_groups)} From headers found")
    for group in from_groups:
        if len(group) > 1:
            warnings.append(
                f"multiple_from_addresses: one From header lists {len(group)} addresses"
            )

    for header_name in _DISPLAY_NAME_CHECKED:
        for addr in flat(header_name.lower()):
            for embedded in _EMAIL_IN_TEXT_RE.findall(addr.display_name):
                if embedded.lower() != addr.address.lower():
                    warnings.append(
                        f"display_name_contains_email: {header_name} display name "
                        f"contains {embedded!r} but the address is {addr.address!r}"
                    )

    sender = flat("sender")
    return_path = flat("return-path")
    date_value = first("date")
    message_id = first("message-id")
    return ParsedEmail(
        headers=headers,
        from_addrs=from_addrs,
        reply_to=flat("reply-to"),
        sender=sender[0] if sender else None,
        return_path=return_path[0] if return_path else None,
        to=flat("to"),
        cc=flat("cc"),
        subject=first("subject") or "",
        date=_parse_date(date_value) if date_value else None,
        message_id=message_id.strip() if message_id else None,
        parse_warnings=warnings,
        raw_bytes=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
    )
