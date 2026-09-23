"""Email parsing: turn raw RFC 822 bytes into a ``ParsedEmail``.

``parse_email`` puts the parser modules together: headers and addresses
(``headers``), the Received chain (``received``), bodies and URLs (``body``) and
attachments, inline images and nested emails (``attachments``). ``message/rfc822`` parts are
parsed recursively into ``nested_emails`` up to ``MAX_NESTED_DEPTH`` levels; deeper messages
are kept as plain attachments. Parsing never raises: problems are recorded in
``ParsedEmail.parse_warnings``.
"""

from __future__ import annotations

import email
import hashlib
from email import policy

from phishlens.models import ParsedEmail
from phishlens.parser.attachments import extract_attachments
from phishlens.parser.body import extract_bodies, extract_urls
from phishlens.parser.headers import parse_headers
from phishlens.parser.received import received_chain_from_headers

__all__ = ["MAX_NESTED_DEPTH", "parse_email"]

MAX_NESTED_DEPTH = 3


def parse_email(raw_bytes: bytes, _depth: int = 0) -> ParsedEmail:
    """Parse a raw email into a complete ``ParsedEmail``. Never raises.

    ``sha256`` is the hash of ``raw_bytes``. Nested emails are parsed from their
    re-serialized bytes, so their ``sha256`` is the hash of those bytes.
    """
    try:
        parsed = parse_headers(raw_bytes)
    except Exception as exc:
        parsed = ParsedEmail(
            raw_bytes=raw_bytes,
            parse_warnings=[f"header_parse_error: {type(exc).__name__}: {exc}"],
        )
    parsed.sha256 = hashlib.sha256(raw_bytes).hexdigest()
    warnings = parsed.parse_warnings
    parsed.auth_results_headers = [
        value for name, value in parsed.headers if name.lower() == "authentication-results"
    ]

    try:
        parsed.received_chain, received_warnings = received_chain_from_headers(parsed.headers)
        warnings.extend(received_warnings)
    except Exception as exc:
        warnings.append(f"received_parse_error: {type(exc).__name__}: {exc}")

    try:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    except Exception as exc:
        warnings.append(f"message_parse_error: {type(exc).__name__}: {exc}")
        return parsed

    try:
        text, html, body_warnings = extract_bodies(msg)
        parsed.text_body, parsed.html_body = text, html
        warnings.extend(body_warnings)
    except Exception as exc:
        warnings.append(f"body_parse_error: {type(exc).__name__}: {exc}")
    try:
        parsed.urls = extract_urls(parsed.text_body, parsed.html_body)
    except Exception as exc:
        warnings.append(f"url_extract_error: {type(exc).__name__}: {exc}")

    parts = extract_attachments(msg)
    warnings.extend(parts.warnings)
    parsed.attachments = parts.attachments
    parsed.inline_images = parts.inline_images
    for nested in parts.nested:
        if _depth + 1 > MAX_NESTED_DEPTH:
            warnings.append(
                f"nested_depth_exceeded: {nested.filename} is deeper than "
                f"{MAX_NESTED_DEPTH} levels; kept as an attachment"
            )
            parsed.attachments.append(nested)
        else:
            parsed.nested_emails.append(parse_email(nested.data, _depth + 1))
    return parsed
