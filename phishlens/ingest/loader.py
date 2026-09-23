"""Load a user input and decide whether it is an email or a standalone file.

Detection is by content, not by file extension:

- RFC 822 headers at the start of the data -> ``"email"`` (``.eml``).
- OLE compound file signature that extract-msg opens as a message -> ``"email"`` (``.msg``).
  The message is converted to raw RFC 822 bytes so later stages only deal with one format.
- Anything else (including OLE documents such as ``.doc`` / ``.xls``) -> ``"file"``.

Nothing is executed or rendered: the input is only read as bytes.
"""

from __future__ import annotations

import email.policy
import re
from pathlib import Path
from typing import Literal

import extract_msg

from phishlens.config import get_settings

InputKind = Literal["email", "file"]

OLE_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Header added to converted .msg files that had no transport headers. The parser turns it into
# a ``ParsedEmail.parse_warnings`` entry.
PARSE_WARNING_HEADER = "X-PhishLens-Parse-Warning"
MSG_NO_TRANSPORT_HEADERS = (
    "msg_no_transport_headers: the .msg file has no transport headers; "
    "headers were rebuilt from MAPI properties"
)

# How much of the input is inspected when looking for a header block.
_SNIFF_BYTES = 64 * 1024
_SNIFF_LINES = 50
# RFC 5322 field name: printable US-ASCII except ':' and space.
_FIELD_RE = re.compile(r"^([!-9;-~]+)[ \t]*:")
_KNOWN_FIELDS = frozenset(
    {
        "from",
        "sender",
        "reply-to",
        "subject",
        "received",
        "return-path",
        "message-id",
        "mime-version",
        "delivered-to",
    }
)


class LoaderError(ValueError):
    """The input cannot be loaded."""


class InputTooLargeError(LoaderError):
    """The input is larger than the configured ``MAX_INPUT_SIZE_MB``."""


class MsgConversionError(LoaderError):
    """A .msg message was recognised but could not be converted to RFC 822."""


def max_input_bytes() -> int:
    """Return the configured maximum input size in bytes."""
    return int(get_settings().max_input_size_mb * 1024 * 1024)


def load_input(
    path_or_bytes: str | Path | bytes | bytearray, filename: str | None = None
) -> tuple[InputKind, bytes]:
    """Read the input and return ``("email", rfc822_bytes)`` or ``("file", raw_bytes)``.

    ``filename`` is only used in error messages; detection never trusts the extension.
    Raises ``InputTooLargeError`` when the input exceeds the configured size limit and
    ``MsgConversionError`` when a recognised .msg message cannot be converted.
    """
    limit = max_input_bytes()
    if isinstance(path_or_bytes, bytes | bytearray):
        data = bytes(path_or_bytes)
        name = filename or "<bytes>"
    else:
        path = Path(path_or_bytes)
        name = filename or path.name
        size = path.stat().st_size
        if size > limit:
            raise InputTooLargeError(_too_large(name, size, limit))
        data = path.read_bytes()
    if len(data) > limit:
        raise InputTooLargeError(_too_large(name, len(data), limit))

    if data.startswith(OLE_SIGNATURE):
        converted = _msg_to_rfc822(data, name)
        if converted is not None:
            return "email", converted
        return "file", data
    if looks_like_rfc822(data):
        return "email", data
    return "file", data


def looks_like_rfc822(data: bytes) -> bool:
    """Return True when ``data`` starts with an RFC 822 header block.

    Every line up to the first blank line (or the sniff limit) must be a header field or a
    folded continuation line. At least two fields are required and one of them must be a
    common mail header, so random text with a colon is not mistaken for an email.
    """
    head = data[:_SNIFF_BYTES]
    if head.startswith(b"\xef\xbb\xbf"):
        head = head[3:]
    head = head.lstrip(b"\r\n\t ")
    if b"\x00" in head:
        return False
    lines = head.decode("latin-1").splitlines()
    if lines and lines[0].startswith("From "):  # mbox separator line
        lines = lines[1:]

    fields: list[str] = []
    for line in lines[:_SNIFF_LINES]:
        if not line.strip():
            break
        if line[0] in " \t":
            if not fields:
                return False
            continue
        match = _FIELD_RE.match(line)
        if match is None:
            return False
        fields.append(match.group(1).lower())
    return len(fields) >= 2 and any(field in _KNOWN_FIELDS for field in fields)


def _msg_to_rfc822(data: bytes, name: str) -> bytes | None:
    """Convert an Outlook .msg to RFC 822 bytes.

    Returns None when the OLE file is not an Outlook message (for example a Word document),
    so the caller treats it as a standalone file.
    """
    try:
        msg = extract_msg.openMsg(data)
    except Exception:
        return None
    try:
        if not hasattr(msg, "asEmailMessage"):
            return None
        try:
            message = msg.asEmailMessage()
            header_text = msg.headerText
        except Exception as exc:
            raise MsgConversionError(f"{name}: could not convert .msg to RFC 822: {exc}") from exc
        if not (header_text and header_text.strip()):
            message[PARSE_WARNING_HEADER] = MSG_NO_TRANSPORT_HEADERS
        try:
            return message.as_bytes(policy=email.policy.default)
        except Exception as exc:
            raise MsgConversionError(f"{name}: could not serialize converted .msg: {exc}") from exc
    finally:
        try:
            msg.close()
        except Exception:
            pass


def _too_large(name: str, size: int, limit: int) -> str:
    return f"{name}: input is {size} bytes, larger than the {limit} byte limit (MAX_INPUT_SIZE_MB)"
