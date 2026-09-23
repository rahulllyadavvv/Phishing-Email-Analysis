"""Extract attachments, inline images and nested emails from a parsed message.

The MIME tree is walked once. Every leaf part that is not a body part becomes an
``Attachment`` with its decoded bytes, size, declared MIME type and md5/sha1/sha256 hashes:

- ``text/plain`` / ``text/html`` parts without ``Content-Disposition: attachment`` are bodies
  (handled by ``phishlens.parser.body``) and are skipped here.
- ``image/*`` parts that are not ``Content-Disposition: attachment`` go to ``inline_images``.
- ``message/rfc822`` (and ``message/global``) parts are re-serialized to bytes and returned in
  ``nested`` so the caller can parse them recursively (or keep them as plain attachments once
  the nesting limit is reached). Other ``message/*`` parts are kept as attachments.
- Everything else goes to ``attachments``.

Archives are not unpacked here and nothing is opened, rendered or executed: the payload is
only transfer-decoded and hashed. Parsing never raises on bad input. Problems are returned as
``"<code>: <detail>"`` warnings.
"""

from __future__ import annotations

import hashlib
import mimetypes
import re
from dataclasses import dataclass, field
from email import policy
from email.message import Message

from phishlens.models import Attachment

# Re-serialize nested messages without refolding headers so they stay close to the original.
_NESTED_POLICY = policy.default.clone(max_line_length=0)
_NESTED_TYPES = frozenset({"message/rfc822", "message/global"})
_BODY_TYPES = frozenset({"text/plain", "text/html"})
_WS_RE = re.compile(r"\s+")


@dataclass
class ExtractedParts:
    """Attachments, inline images and nested messages found in one message."""

    attachments: list[Attachment] = field(default_factory=list)
    inline_images: list[Attachment] = field(default_factory=list)
    nested: list[Attachment] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def make_attachment(
    filename: str,
    data: bytes,
    declared_type: str | None = None,
    parent: str | None = None,
    depth: int = 0,
) -> Attachment:
    """Build an ``Attachment`` for ``data`` with its size and md5/sha1/sha256 hashes."""
    return Attachment(
        filename=filename,
        declared_type=declared_type,
        size=len(data),
        data=data,
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        parent=parent,
        depth=depth,
    )


def _filename(part: Message, index: int, warnings: list[str]) -> str:
    """Declared filename (Content-Disposition, then Content-Type ``name``) or a generated one."""
    name: object = None
    try:
        name = part.get_filename() or part.get_param("name", header="content-type")
    except Exception as exc:
        warnings.append(f"attachment_filename_error: part {index}: {type(exc).__name__}")
    if isinstance(name, tuple):  # RFC 2231 value that was not decoded
        name = str(name[2])
    if isinstance(name, str):
        name = _WS_RE.sub(" ", name).strip()
        if name:
            return name
    content_type = part.get_content_type()
    if content_type in _NESTED_TYPES:
        extension = ".eml"
    else:
        extension = mimetypes.guess_extension(content_type, strict=False) or ".bin"
    return f"part-{index}{extension}"


def _payload(part: Message, index: int, warnings: list[str]) -> bytes:
    """Transfer-decoded bytes of a leaf part (``message/*`` parts are re-serialized)."""
    if part.get_content_maintype() == "message":
        inner = part.get_payload()
        chunks: list[bytes] = []
        for sub in inner if isinstance(inner, list) else [inner]:
            if isinstance(sub, Message):
                chunks.append(sub.as_bytes(policy=_NESTED_POLICY))
            elif isinstance(sub, str):
                chunks.append(sub.encode("utf-8", errors="surrogateescape"))
            elif isinstance(sub, bytes):
                chunks.append(sub)
        return b"".join(chunks)
    data = part.get_payload(decode=True)
    if isinstance(data, bytes):
        return data
    warnings.append(f"attachment_decode_error: part {index} has no decodable payload")
    return b""


def _walk(part: Message, out: ExtractedParts, counter: list[int]) -> None:
    content_type = part.get_content_type()
    maintype = part.get_content_maintype()
    if part.is_multipart() and maintype != "message":
        payload = part.get_payload()
        for sub in payload if isinstance(payload, list) else []:
            _walk(sub, out, counter)
        return
    disposition = part.get_content_disposition()
    if content_type in _BODY_TYPES and disposition != "attachment":
        return
    counter[0] += 1
    index = counter[0]
    attachment = make_attachment(
        _filename(part, index, out.warnings),
        _payload(part, index, out.warnings),
        declared_type=content_type,
    )
    if content_type in _NESTED_TYPES:
        out.nested.append(attachment)
    elif maintype == "image" and disposition != "attachment":
        out.inline_images.append(attachment)
    else:
        out.attachments.append(attachment)


def extract_attachments(msg: Message) -> ExtractedParts:
    """Return the attachments, inline images and nested messages of ``msg``.

    Never raises: an unexpected error stops the walk and is recorded as a warning, and the
    parts found so far are kept.
    """
    out = ExtractedParts()
    try:
        _walk(msg, out, [0])
    except Exception as exc:
        out.warnings.append(f"attachment_extract_error: {type(exc).__name__}: {exc}")
    return out
