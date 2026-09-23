"""Tests for phishlens.parser.attachments."""

from __future__ import annotations

import base64
import email
import hashlib
import io
import zipfile
from email import policy
from pathlib import Path

from phishlens.parser.attachments import extract_attachments, make_attachment

FIXTURES = Path(__file__).parent / "fixtures"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _extract(raw: bytes):
    return extract_attachments(email.message_from_bytes(raw, policy=policy.default))


def _fixture(name: str):
    return _extract((FIXTURES / name).read_bytes())


def _mime(body_parts: str, boundary: str = "BOUND") -> bytes:
    head = (
        "From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n"
        f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n\r\n'
    )
    return (head + body_parts + f"--{boundary}--\r\n").encode("latin-1")


def test_make_attachment_hashes():
    att = make_attachment("a.bin", b"abc", declared_type="application/octet-stream")
    assert att.size == 3
    assert att.md5 == hashlib.md5(b"abc").hexdigest()
    assert att.sha1 == hashlib.sha1(b"abc").hexdigest()
    assert att.sha256 == hashlib.sha256(b"abc").hexdigest()
    assert att.depth == 0 and att.parent is None
    assert "data" not in att.model_dump()


# --- fixture 7: zip attachment ---------------------------------------------------------


def test_zip_attachment_extracted_not_unpacked():
    parts = _fixture("zip_attachment.eml")
    assert parts.warnings == []
    assert parts.inline_images == [] and parts.nested == []
    assert len(parts.attachments) == 1
    att = parts.attachments[0]
    assert att.filename == "notes.zip"
    assert att.declared_type == "application/zip"
    assert att.detected_type is None
    assert att.size == len(att.data)
    assert att.sha256 == hashlib.sha256(att.data).hexdigest()
    # The zip is kept whole; the bytes are a valid archive (unpacking is Phase 6).
    assert zipfile.ZipFile(io.BytesIO(att.data)).namelist() == ["notes.txt"]


# --- fixture 12: QR code inline image --------------------------------------------------


def test_qr_code_inline_image():
    parts = _fixture("qr_code.eml")
    assert parts.warnings == []
    assert parts.attachments == []
    assert len(parts.inline_images) == 1
    img = parts.inline_images[0]
    assert img.filename == "qrcode.png"
    assert img.declared_type == "image/png"
    assert img.data.startswith(b"\x89PNG\r\n\x1a\n")
    assert img.md5 == hashlib.md5(img.data).hexdigest()
    assert img.sha1 == hashlib.sha1(img.data).hexdigest()
    assert img.sha256 == hashlib.sha256(img.data).hexdigest()


# --- fixture 13: forwarded nested email ------------------------------------------------


def test_forwarded_nested_message_returned_as_nested():
    parts = _fixture("forwarded_nested.eml")
    assert parts.warnings == []
    assert parts.attachments == [] and parts.inline_images == []
    assert len(parts.nested) == 1
    nested = parts.nested[0]
    assert nested.declared_type == "message/rfc822"
    assert nested.filename == "part-1.eml"
    assert b"From: Microsoft Account Team <account-security@microsoft.com>" in nested.data
    assert nested.sha256 == hashlib.sha256(nested.data).hexdigest()


# --- fixture 14: EICAR attachment ------------------------------------------------------


def test_eicar_attachment_hash():
    parts = _fixture("eicar_attachment.eml")
    assert parts.warnings == []
    assert len(parts.attachments) == 1
    att = parts.attachments[0]
    assert att.filename == "eicar.com"
    assert att.declared_type == "application/octet-stream"
    assert att.size == 68
    assert att.sha256 == EICAR_SHA256


# --- edge cases ------------------------------------------------------------------------


def test_bodies_skipped_attached_text_kept():
    raw = _mime(
        "--BOUND\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
        "--BOUND\r\nContent-Type: text/html\r\n\r\n<p>body</p>\r\n"
        "--BOUND\r\nContent-Type: text/html\r\n"
        'Content-Disposition: attachment; filename="page.html"\r\n\r\n<p>x</p>\r\n'
    )
    parts = _extract(raw)
    assert [a.filename for a in parts.attachments] == ["page.html"]
    assert parts.attachments[0].declared_type == "text/html"


def test_filename_from_content_type_name_and_generated():
    data = base64.b64encode(b"%PDF-1.4 harmless").decode()
    raw = _mime(
        '--BOUND\r\nContent-Type: application/pdf; name="doc.pdf"\r\n'
        f"Content-Transfer-Encoding: base64\r\n\r\n{data}\r\n"
        "--BOUND\r\nContent-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment\r\n\r\nxyz\r\n"
    )
    parts = _extract(raw)
    assert [a.filename for a in parts.attachments] == ["doc.pdf", "part-2.bin"]
    assert parts.attachments[0].data == b"%PDF-1.4 harmless"


def test_encoded_filename_decoded():
    raw = _mime(
        "--BOUND\r\nContent-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename*=utf-8''r%C3%A9sum%C3%A9.pdf\r\n\r\nx\r\n"
    )
    assert _extract(raw).attachments[0].filename == "résumé.pdf"


def test_image_with_attachment_disposition_is_attachment():
    raw = _mime(
        "--BOUND\r\nContent-Type: image/png\r\n"
        'Content-Disposition: attachment; filename="photo.png"\r\n\r\nx\r\n'
        "--BOUND\r\nContent-Type: image/gif\r\nContent-ID: <logo>\r\n\r\ny\r\n"
    )
    parts = _extract(raw)
    assert [a.filename for a in parts.attachments] == ["photo.png"]
    assert [a.filename for a in parts.inline_images] == ["part-2.gif"]


def test_bad_structure_never_raises():
    raw = _mime(
        "--BOUND\r\nContent-Type: application/octet-stream\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        'Content-Disposition: attachment; filename="bad.bin"\r\n\r\n!!!not base64@@\r\n',
        boundary="OTHER",
    )
    parts = _extract(raw)
    assert isinstance(parts.warnings, list)
    assert _extract(b"\x00\xff garbage").warnings is not None
