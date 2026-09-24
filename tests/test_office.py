"""Tests for phishlens.analyzers.office. All documents are built in the test from harmless
bytes; nothing is opened in Office or executed."""

from __future__ import annotations

import io
import struct
import zipfile

import pytest

from phishlens.analyzers import office
from phishlens.analyzers.office import analyze_office, is_office_type

DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
VBA_TEXT = b'''Attribute VB_Name = "Module1"
Sub AutoOpen()
    Dim s As String
    s = "https://payload.example.test/stage2"
    Set o = CreateObject("WScript.Shell")
    o.Run "powershell -nop -c echo harmless-test"
End Sub
'''


def _flags(report) -> dict:
    return dict(report.flags)


def _docx(rels: list[tuple[str, str, str]], extra: dict[str, bytes] | None = None) -> bytes:
    """A minimal .docx whose document relationships are (id, type suffix, target) external."""
    rel_xml = "".join(
        f'<Relationship Id="{rid}" '
        f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/{kind}" '
        f'Target="{target}" TargetMode="External"/>'
        for rid, kind, target in rels
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<w:document/>")
        archive.writestr(
            "word/_rels/settings.xml.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/'
            f'package/2006/relationships">{rel_xml}</Relationships>',
        )
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return buf.getvalue()


def test_is_office_type() -> None:
    assert is_office_type(DOCX)
    assert is_office_type("application/msword")
    assert is_office_type("application/vnd.ms-excel.sheet.macroenabled.12")
    assert is_office_type("text/rtf")
    assert not is_office_type("application/pdf")
    assert not is_office_type(None)


def test_real_olevba_macro_findings() -> None:
    report = analyze_office("module.bas", VBA_TEXT, "text/plain", [])
    flags = _flags(report)
    assert flags["office_macro_autoexec"]["triggers"] == ["AutoOpen"]
    suspicious = flags["office_macro_suspicious_calls"]
    assert {"CreateObject", "WScript.Shell", "powershell"} <= set(suspicious["keywords"])
    assert "CreateObject" in suspicious["key_calls"]
    assert suspicious["mraptor"]["suspicious"] is True
    assert report.urls == ["https://payload.example.test/stage2"]
    assert report.info["macros"]["vba"] is True
    assert report.errors == []


def test_xlm_macro_with_mocked_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_scan(filename: str, data: bytes) -> dict:
        return {
            "vba": False,
            "xlm": True,
            "analysis": [("Suspicious", "EXEC", "May run an executable")],
            "mraptor": None,
        }

    monkeypatch.setattr(office, "_scan_macros", fake_scan)
    report = analyze_office("book.xls", b"\xd0\xcf\x11\xe0 fake", "application/vnd.ms-excel", [])
    flags = _flags(report)
    assert flags["xlm_macro"] == {"keywords": ["EXEC"]}
    assert "office_macro_suspicious_calls" not in flags  # XLM only, no VBA


def test_remote_template_injection_and_external_links() -> None:
    data = _docx(
        [
            ("rId1", "attachedTemplate", "https://templates.example.test/t.dotm"),
            ("rId2", "oleObject", "file://share.example.test/obj.bin"),
            ("rId3", "hyperlink", "https://www.example.test/help"),
        ],
        extra={"word/embeddings/oleObject1.bin": b"stub"},
    )
    report = analyze_office("letter.docx", data, DOCX, [])
    flags = _flags(report)
    assert flags["remote_template_injection"] == {
        "type": "attachedTemplate",
        "target": "https://templates.example.test/t.dotm",
        "part": "word/_rels/settings.xml.rels",
    }
    assert flags["office_external_link"]["type"] == "oleObject"
    assert "https://templates.example.test/t.dotm" in report.urls
    assert "https://www.example.test/help" in report.urls  # hyperlinks: URL only, no finding
    assert report.info["embedded_objects"] == ["word/embeddings/oleObject1.bin"]
    assert len(report.info["external_relationships"]) == 3


def test_plain_docx_is_clean() -> None:
    report = analyze_office("plain.docx", _docx([]), DOCX, [])
    assert report.flags == [] and report.urls == [] and report.errors == []


def _ole1(class_name: bytes) -> bytes:
    def lps(value: bytes) -> bytes:
        value = value + b"\0" if value else b""
        return struct.pack("<I", len(value)) + value

    return (
        struct.pack("<II", 0x0501, 2) + lps(class_name) + lps(b"") + lps(b"")
        + struct.pack("<I", 4) + b"\0\0\0\0"
    )


def test_rtf_embedded_equation_object() -> None:
    rtf = (
        b"{\\rtf1{\\object\\objemb{\\*\\objclass Equation.3}\\objw1\\objh1{\\*\\objdata "
        + _ole1(b"Equation.3").hex().encode()
        + b"}}{\\field{\\*\\fldinst HYPERLINK \"http://rtf.example.test/x\"}}}"
    )
    report = analyze_office("doc.rtf", rtf, "text/rtf", [])
    [obj] = _flags(report)["rtf_embedded_object"]["objects"]
    assert obj["class_name"] == "Equation.3"
    assert obj["equation_editor"] is True
    assert report.urls == ["http://rtf.example.test/x"]


class FakeOfficeFile:
    """Stand-in for msoffcrypto.OfficeFile: encrypted, opens with one password."""

    def __init__(self, fp, password: str = "Doc2026", plain: bytes = b"decrypted") -> None:
        self.password = password
        self.plain = plain
        self.key = None

    def is_encrypted(self) -> bool:
        return True

    def load_key(self, password: str) -> None:
        self.key = password

    def decrypt(self, out) -> None:
        if self.key != self.password:
            raise ValueError("bad password")
        out.write(self.plain)


@pytest.mark.parametrize(
    ("passwords", "correct", "expected"),
    [
        (["nope", "Doc2026"], "Doc2026", {"decrypted": True, "password_source": "body"}),
        ([], "VelvetSweatshop", {"decrypted": True, "password_source": "default"}),
        (["nope"], "Doc2026", {"decrypted": False}),
    ],
)
def test_encrypted_office_document(monkeypatch, passwords, correct, expected) -> None:
    scanned: list[bytes] = []
    monkeypatch.setattr(
        office.msoffcrypto, "OfficeFile", lambda fp: FakeOfficeFile(fp, password=correct)
    )
    monkeypatch.setattr(
        office,
        "_scan_macros",
        lambda name, data: scanned.append(data)
        or {"vba": False, "xlm": False, "analysis": [], "mraptor": None},
    )
    report = analyze_office("secret.docx", b"\xd0\xcf\x11\xe0 enc", DOCX, passwords)
    assert _flags(report)["encrypted_office_document"] == expected
    assert scanned == [b"decrypted" if expected["decrypted"] else b"\xd0\xcf\x11\xe0 enc"]


def test_broken_input_never_raises() -> None:
    ole_junk = bytes.fromhex("d0cf11e0a1b11ae1") + b"garbage"
    report = analyze_office("junk.doc", ole_junk, "application/msword", [])
    assert isinstance(report.errors, list)
    report = analyze_office("junk.rtf", b"{\\rtf1 {\\object unterminated", "text/rtf", [])
    assert report.flags == []
