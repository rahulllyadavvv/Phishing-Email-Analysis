"""Tests for phishlens.analyzers.filetype (content sniffing and filename tricks)."""

from __future__ import annotations

import io
import zipfile

import pytest

from phishlens.analyzers import filetype
from phishlens.analyzers.filetype import category_of_mime, detect_type, extension, filename_checks

PE = b"MZ" + b"\x00" * 200


@pytest.fixture(params=["libmagic", "fallback"])
def sniffer(request, monkeypatch: pytest.MonkeyPatch) -> str:
    """Run type tests with libmagic (when installed) and with the built-in fallback table."""
    if request.param == "libmagic":
        if not filetype.libmagic_available():
            pytest.skip("libmagic not installed (see docs/SETUP_NOTES.md)")
    else:
        monkeypatch.setattr(filetype, "_magic", lambda: None)
    return request.param


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buf.getvalue()


@pytest.mark.parametrize(
    ("data", "category"),
    [
        (PE, "executable"),
        (b"%PDF-1.7\n%...", "document"),
        (b"PK\x03\x04" + _zip({"a.txt": b"x"})[4:], "archive"),
        (b"\x1f\x8b\x08\x00" + b"\x00" * 20, "archive"),
        (b"<!DOCTYPE html><html><body>hi</body></html>", "html"),
        (b'<svg xmlns="http://www.w3.org/2000/svg"></svg>', "html"),
        (b"\x89PNG\r\n\x1a\n" + b"\x00" * 20, "image"),
        (b"just some harmless text\n", "text"),
    ],
)
def test_detect_type_categories(sniffer: str, data: bytes, category: str) -> None:
    assert category_of_mime(detect_type(data)) == category


def test_fallback_specific_signatures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(filetype, "_magic", lambda: None)
    lnk = bytes.fromhex("4c0000000114020000000000c000000000000046") + b"\x00" * 40
    assert detect_type(lnk) == "application/x-ms-shortcut"
    iso = b"\x00" * 32769 + b"CD001" + b"\x00" * 10
    assert detect_type(iso) == "application/x-iso9660-image"
    assert detect_type(b"\x00" * 257 + b"ustar\x00") == "application/x-tar"
    assert detect_type(b"") == "application/x-empty"


def test_ooxml_refinement(sniffer: str) -> None:
    docx = _zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>"})
    docm = _zip(
        {
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": b"<w/>",
            "word/vbaProject.bin": b"stub",
        }
    )
    assert category_of_mime(detect_type(docx)) == "document"
    assert category_of_mime(detect_type(docm)) == "office_macro"


def test_extension() -> None:
    assert extension("Invoice.PDF") == "pdf"
    assert extension("folder/archive.tar.gz") == "gz"
    assert extension("noext") == ""
    assert extension("ann‮exe.pdf") == "pdf"


def _ids(flags) -> list[str]:
    return [f for f, _ in flags]


@pytest.mark.parametrize(
    ("name", "detected", "expected"),
    [
        ("invoice.pdf.exe", "application/x-dosexec", ["double_extension", "high_risk_file_type"]),
        ("invoice.pdf", "application/x-dosexec", ["type_mismatch", "high_risk_file_type"]),
        ("invoice", "application/x-dosexec", ["type_mismatch", "high_risk_file_type"]),
        ("report.docx", "application/vnd.ms-word.document.macroenabled.12",
         ["type_mismatch", "high_risk_file_type"]),
        ("photo.jpg", "application/zip", ["type_mismatch"]),
        ("notes.zip", "application/zip", []),
        ("report.pdf", "application/pdf", []),
        ("readme.txt", "text/plain", []),
        ("page.html", "text/html", ["high_risk_file_type"]),
        ("setup.exe", "application/x-dosexec", ["high_risk_file_type"]),
        ("invoice.pdf      .exe", "application/x-dosexec",
         ["double_extension", "whitespace_padded_extension", "high_risk_file_type"]),
    ],
)
def test_filename_checks(name: str, detected: str, expected: list[str]) -> None:
    assert _ids(filename_checks(name, detected)) == expected


def test_rtlo_filename() -> None:
    name = "invoice_‮fdp.exe"  # displays as invoice_exe.pdf
    flags = dict(filename_checks(name, "application/x-dosexec"))
    assert flags["rtlo_filename"]["characters"] == ["U+202E"]
    assert flags["rtlo_filename"]["without_controls"] == "invoice_fdp.exe"
    assert "high_risk_file_type" in flags


def test_mismatch_details() -> None:
    [(flag, details), _] = filename_checks("scan.pdf", "application/x-dosexec", "application/pdf")
    assert flag == "type_mismatch"
    assert details == {
        "extension": "pdf",
        "claims": "document",
        "declared_type": "application/pdf",
        "detected_type": "application/x-dosexec",
        "actual": "executable",
    }


def test_high_risk_list_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    from phishlens.config import get_settings

    monkeypatch.setenv("HIGH_RISK_EXTENSIONS", "txt")
    get_settings.cache_clear()
    assert _ids(filename_checks("readme.txt", "text/plain")) == ["high_risk_file_type"]
    assert _ids(filename_checks("setup.exe", "application/x-dosexec")) == []
