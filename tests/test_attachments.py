"""Tests for phishlens.analyzers.attachments (unpacking, identification, filename tricks)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from phishlens.analyzers import attachments
from phishlens.config import get_settings
from phishlens.models import ParsedEmail, Severity
from phishlens.parser import parse_email
from phishlens.parser.attachments import make_attachment

FIXTURES = Path(__file__).parent / "fixtures"
ALL_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.eml"))


def _fixture(name: str) -> ParsedEmail:
    return parse_email((FIXTURES / name).read_bytes())


def _ids(result) -> dict:
    return {f.id: f for f in result.findings}


def _zip(entries: dict[str, bytes], password: bytes | None = None) -> bytes:
    import pyzipper

    buf = io.BytesIO()
    kwargs = {"encryption": pyzipper.WZ_AES} if password else {}
    with pyzipper.AESZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, **kwargs) as archive:
        if password:
            archive.setpassword(password)
        for name, data in entries.items():
            archive.writestr(name, data)
    return buf.getvalue()


async def test_fixture_9_password_zip_opened_with_4455() -> None:
    result = await attachments.analyze(_fixture("password_zip.eml"))
    assert result.errors == []
    assert result.raw["password_candidates"][0] == "4455"
    finding = _ids(result)["encrypted_archive_password_in_body"]
    assert finding.severity == Severity.HIGH
    assert finding.evidence["files"] == [
        {"archive": "invoice.zip", "password": "4455", "source": "body"}
    ]
    rows = {r["filename"]: r for r in result.raw["attachments"]}
    assert rows["invoice.txt"]["parent"] == "invoice.zip"
    assert rows["invoice.txt"]["depth"] == 1
    assert len(rows["invoice.txt"]["sha256"]) == 64


async def test_fixture_8_double_extension() -> None:
    result = await attachments.analyze(_fixture("double_extension.eml"))
    finding = _ids(result)["double_extension"]
    assert finding.severity == Severity.HIGH
    [entry] = finding.evidence["files"]
    assert (entry["file"], entry["shown_as"], entry["real"]) == ("invoice.pdf.exe", "pdf", "exe")
    assert "high_risk_file_type" in _ids(result)


async def test_fixture_7_zip_is_unpacked() -> None:
    result = await attachments.analyze(_fixture("zip_attachment.eml"))
    rows = result.raw["attachments"]
    assert [(r["filename"], r["parent"]) for r in rows] == [
        ("notes.zip", None),
        ("notes.txt", "notes.zip"),
    ]
    assert result.findings == []


def test_body_passwords() -> None:
    email = ParsedEmail(
        text_body="The password for the file is: 'Xk92!pq'. Use PIN 7781 to open.",
        html_body="<p>Archive <b>passcode</b>: <code>zz-11</code></p>",
    )
    assert attachments.body_passwords(email) == ["Xk92!pq", "7781", "zz-11"]
    assert attachments.body_passwords(ParsedEmail(text_body="no secrets here")) == []


async def test_hidden_executable_inside_encrypted_zip() -> None:
    inner = _zip({"scan.pdf": b"MZ" + b"\0" * 64}, password=b"Doc2026")
    email = ParsedEmail(
        text_body="Documents attached. Password: Doc2026",
        attachments=[make_attachment("scan.zip", inner)],
    )
    result = await attachments.analyze(email)
    findings = _ids(result)
    assert "encrypted_archive_password_in_body" in findings
    mismatch = findings["type_mismatch"].evidence["files"][0]
    assert mismatch["file"] == "scan.pdf" and mismatch["actual"] == "executable"


async def test_unopened_encrypted_archive() -> None:
    email = ParsedEmail(
        attachments=[make_attachment("locked.zip", _zip({"a.txt": b"x"}, password=b"zzz999"))]
    )
    finding = _ids(await attachments.analyze(email))["encrypted_archive_unopened"]
    assert finding.severity == Severity.HIGH
    assert finding.evidence["files"][0]["archive"] == "locked.zip"


async def test_default_password_opens_without_body_finding() -> None:
    email = ParsedEmail(
        attachments=[make_attachment("sample.zip", _zip({"a.txt": b"x"}, password=b"infected"))]
    )
    result = await attachments.analyze(email)
    assert "encrypted_archive_password_in_body" not in _ids(result)
    assert "encrypted_archive_unopened" not in _ids(result)
    assert result.raw["archive_events"][0]["source"] == "default"


async def test_archive_limit_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARCHIVE_MAX_TOTAL_MB", "1")
    get_settings.cache_clear()
    bomb = _zip({"zeros.bin": b"\0" * (3 * 1024 * 1024)})
    result = await attachments.analyze(ParsedEmail(attachments=[make_attachment("b.zip", bomb)]))
    finding = _ids(result)["archive_limit_exceeded"]
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["files"][0]["limit"] == "size"


async def test_rtlo_name_is_made_visible() -> None:
    email = ParsedEmail(attachments=[make_attachment("pay‮fdp.exe", b"MZ" + b"\0" * 40)])
    result = await attachments.analyze(email)
    [row] = result.raw["attachments"]
    assert row["safe_name"] == "pay<U+202E>fdp.exe"
    assert _ids(result)["rtlo_filename"].evidence["files"][0]["file"] == "pay<U+202E>fdp.exe"


async def test_no_attachments_is_skipped() -> None:
    result = await attachments.analyze(ParsedEmail())
    assert result.skipped and result.raw["attachments"] == [] and result.findings == []


async def test_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(*args: object) -> None:
        raise RuntimeError("unpack exploded")

    monkeypatch.setattr(attachments, "prepare_files", boom)
    result = await attachments.analyze(_fixture("zip_attachment.eml"))
    assert result.errors == ["attachments: RuntimeError: unpack exploded"]


@pytest.mark.parametrize("name", ALL_FIXTURES)
async def test_every_fixture(name: str) -> None:
    result = await attachments.analyze(_fixture(name))
    assert result.errors == []
