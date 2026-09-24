"""Tests for phishlens.analyzers.attachments (unpacking, identification, filename tricks)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from phishlens.analyzers import attachments
from phishlens.config import get_settings
from phishlens.models import EnrichmentResult, ParsedEmail, Severity
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


# --- Hash reputation ----------------------------------------------------------------------------

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


async def test_fixture_14_eicar_mocked_malwarebazaar_hit(
    respx_mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real lookup chain: MalwareBazaar says malicious, so VirusTotal is never asked."""
    from phishlens.enrichment import abusech, virustotal

    monkeypatch.setenv("ABUSECH_API_KEY", "fake-abusech")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-vt")
    get_settings.cache_clear()
    respx_mock.post(abusech.MALWAREBAZAAR_API).respond(
        200,
        json={
            "query_status": "ok",
            "data": [{"sha256_hash": EICAR_SHA256, "signature": "EICAR-Test-File"}],
        },
    )
    vt = respx_mock.get(url__startswith=virustotal.API_URL).respond(404)

    result = await attachments.analyze(_fixture("eicar_attachment.eml"))
    finding = _ids(result)["attachment_known_malicious"]
    assert finding.severity == Severity.CRITICAL
    [entry] = finding.evidence["files"]
    assert entry["file"] == "eicar.com" and entry["sha256"] == EICAR_SHA256
    assert entry["services"] == ["abusech"]
    assert entry["families"] == ["EICAR-Test-File"]
    assert entry["links"] == [f"https://bazaar.abuse.ch/sample/{EICAR_SHA256}/"]
    [row] = result.raw["attachments"]
    assert row["reputation_verdict"] == "malicious"
    assert row["deep_analysis_skipped"] is True
    assert row["skip_reason"] == "known malicious by hash reputation"
    assert vt.call_count == 0


def _res(service: str, status: str, **fields) -> EnrichmentResult:
    return EnrichmentResult(service=service, query="q", status=status, **fields)


async def test_virustotal_detections_and_family(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake(sha256: str) -> list[EnrichmentResult]:
        return [
            _res("abusech", "unknown"),
            _res(
                "virustotal",
                "malicious",
                detections=61,
                total_engines=70,
                details={
                    "popular_threat_classification": {"suggested_threat_label": "trojan.agent"}
                },
            ),
        ]

    monkeypatch.setattr(attachments, "hash_reputation", fake)
    result = await attachments.analyze(_fixture("double_extension.eml"))
    [entry] = _ids(result)["attachment_known_malicious"].evidence["files"]
    assert entry["detections"] == {"virustotal": "61/70"}
    assert entry["families"] == ["trojan.agent"]


async def test_only_malicious_files_are_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    looked_up: list[str] = []
    bad = make_attachment("bad.exe", b"MZ bad")
    good = make_attachment("good.txt", b"fine")
    empty = make_attachment("empty.txt", b"")

    async def fake(sha256: str) -> list[EnrichmentResult]:
        looked_up.append(sha256)
        status = "malicious" if sha256 == bad.sha256 else "unknown"
        return [_res("abusech", status)]

    monkeypatch.setattr(attachments, "hash_reputation", fake)
    email = ParsedEmail(attachments=[bad, good, empty, bad.model_copy()])
    result = await attachments.analyze(email)
    rows = result.raw["attachments"]
    assert [r["deep_analysis_skipped"] for r in rows] == [True, False, False, True]
    assert rows[2]["reputation"] == [] and rows[2]["reputation_verdict"] is None
    assert sorted(looked_up) == sorted([bad.sha256, good.sha256])  # deduplicated, empty skipped
    assert _ids(result)["attachment_known_malicious"].evidence["count"] == 2


async def test_unpacked_files_are_looked_up_too(monkeypatch: pytest.MonkeyPatch) -> None:
    looked_up: list[str] = []

    async def fake(sha256: str) -> list[EnrichmentResult]:
        looked_up.append(sha256)
        return [_res("abusech", "unknown")]

    monkeypatch.setattr(attachments, "hash_reputation", fake)
    result = await attachments.analyze(_fixture("zip_attachment.eml"))
    assert {r["sha256"] for r in result.raw["attachments"]} == set(looked_up)
    assert len(looked_up) == 2


async def test_no_keys_all_not_configured() -> None:
    result = await attachments.analyze(_fixture("eicar_attachment.eml"))
    [row] = result.raw["attachments"]
    assert row["reputation_verdict"] == "not_configured"
    assert [r["service"] for r in row["reputation"]] == ["abusech", "virustotal"]
    assert "attachment_known_malicious" not in _ids(result)
    assert result.errors == []


async def test_reputation_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(sha256: str) -> list:
        raise AssertionError("must not be called")

    monkeypatch.setattr(attachments, "hash_reputation", boom)
    result = await attachments.analyze(_fixture("eicar_attachment.eml"), reputation=False)
    assert "reputation" not in result.raw["attachments"][0]
    assert result.errors == []


# --- Office content analysis ---------------------------------------------------------------------


def _template_docx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<w:document/>")
        archive.writestr(
            "word/_rels/settings.xml.rels",
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
            '2006/relationships/attachedTemplate" Target="https://tpl.example.test/a.dotm" '
            'TargetMode="External"/></Relationships>',
        )
    return buf.getvalue()


async def test_office_findings_and_extracted_urls() -> None:
    email = ParsedEmail(attachments=[make_attachment("offer.docx", _template_docx())])
    result = await attachments.analyze(email)
    finding = _ids(result)["remote_template_injection"]
    assert finding.severity == Severity.HIGH
    assert finding.evidence["files"][0]["target"] == "https://tpl.example.test/a.dotm"
    assert [(u.url, u.source.value) for u in result.extracted_urls] == [
        ("https://tpl.example.test/a.dotm", "attachment")
    ]
    [row] = result.raw["attachments"]
    assert "remote_template_injection" in row["flags"]
    assert row["office"]["external_relationships"][0]["type"] == "attachedTemplate"


async def test_known_malicious_file_skips_content_analysis(monkeypatch) -> None:
    async def fake(sha256: str) -> list[EnrichmentResult]:
        return [_res("abusech", "malicious")]

    monkeypatch.setattr(attachments, "hash_reputation", fake)
    email = ParsedEmail(attachments=[make_attachment("offer.docx", _template_docx())])
    result = await attachments.analyze(email)
    assert "remote_template_injection" not in _ids(result)
    assert "office" not in result.raw["attachments"][0]
    assert result.extracted_urls == []


async def test_office_inside_zip_is_analyzed() -> None:
    outer = _zip({"docs/offer.docx": _template_docx()})
    result = await attachments.analyze(
        ParsedEmail(attachments=[make_attachment("docs.zip", outer)])
    )
    entry = _ids(result)["remote_template_injection"].evidence["files"][0]
    assert entry["file"] == "docs/offer.docx"
