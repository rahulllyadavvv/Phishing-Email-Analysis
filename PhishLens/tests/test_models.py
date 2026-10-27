import base64
import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from phishlens.models import (
    IOC,
    Address,
    AnalysisReport,
    AnalyzerResult,
    Attachment,
    CaseType,
    EnrichmentResult,
    EnrichmentStatus,
    Finding,
    IOCType,
    MitreTechnique,
    ParsedEmail,
    ReceivedHop,
    Severity,
    UrlRef,
    UrlSource,
    Verdict,
    VerdictLabel,
)

RAW_EMAIL = b"From: a@example.com\r\nSubject: RAW-EMAIL-MARKER\r\n\r\nbody"
ATTACHMENT_BYTES = b"ATTACHMENT-BYTES-MARKER"


def make_attachment(**kwargs) -> Attachment:
    defaults = dict(
        filename="invoice.zip",
        declared_type="application/zip",
        detected_type="application/zip",
        size=len(ATTACHMENT_BYTES),
        data=ATTACHMENT_BYTES,
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    defaults.update(kwargs)
    return Attachment(**defaults)


def make_finding() -> Finding:
    return Finding(
        id="spf_pass_unaligned",
        module="auth",
        title="SPF passed but is not aligned",
        description="SPF domain does not match the From domain.",
        severity=Severity.MEDIUM,
        score=15,
        evidence={"spf_domain": "bulk.example.net", "from_domain": "example.com"},
        mitre=["T1566.001"],
    )


def make_email() -> ParsedEmail:
    sender = Address(
        display_name="Alice",
        address="alice@mail.example.co.uk",
        domain="mail.example.co.uk",
        org_domain="example.co.uk",
    )
    nested = ParsedEmail(subject="original", raw_bytes=RAW_EMAIL)
    return ParsedEmail(
        headers=[("Received", "hop 1"), ("Received", "hop 2"), ("Subject", "Hi")],
        from_addrs=[sender],
        reply_to=[Address(address="bob@evil.test", domain="evil.test", org_domain="evil.test")],
        return_path=sender,
        sender=sender,
        to=[Address(address="victim@corp.test")],
        cc=[],
        subject="Hi",
        date=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        message_id="<abc@example.co.uk>",
        received_chain=[
            ReceivedHop(from_host="mx.evil.test", by_host="mx.corp.test", ip="203.0.113.5",
                        timestamp=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC), raw="from mx...")
        ],
        auth_results_headers=["mx.corp.test; spf=pass smtp.mailfrom=bulk.example.net"],
        text_body="Click http://evil.test/login",
        html_body='<a href="http://evil.test/login">bank.com</a>',
        urls=[UrlRef(url="http://evil.test/login", visible_text="bank.com",
                     source=UrlSource.HTML_HREF)],
        attachments=[
            make_attachment(),
            make_attachment(filename="payload.exe", parent="invoice.zip", depth=1),
        ],
        inline_images=[make_attachment(filename="logo.png", declared_type="image/png")],
        nested_emails=[nested],
        parse_warnings=["duplicate Subject header"],
        raw_bytes=RAW_EMAIL,
        sha256="0" * 64,
    )


def make_report() -> AnalysisReport:
    finding = make_finding()
    return AnalysisReport(
        case_id="PL-0001",
        case_type=CaseType.EMAIL,
        email=make_email(),
        file_info=make_attachment(),
        results={
            "auth": AnalyzerResult(
                module="auth",
                findings=[finding],
                raw={"spf": "pass"},
                extracted_urls=[UrlRef(url="http://qr.test", source=UrlSource.QR_CODE)],
                duration_ms=12,
            ),
            "sandbox": AnalyzerResult(module="sandbox", skipped=True, errors=["not configured"]),
        },
        iocs=[IOC(type=IOCType.DOMAIN, value="evil.test", defanged="evil[.]test",
                  source_module="urls", verdict="malicious", context="link in body")],
        mitre=[MitreTechnique(id="T1566.001", name="Spearphishing Attachment",
                              tactics=["initial-access"],
                              url="https://attack.mitre.org/techniques/T1566/001/",
                              triggered_by=["spf_pass_unaligned"])],
        verdict=Verdict(label=VerdictLabel.SUSPICIOUS, total_score=45, confidence=0.8,
                        module_scores={"auth": 15}, top_findings=[finding],
                        overrides_applied=[]),
        services_used=["virustotal"],
        services_not_configured=["urlscan"],
        tool_version="0.1.0",
    )


def test_address_defaults():
    addr = Address(address="a@b.test")
    assert addr.display_name == "" and addr.domain == "" and addr.org_domain == ""


def test_received_hop_optional_fields():
    hop = ReceivedHop(raw="from unknown")
    assert hop.ip is None and hop.timestamp is None


def test_url_ref_source_enum():
    for source in ["text_body", "html_href", "html_src", "form_action", "attachment",
                   "qr_code", "artifact"]:
        assert UrlRef(url="http://x.test", source=source).source == source
    with pytest.raises(ValidationError):
        UrlRef(url="http://x.test", source="nowhere")


def test_attachment_data_excluded():
    att = make_attachment()
    assert att.data == ATTACHMENT_BYTES
    dumped = att.model_dump()
    assert "data" not in dumped
    assert "ATTACHMENT-BYTES-MARKER" not in att.model_dump_json()
    assert "ATTACHMENT-BYTES-MARKER" not in repr(att)


def test_parsed_email_keeps_duplicate_headers_and_excludes_raw():
    email = make_email()
    assert [name for name, _ in email.headers].count("Received") == 2
    assert email.raw_bytes == RAW_EMAIL
    dumped = email.model_dump()
    assert "raw_bytes" not in dumped
    assert "raw_bytes" not in dumped["nested_emails"][0]
    assert all("data" not in a for a in dumped["attachments"])


def test_finding_id_must_be_snake_case():
    assert make_finding().severity == "medium"
    with pytest.raises(ValidationError):
        Finding(id="SPF-Pass", module="auth", title="x")
    with pytest.raises(ValidationError):
        Finding(id="ok_id", module="auth", title="x", severity="extreme")


def test_analyzer_result_defaults():
    result = AnalyzerResult(module="headers")
    assert result.findings == [] and result.errors == [] and not result.skipped


def test_ioc_and_mitre():
    ioc = IOC(type="sha256", value="a" * 64)
    assert ioc.type is IOCType.SHA256 and ioc.verdict is None
    with pytest.raises(ValidationError):
        IOC(type="registry_key", value="x")
    tech = MitreTechnique(id="T1204.002", name="Malicious File")
    assert tech.triggered_by == []


def test_verdict_bounds():
    assert Verdict(label="clean").total_score == 0
    with pytest.raises(ValidationError):
        Verdict(label="clean", total_score=101)
    with pytest.raises(ValidationError):
        Verdict(label="clean", confidence=1.5)
    with pytest.raises(ValidationError):
        Verdict(label="unknown")


def test_case_type_restricted():
    assert AnalysisReport(case_id="x", case_type="file").case_type is CaseType.FILE
    with pytest.raises(ValidationError):
        AnalysisReport(case_id="x", case_type="url")


def test_analysis_report_json_has_no_bytes():
    report = make_report()
    text = report.model_dump_json()
    data = json.loads(text)

    for marker in (b"RAW-EMAIL-MARKER", ATTACHMENT_BYTES):
        assert marker.decode() not in text
        assert base64.b64encode(marker).decode() not in text
    assert "raw_bytes" not in text
    assert '"data"' not in text

    assert data["case_type"] == "email"
    assert data["email"]["headers"][0] == ["Received", "hop 1"]
    assert data["email"]["urls"][0]["source"] == "html_href"
    assert data["email"]["attachments"][1]["parent"] == "invoice.zip"
    assert data["results"]["auth"]["findings"][0]["id"] == "spf_pass_unaligned"
    assert data["results"]["sandbox"]["skipped"] is True
    assert data["verdict"]["label"] == "suspicious"
    assert data["iocs"][0]["defanged"] == "evil[.]test"


def test_analysis_report_round_trip():
    report = make_report()
    restored = AnalysisReport.model_validate_json(report.model_dump_json())
    assert restored.case_id == report.case_id
    assert restored.email is not None and restored.email.raw_bytes == b""
    assert restored.email.headers == report.email.headers
    assert restored.verdict == report.verdict
    assert restored.results == report.results


def test_enrichment_result_roundtrip():
    result = EnrichmentResult(
        service="virustotal",
        query="example.com",
        status="malicious",
        detections=5,
        total_engines=90,
        details={"categories": ["phishing"]},
        link="https://www.virustotal.com/gui/domain/example.com",
    )
    assert result.status is EnrichmentStatus.MALICIOUS
    assert EnrichmentResult.model_validate_json(result.model_dump_json()) == result
    assert result.cached is False and result.error is None
    with pytest.raises(ValidationError):
        EnrichmentResult(service="x", query="y", status="bad")
