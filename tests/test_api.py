"""Tests for the FastAPI endpoints (api/main.py) with the synchronous queue, a temporary
database and the fake internet (``world``)."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api import db, worker
from api.main import create_app
from phishlens.config import get_settings

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, world):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'api.sqlite'}")
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("JOB_QUEUE", "sync")
    get_settings.cache_clear()
    worker._memory_store._data.clear()
    with TestClient(create_app()) as test_client:
        test_client.tmp = tmp_path
        yield test_client


def _upload(client, name: str, data: bytes | None = None, path: str = "/api/analyze"):
    data = data if data is not None else (FIXTURES / name).read_bytes()
    return client.post(path, files={"file": (name, data, "message/rfc822")})


def test_analyze_email_end_to_end(client) -> None:
    response = _upload(client, "lookalike_domain.eml")
    assert response.status_code == 202
    case_id = response.json()["case_id"]

    status = client.get(f"/api/cases/{case_id}/status").json()
    assert status["status"] == "done" and status["verdict"] == "malicious"
    assert status["progress"]["header"] == "done" and status["progress"]["job"] == "done"

    report = client.get(f"/api/cases/{case_id}").json()
    assert report["case_id"] == case_id and report["verdict"]["label"] == "malicious"
    body = json.dumps(report)
    assert "micros0ft-support.example" not in body  # API responses are defanged
    assert "micros0ft-support[.]example" in body


def test_report_downloads(client) -> None:
    case_id = _upload(client, "link_mismatch.eml").json()["case_id"]
    html = client.get(f"/api/cases/{case_id}/report", params={"format": "html"})
    assert html.status_code == 200 and html.headers["content-type"].startswith("text/html")
    assert "attachment" in html.headers["content-disposition"]
    assert f"{case_id}_malicious.html" in html.headers["content-disposition"]
    for fmt in ("json", "csv", "stix", "zip"):
        assert client.get(f"/api/cases/{case_id}/report", params={"format": fmt}).status_code == 200
    archive = client.get(f"/api/cases/{case_id}/report", params={"format": "zip"}).content
    assert zipfile.ZipFile(io.BytesIO(archive)).namelist()
    bad = client.get(f"/api/cases/{case_id}/report", params={"format": "exe"})
    assert bad.status_code == 422
    from phishlens.reporting.generate import pdf_available

    pdf = client.get(f"/api/cases/{case_id}/report", params={"format": "pdf"})
    assert pdf.status_code == (200 if pdf_available() else 404)


def test_analyze_rejects_non_email_and_bad_sizes(client, monkeypatch) -> None:
    not_email = _upload(client, "notes.txt", b"just a text file, not a message")
    assert not_email.status_code == 400 and "/api/analyze-file" in not_email.json()["detail"]
    empty = _upload(client, "empty.eml", b"")
    assert empty.status_code == 400 and "empty" in empty.json()["detail"]
    monkeypatch.setenv("MAX_INPUT_SIZE_MB", "0.001")
    get_settings.cache_clear()
    too_big = _upload(client, "big.eml", b"From: a@b.test\r\n\r\n" + b"x" * 5000)
    assert too_big.status_code == 413


def test_analyze_files_several(client) -> None:
    files = [
        ("files", ("notes.txt", b"Meeting notes.", "text/plain")),
        ("files", ("../../etc/evil\x00name.html", b"<form action='https://c.example.test/p'>"
                   b"<input type=password></form>", "text/html")),
    ]
    response = client.post("/api/analyze-file", files=files)
    assert response.status_code == 202
    created = response.json()
    names = [c["filename"] for c in created]
    assert names[0] == "notes.txt"
    assert "/" not in names[1] and ".." not in names[1] and names[1].endswith("name.html")
    verdicts = [client.get(f"/api/cases/{c['case_id']}/status").json() for c in created]
    assert all(v["status"] == "done" for v in verdicts)
    report = client.get(f"/api/cases/{created[1]['case_id']}").json()
    assert report["case_type"] == "file"


def test_analyze_raw(client) -> None:
    source = (FIXTURES / "spoof_unaligned.eml").read_text()
    response = client.post("/api/analyze-raw", json={"raw_source": source})
    assert response.status_code == 202
    status = client.get(f"/api/cases/{response.json()['case_id']}/status").json()
    assert status["status"] == "done" and status["verdict"] == "malicious"
    bad = client.post("/api/analyze-raw", json={"raw_source": "hello, is this phishing?"})
    assert bad.status_code == 400 and "headers" in bad.json()["detail"]
    assert client.post("/api/analyze-raw", json={"raw_source": ""}).status_code == 422


def test_list_filters_and_stats(client) -> None:
    for name in ("clean_newsletter.eml", "link_mismatch.eml", "lookalike_domain.eml"):
        _upload(client, name)
    listing = client.get("/api/cases").json()
    assert listing["total"] == 3 and len(listing["items"]) == 3
    assert client.get("/api/cases", params={"verdict": "malicious"}).json()["total"] == 2
    assert client.get("/api/cases", params={"q": "newsletter"}).json()["total"] == 1
    page = client.get("/api/cases", params={"page": 2, "page_size": 2}).json()
    assert len(page["items"]) == 1 and page["page"] == 2
    item = client.get("/api/cases", params={"q": "micros0ft"}).json()["items"][0]
    assert "[.]" in item["sender"]  # defanged in listings too
    assert client.get("/api/cases", params={"verdict": "evil"}).status_code == 422

    stats = client.get("/api/stats").json()
    assert stats["total"] == 3
    assert stats["by_verdict"]["malicious"] == 2 and stats["by_verdict"]["clean"] == 1
    assert len(stats["per_day"]) == 30 and stats["per_day"][-1]["count"] == 3


def test_delete_removes_everything(client) -> None:
    case_id = _upload(client, "zip_attachment.eml").json()["case_id"]
    upload = worker.upload_path(case_id)
    reports = worker.reports_path(case_id)
    quarantine = Path(get_settings().quarantine_dir) / case_id
    assert upload.exists() and reports.exists() and quarantine.exists()
    assert client.delete(f"/api/cases/{case_id}").status_code == 204
    assert not upload.exists() and not reports.exists() and not quarantine.exists()
    assert client.get(f"/api/cases/{case_id}").status_code == 404
    assert client.delete(f"/api/cases/{case_id}").status_code == 404


def test_status_codes_for_missing_and_pending(client) -> None:
    assert client.get("/api/cases/PL-00000000-XXXXX/status").status_code == 404
    assert client.get("/api/cases/PL-00000000-XXXXX").status_code == 404
    with db.session_scope() as session:
        pending = db.create_case(session, input_sha256="2" * 64).id
    assert client.get(f"/api/cases/{pending}").status_code == 409
    assert client.get(f"/api/cases/{pending}/report").status_code == 404


def test_health(client, monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "secret-value")
    get_settings.cache_clear()
    health = client.get("/api/health").json()
    assert health["status"] == "ok" and health["version"]
    assert health["queue"]["queue"] == "sync"
    assert health["services"]["virustotal"] is True
    assert "secret-value" not in json.dumps(health)
