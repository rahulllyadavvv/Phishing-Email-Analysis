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
from api.security import UploadRateLimiter, upload_limiter
from phishlens.config import get_settings

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, world):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'api.sqlite'}")
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("JOB_QUEUE", "sync")
    get_settings.cache_clear()
    worker._memory_store._data.clear()
    upload_limiter.reset()
    for name in ("PHISHLENS_API_KEY", "UPLOAD_RATE_LIMIT", "CORS_ORIGINS"):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
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


# --- P12.4: security and deduplication ------------------------------------------------------------


def _secured(monkeypatch, key: str = "test-api-key") -> None:
    monkeypatch.setenv("PHISHLENS_API_KEY", key)
    get_settings.cache_clear()


def test_unauthenticated_requests_are_rejected(client, monkeypatch) -> None:
    _secured(monkeypatch)
    for method, path in [("get", "/api/cases"), ("get", "/api/stats"),
                         ("get", "/api/cases/PL-1/status"), ("delete", "/api/cases/PL-1")]:
        response = getattr(client, method)(path)
        assert response.status_code == 401, path
        assert response.json()["detail"] == "missing or invalid API key"
    assert _upload(client, "zip_attachment.eml").status_code == 401
    wrong = client.get("/api/cases", headers={"X-API-Key": "wrong-key"})
    assert wrong.status_code == 401
    health = client.get("/api/health")
    assert health.status_code == 200 and health.json()["auth"] == "api_key"


def test_authenticated_requests_work(client, monkeypatch) -> None:
    _secured(monkeypatch)
    headers = {"X-API-Key": "test-api-key"}
    response = client.post(
        "/api/analyze",
        files={"file": ("m.eml", (FIXTURES / "zip_attachment.eml").read_bytes())},
        headers=headers,
    )
    assert response.status_code == 202
    assert client.get("/api/cases", headers=headers).json()["total"] == 1


def test_duplicate_upload_returns_existing_case(client) -> None:
    first = _upload(client, "link_mismatch.eml").json()
    again = _upload(client, "link_mismatch.eml").json()
    assert again == {"case_id": first["case_id"], "duplicate": True}
    assert client.get("/api/cases").json()["total"] == 1

    forced = client.post(
        "/api/analyze",
        params={"force": "true"},
        files={"file": ("m.eml", (FIXTURES / "link_mismatch.eml").read_bytes())},
    ).json()
    assert forced["duplicate"] is False and forced["case_id"] != first["case_id"]
    assert client.get("/api/cases").json()["total"] == 2

    raw = (FIXTURES / "link_mismatch.eml").read_text()
    pasted = client.post("/api/analyze-raw", json={"raw_source": raw}).json()
    assert pasted["duplicate"] is True  # the same bytes as the upload


def test_dedup_respects_case_type(client) -> None:
    data = (FIXTURES / "clean_newsletter.eml").read_bytes()
    email_case = _upload(client, "n.eml", data).json()
    file_case = client.post("/api/analyze-file", files=[("files", ("n.eml", data))]).json()[0]
    assert file_case["duplicate"] is False and file_case["case_id"] != email_case["case_id"]
    again = client.post("/api/analyze-file", files=[("files", ("n.eml", data))]).json()[0]
    assert again["duplicate"] is True and again["case_id"] == file_case["case_id"]


def test_failed_cases_are_not_reused(client, monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise OSError("disk full")

    with monkeypatch.context() as patched:
        patched.setattr(worker, "generate_report", fail)
        first = _upload(client, "zip_attachment.eml").json()
    assert client.get(f"/api/cases/{first['case_id']}/status").json()["status"] == "error"
    second = _upload(client, "zip_attachment.eml").json()
    assert second["duplicate"] is False


def test_upload_rate_limit(client, monkeypatch) -> None:
    monkeypatch.setenv("UPLOAD_RATE_LIMIT", "2/60")
    get_settings.cache_clear()
    assert _upload(client, "a.eml", b"From: a@b.test\r\nSubject: 1\r\n\r\nx").status_code == 202
    assert _upload(client, "b.eml", b"From: a@b.test\r\nSubject: 2\r\n\r\nx").status_code == 202
    third = _upload(client, "c.eml", b"From: a@b.test\r\nSubject: 3\r\n\r\nx")
    assert third.status_code == 429 and int(third.headers["Retry-After"]) >= 1
    assert client.get("/api/cases").status_code == 200  # reads are not limited


def test_rate_limiter_window() -> None:
    now = [0.0]
    limiter = UploadRateLimiter(clock=lambda: now[0])
    assert limiter.check("1.2.3.4", 2, 10) is None
    assert limiter.check("1.2.3.4", 2, 10) is None
    assert limiter.check("1.2.3.4", 2, 10) == 10.0
    assert limiter.check("5.6.7.8", 2, 10) is None  # per client
    now[0] = 10.5
    assert limiter.check("1.2.3.4", 2, 10) is None
    assert limiter.check("1.2.3.4", 0, 10) is None  # 0 = unlimited


def test_cors_only_for_the_ui_origin(client) -> None:
    allowed = client.options(
        "/api/cases",
        headers={"Origin": "http://localhost:8501", "Access-Control-Request-Method": "GET"},
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:8501"
    denied = client.options(
        "/api/cases",
        headers={"Origin": "https://evil.example.test", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in denied.headers


def test_downloads_never_leave_the_reports_folder(client) -> None:
    case_id = _upload(client, "zip_attachment.eml").json()["case_id"]
    stored = worker.upload_path(case_id)
    with db.session_scope() as session:
        db.update_case(session, case_id, report_files={"html": str(stored)})  # tampered row
    response = client.get(f"/api/cases/{case_id}/report", params={"format": "html"})
    assert response.status_code == 404
