"""Tests for api/worker.py: the analysis job with the fake synchronous queue, in the fake
internet (``world`` fixture), with a temporary SQLite database."""

from __future__ import annotations

import json
from pathlib import Path

import fakeredis
import pytest

from api import db, worker
from phishlens.config import get_settings
from phishlens.pipeline import EMAIL_MODULES

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def api_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'cases.sqlite'}")
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("JOB_QUEUE", "sync")
    get_settings.cache_clear()
    db.init_db()
    return tmp_path


def _submit(data: bytes, filename: str, **fields) -> tuple[str, str]:
    with db.session_scope() as session:
        case = db.create_case(session, input_sha256="0" * 64, original_filename=filename, **fields)
        case_id = case.id
    path, sha256 = worker.store_upload(case_id, data)
    with db.session_scope() as session:
        db.update_case(session, case_id, input_sha256=sha256)
    return case_id, str(path)


def test_upload_is_stored_under_a_generated_name(api_env) -> None:
    path, sha256 = worker.store_upload("PL-20260925-ABCDE", b"data")
    assert path == api_env / "quarantine" / "uploads" / "PL-20260925-ABCDE" / "input.bin"
    assert path.read_bytes() == b"data" and len(sha256) == 64


def test_job_completes_and_every_module_is_done(api_env, world) -> None:
    store = worker.MemoryProgressStore()
    queue = worker.SyncQueue(store)
    case_id, path = _submit((FIXTURES / "lookalike_domain.eml").read_bytes(), "mail.eml")
    assert queue.enqueue_analysis(case_id, path, "mail.eml") == "done"

    progress = store.get(case_id)
    for module in EMAIL_MODULES:
        assert progress[module] == "done", (module, progress)
    assert progress["scoring"] == "done" and progress["job"] == "done"

    with db.session_scope() as session:
        case = db.get_case(session, case_id)
    assert (case.status, case.verdict, case.case_type) == ("done", "malicious", "email")
    assert case.subject.startswith("URGENT") and case.sender.endswith("micros0ft-support.example")
    assert case.score == 100 and 0 < case.confidence <= 1
    formats = set(case.report_files)
    assert {"html", "json", "csv", "stix", "zip"} <= formats
    for file in case.report_files.values():
        assert Path(file).parent == api_env / "reports" / case_id
    report = json.loads(Path(case.report_json_path).read_text())
    assert report["case_id"] == case_id


def test_file_mode_and_email_mode(api_env, world) -> None:
    store = worker.MemoryProgressStore()
    case_id, path = _submit((FIXTURES / "clean_newsletter.eml").read_bytes(), "x.eml")
    assert worker.run_analysis(case_id, path, "x.eml", "file", store) == "done"
    with db.session_scope() as session:
        assert db.get_case(session, case_id).case_type == "file"
    assert store.get(case_id)["header"] == "skipped"

    raw_id, raw_path = _submit(b"From: a@b.test\r\nSubject: pasted\r\n\r\nhello", "pasted.eml")
    assert worker.run_analysis(raw_id, raw_path, None, "email", store) == "done"
    with db.session_scope() as session:
        assert db.get_case(session, raw_id).subject == "pasted"


def test_missing_input_is_an_error(api_env) -> None:
    store = worker.MemoryProgressStore()
    with db.session_scope() as session:
        case_id = db.create_case(session, input_sha256="1" * 64).id
    assert worker.run_analysis(case_id, "/nowhere/input.bin", "x", "auto", store) == "error"
    with db.session_scope() as session:
        case = db.get_case(session, case_id)
    assert case.status == "error" and "FileNotFoundError" in case.error_message
    assert store.get(case_id)["job"] == "error"


def test_report_failure_keeps_partial_reports(
    api_env, world, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []
    real = worker.generate_report

    def flaky(report, formats, out_dir):
        calls.append(list(formats))
        if len(calls) == 1:
            raise OSError("disk full")
        return real(report, formats, out_dir)

    monkeypatch.setattr(worker, "generate_report", flaky)
    store = worker.MemoryProgressStore()
    case_id, path = _submit((FIXTURES / "link_mismatch.eml").read_bytes(), "m.eml")
    assert worker.run_analysis(case_id, path, "m.eml", "auto", store) == "error"
    with db.session_scope() as session:
        case = db.get_case(session, case_id)
    assert case.status == "error" and "disk full" in case.error_message
    assert set(case.report_files) == {"json", "html"}  # the partial report was still saved
    assert case.verdict == "malicious"


def test_redis_progress_store() -> None:
    store = worker.RedisProgressStore(fakeredis.FakeRedis())
    store.set("PL-1", "header", "running")
    store.set("PL-1", "header", "done")
    store.set("PL-1", "urls", "pending")
    assert store.get("PL-1") == {"header": "done", "urls": "pending"}
    assert store.client.ttl("progress:PL-1") > 0
    store.clear("PL-1")
    assert store.get("PL-1") == {}


def test_queue_selection(api_env, monkeypatch: pytest.MonkeyPatch) -> None:
    assert isinstance(worker.get_queue(), worker.SyncQueue)
    assert isinstance(worker.get_progress_store(), worker.MemoryProgressStore)
    assert worker.SyncQueue().healthy() == {"queue": "sync", "redis": None, "workers": None}
