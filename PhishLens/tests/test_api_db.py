"""Tests for api/db.py with an in-memory SQLite database."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import SQLModel

from api import db


@pytest.fixture
def engine():
    engine = db.get_engine("sqlite://")
    SQLModel.metadata.drop_all(engine)
    db.init_db(engine)
    return engine


def _new(session, **fields):
    defaults = {"input_sha256": "a" * 64, "case_type": "email"}
    return db.create_case(session, **{**defaults, **fields})


def test_case_id_format() -> None:
    case_id = db.new_case_id(datetime(2026, 9, 24, tzinfo=UTC))
    assert re.fullmatch(r"PL-20260924-[2-9A-HJ-NP-Z]{5}", case_id)
    assert len({db.new_case_id() for _ in range(200)}) == 200


def test_create_read_update_delete(engine) -> None:
    with db.session_scope(engine) as session:
        case = _new(session, original_filename="mail.eml", subject="Hello", sender="a@b.test")
        case_id = case.id
    with db.session_scope(engine) as session:
        stored = db.get_case(session, case_id)
        assert stored.status == "queued" and stored.report_files == {}
        assert stored.created_at is not None
        db.update_case(
            session, case_id, status="done", verdict="malicious", score=90, confidence=0.8,
            report_files={"html": "/r/x.html", "json": "/r/x.json"},
        )
    with db.session_scope(engine) as session:
        stored = db.get_case(session, case_id)
        assert (stored.status, stored.verdict, stored.score) == ("done", "malicious", 90)
        assert stored.report_files["html"] == "/r/x.html"
        assert stored.updated_at >= stored.created_at.replace(tzinfo=stored.updated_at.tzinfo)
        deleted = db.delete_case(session, case_id)
        assert deleted.id == case_id
    with db.session_scope(engine) as session:
        assert db.get_case(session, case_id) is None
        assert db.delete_case(session, case_id) is None
        assert db.update_case(session, case_id, status="done") is None


def test_update_validation(engine) -> None:
    with db.session_scope(engine) as session:
        case = _new(session)
        with pytest.raises(ValueError, match="invalid status"):
            db.update_case(session, case.id, status="paused")
        with pytest.raises(ValueError, match="unknown Case fields"):
            db.update_case(session, case.id, colour="red")


def test_list_filters_search_and_paging(engine) -> None:
    now = datetime.now(UTC)
    with db.session_scope(engine) as session:
        _new(session, subject="Invoice overdue", sender="billing@shop.test", verdict="malicious",
             status="done", created_at=now - timedelta(days=3))
        _new(session, subject="Team lunch", sender="hr@corp.test", verdict="clean",
             status="done", created_at=now - timedelta(days=1))
        _new(session, case_type="file", original_filename="Invoice.pdf.exe",
             verdict="malicious", status="done", created_at=now)
    with db.session_scope(engine) as session:
        items, total = db.list_cases(session)
        assert total == 3
        assert [c.created_at for c in items] == sorted((c.created_at for c in items), reverse=True)
        assert db.list_cases(session, verdict="malicious")[1] == 2
        assert db.list_cases(session, case_type="file")[1] == 1
        assert db.list_cases(session, q="INVOICE")[1] == 2  # subject or file name
        assert db.list_cases(session, q="hr@corp")[1] == 1
        assert db.list_cases(session, date_from=now - timedelta(days=2))[1] == 2
        assert db.list_cases(session, date_to=now - timedelta(days=2))[1] == 1
        page, total = db.list_cases(session, offset=1, limit=1)
        assert total == 3 and len(page) == 1


def test_find_completed_by_sha256(engine) -> None:
    with db.session_scope(engine) as session:
        _new(session, input_sha256="b" * 64, status="error")
        assert db.find_completed_by_sha256(session, "b" * 64) is None
        done = _new(session, input_sha256="b" * 64, status="done")
        assert db.find_completed_by_sha256(session, "b" * 64).id == done.id


def test_session_rolls_back_on_error(engine) -> None:
    with pytest.raises(RuntimeError), db.session_scope(engine) as session:
        _new(session, subject="never saved")
        raise RuntimeError("boom")
    with db.session_scope(engine) as session:
        assert db.list_cases(session)[1] == 0
