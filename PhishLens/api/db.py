"""Database models and helpers for the API (SQLModel; SQLite by default, Postgres via
``DATABASE_URL``).

A ``Case`` is one submitted email or file: its status while it is analyzed, the headline of the
result (verdict, score, confidence, subject, sender) for listing and searching, and where its
reports were written. The full report lives in the JSON file, not in the database.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import cache
from typing import Any

from sqlalchemy import JSON, Column, func
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool
from sqlmodel import Field, Session, SQLModel, col, create_engine, select

from phishlens.config import get_settings

__all__ = [
    "CASE_STATUSES",
    "Case",
    "create_case",
    "delete_case",
    "find_completed_by_sha256",
    "get_case",
    "get_engine",
    "init_db",
    "list_cases",
    "new_case_id",
    "session_scope",
    "update_case",
]

CASE_STATUSES = ("queued", "running", "done", "error")
_ID_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # no 0/O, 1/I/L


def _now() -> datetime:
    return datetime.now(UTC)


def new_case_id(when: datetime | None = None) -> str:
    """A short, readable, URL- and file-name-safe ID such as ``PL-20260924-7K3QM``."""
    when = when or _now()
    suffix = "".join(secrets.choice(_ID_ALPHABET) for _ in range(5))
    return f"PL-{when:%Y%m%d}-{suffix}"


class Case(SQLModel, table=True):
    id: str = Field(default_factory=new_case_id, primary_key=True, max_length=32)
    created_at: datetime = Field(default_factory=_now, index=True)
    updated_at: datetime = Field(default_factory=_now)
    case_type: str = Field(default="email", index=True)  # email | file
    original_filename: str | None = None
    input_sha256: str = Field(index=True, max_length=64)
    subject: str | None = None
    sender: str | None = None
    verdict: str | None = Field(default=None, index=True)  # clean | suspicious | malicious
    score: int | None = None
    confidence: float | None = None
    status: str = Field(default="queued", index=True)  # queued | running | done | error
    error_message: str | None = None
    report_json_path: str | None = None
    report_files: dict[str, str] = Field(default_factory=dict, sa_column=Column(JSON))


@cache
def _engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        kwargs: dict[str, Any] = {"connect_args": {"check_same_thread": False}}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool  # one shared in-memory database
        return create_engine(url, **kwargs)
    return create_engine(url, pool_pre_ping=True)


def get_engine(url: str | None = None) -> Engine:
    return _engine(url or get_settings().database_url)


def init_db(engine: Engine | None = None) -> Engine:
    """Create the tables if they do not exist (called on API startup)."""
    engine = engine or get_engine()
    SQLModel.metadata.create_all(engine)
    return engine


@contextmanager
def session_scope(engine: Engine | None = None) -> Iterator[Session]:
    """A session that commits on success and rolls back on error."""
    with Session(engine or get_engine(), expire_on_commit=False) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


def create_case(session: Session, **fields: Any) -> Case:
    case = Case(**fields)
    session.add(case)
    session.flush()
    return case


def get_case(session: Session, case_id: str) -> Case | None:
    return session.get(Case, case_id)


def update_case(session: Session, case_id: str, **fields: Any) -> Case | None:
    case = session.get(Case, case_id)
    if case is None:
        return None
    unknown = set(fields) - set(Case.model_fields)
    if unknown:
        raise ValueError(f"unknown Case fields: {sorted(unknown)}")
    if "status" in fields and fields["status"] not in CASE_STATUSES:
        raise ValueError(f"invalid status {fields['status']!r}")
    for name, value in fields.items():
        setattr(case, name, value)
    case.updated_at = _now()
    session.add(case)
    session.flush()
    return case


def delete_case(session: Session, case_id: str) -> Case | None:
    """Delete the row and return it (the caller removes the files it points to)."""
    case = session.get(Case, case_id)
    if case is not None:
        session.delete(case)
        session.flush()
    return case


def find_completed_by_sha256(
    session: Session, sha256: str, case_type: str | None = None
) -> Case | None:
    """The newest finished case for the same input (and case type), for deduplication."""
    conditions = [Case.input_sha256 == sha256, Case.status == "done"]
    if case_type:
        conditions.append(Case.case_type == case_type)
    statement = select(Case).where(*conditions).order_by(col(Case.created_at).desc())
    return session.exec(statement).first()


def list_cases(
    session: Session,
    *,
    verdict: str | None = None,
    case_type: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    q: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[Case], int]:
    """Cases matching the filters, newest first, and the total number of matches."""
    conditions = []
    if verdict:
        conditions.append(Case.verdict == verdict)
    if case_type:
        conditions.append(Case.case_type == case_type)
    if date_from:
        conditions.append(Case.created_at >= date_from)
    if date_to:
        conditions.append(Case.created_at <= date_to)
    if q:
        pattern = f"%{q.lower()}%"
        conditions.append(
            func.lower(func.coalesce(Case.subject, "")).like(pattern)
            | func.lower(func.coalesce(Case.sender, "")).like(pattern)
            | func.lower(func.coalesce(Case.original_filename, "")).like(pattern)
        )
    total = session.exec(select(func.count()).select_from(Case).where(*conditions)).one()
    statement = (
        select(Case)
        .where(*conditions)
        .order_by(col(Case.created_at).desc())
        .offset(max(0, offset))
        .limit(max(1, min(limit, 500)))
    )
    return list(session.exec(statement).all()), int(total)
