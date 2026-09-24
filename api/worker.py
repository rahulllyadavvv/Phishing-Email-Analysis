"""Background analysis jobs for the API: storage of uploads, progress tracking and the queue.

- Uploaded inputs are written to ``<QUARANTINE_DIR>/uploads/<case_id>/input.bin`` (a generated
  name, never the uploader's file name, never inside a web-served folder).
- ``run_analysis(case_id, stored_input_path, filename, mode)`` is the job: it runs the pipeline
  (``mode``: ``auto`` routes by content, ``file`` forces a file case, ``email`` forces an email
  case), records per-module progress, writes every report format to
  ``<REPORTS_DIR>/<case_id>/`` and updates the ``Case`` row. A failure sets status ``error``
  with a message; reports already produced are kept.
- Progress lives in Redis (hash ``progress:<case_id>``, module -> status) or, for tests and
  ``JOB_QUEUE=sync``, in memory.
- ``get_queue()`` returns an RQ queue (run workers with ``rq worker phishlens``) or a
  synchronous queue that runs the job immediately (``JOB_QUEUE=sync``, and tests).
"""

from __future__ import annotations

import asyncio
import hashlib
import threading
from pathlib import Path
from typing import Any, Literal, Protocol

from api import db
from phishlens.config import get_settings
from phishlens.ingest.loader import LoaderError
from phishlens.models import AnalysisReport
from phishlens.pipeline import analyze_email, analyze_file, analyze_input
from phishlens.reporting.generate import FORMATS, generate_report

__all__ = [
    "PROGRESS_TTL_SECONDS",
    "QUEUE_NAME",
    "MemoryProgressStore",
    "ProgressStore",
    "RedisProgressStore",
    "SyncQueue",
    "get_progress_store",
    "get_queue",
    "reports_path",
    "run_analysis",
    "store_upload",
    "upload_path",
]

QUEUE_NAME = "phishlens"
PROGRESS_TTL_SECONDS = 7 * 24 * 3600
Mode = Literal["auto", "file", "email"]


# --- Storage --------------------------------------------------------------------------------------


def upload_path(case_id: str) -> Path:
    return Path(get_settings().quarantine_dir) / "uploads" / case_id / "input.bin"


def reports_path(case_id: str) -> Path:
    return Path(get_settings().reports_dir) / case_id


def store_upload(case_id: str, data: bytes) -> tuple[Path, str]:
    """Write the upload under a generated name; returns the path and the SHA-256."""
    path = upload_path(case_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


# --- Progress -------------------------------------------------------------------------------------


class ProgressStore(Protocol):
    def set(self, case_id: str, module: str, status: str) -> None: ...

    def get(self, case_id: str) -> dict[str, str]: ...

    def clear(self, case_id: str) -> None: ...


class MemoryProgressStore:
    """In-process progress (tests and ``JOB_QUEUE=sync``)."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, str]] = {}
        self._lock = threading.Lock()

    def set(self, case_id: str, module: str, status: str) -> None:
        with self._lock:
            self._data.setdefault(case_id, {})[module] = status

    def get(self, case_id: str) -> dict[str, str]:
        with self._lock:
            return dict(self._data.get(case_id, {}))

    def clear(self, case_id: str) -> None:
        with self._lock:
            self._data.pop(case_id, None)


class RedisProgressStore:
    """Progress in a Redis hash ``progress:<case_id>`` (expires after a week)."""

    def __init__(self, client: Any) -> None:
        self.client = client

    @staticmethod
    def key(case_id: str) -> str:
        return f"progress:{case_id}"

    def set(self, case_id: str, module: str, status: str) -> None:
        key = self.key(case_id)
        self.client.hset(key, module, status)
        self.client.expire(key, PROGRESS_TTL_SECONDS)

    def get(self, case_id: str) -> dict[str, str]:
        raw = self.client.hgetall(self.key(case_id))
        return {_text(k): _text(v) for k, v in raw.items()}

    def clear(self, case_id: str) -> None:
        self.client.delete(self.key(case_id))


def _text(value: Any) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


_memory_store = MemoryProgressStore()
_redis_clients: dict[str, Any] = {}


def _redis() -> Any:
    import redis

    url = get_settings().redis_url
    if url not in _redis_clients:
        _redis_clients[url] = redis.Redis.from_url(url)
    return _redis_clients[url]


def get_progress_store() -> ProgressStore:
    if get_settings().job_queue == "sync":
        return _memory_store
    return RedisProgressStore(_redis())


# --- The job --------------------------------------------------------------------------------------


def _headline(report: AnalysisReport) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if report.verdict is not None:
        fields.update(
            verdict=report.verdict.label.value,
            score=report.verdict.total_score,
            confidence=report.verdict.confidence,
        )
    if report.email is not None:
        fields["subject"] = report.email.subject[:500] or None
        if report.email.from_addrs:
            fields["sender"] = report.email.from_addrs[0].address[:320]
    fields["case_type"] = report.case_type.value
    return fields


async def _analyze(
    data: bytes, filename: str | None, mode: Mode, case_id: str, progress: Any
) -> AnalysisReport:
    if mode == "file":
        return await analyze_file(data, filename or "upload.bin", progress, case_id=case_id)
    if mode == "email":
        return await analyze_email(data, progress, case_id=case_id)
    return await analyze_input(data, filename, progress, case_id=case_id)


def run_analysis(
    case_id: str,
    stored_input_path: str,
    filename: str | None = None,
    mode: Mode = "auto",
    progress_store: ProgressStore | None = None,
) -> str:
    """Analyze a stored upload and record the outcome on its Case. Returns the final status."""
    store = progress_store or get_progress_store()
    with db.session_scope() as session:
        db.update_case(session, case_id, status="running", error_message=None)
    store.set(case_id, "job", "running")

    def progress(module: str, status: str) -> None:
        store.set(case_id, module, status)

    report: AnalysisReport | None = None
    try:
        data = Path(stored_input_path).read_bytes()
        report = asyncio.run(_analyze(data, filename, mode, case_id, progress))
        generated = generate_report(report, list(FORMATS), reports_path(case_id))
    except (LoaderError, OSError, ValueError) as exc:
        return _fail(case_id, store, f"{type(exc).__name__}: {exc}", report)
    except Exception as exc:  # the pipeline should not raise; record anything unexpected
        return _fail(case_id, store, f"unexpected error: {type(exc).__name__}: {exc}", report)

    files = {fmt: str(path) for fmt, path in generated.paths.items()}
    with db.session_scope() as session:
        db.update_case(
            session,
            case_id,
            status="done",
            report_json_path=files.get("json"),
            report_files=files,
            **_headline(report),
        )
    store.set(case_id, "job", "done")
    return "done"


def _fail(
    case_id: str, store: ProgressStore, message: str, report: AnalysisReport | None
) -> str:
    """Record the error; keep whatever report can still be written."""
    fields: dict[str, Any] = {"status": "error", "error_message": message[:2000]}
    if report is not None:
        try:
            generated = generate_report(report, ["json", "html"], reports_path(case_id))
        except Exception:
            generated = None
        if generated is not None:
            files = {fmt: str(path) for fmt, path in generated.paths.items()}
            fields.update(report_files=files, report_json_path=files.get("json"))
            fields.update(_headline(report))
    with db.session_scope() as session:
        db.update_case(session, case_id, **fields)
    store.set(case_id, "job", "error")
    return "error"


# --- Queues ---------------------------------------------------------------------------------------


class SyncQueue:
    """Runs each job immediately in the calling thread (tests, ``JOB_QUEUE=sync``)."""

    def __init__(self, progress_store: ProgressStore | None = None) -> None:
        self.progress_store = progress_store
        self.jobs: list[tuple[str, str, str | None, str]] = []

    def enqueue_analysis(
        self, case_id: str, stored_input_path: str, filename: str | None, mode: Mode = "auto"
    ) -> str:
        self.jobs.append((case_id, stored_input_path, filename, mode))
        return run_analysis(case_id, stored_input_path, filename, mode, self.progress_store)

    def healthy(self) -> dict[str, Any]:
        return {"queue": "sync", "redis": None, "workers": None}


class RQQueue:
    """Jobs go to Redis; ``rq worker phishlens`` processes run them."""

    def __init__(self) -> None:
        from rq import Queue

        self.queue = Queue(QUEUE_NAME, connection=_redis(), default_timeout=3600)

    def enqueue_analysis(
        self, case_id: str, stored_input_path: str, filename: str | None, mode: Mode = "auto"
    ) -> str:
        job = self.queue.enqueue(
            run_analysis, case_id, stored_input_path, filename, mode, job_id=f"analysis-{case_id}"
        )
        return job.id

    def healthy(self) -> dict[str, Any]:
        from rq import Worker

        try:
            _redis().ping()
            workers = len(Worker.all(connection=_redis()))
            return {"queue": "rq", "redis": True, "workers": workers}
        except Exception:
            return {"queue": "rq", "redis": False, "workers": 0}


def get_queue() -> SyncQueue | RQQueue:
    return SyncQueue() if get_settings().job_queue == "sync" else RQQueue()
