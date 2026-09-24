"""PhishLens REST API (FastAPI). Run with ``uvicorn api.main:app``.

Endpoints (all under ``/api``):

- ``POST /analyze``: one .eml/.msg upload -> ``{case_id}``
- ``POST /analyze-file``: one or more files of any type -> ``[{case_id, filename}]``
- ``POST /analyze-raw``: JSON ``{raw_source}`` with pasted email source -> ``{case_id}``
- ``GET /cases/{id}/status``: status and per-module progress
- ``GET /cases/{id}``: the full AnalysisReport plus ``summary`` and ``recommendations``
  (every string defanged)
- ``GET /cases/{id}/report?format=html|pdf|json|csv|stix|zip``: file download
- ``GET /cases``: paginated list with filters (verdict, case_type, date_from, date_to, q)
- ``GET /stats``: counts per verdict and cases per day (last 30 days)
- ``DELETE /cases/{id}``: the case, its reports and its quarantined input
- ``GET /health``: queue/Redis/worker status, configured services (true/false), version

Analyses run in the background (RQ, or a background task with ``JOB_QUEUE=sync``), so
uploads return a case ID at once. Nothing uploaded is ever served back: downloads are only the
generated reports.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlmodel import select

from api import db, worker
from api.security import API_KEY_HEADER, auth_enabled, require_api_key, upload_limit
from phishlens import __version__
from phishlens.config import get_settings
from phishlens.ingest.loader import OLE_SIGNATURE, LoaderError, load_input, looks_like_rfc822
from phishlens.models import AnalysisReport
from phishlens.reporting.generate import FORMATS
from phishlens.reporting.safe import defang_text
from phishlens.reporting.summary import build_recommendations, build_summary

__all__ = ["app", "create_app"]

MEDIA_TYPES = {
    "html": "text/html",
    "pdf": "application/pdf",
    "json": "application/json",
    "csv": "text/csv",
    "stix": "application/json",
    "zip": "application/zip",
}
CHUNK = 1024 * 1024


class RawSource(BaseModel):
    raw_source: str = Field(min_length=1)


class CaseCreated(BaseModel):
    case_id: str
    duplicate: bool = False  # an identical input was already analyzed: this is that case


class FileCaseCreated(BaseModel):
    case_id: str
    filename: str
    duplicate: bool = False


# --- Helpers ---------------------------------------------------------------------------------


async def _read_upload(upload: UploadFile) -> bytes:
    """Read an upload, refusing anything above MAX_INPUT_SIZE_MB with 413."""
    limit = int(get_settings().max_input_size_mb * 1024 * 1024)
    data = bytearray()
    while chunk := await upload.read(CHUNK):
        data += chunk
        if len(data) > limit:
            raise HTTPException(
                413, f"{upload.filename or 'upload'} is larger than {limit // (1024 * 1024)} MB"
            )
    if not data:
        raise HTTPException(400, f"{upload.filename or 'upload'} is empty")
    return bytes(data)


def _safe_name(filename: str | None) -> str:
    """Keep only the base name, printable, at most 200 characters (for display and routing)."""
    name = (filename or "upload.bin").replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if ch.isprintable()).strip()
    return name[:200] or "upload.bin"


def _start(
    background: BackgroundTasks, data: bytes, filename: str | None, mode: worker.Mode,
    case_type: str, force: bool = False,
) -> tuple[str, bool]:
    """Start a case, or return an existing finished case for the same input (unless
    ``force``). Returns (case_id, duplicate)."""
    if not force:
        sha256 = hashlib.sha256(data).hexdigest()
        with db.session_scope() as session:
            existing = db.find_completed_by_sha256(session, sha256, case_type)
            if existing is not None:
                return existing.id, True
    with db.session_scope() as session:
        case = db.create_case(
            session, input_sha256="0" * 64, original_filename=filename, case_type=case_type
        )
        case_id = case.id
    path, sha256 = worker.store_upload(case_id, data)
    with db.session_scope() as session:
        db.update_case(session, case_id, input_sha256=sha256)
    queue = worker.get_queue()
    worker.get_progress_store().set(case_id, "job", "queued")
    if isinstance(queue, worker.SyncQueue):
        background.add_task(queue.enqueue_analysis, case_id, str(path), filename, mode)
    else:
        queue.enqueue_analysis(case_id, str(path), filename, mode)
    return case_id, False


def _case_or_404(case_id: str) -> db.Case:
    with db.session_scope() as session:
        case = db.get_case(session, case_id)
    if case is None:
        raise HTTPException(404, f"case {case_id} not found")
    return case


def _defang_tree(value: Any) -> Any:
    """Defang every string in a JSON-like structure (API responses must never carry live
    indicators)."""
    if isinstance(value, str):
        return defang_text(value)
    if isinstance(value, list):
        return [_defang_tree(v) for v in value]
    if isinstance(value, dict):
        return {defang_text(k): _defang_tree(v) for k, v in value.items()}
    return value


def _summary(case: db.Case) -> dict[str, Any]:
    return {
        "case_id": case.id,
        "created_at": case.created_at.isoformat(),
        "case_type": case.case_type,
        "filename": case.original_filename,
        "subject": defang_text(case.subject) if case.subject else None,
        "sender": defang_text(case.sender) if case.sender else None,
        "verdict": case.verdict,
        "score": case.score,
        "confidence": case.confidence,
        "status": case.status,
    }


# --- App -------------------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(app: FastAPI):
    db.init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="PhishLens API",
        version=__version__,
        description="Automated phishing email analysis. All indicators are defanged.",
        lifespan=_lifespan,
        dependencies=[Depends(require_api_key)],
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_settings().cors_origins,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=[API_KEY_HEADER, "Content-Type"],
    )
    uploads = [Depends(upload_limit)]

    @app.post("/api/analyze", response_model=CaseCreated, status_code=202, dependencies=uploads)
    async def analyze(
        background: BackgroundTasks, file: Annotated[UploadFile, File()], force: bool = False
    ) -> CaseCreated:
        data = await _read_upload(file)
        filename = _safe_name(file.filename)
        try:
            kind, _ = load_input(data, filename)
        except LoaderError as exc:
            raise HTTPException(400, str(exc)) from None
        if kind != "email":
            raise HTTPException(
                400,
                f"{filename} is not an email (.eml or Outlook .msg); "
                "use /api/analyze-file for other files",
            )
        case_id, duplicate = _start(background, data, filename, "auto", "email", force)
        return CaseCreated(case_id=case_id, duplicate=duplicate)

    @app.post(
        "/api/analyze-file",
        response_model=list[FileCaseCreated],
        status_code=202,
        dependencies=uploads,
    )
    async def analyze_files(
        background: BackgroundTasks,
        files: Annotated[list[UploadFile], File()],
        force: bool = False,
    ) -> list[FileCaseCreated]:
        if not files:
            raise HTTPException(400, "no files uploaded")
        received = [(_safe_name(f.filename), await _read_upload(f)) for f in files]
        created = []
        for name, data in received:
            case_id, duplicate = _start(background, data, name, "file", "file", force)
            created.append(FileCaseCreated(case_id=case_id, filename=name, duplicate=duplicate))
        return created

    @app.post(
        "/api/analyze-raw", response_model=CaseCreated, status_code=202, dependencies=uploads
    )
    async def analyze_raw(
        background: BackgroundTasks, body: RawSource, force: bool = False
    ) -> CaseCreated:
        data = body.raw_source.encode("utf-8", errors="replace")
        limit = int(get_settings().max_input_size_mb * 1024 * 1024)
        if len(data) > limit:
            raise HTTPException(413, "the pasted source is too large")
        if data.startswith(OLE_SIGNATURE) or not looks_like_rfc822(data):
            raise HTTPException(
                400, "this does not look like email source: paste the full message with headers"
            )
        case_id, duplicate = _start(background, data, "pasted.eml", "email", "email", force)
        return CaseCreated(case_id=case_id, duplicate=duplicate)

    @app.get("/api/cases/{case_id}/status")
    def status(case_id: str) -> dict[str, Any]:
        case = _case_or_404(case_id)
        return {
            "case_id": case.id,
            "status": case.status,
            "error_message": defang_text(case.error_message) if case.error_message else None,
            "verdict": case.verdict,
            "score": case.score,
            "progress": worker.get_progress_store().get(case.id),
        }

    @app.get("/api/cases/{case_id}")
    def case_report(case_id: str) -> dict[str, Any]:
        case = _case_or_404(case_id)
        if case.status in ("queued", "running"):
            raise HTTPException(409, f"case {case_id} is still {case.status}")
        if not case.report_json_path or not Path(case.report_json_path).is_file():
            raise HTTPException(404, f"no report for case {case_id}: {case.error_message or ''}")
        data = json.loads(Path(case.report_json_path).read_text("utf-8"))
        try:
            report = AnalysisReport.model_validate(data)
            data["summary"] = build_summary(report)
            data["recommendations"] = build_recommendations(report)
        except ValueError:
            data["summary"], data["recommendations"] = [], []
        return _defang_tree(data)

    @app.get("/api/cases/{case_id}/report")
    def download(
        case_id: str, format: Literal["html", "pdf", "json", "csv", "stix", "zip"] = "html"
    ) -> FileResponse:
        case = _case_or_404(case_id)
        path = (case.report_files or {}).get(format)
        reports_root = Path(get_settings().reports_dir).resolve()
        if path and not Path(path).resolve().is_relative_to(reports_root):
            path = None  # only generated reports can ever be downloaded
        if not path or not Path(path).is_file():
            available = ", ".join(sorted(case.report_files or {})) or "none"
            raise HTTPException(404, f"no {format} report for {case_id} (available: {available})")
        return FileResponse(
            path,
            media_type=MEDIA_TYPES[format],
            filename=Path(path).name,
            content_disposition_type="attachment",
        )

    @app.get("/api/cases")
    def cases(
        verdict: Literal["clean", "suspicious", "malicious"] | None = None,
        case_type: Literal["email", "file"] | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        q: Annotated[str | None, Query(max_length=200)] = None,
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=200)] = 25,
    ) -> dict[str, Any]:
        with db.session_scope() as session:
            items, total = db.list_cases(
                session,
                verdict=verdict,
                case_type=case_type,
                date_from=date_from,
                date_to=date_to,
                q=q,
                offset=(page - 1) * page_size,
                limit=page_size,
            )
        return {
            "items": [_summary(c) for c in items],
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    @app.get("/api/stats")
    def stats() -> dict[str, Any]:
        since = datetime.now(UTC) - timedelta(days=30)
        with db.session_scope() as session:
            rows = session.exec(select(db.Case.verdict, db.Case.created_at, db.Case.status)).all()
        verdicts = Counter(v or "pending" for v, _, s in rows if s != "error")
        recent = Counter(
            created.date().isoformat()
            for _, created, _ in rows
            if created.replace(tzinfo=created.tzinfo or UTC) >= since
        )
        today = datetime.now(UTC).date()
        days = [(today - timedelta(days=n)).isoformat() for n in range(29, -1, -1)]
        return {
            "total": len(rows),
            "by_verdict": {k: verdicts.get(k, 0) for k in
                           ("clean", "suspicious", "malicious", "pending")},
            "errors": sum(1 for _, _, s in rows if s == "error"),
            "per_day": [{"date": d, "count": recent.get(d, 0)} for d in days],
        }

    @app.delete("/api/cases/{case_id}", status_code=204)
    def delete(case_id: str) -> None:
        with db.session_scope() as session:
            case = db.delete_case(session, case_id)
        if case is None:
            raise HTTPException(404, f"case {case_id} not found")
        settings = get_settings()
        quarantine = Path(settings.quarantine_dir)
        folders = [worker.reports_path(case_id), worker.upload_path(case_id).parent]
        folders += [quarantine / case_id, *quarantine.glob(f"{case_id}_nested*")]
        for folder in folders:
            shutil.rmtree(folder, ignore_errors=True)
        try:
            worker.get_progress_store().clear(case_id)
        except Exception:
            pass

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        try:
            queue = worker.get_queue().healthy()
        except Exception as exc:
            queue = {"queue": get_settings().job_queue, "redis": False, "error": type(exc).__name__}
        return {
            "status": "ok",
            "version": __version__,
            "queue": queue,
            "auth": "api_key" if auth_enabled() else "disabled",
            "services": get_settings().configured_services(),
            "formats": list(FORMATS),
        }

    return app


app = create_app()
