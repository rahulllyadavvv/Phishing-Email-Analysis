"""Typed client for the PhishLens API: the UI's only way to reach the backend.

Configuration comes from the environment: ``PHISHLENS_API_URL`` (default
``http://localhost:8000``) and ``PHISHLENS_API_KEY`` (sent as ``X-API-Key`` when set).

Every function raises ``ApiError`` with a message a person can act on (backend not running,
wrong API key, file too large, too many uploads, ...) instead of an HTTP stack trace.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

__all__ = [
    "ApiError",
    "analyze_email",
    "analyze_files",
    "analyze_raw",
    "api_url",
    "case_status",
    "delete_case",
    "download_report",
    "get_case",
    "health",
    "list_cases",
    "stats",
]

TIMEOUT = httpx.Timeout(30.0, connect=5.0)
UPLOAD_TIMEOUT = httpx.Timeout(300.0, connect=5.0)


@dataclass
class ApiError(Exception):
    message: str
    status: int | None = None

    def __str__(self) -> str:
        return self.message


def api_url() -> str:
    return os.environ.get("PHISHLENS_API_URL", "http://localhost:8000").rstrip("/")


def _headers() -> dict[str, str]:
    key = os.environ.get("PHISHLENS_API_KEY", "").strip()
    return {"X-API-Key": key} if key else {}


def _friendly(response: httpx.Response) -> ApiError:
    try:
        detail = response.json().get("detail")
    except ValueError:
        detail = None
    if isinstance(detail, list):  # FastAPI validation errors
        detail = "; ".join(str(d.get("msg", d)) for d in detail)
    status = response.status_code
    if status == 401:
        return ApiError("The backend refused the API key. Set PHISHLENS_API_KEY for the UI.", 401)
    if status == 413:
        return ApiError(detail or "The file is too large for the backend.", 413)
    if status == 429:
        wait = response.headers.get("Retry-After", "a few")
        return ApiError(f"Too many uploads right now; wait {wait} seconds and try again.", 429)
    if status == 404:
        return ApiError(detail or "Not found.", 404)
    return ApiError(detail or f"The backend answered with an error ({status}).", status)


def _request(
    method: str, path: str, *, timeout: httpx.Timeout = TIMEOUT, **kwargs: Any
) -> httpx.Response:
    try:
        response = httpx.request(
            method, f"{api_url()}{path}", headers=_headers(), timeout=timeout, **kwargs
        )
    except httpx.ConnectError:
        raise ApiError(
            f"Cannot reach the PhishLens backend at {api_url()}. Is it running "
            "(uvicorn api.main:app)?"
        ) from None
    except httpx.TimeoutException:
        raise ApiError("The backend did not answer in time; try again.") from None
    except httpx.HTTPError as exc:
        raise ApiError(f"Could not talk to the backend: {type(exc).__name__}.") from None
    if response.status_code >= 400:
        raise _friendly(response)
    return response


def health() -> dict[str, Any]:
    return _request("GET", "/api/health").json()


def analyze_email(filename: str, data: bytes, force: bool = False) -> dict[str, Any]:
    """Upload one .eml/.msg. Returns ``{case_id, duplicate}``."""
    return _request(
        "POST",
        "/api/analyze",
        params={"force": "true"} if force else None,
        files={"file": (filename, data)},
        timeout=UPLOAD_TIMEOUT,
    ).json()


def analyze_files(files: list[tuple[str, bytes]], force: bool = False) -> list[dict[str, Any]]:
    """Upload files of any type. Returns ``[{case_id, filename, duplicate}]``."""
    return _request(
        "POST",
        "/api/analyze-file",
        params={"force": "true"} if force else None,
        files=[("files", (name, data)) for name, data in files],
        timeout=UPLOAD_TIMEOUT,
    ).json()


def analyze_raw(source: str, force: bool = False) -> dict[str, Any]:
    return _request(
        "POST",
        "/api/analyze-raw",
        params={"force": "true"} if force else None,
        json={"raw_source": source},
        timeout=UPLOAD_TIMEOUT,
    ).json()


def case_status(case_id: str) -> dict[str, Any]:
    return _request("GET", f"/api/cases/{case_id}/status").json()


def get_case(case_id: str) -> dict[str, Any]:
    """The full (defanged) AnalysisReport of a finished case."""
    return _request("GET", f"/api/cases/{case_id}").json()


def download_report(case_id: str, fmt: str) -> tuple[bytes, str]:
    """Report file bytes and the file name the backend suggests."""
    response = _request("GET", f"/api/cases/{case_id}/report", params={"format": fmt})
    disposition = response.headers.get("content-disposition", "")
    name = (
        disposition.split("filename=")[-1].strip('"')
        if "filename=" in disposition
        else (f"{case_id}.{fmt}")
    )
    return response.content, name


def list_cases(**filters: Any) -> dict[str, Any]:
    params = {k: v for k, v in filters.items() if v not in (None, "", "All")}
    return _request("GET", "/api/cases", params=params).json()


def stats() -> dict[str, Any]:
    return _request("GET", "/api/stats").json()


def delete_case(case_id: str) -> None:
    _request("DELETE", f"/api/cases/{case_id}")
