"""Tests for the UI foundation: the API client (respx) and the app shell (Streamlit AppTest).
The UI never talks to anything but the API, and in tests not even to that."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx
import streamlit as st
from streamlit.testing.v1 import AppTest

from ui import api_client

API = "http://api.test"
APP = str(Path(__file__).parent.parent / "ui" / "app.py")


@pytest.fixture(autouse=True)
def api_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PHISHLENS_API_URL", API + "/")
    monkeypatch.delenv("PHISHLENS_API_KEY", raising=False)
    st.cache_data.clear()


@respx.mock
def test_client_calls_and_key_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PHISHLENS_API_KEY", "ui-key")
    route = respx.get(f"{API}/api/health").respond(200, json={"status": "ok", "version": "1"})
    assert api_client.health()["status"] == "ok"
    assert route.calls.last.request.headers["x-api-key"] == "ui-key"

    upload = respx.post(f"{API}/api/analyze").respond(
        202, json={"case_id": "PL-1", "duplicate": False}
    )
    assert api_client.analyze_email("m.eml", b"data", force=True)["case_id"] == "PL-1"
    assert upload.calls.last.request.url.params["force"] == "true"
    assert b'filename="m.eml"' in upload.calls.last.request.content

    respx.post(f"{API}/api/analyze-file").respond(202, json=[{"case_id": "PL-2", "filename": "a"}])
    assert api_client.analyze_files([("a", b"1")])[0]["case_id"] == "PL-2"
    raw = respx.post(f"{API}/api/analyze-raw").respond(202, json={"case_id": "PL-3"})
    api_client.analyze_raw("From: a@b.test")
    assert b"raw_source" in raw.calls.last.request.content

    listing = respx.get(f"{API}/api/cases").respond(200, json={"items": [], "total": 0})
    api_client.list_cases(verdict="All", q="", case_type="email", page=2)
    assert dict(listing.calls.last.request.url.params) == {"case_type": "email", "page": "2"}

    respx.get(f"{API}/api/cases/PL-1/report").respond(
        200,
        content=b"<html>",
        headers={"content-disposition": 'attachment; filename="PL-1_clean.html"'},
    )
    assert api_client.download_report("PL-1", "html") == (b"<html>", "PL-1_clean.html")
    respx.delete(f"{API}/api/cases/PL-1").respond(204)
    api_client.delete_case("PL-1")


@pytest.mark.parametrize(
    ("status", "body", "headers", "expected"),
    [
        (401, {"detail": "missing or invalid API key"}, {}, "refused the API key"),
        (413, {"detail": "mail.eml is larger than 25 MB"}, {}, "larger than 25 MB"),
        (429, {"detail": "too many"}, {"Retry-After": "30"}, "wait 30 seconds"),
        (404, {"detail": "case PL-9 not found"}, {}, "case PL-9 not found"),
        (422, {"detail": [{"msg": "field required"}]}, {}, "field required"),
        (500, "not json", {}, "error (500)"),
    ],
)
@respx.mock
def test_friendly_errors(status, body, headers, expected) -> None:
    kwargs = {"json": body} if isinstance(body, dict) else {"content": body.encode()}
    respx.get(f"{API}/api/stats").respond(status, headers=headers, **kwargs)
    with pytest.raises(api_client.ApiError) as info:
        api_client.stats()
    assert expected in str(info.value) and info.value.status == status


@respx.mock
def test_backend_down() -> None:
    respx.get(f"{API}/api/health").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(api_client.ApiError, match="Cannot reach the PhishLens backend"):
        api_client.health()
    respx.get(f"{API}/api/stats").mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(api_client.ApiError, match="did not answer in time"):
        api_client.stats()


def _app(monkeypatch: pytest.MonkeyPatch, health) -> AppTest:
    monkeypatch.setattr(api_client, "health", health)
    app = AppTest.from_file(APP, default_timeout=30)
    app.run()
    return app


def _sidebar_text(app: AppTest) -> str:
    parts = [m.value for m in app.sidebar.markdown] + [c.value for c in app.sidebar.caption]
    return " ".join(parts)


def test_app_shows_backend_online(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(monkeypatch, lambda: {"status": "ok", "version": "0.1.0", "queue": {"redis": True}})
    assert not app.exception
    text = _sidebar_text(app)
    assert "Backend online (v0.1.0)" in text and "PhishLens" in text.replace("*", "")
    assert app.title[0].value == "Analyze"  # the default page


def test_app_shows_backend_down(monkeypatch: pytest.MonkeyPatch) -> None:
    def down():
        raise api_client.ApiError("Cannot reach the PhishLens backend at http://api.test.")

    app = _app(monkeypatch, down)
    assert not app.exception
    assert "Cannot reach the PhishLens backend" in _sidebar_text(app)


def test_app_warns_when_redis_is_down(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(monkeypatch, lambda: {"version": "1", "queue": {"redis": False}})
    assert "Job queue unavailable" in _sidebar_text(app)


def test_theme_colors_are_defined_once() -> None:
    from ui import theme

    assert set(theme.VERDICT_COLORS) == {"clean", "suspicious", "malicious", "unknown"}
    assert theme.verdict_color("MALICIOUS") == theme.VERDICT_COLORS["malicious"]
    assert theme.verdict_color(None) == theme.VERDICT_COLORS["unknown"]
    assert "&lt;" in theme.severity_pill("<script>")
