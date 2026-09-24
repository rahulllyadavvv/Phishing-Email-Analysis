"""Tests for the Analyze page and its progress logic (the API is replaced by fakes)."""

from __future__ import annotations

from pathlib import Path

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from ui import api_client, progress
from ui.progress import poll, steps

APP = str(Path(__file__).parent.parent / "ui" / "app.py")


def _status(overall: str, **modules: str) -> dict:
    return {"status": overall, "progress": modules}


def test_steps_while_running() -> None:
    rows = dict(steps(_status("running", job="running", header="done", domain="running")))
    assert rows["Parsing"] == "done" and rows["Header"] == "done"
    assert rows["Sender & domain"] == "running" and rows["URLs"] == "pending"
    assert rows["IOCs"] == rows["MITRE mapping"] == "pending" and rows["Report"] == "pending"
    assert len(steps({})) == 11


def test_steps_scoring_and_done() -> None:
    scoring = dict(steps(_status("running", job="running", header="done", scoring="done")))
    assert scoring["IOCs"] == "done" and scoring["Report"] == "running"
    done = dict(steps(_status("done", job="done", header="done", urls="done")))
    assert set(done.values()) == {"done"}  # finished cases show every step done
    file_case = dict(steps(_status("done", header="skipped", attachments="done")))
    assert file_case["Header"] == "skipped"


def test_steps_error() -> None:
    early = dict(steps(_status("error", job="error")))
    assert early["Parsing"] == "error" and early["Report"] == "error"
    late = dict(steps(_status("error", header="done", attachments="error")))
    assert late["Parsing"] == "done" and late["Attachments"] == "error"


def test_poll_until_finished() -> None:
    answers = {
        "A": iter([_status("queued"), _status("running"), _status("done")]),
        "B": iter([_status("running"), _status("error")]),
    }
    rendered: list[tuple[str, str]] = []
    sleeps: list[float] = []
    final = poll(
        ["A", "B"],
        lambda cid: next(answers[cid]),
        lambda cid, s: rendered.append((cid, s["status"])),
        sleep=sleeps.append,
    )
    assert final["A"]["status"] == "done" and final["B"]["status"] == "error"
    assert rendered == [("A", "queued"), ("B", "running"), ("A", "running"), ("B", "error"),
                        ("A", "done")]
    assert sleeps == [1.0, 1.0]


def test_poll_timeout() -> None:
    final = poll(["A"], lambda cid: _status("running"), lambda *a: None, sleep=lambda s: None,
                 timeout=3)
    assert final["A"]["status"] == "running"


# --- The page (Streamlit AppTest) ---------------------------------------------------------------


@pytest.fixture
def fake_api(monkeypatch: pytest.MonkeyPatch):
    st.cache_data.clear()
    calls: dict[str, list] = {"raw": [], "status": []}
    statuses = iter(
        [_status("running", job="running", header="running"),
         {**_status("done", job="done"), "verdict": "malicious", "score": 90}]
    )
    monkeypatch.setattr(api_client, "health", lambda: {"version": "1", "queue": {}})

    def analyze_raw(source, force=False):
        calls["raw"].append((source, force))
        return {"case_id": "PL-20260925-AAAAA", "duplicate": False}

    done = {**_status("done", job="done"), "verdict": "malicious", "score": 90}

    def case_status(case_id):
        calls["status"].append(case_id)
        return next(statuses, done)  # the case view asks again after the switch

    monkeypatch.setattr(api_client, "analyze_raw", analyze_raw)
    monkeypatch.setattr(api_client, "case_status", case_status)
    monkeypatch.setattr(
        api_client, "get_case", lambda cid: {"case_id": cid, "verdict": {"label": "malicious"}}
    )
    monkeypatch.setattr(progress, "_sleep", lambda s: None)
    return calls


def test_page_has_three_tabs_and_help(fake_api) -> None:
    app = AppTest.from_file(APP, default_timeout=30)
    app.run()
    assert not app.exception
    assert [t.label for t in app.tabs] == ["Analyze email", "Analyze file", "Paste email source"]
    assert any("Download message" in m.value for m in app.expander[0].markdown)
    assert any("Only the file is analyzed" in c.value for c in app.caption)


def test_paste_flow_polls_then_opens_the_case(fake_api) -> None:
    app = AppTest.from_file(APP, default_timeout=30)
    app.run()
    app.text_area(key="raw_source").input("From: a@b.test\nSubject: hi\n\nbody").run()
    app.button(key="go_raw").click().run()
    assert not app.exception
    assert fake_api["raw"] == [("From: a@b.test\nSubject: hi\n\nbody", False)]
    assert fake_api["status"][:2] == ["PL-20260925-AAAAA", "PL-20260925-AAAAA"]
    assert app.session_state["case_id"] == "PL-20260925-AAAAA"
    assert app.title[0].value == "Case view"


def test_api_errors_are_shown(monkeypatch: pytest.MonkeyPatch, fake_api) -> None:
    def refuse(source, force=False):
        raise api_client.ApiError("this does not look like email source")

    monkeypatch.setattr(api_client, "analyze_raw", refuse)
    app = AppTest.from_file(APP, default_timeout=30)
    app.run()
    app.text_area(key="raw_source").input("hello").run()
    app.button(key="go_raw").click().run()
    assert [e.value for e in app.error] == ["this does not look like email source"]
