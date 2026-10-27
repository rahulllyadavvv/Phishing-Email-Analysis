"""Tests for the History and Settings pages and their helpers (the API is replaced by fakes)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from phishlens.config import SERVICE_FIELDS
from ui import api_client, history_data

APP = str(Path(__file__).parent.parent / "ui" / "app.py")


def _item(n: int, verdict: str = "malicious", case_type: str = "email") -> dict:
    return {"case_id": f"PL-20260925-{n:05d}", "created_at": "2026-09-25T10:30:00+00:00",
            "case_type": case_type, "filename": "x.eml", "subject": f"Invoice {n}",
            "sender": "billing@evil[.]test", "verdict": verdict, "score": 80, "status": "done"}


# --- helpers ------------------------------------------------------------------------------------


def test_shares_and_pages() -> None:
    stats = {"total": 4, "by_verdict": {"malicious": 2, "clean": 1, "suspicious": 1}}
    assert history_data.shares(stats) == {"clean": 25.0, "suspicious": 25.0, "malicious": 50.0}
    assert history_data.shares({"total": 0}) == {"clean": 0.0, "suspicious": 0.0,
                                                 "malicious": 0.0}
    assert [history_data.page_count(n, 25) for n in (0, 1, 25, 26)] == [1, 1, 1, 2]


def test_date_params_needs_a_full_range() -> None:
    assert history_data.date_params(()) == {}
    assert history_data.date_params((date(2026, 9, 1),)) == {}
    assert history_data.date_params((date(2026, 9, 1), date(2026, 9, 25))) == {
        "date_from": "2026-09-01T00:00:00", "date_to": "2026-09-25T23:59:59.999999"
    }


def test_table_rows() -> None:
    row = history_data.table_rows([_item(1), {**_item(2), "subject": None, "verdict": None,
                                              "status": "running"}])
    assert row[0]["verdict"] == "MALICIOUS" and row[0]["open"] == "case?id=PL-20260925-00001"
    assert row[0]["date"] == "2026-09-25 10:30"
    assert row[1]["subject / file"] == "x.eml" and row[1]["verdict"] == "RUNNING"


def test_services_cover_every_configurable_service() -> None:
    services = history_data.services()
    assert set(services) == set(SERVICE_FIELDS)
    assert all(s["signup"].startswith("https://") and s["setting"] for s in services.values())


# --- the pages ----------------------------------------------------------------------------------


@pytest.fixture
def fake_api(monkeypatch: pytest.MonkeyPatch):
    st.cache_data.clear()
    state: dict = {"calls": [], "deleted": [], "items": [_item(n) for n in range(1, 31)]}
    health = {
        "status": "ok", "version": "0.9.0", "auth": "disabled", "formats": ["html", "json"],
        "queue": {"queue": "rq", "redis": True, "workers": 2},
        "services": {name: name == "virustotal" for name in SERVICE_FIELDS},
        "config": {"thresholds": {"email": {"suspicious": 30, "malicious": 60}},
                   "scorer": "rule", "vt_malicious_threshold": 3, "upload_files_to_vt": False},
    }
    stats = {"total": 30, "by_verdict": {"malicious": 30}, "per_day": [
        {"date": "2026-09-25", "count": 30, "clean": 0, "suspicious": 0, "malicious": 30}
    ]}
    monkeypatch.setattr(api_client, "health", lambda: health)
    monkeypatch.setattr(api_client, "stats", lambda: stats)

    def list_cases(**filters):
        state["calls"].append(filters)
        size, page = filters["page_size"], filters["page"]
        items = [i for i in state["items"]
                 if filters.get("verdict") in (None, "All", i["verdict"])]
        return {"items": items[(page - 1) * size: page * size], "total": len(items),
                "page": page, "page_size": size}

    def delete_case(case_id):
        state["deleted"].append(case_id)
        state["items"] = [i for i in state["items"] if i["case_id"] != case_id]

    monkeypatch.setattr(api_client, "list_cases", list_cases)
    monkeypatch.setattr(api_client, "delete_case", delete_case)
    return state


def _open(page: str) -> AppTest:
    app = AppTest.from_file(APP, default_timeout=30)
    app.run()
    app.switch_page(f"pages/{page}.py").run()
    return app


def test_history_metrics_table_and_paging(fake_api) -> None:
    app = _open("history")
    assert not app.exception
    assert [m.value for m in app.metric] == ["30", "0%", "0%", "100%"]
    assert len(app.dataframe) == 1 and app.caption[-1].value == "30 matching cases"
    app.number_input(key="f-page").set_value(2).run()
    assert fake_api["calls"][-1]["page"] == 2
    assert len(app.selectbox(key="chosen-case").options) == 5


def test_history_filters_reset_the_page(fake_api) -> None:
    app = _open("history")
    app.number_input(key="f-page").set_value(2).run()
    app.selectbox(key="f-verdict").set_value("clean").run()
    assert fake_api["calls"][-1]["verdict"] == "clean" and fake_api["calls"][-1]["page"] == 1
    assert any("No cases match" in i.value for i in app.info)
    app.selectbox(key="f-verdict").set_value("All").run()
    app.text_input(key="f-query").input("invoice").run()
    assert fake_api["calls"][-1]["q"] == "invoice"


def test_history_delete_needs_confirmation(fake_api) -> None:
    app = _open("history")
    app.button(key="delete-case").click().run()
    assert fake_api["deleted"] == [] and "cannot be undone" in app.warning[0].value
    app.button(key="cancel-delete").click().run()
    assert fake_api["deleted"] == [] and not app.warning
    app.button(key="delete-case").click().run()
    app.button(key="confirm-delete").click().run()
    assert fake_api["deleted"] == ["PL-20260925-00001"]
    assert any("Deleted case PL-20260925-00001" in s.value for s in app.success)


def test_history_open_case(fake_api, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api_client, "case_status", lambda cid: {"status": "running"})
    app = _open("history")
    app.button(key="open-case").click().run()
    assert app.session_state["case_id"] == "PL-20260925-00001"
    assert app.title[0].value == "Case view"


def test_settings_reflect_configuration(fake_api) -> None:
    app = _open("settings")
    assert not app.exception
    text = " ".join(m.value for m in app.markdown) + " ".join(c.value for c in app.caption)
    assert "VirusTotal" in text and "configured" in text
    assert "Set `URLSCAN_API_KEY` to enable it" in text  # missing services get a sign-up hint
    assert "Set `VIRUSTOTAL_API_KEY`" not in text
    assert "Redis reachable" in text and "2 worker(s) running" in text
    assert "Upload files to VirusTotal: no" in text and "version 0.9.0" in text
    assert app.dataframe[0].value.iloc[0]["malicious from"] == 60
    assert "Hidden artifacts" in app.expander[0].markdown[0].value
