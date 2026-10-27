"""Tests for the Case view page and its data helpers (the API is replaced by fakes)."""

from __future__ import annotations

from pathlib import Path

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from ui import api_client, case_data

APP = str(Path(__file__).parent.parent / "ui" / "app.py")
CASE = "PL-20260925-AAAAA"
ALL_TABS = ["Overview", "Headers", "Sender & domain", "Body", "URLs", "Attachments",
            "Artifacts", "IOCs", "MITRE ATT&CK", "All findings"]


def _finding(fid: str, module: str, severity: str, score: int) -> dict:
    return {"id": fid, "module": module, "title": fid.replace("_", " "), "severity": severity,
            "score": score, "description": f"about {fid}", "evidence": {"x": 1}, "mitre": []}


def _report(case_type: str = "email") -> dict:
    return {
        "case_id": CASE,
        "case_type": case_type,
        "summary": ["The sender pretends to be PayPal."],
        "recommendations": ["Delete the email."],
        "email": {"received_chain": [{"from_host": "mx[.]example[.]test", "by_host": "mx2",
                                      "ip": "192.0.2[.]1", "timestamp": None}]},
        "verdict": {
            "label": "malicious", "total_score": 88, "confidence": 0.9,
            "module_scores": {"header": 30, "urls": 40, "artifacts": 0},
            "top_findings": [_finding("dmarc_fail", "header", "high", 30)],
        },
        "results": {
            "header": {
                "findings": [_finding("dmarc_fail", "header", "high", 30)],
                "raw": {
                    "auth_summary": [
                        {"mechanism": "spf", "result": "pass", "domain": "evil[.]test",
                         "aligned": False},
                        {"mechanism": "dmarc", "result": "fail", "domain": "paypal[.]com",
                         "aligned": False},
                    ],
                    "arc": {"chain": "none"},
                    "header_verdict": {"verdict": "spoofing", "reason": "unaligned"},
                },
            },
            "artifacts": {"skipped": True, "findings": []},
            "tone": {"findings": [], "raw": {
                "normalized_text": "urgent: verify your account now",
                "highlights": [["urgency", "urgent", 0, 6],
                               ["credential_request", "verify your account", 8, 27]],
            }},
            "urls": {
                "findings": [_finding("url_ip_host", "urls", "medium", 10)],
                "raw": {"urls": [{
                    "url": "hxxp://evil[.]test/login", "defanged": "hxxp://evil[.]test/login",
                    "visible_texts": ["PayPal"], "sources": ["html"], "flags": ["ip_host"],
                    "reputation": [{"service": "virustotal", "status": "malicious"}],
                    "reputation_verdict": "malicious",
                    "screenshot_url": "hxxps://urlscan[.]io/screenshots/abc.png",
                }]},
            },
            "attachments": {"findings": [], "raw": {"attachments": [
                {"filename": "a.zip", "safe_name": "a.zip", "parent": None,
                 "detected_type": "zip", "size": 10, "md5": "m1", "sha256": "s1", "flags": []},
                {"filename": "doc.exe", "safe_name": "doc.exe", "parent": "a.zip",
                 "detected_type": "pe", "size": 5, "md5": "m2", "sha256": "s2",
                 "flags": ["double_extension"],
                 "sandbox": {"status": "skipped", "reason": "not configured"}},
            ]}},
        },
        "iocs": [
            {"type": "url", "value": "hxxp://evil[.]test/login",
             "defanged": "hxxp://evil[.]test/login", "verdict": "malicious",
             "source_module": "urls"},
            {"type": "domain", "value": "evil[.]test", "defanged": "evil[.]test",
             "verdict": None, "source_module": "domain"},
        ],
        "mitre": [
            {"id": "T1566.002", "name": "Spearphishing Link", "tactics": ["initial-access"],
             "url": "hxxps://attack[.]mitre[.]org/techniques/T1566/002/",
             "triggered_by": ["url_ip_host"]},
        ],
    }


# --- helpers ------------------------------------------------------------------------------------


def test_highlight_segments_follow_defanged_text() -> None:
    text = "urgent: verify your account at evil[.]test now"
    segments = case_data.highlight_segments(
        text,
        [["credential_request", "verify your account", 8, 27], ["urgency", "urgent", 0, 6],
         ["fear", "never appears", 40, 50], ["bad"]],
    )
    assert "".join(piece for piece, _ in segments) == text
    assert [(p, c) for p, c in segments if c] == [
        ("urgent", "urgency"), ("verify your account", "credential_request")
    ]
    assert case_data.highlight_segments("", []) == []


def test_screenshot_url_only_for_urlscan() -> None:
    assert case_data.screenshot_url("hxxps://urlscan[.]io/screenshots/a.png") == (
        "https://urlscan.io/screenshots/a.png"
    )
    assert case_data.screenshot_url("hxxps://evil[.]test/urlscan[.]io/") is None
    assert case_data.screenshot_url("hxxps://urlscan[.]io[.]evil[.]test/x.png") is None
    assert case_data.screenshot_url(None) is None


def test_rows_tree_and_scores() -> None:
    report = _report()
    rows = case_data.attachment_rows(report)
    assert rows[1]["sandbox"] == "not configured" and rows[1]["inside"] == "a.zip"
    assert case_data.archive_tree(rows) == ["- a.zip (zip)", "    - doc.exe (pe)"]
    urls = case_data.url_rows(report)
    assert urls[0]["virustotal"] == "malicious"
    assert urls[0]["_screenshot"] == "https://urlscan.io/screenshots/abc.png"
    assert case_data.module_scores(report) == {"header": 30, "urls": 40}
    assert [c["mechanism"] for c in case_data.auth_cards(report)] == ["SPF", "DMARC"]
    assert case_data.received_rows(report)[0]["hop"] == 1


def test_filters_grouping_and_order() -> None:
    report = _report()
    assert [i["type"] for i in case_data.filter_iocs(report["iocs"], ["domain"])] == ["domain"]
    assert [i["verdict"] for i in case_data.filter_iocs(report["iocs"], None, ["unknown"])] == [
        "unknown"
    ]
    assert list(case_data.mitre_by_tactic(report)) == ["initial-access"]
    assert [r["id"] for r in case_data.findings_rows(report)] == ["dmarc_fail", "url_ip_host"]


# --- the page -----------------------------------------------------------------------------------


@pytest.fixture
def fake_api(monkeypatch: pytest.MonkeyPatch):
    st.cache_data.clear()
    state = {"status": {"status": "done", "verdict": "malicious"}, "report": _report(),
             "downloads": []}
    monkeypatch.setattr(api_client, "health", lambda: {"version": "1", "queue": {}})
    monkeypatch.setattr(api_client, "case_status", lambda cid: state["status"])
    monkeypatch.setattr(api_client, "get_case", lambda cid: state["report"])

    def download(cid, fmt):
        state["downloads"].append((cid, fmt))
        return b"data", f"{cid}.{fmt}"

    monkeypatch.setattr(api_client, "download_report", download)
    return state


def _open(case_id: str | None = CASE) -> AppTest:
    app = AppTest.from_file(APP, default_timeout=30)
    if case_id:
        app.session_state["case_id"] = case_id
    app.run()
    app.switch_page("pages/case_view.py").run()
    return app


def test_email_case_shows_all_tabs(fake_api) -> None:
    app = _open()
    assert not app.exception
    assert [t.label for t in app.tabs] == ALL_TABS
    text = " ".join(m.value for m in app.markdown)
    assert "MALICIOUS" in text and "PayPal" in text and "Delete the email." in text
    assert "<mark" in text and "urgency" in text
    assert "https://attack.mitre.org/techniques/T1566/002/" in text
    assert "http://evil" not in text  # malicious values stay defanged
    assert fake_api["downloads"] == []  # reports are fetched only on click


def test_file_case_hides_email_tabs(fake_api) -> None:
    fake_api["report"] = _report("file")
    app = _open()
    assert not app.exception
    labels = [t.label for t in app.tabs]
    assert "Headers" not in labels and "Body" not in labels and "Attachments" in labels
    assert any("standalone file case" in i.value for i in app.info)


def test_running_case_shows_status(fake_api) -> None:
    fake_api["status"] = {"status": "running"}
    app = _open()
    assert not app.exception
    assert any("still running" in w.value for w in app.warning)
    assert not app.tabs


def test_unknown_case_and_no_case(fake_api, monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(cid):
        raise api_client.ApiError("case not found")

    monkeypatch.setattr(api_client, "case_status", missing)
    assert [e.value for e in _open().error] == ["case not found"]
    assert any("enter a case ID" in i.value for i in _open(None).info)
