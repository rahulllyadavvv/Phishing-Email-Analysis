"""History and Settings page helpers (pure functions, testable without a browser)."""

from __future__ import annotations

from datetime import date
from functools import cache
from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "CHART_VERDICTS",
    "date_params",
    "page_count",
    "services",
    "shares",
    "table_rows",
]

CHART_VERDICTS = ("clean", "suspicious", "malicious")
SERVICES_FILE = Path(__file__).parent / "services.yaml"


def shares(stats: dict[str, Any]) -> dict[str, float]:
    """Percentage of all cases per verdict (0 when there are no cases)."""
    total = stats.get("total") or 0
    by_verdict = stats.get("by_verdict") or {}
    return {v: (100.0 * by_verdict.get(v, 0) / total if total else 0.0) for v in CHART_VERDICTS}


def date_params(selected: Any) -> dict[str, str]:
    """``date_from`` / ``date_to`` query values for a ``st.date_input`` range (inclusive)."""
    if not isinstance(selected, list | tuple) or len(selected) != 2:
        return {}
    start, end = selected
    if not isinstance(start, date) or not isinstance(end, date):
        return {}
    return {
        "date_from": f"{start.isoformat()}T00:00:00",
        "date_to": f"{end.isoformat()}T23:59:59.999999",
    }


def page_count(total: int, page_size: int) -> int:
    return max(1, -(-total // page_size))


def table_rows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rows for the history table. ``open`` is a relative link to the case view (the only
    link in the table; subjects and senders arrive defanged from the API)."""
    return [
        {
            "date": (item.get("created_at") or "")[:16].replace("T", " "),
            "type": item.get("case_type"),
            "subject / file": item.get("subject") or item.get("filename") or "(no subject)",
            "sender": item.get("sender") or "",
            "verdict": (item.get("verdict") or item.get("status") or "").upper(),
            "score": item.get("score"),
            "case": item.get("case_id"),
            "open": f"case?id={item.get('case_id')}",
        }
        for item in items
    ]


@cache
def services() -> dict[str, dict[str, str]]:
    return yaml.safe_load(SERVICES_FILE.read_text("utf-8")) or {}
