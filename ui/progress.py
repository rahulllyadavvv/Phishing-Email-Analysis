"""Progress display logic for analyses (pure functions, testable without a browser).

The API reports progress per pipeline module (``header``, ``domain``, ..., ``scoring``) plus a
``job`` entry. ``steps(status)`` turns that into the 11 steps people see, each ``pending``,
``running``, ``done``, ``error`` or ``skipped``. ``poll`` refreshes the status of several cases
until all are finished.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

__all__ = ["FINISHED", "ICONS", "STEPS", "poll", "steps"]

# (label, module key in the progress map, or a special rule)
STEPS: list[tuple[str, str]] = [
    ("Parsing", "@parsing"),
    ("Header", "header"),
    ("Sender & domain", "domain"),
    ("Body tone", "tone"),
    ("URLs", "urls"),
    ("Attachments", "attachments"),
    ("Hidden artifacts", "artifacts"),
    ("IOCs", "@after_analysis"),
    ("MITRE mapping", "@after_analysis"),
    ("Scoring", "scoring"),
    ("Report", "@report"),
]
ICONS = {"pending": "○", "running": "◐", "done": "✓", "error": "✗", "skipped": "–"}
FINISHED = frozenset({"done", "error"})
_sleep = time.sleep  # replaced in tests (never patch time.sleep itself)
MODULES = ("header", "domain", "tone", "urls", "attachments", "artifacts")


def steps(status: dict[str, Any]) -> list[tuple[str, str]]:
    """(label, state) for every step, from a ``/api/cases/{id}/status`` answer."""
    progress: dict[str, str] = status.get("progress") or {}
    overall = status.get("status", "queued")
    job = progress.get("job", overall)
    started = any(progress.get(m) in ("running", "done", "error", "skipped") for m in MODULES)
    scoring = progress.get("scoring", "pending")
    rows = []
    for label, key in STEPS:
        if key == "@parsing":
            state = "done" if started or overall == "done" else (
                "running" if job == "running" else "pending"
            )
            if overall == "error" and not started:
                state = "error"
        elif key == "@after_analysis":
            state = "done" if scoring in ("running", "done") or overall == "done" else "pending"
        elif key == "@report":
            if overall == "done":
                state = "done"
            elif overall == "error":
                state = "error"
            else:
                state = "running" if scoring == "done" else "pending"
        else:
            state = progress.get(key, "pending")
            if overall == "done" and state in ("pending", "running"):
                state = "done"
        rows.append((label, state))
    return rows


def poll(
    case_ids: list[str],
    get_status: Callable[[str], dict[str, Any]],
    render: Callable[[str, dict[str, Any]], None],
    sleep: Callable[[float], None] | None = None,
    interval: float = 1.0,
    timeout: float = 1800.0,
) -> dict[str, dict[str, Any]]:
    """Refresh every case's status (calling ``render``) until all are done or failed, or
    ``timeout`` seconds passed. Returns the last status of each case."""
    last: dict[str, dict[str, Any]] = {}
    waited = 0.0
    while True:
        for case_id in case_ids:
            if last.get(case_id, {}).get("status") in FINISHED:
                continue
            last[case_id] = get_status(case_id)
            render(case_id, last[case_id])
        if all(last[c].get("status") in FINISHED for c in case_ids) or waited >= timeout:
            return last
        (sleep or _sleep)(interval)
        waited += interval
