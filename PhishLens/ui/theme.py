"""Shared look for the UI: verdict and severity colors (defined only here) and small
components.

Everything shown comes from the API and is already defanged. HTML is only used for these
components, built from escaped values; email or attachment content is never rendered.
"""

from __future__ import annotations

import html

import streamlit as st

__all__ = [
    "SEVERITY_COLORS",
    "VERDICT_COLORS",
    "defanged_code",
    "score_gauge",
    "severity_pill",
    "status_dot",
    "verdict_badge",
    "verdict_color",
]

# label -> (text color, background)
VERDICT_COLORS = {
    "clean": ("#1d7a46", "#e3f4ea"),
    "suspicious": ("#9a5b00", "#fdf0d8"),
    "malicious": ("#b3261e", "#fbe3e1"),
    "unknown": ("#5d6778", "#f4f6f9"),
}
SEVERITY_COLORS = {
    "critical": "#b3261e",
    "high": "#c2410c",
    "medium": "#9a5b00",
    "low": "#5d6778",
    "info": "#8a93a3",
}


def verdict_color(label: str | None) -> tuple[str, str]:
    return VERDICT_COLORS.get((label or "unknown").lower(), VERDICT_COLORS["unknown"])


def _html(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def verdict_badge(label: str | None, large: bool = True) -> None:
    fg, bg = verdict_color(label)
    size = "26px" if large else "13px"
    pad = "10px 22px" if large else "2px 10px"
    text = html.escape((label or "unknown").upper())
    _html(
        f'<span style="display:inline-block;padding:{pad};border-radius:10px;'
        f"background:{bg};color:{fg};border:1px solid {fg};font-weight:700;"
        f'font-size:{size};letter-spacing:1px">{text}</span>'
    )


def score_gauge(score: int | float | None, label: str | None = None) -> None:
    """A horizontal 0-100 bar in the verdict's color."""
    value = max(0, min(100, int(score or 0)))
    fg, bg = verdict_color(label)
    _html(
        f'<div style="font-size:13px;color:#5d6778">Score {value}/100</div>'
        f'<div style="background:{bg};border-radius:6px;height:14px;width:100%">'
        f'<div style="background:{fg};width:{value}%;height:14px;border-radius:6px"></div></div>'
    )


def severity_pill(severity: str | None) -> str:
    """HTML for a small severity label (use inside st.markdown(..., unsafe_allow_html=True))."""
    color = SEVERITY_COLORS.get((severity or "info").lower(), SEVERITY_COLORS["info"])
    text = html.escape((severity or "info").upper())
    return (
        f'<span style="display:inline-block;padding:0 8px;border-radius:8px;'
        f'border:1px solid {color};color:{color};font-size:11px;font-weight:600">{text}</span>'
    )


def status_dot(ok: bool | None, text: str) -> None:
    color = {True: "#1d7a46", False: "#b3261e", None: "#9a5b00"}[ok]
    _html(
        f'<span style="color:{color};font-size:16px">&#9679;</span> '
        f'<span style="font-size:13px">{html.escape(text)}</span>'
    )


def defanged_code(value: str) -> None:
    """A defanged indicator in monospace, with Streamlit's copy button."""
    st.code(value, language=None)
