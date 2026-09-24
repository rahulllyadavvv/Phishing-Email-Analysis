"""History page: verdict statistics and a searchable, paginated list of past cases."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from ui import api_client, history_data, theme

CASE_PAGE = Path(__file__).parent / "case_view.py"
PAGE_SIZE = 25


def _stats() -> None:
    try:
        stats = api_client.stats()
    except api_client.ApiError as exc:
        st.error(str(exc))
        return
    shares = history_data.shares(stats)
    cols = st.columns(4)
    cols[0].metric("Total cases", stats.get("total", 0))
    for col, verdict in zip(cols[1:], history_data.CHART_VERDICTS, strict=True):
        col.metric(verdict.capitalize(), f"{shares[verdict]:.0f}%")
    per_day = pd.DataFrame(stats.get("per_day") or [])
    if not per_day.empty:
        st.caption("Cases per day, last 30 days")
        verdicts = [v for v in history_data.CHART_VERDICTS if v in per_day]
        st.bar_chart(
            per_day,
            x="date",
            y=verdicts,
            color=[theme.verdict_color(v)[0] for v in verdicts],
            height=220,
        )


def _verdict_style(value: str) -> str:
    fg, bg = theme.verdict_color(value.lower())
    return f"color: {fg}; background-color: {bg}; font-weight: 600"


def _confirm_delete(case_id: str) -> None:
    st.warning(
        f"Delete case {case_id} with its reports and quarantined files? This cannot be undone."
    )
    yes, no = st.columns(2)
    if yes.button("Yes, delete", type="primary", key="confirm-delete"):
        try:
            api_client.delete_case(case_id)
        except api_client.ApiError as exc:
            st.error(str(exc))
        else:
            st.session_state.pop("delete_pending", None)
            st.session_state["deleted"] = case_id
            st.rerun()
    if no.button("Cancel", key="cancel-delete"):
        st.session_state.pop("delete_pending", None)
        st.rerun()


def _first_page() -> None:
    st.session_state["f-page"] = 1


st.title("History")
_stats()
if deleted := st.session_state.pop("deleted", None):
    st.success(f"Deleted case {deleted}.")

left, middle, right = st.columns([1, 1, 2])
verdict = left.selectbox(
    "Verdict", ["All", "malicious", "suspicious", "clean"], key="f-verdict", on_change=_first_page
)
case_type = middle.selectbox(
    "Case type", ["All", "email", "file"], key="f-type", on_change=_first_page
)
dates = right.date_input("Date range", value=(), key="f-dates", on_change=_first_page)
query = st.text_input(
    "Search subject, sender or file name", key="f-query", on_change=_first_page, max_chars=200
)

page = st.session_state.get("f-page", 1)
try:
    result = api_client.list_cases(
        verdict=verdict,
        case_type=case_type,
        q=query.strip(),
        page=page,
        page_size=PAGE_SIZE,
        **history_data.date_params(dates),
    )
except api_client.ApiError as exc:
    st.error(str(exc))
    st.stop()

items = result.get("items") or []
pages = history_data.page_count(result.get("total", 0), PAGE_SIZE)
if not items and page > 1 and result.get("total", 0):
    st.session_state["f-page"] = pages  # the page no longer exists (cases were deleted)
    st.rerun()
if not items:
    st.info("No cases match these filters.")
    st.stop()

table = pd.DataFrame(history_data.table_rows(items))
st.dataframe(
    table.style.map(_verdict_style, subset=["verdict"]),
    width="stretch",
    hide_index=True,
    column_config={
        "open": st.column_config.LinkColumn("open", display_text="Open"),
        "score": st.column_config.NumberColumn("score", format="%d"),
    },
)
st.number_input(f"Page (of {pages})", min_value=1, max_value=pages, step=1, key="f-page")
st.caption(f"{result.get('total', 0)} matching cases")

labels = {
    item["case_id"]: f"{item['case_id']} · {item.get('subject') or item.get('filename') or ''}"
    for item in items
}
chosen = st.selectbox("Case", list(labels), format_func=labels.get, key="chosen-case")
open_col, delete_col, _ = st.columns([1, 1, 4])
if open_col.button("Open case", type="primary", key="open-case"):
    st.session_state["case_id"] = chosen
    st.switch_page(CASE_PAGE, query_params={"id": chosen})
if delete_col.button("Delete case", key="delete-case"):
    st.session_state["delete_pending"] = chosen
if pending := st.session_state.get("delete_pending"):
    _confirm_delete(pending)
