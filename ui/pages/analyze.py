"""Analyze page: submit an email, files or pasted source, then follow the analysis live."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import streamlit as st

from ui import api_client
from ui.progress import ICONS, poll, steps

CASE_PAGE = Path(__file__).parent / "case_view.py"

HOW_TO_GET_THE_FILE = """
**Gmail**: open the message, click the three-dot menu (⋮) next to Reply, choose
**Download message**. You get a `.eml` file.

**Outlook desktop**: open the message and use **File → Save As** (or drag the email from the
list onto your desktop). You get a `.msg` file.

**Outlook on the web**: open the message, click the three-dot menu (…) → **Download** (or
*Save as*). You get a `.eml` file.

**Thunderbird**: right-click the message → **Save As…**. You get a `.eml` file.

Screenshots, PDFs or copied text will **not** work: the analysis needs the full message with
its headers. Forwarding the message to someone usually loses the original headers too, so
download the original instead.
"""


def _render_progress(placeholder: Any, title: str) -> Any:
    def render(case_id: str, status: dict[str, Any]) -> None:
        with placeholder.container(border=True):
            st.markdown(f"**{title}** · `{case_id}`")
            cols = st.columns(4)
            for index, (label, state) in enumerate(steps(status)):
                cols[index % 4].markdown(f"{ICONS[state]} {label}")
            if status.get("status") == "error":
                st.error(status.get("error_message") or "The analysis failed.")
            elif status.get("status") == "done":
                verdict = (status.get("verdict") or "unknown").capitalize()
                st.success(f"Done: {verdict} (score {status.get('score')})")

    return render


def _follow(created: list[dict[str, Any]]) -> None:
    """Show one live progress card per case, then open the case view."""
    cards = {
        c["case_id"]: (st.empty(), c.get("filename") or "Email") for c in created
    }
    renderers = {cid: _render_progress(box, title) for cid, (box, title) in cards.items()}
    final = poll(
        list(cards),
        api_client.case_status,
        lambda cid, status: renderers[cid](cid, status),
    )
    done = [cid for cid, status in final.items() if status.get("status") == "done"]
    if len(created) == 1 and done:
        st.session_state["case_id"] = done[0]
        st.switch_page(CASE_PAGE, query_params={"id": done[0]})
    for case_id in done:
        if st.button(f"Open {case_id}", key=f"open-{case_id}"):
            st.session_state["case_id"] = case_id
            st.switch_page(CASE_PAGE, query_params={"id": case_id})


def _submit(action: Any) -> list[dict[str, Any]] | None:
    try:
        result = action()
    except api_client.ApiError as exc:
        st.error(str(exc))
        return None
    items = result if isinstance(result, list) else [result]
    for item in items:
        if item.get("duplicate"):
            st.info(
                f"{item.get('filename') or 'This email'} was already analyzed: showing case "
                f"{item['case_id']}. Tick *Analyze again* to run a fresh analysis."
            )
    return items


st.title("Analyze")
force = st.toggle("Analyze again even if this input was analyzed before", value=False)
email_tab, file_tab, paste_tab = st.tabs(["Analyze email", "Analyze file", "Paste email source"])

with email_tab:
    upload = st.file_uploader(
        "Drop an email file (.eml or Outlook .msg)", type=["eml", "msg"], key="email_upload"
    )
    with st.expander("How do I get the email file?"):
        st.markdown(HOW_TO_GET_THE_FILE)
    if st.button("Analyze email", type="primary", disabled=upload is None, key="go_email"):
        created = _submit(
            lambda: api_client.analyze_email(upload.name, upload.getvalue(), force=force)
        )
        if created:
            _follow(created)

with file_tab:
    files = st.file_uploader(
        "Drop one or more files of any type", accept_multiple_files=True, key="file_upload"
    )
    st.caption(
        "Only the file is analyzed. Upload the full email for header, sender and content checks."
    )
    if st.button("Analyze files", type="primary", disabled=not files, key="go_files"):
        created = _submit(
            lambda: api_client.analyze_files([(f.name, f.getvalue()) for f in files], force=force)
        )
        if created:
            _follow(created)

with paste_tab:
    source = st.text_area(
        "Paste the complete email source, headers included",
        height=260,
        placeholder="Received: from ...\nFrom: ...\nSubject: ...\n\n...",
        key="raw_source",
    )
    st.caption(
        "Gmail: ⋮ → Show original → Copy to clipboard. Outlook: File → Properties → Internet "
        "headers (headers only; prefer downloading the message)."
    )
    if st.button("Analyze source", type="primary", disabled=not source.strip(), key="go_raw"):
        created = _submit(lambda: api_client.analyze_raw(source, force=force))
        if created:
            _follow(created)
