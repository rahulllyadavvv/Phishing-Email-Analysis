"""PhishLens web UI (Streamlit). Run with ``streamlit run ui/app.py``.

The UI talks only to the FastAPI backend (``ui.api_client``); it never analyzes anything
itself and never renders email HTML or attachment content.
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from ui import api_client, theme

HERE = Path(__file__).parent

st.set_page_config(page_title="PhishLens", page_icon=":mag:", layout="wide")


@st.cache_data(ttl=10, show_spinner=False)
def _health() -> tuple[bool, str, dict]:
    try:
        info = api_client.health()
    except api_client.ApiError as exc:
        return False, str(exc), {}
    return True, f"Backend online (v{info.get('version', '?')})", info


def sidebar() -> None:
    with st.sidebar:
        st.markdown("## Phish**Lens**")
        st.caption("Automated phishing email analysis")
        ok, text, info = _health()
        theme.status_dot(ok, text)
        if ok and info.get("queue", {}).get("redis") is False:
            theme.status_dot(None, "Job queue unavailable (Redis)")
        st.caption(f"API: {api_client.api_url()}")


pages = [
    st.Page(HERE / "pages" / "analyze.py", title="Analyze", icon=":material/upload_file:",
            default=True),
    st.Page(HERE / "pages" / "case_view.py", title="Case view", icon=":material/find_in_page:",
            url_path="case"),
    st.Page(HERE / "pages" / "history.py", title="History", icon=":material/history:"),
    st.Page(HERE / "pages" / "settings.py", title="Settings", icon=":material/settings:"),
]
navigation = st.navigation(pages)
sidebar()
navigation.run()
