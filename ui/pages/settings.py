"""Settings page: which services are configured, queue status, thresholds and how it works."""

from __future__ import annotations

import streamlit as st

from ui import api_client, history_data, theme

HOW_IT_WORKS = """
1. **Parsing.** The `.eml` / `.msg` file is read into headers, addresses, text, HTML, links and
   attachments. Nothing is opened or rendered.
2. **Header authentication.** SPF, DKIM, DMARC and ARC are checked, together with whether they
   line up with the visible From address, and the Received chain is examined.
3. **Sender and domain.** From, Reply-To and Return-Path are compared; lookalike domains,
   brand impersonation, very new domains and missing mail servers are detected.
4. **Body tone.** The text is scored for urgency, fear, rewards, authority and requests for
   passwords or payments.
5. **URLs.** Every link is checked statically (IP hosts, shorteners, mismatched text) and by
   reputation services. Pages are never fetched from this machine.
6. **Attachments.** Files are identified by their bytes, archives are unpacked in memory,
   documents are inspected for macros and scripts, and hashes are looked up.
7. **Hidden artifacts.** Hidden text, tracking pixels, invisible characters and other tricks
   in the HTML are reported.

Afterwards the indicators (IOCs) are collected and defanged, the findings are mapped to
MITRE ATT&CK, and the score decides Clean, Suspicious or Malicious.
"""


st.title("Settings")
st.caption(
    "Read-only. Settings come from the backend's environment or `.env` file; restart "
    "the API after changing them."
)
try:
    health = api_client.health()
except api_client.ApiError as exc:
    st.error(str(exc))
    st.stop()

st.subheader("Threat-intel services")
configured = health.get("services") or {}
for key, info in history_data.services().items():
    enabled = bool(configured.get(key))
    with st.container(border=True):
        name, status = st.columns([3, 1])
        name.markdown(f"**{info['name']}**: {info['purpose']}")
        with status:
            theme.status_dot(enabled, "configured" if enabled else "not configured")
        if not enabled:
            st.caption(f"Set `{info['setting']}` to enable it. [Get access]({info['signup']})")

st.subheader("Job queue")
queue = health.get("queue") or {}
if queue.get("queue") == "rq":
    theme.status_dot(
        queue.get("redis"), "Redis reachable" if queue.get("redis") else "Redis unreachable"
    )
    workers = queue.get("workers") or 0
    theme.status_dot(workers > 0, f"{workers} worker(s) running")
else:
    theme.status_dot(True, "Built-in queue (analyses run inside the API process)")

st.subheader("Thresholds")
config = health.get("config") or {}
rows = [
    {
        "case type": case_type,
        "suspicious from": t.get("suspicious"),
        "malicious from": t.get("malicious"),
    }
    for case_type, t in (config.get("thresholds") or {}).items()
]
st.dataframe(rows, width="stretch", hide_index=True)
st.markdown(
    f"- Scorer: `{config.get('scorer', '?')}`\n"
    f"- VirusTotal engines needed for *malicious*: {config.get('vt_malicious_threshold', '?')}\n"
    f"- ML tone threshold: {config.get('ml_phishing_threshold', '?')}\n"
    f"- Upload files to VirusTotal: {'yes' if config.get('upload_files_to_vt') else 'no'}\n"
    f"- Upload files to Hybrid Analysis: "
    f"{'yes' if config.get('upload_files_to_hybrid_analysis') else 'no'}\n"
    f"- Claude tone check: {'on' if config.get('llm_tone_enabled') else 'off'}"
)
st.caption(
    f"API authentication: {health.get('auth', '?')} · report formats: "
    f"{', '.join(health.get('formats') or [])}"
)

st.subheader("About")
st.write(f"PhishLens version {health.get('version', '?')} · API {api_client.api_url()}")
with st.expander("How PhishLens works", expanded=True):
    st.markdown(HOW_IT_WORKS)
