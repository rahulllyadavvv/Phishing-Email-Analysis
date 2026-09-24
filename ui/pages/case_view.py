"""Case view: the verdict, summary, downloads and one tab per analysis area."""

from __future__ import annotations

import html
from typing import Any

import streamlit as st

from ui import api_client, case_data, theme

FORMATS = [
    ("HTML", "html", "html"),
    ("PDF", "pdf", "pdf"),
    ("JSON", "json", "json"),
    ("IOC CSV", "csv", "csv"),
    ("STIX", "stix", "stix.json"),
    ("ZIP", "zip", "zip"),
]
TABS = [
    "Overview",
    "Headers",
    "Sender & domain",
    "Body",
    "URLs",
    "Attachments",
    "Artifacts",
    "IOCs",
    "MITRE ATT&CK",
    "All findings",
]


def _case_id() -> str | None:
    case_id = st.query_params.get("id") or st.session_state.get("case_id")
    typed = st.text_input("Case ID", value=case_id or "", placeholder="PL-20260925-XXXXX")
    return typed.strip() or None


def _downloader(case_id: str, fmt: str):
    def fetch() -> bytes:
        data, _ = api_client.download_report(case_id, fmt)
        return data

    return fetch


def _header(report: dict[str, Any]) -> None:
    verdict = report.get("verdict") or {}
    label = verdict.get("label")
    left, right = st.columns([1, 2])
    with left:
        theme.verdict_badge(label)
        theme.score_gauge(verdict.get("total_score"), label)
        st.caption(
            f"Confidence {round((verdict.get('confidence') or 0) * 100)}% · "
            f"{report.get('case_type', 'email')} case · {report.get('case_id')}"
        )
    with right:
        for sentence in report.get("summary") or []:
            st.markdown(f"- {html.escape(sentence)}")
    cols = st.columns(len(FORMATS))
    case_id, name = report["case_id"], label or "unscored"
    for col, (title, fmt, ext) in zip(cols, FORMATS, strict=True):
        col.download_button(
            title,
            data=_downloader(case_id, fmt),
            file_name=f"{case_id}_{name}.{ext}",
            key=f"dl-{fmt}",
            use_container_width=True,
        )


def _overview(report: dict[str, Any]) -> None:
    st.subheader("Top findings")
    for finding in (report.get("verdict") or {}).get("top_findings") or []:
        st.markdown(
            f"{theme.severity_pill(finding.get('severity'))} **{html.escape(finding['title'])}**"
            f" · {finding.get('score', 0)} points",
            unsafe_allow_html=True,
        )
    scores = case_data.module_scores(report)
    if scores:
        st.subheader("Points per analysis")
        st.bar_chart(scores, horizontal=True)
    actions = report.get("recommendations") or []
    st.subheader("Recommended actions")
    for action in actions or ["No action needed."]:
        st.markdown(f"- {html.escape(action)}")


def _headers(report: dict[str, Any]) -> None:
    cards = case_data.auth_cards(report)
    if cards:
        for col, card in zip(st.columns(len(cards)), cards, strict=True):
            with col.container(border=True):
                st.markdown(f"**{card['mechanism']}**")
                st.write(card["result"])
                st.caption(f"domain: {card['domain']}")
                st.caption("aligned with From" if card["aligned"] else "not aligned with From")
    else:
        st.info("Authentication could not be evaluated.")
    header = case_data.raw(report, "header")
    arc = header.get("arc") or {}
    verdict = header.get("header_verdict") or {}
    st.write(
        f"**ARC:** {arc.get('chain') or 'none'}"
        + (f", sealed by {arc.get('sealer')}" if arc.get("sealer") else "")
    )
    st.write(
        f"**Header verdict:** {verdict.get('verdict', 'unknown')} — {verdict.get('reason', '')}"
    )
    st.subheader("Received chain (oldest first)")
    st.dataframe(case_data.received_rows(report), use_container_width=True, hide_index=True)


def _sender(report: dict[str, Any]) -> None:
    domain = case_data.raw(report, "domain")
    st.subheader("Addresses")
    st.dataframe(domain.get("domain_table") or [], use_container_width=True, hide_index=True)
    lookalikes = [m for matches in (domain.get("lookalikes") or {}).values() for m in matches]
    st.subheader("Lookalike domains")
    if lookalikes:
        st.dataframe(lookalikes, use_container_width=True, hide_index=True)
    else:
        st.caption("No findings")
    st.subheader("Domain age")
    ages = [{"domain": k, **v} for k, v in (domain.get("domain_age") or {}).items()]
    st.dataframe(ages or [], use_container_width=True, hide_index=True)
    identity = domain.get("identity") or {}
    with st.container(border=True):
        st.markdown("**Identity binding**")
        claims = identity.get("claimed_brands") or {}
        st.write(
            "Claimed brands: "
            + (", ".join(f"{b} ({', '.join(w)})" for b, w in claims.items()) or "none")
        )
        authenticated = identity.get("authenticated")
        st.write(
            f"Sender domain: {identity.get('sender_domain') or '-'} — "
            + {True: "authenticated", False: "NOT authenticated"}.get(
                authenticated, "authentication unknown"
            )
        )


def _body(report: dict[str, Any]) -> None:
    tone = case_data.raw(report, "tone")
    text = tone.get("normalized_text") or ""
    if not text:
        st.caption("No text to show.")
        return
    legend = " ".join(
        f'<span style="background:{color};padding:0 6px;border-radius:4px">'
        f"{html.escape(name.replace('_', ' '))}</span>"
        for name, color in case_data.CATEGORY_COLORS.items()
    )
    st.markdown(legend, unsafe_allow_html=True)
    pieces = []
    for piece, category in case_data.highlight_segments(text, tone.get("highlights") or []):
        escaped = html.escape(piece).replace("\n", "<br>")
        if category:
            color = case_data.CATEGORY_COLORS.get(category, "#eee")
            pieces.append(
                f'<mark style="background:{color}" title="{html.escape(category)}">{escaped}</mark>'
            )
        else:
            pieces.append(escaped)
    st.markdown(
        '<div style="font-family:ui-monospace,monospace;font-size:13px;white-space:normal">'
        + "".join(pieces)
        + "</div>",
        unsafe_allow_html=True,
    )
    st.caption("Sanitized text (lowercased, defanged); the original email is never rendered.")


def _urls(report: dict[str, Any]) -> None:
    rows = case_data.url_rows(report)
    if not rows:
        st.caption("No URLs.")
        return
    st.dataframe(
        [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows],
        use_container_width=True,
        hide_index=True,
    )
    shots = [r for r in rows if r["_screenshot"]]
    if shots:
        st.subheader("urlscan.io screenshots")
        for col, row in zip(st.columns(min(3, len(shots))), shots, strict=False):
            col.image(row["_screenshot"], caption=row["url"])


def _attachments(report: dict[str, Any]) -> None:
    rows = case_data.attachment_rows(report)
    if not rows:
        st.caption("No attachments.")
        return
    st.dataframe(
        [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows],
        use_container_width=True,
        hide_index=True,
    )
    tree = case_data.archive_tree(rows)
    if any(line.startswith(" ") for line in tree):
        st.subheader("Archive contents")
        st.code("\n".join(tree), language=None)
    st.subheader("Hashes")
    for row in rows:
        st.caption(row["file"])
        theme.defanged_code(f"SHA-256 {row['sha256']}\nMD5     {row['md5']}")


def _findings_list(report: dict[str, Any], module: str) -> None:
    rows = [r for r in case_data.findings_rows(report) if r["module"] == module]
    if not rows:
        st.caption("No findings")
    for row in rows:
        st.markdown(
            f"{theme.severity_pill(row['severity'])} **{html.escape(row['finding'])}**",
            unsafe_allow_html=True,
        )
        st.caption(row["_description"])


def _iocs(report: dict[str, Any]) -> None:
    iocs = report.get("iocs") or []
    if not iocs:
        st.caption("No findings")
        return
    types = sorted({i.get("type") for i in iocs})
    verdicts = sorted({i.get("verdict") or "unknown" for i in iocs})
    left, right = st.columns(2)
    chosen_types = left.multiselect("Type", types, key="ioc-types")
    chosen_verdicts = right.multiselect("Verdict", verdicts, key="ioc-verdicts")
    rows = case_data.filter_iocs(iocs, chosen_types, chosen_verdicts)
    st.dataframe(rows, use_container_width=True, hide_index=True)
    st.caption("Defanged values, one per line (use the copy button):")
    theme.defanged_code("\n".join(r["value"] for r in rows) or "-")


def _mitre(report: dict[str, Any]) -> None:
    grouped = case_data.mitre_by_tactic(report)
    if not grouped:
        st.caption("No techniques mapped.")
        return
    for tactic, techniques in grouped.items():
        st.subheader(tactic.replace("-", " ").title())
        for col, technique in zip(st.columns(min(3, len(techniques))), techniques, strict=False):
            with col.container(border=True):
                url = (
                    (technique.get("url") or "").replace("hxxps://", "https://").replace("[.]", ".")
                )
                if url.startswith("https://attack.mitre.org/"):
                    st.markdown(f"[{technique['id']}]({url})")
                else:
                    st.markdown(f"**{technique['id']}**")
                st.write(technique.get("name"))
                st.caption("Triggered by: " + ", ".join(technique.get("triggered_by") or []))


def _all_findings(report: dict[str, Any]) -> None:
    rows = case_data.findings_rows(report)
    if not rows:
        st.caption("No findings")
        return
    st.dataframe(
        [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows],
        use_container_width=True,
        hide_index=True,
    )
    for row in rows:
        with st.expander(f"{row['severity'].upper()} · {row['finding']}"):
            st.write(row["_description"])
            st.json(row["_evidence"], expanded=False)


def show(report: dict[str, Any]) -> None:
    _header(report)
    is_file = report.get("case_type") == "file"
    names = [t for t in TABS if not (is_file and t in case_data.EMAIL_ONLY_TABS)]
    if is_file:
        st.info(
            "This is a standalone file case: header, sender, body and hidden-artifact checks "
            "only apply to emails, so those tabs are hidden."
        )
    renderers = {
        "Overview": _overview,
        "Headers": _headers,
        "Sender & domain": _sender,
        "Body": _body,
        "URLs": _urls,
        "Attachments": _attachments,
        "Artifacts": lambda r: _findings_list(r, "artifacts"),
        "IOCs": _iocs,
        "MITRE ATT&CK": _mitre,
        "All findings": _all_findings,
    }
    for tab, name in zip(st.tabs(names), names, strict=True):
        with tab:
            renderers[name](report)


st.title("Case view")
case_id = _case_id()
if not case_id:
    st.info("Analyze something first, or enter a case ID.")
    st.stop()
try:
    status = api_client.case_status(case_id)
except api_client.ApiError as exc:
    st.error(str(exc))
    st.stop()
if status.get("status") in ("queued", "running"):
    st.warning(f"Case {case_id} is still {status['status']}.")
    st.button("Refresh")
    st.stop()
if status.get("status") == "error" and not status.get("verdict"):
    st.error(status.get("error_message") or "The analysis failed.")
    st.stop()
try:
    report = api_client.get_case(case_id)
except api_client.ApiError as exc:
    st.error(str(exc))
    st.stop()
if status.get("status") == "error":
    st.warning(f"The analysis finished with an error: {status.get('error_message')}")
show(report)
