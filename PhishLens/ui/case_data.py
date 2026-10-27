"""Turn a case report (the API's defanged AnalysisReport JSON) into what the Case view shows.

Pure functions, no Streamlit, so they are easy to test. Values are already defanged by the
API; the only thing ever turned back into a live URL is a urlscan.io screenshot, which the
browser loads directly from urlscan (CLAUDE.md allows screenshot links).
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "CATEGORY_COLORS",
    "EMAIL_ONLY_TABS",
    "SEVERITY_ORDER",
    "archive_tree",
    "attachment_rows",
    "auth_cards",
    "filter_iocs",
    "findings_rows",
    "highlight_segments",
    "mitre_by_tactic",
    "module_scores",
    "raw",
    "received_rows",
    "screenshot_url",
    "url_rows",
]

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
EMAIL_ONLY_TABS = ("Headers", "Sender & domain", "Body", "Artifacts")
CATEGORY_COLORS = {
    "urgency": "#fde2c4",
    "fear": "#f9d0cc",
    "greed": "#d6ecc9",
    "authority": "#dcdff7",
    "credential_request": "#f7c6d9",
    "payment_request": "#f5e3a3",
    "secrecy": "#e3d2f0",
    "generic_greeting": "#e2e6ec",
}
SCREENSHOT_HOSTS = ("hxxps://urlscan[.]io/", "https://urlscan.io/")


def raw(report: dict[str, Any], module: str) -> dict[str, Any]:
    return ((report.get("results") or {}).get(module) or {}).get("raw") or {}


def module_scores(report: dict[str, Any]) -> dict[str, int]:
    """Points per analyzer that actually ran (skipped ones left out)."""
    verdict = report.get("verdict") or {}
    results = report.get("results") or {}
    return {
        name: score
        for name, score in (verdict.get("module_scores") or {}).items()
        if not (results.get(name) or {}).get("skipped")
    }


def auth_cards(report: dict[str, Any]) -> list[dict[str, Any]]:
    """One card per mechanism row of the header analyzer's auth summary."""
    return [
        {
            "mechanism": (row.get("mechanism") or "").upper(),
            "result": row.get("result") or "none",
            "domain": row.get("domain") or "-",
            "aligned": bool(row.get("aligned")),
        }
        for row in raw(report, "header").get("auth_summary") or []
    ]


def received_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    chain = (report.get("email") or {}).get("received_chain") or []
    return [
        {
            "hop": i,
            "from": hop.get("from_host"),
            "by": hop.get("by_host"),
            "ip": hop.get("ip"),
            "time": hop.get("timestamp"),
        }
        for i, hop in enumerate(chain, start=1)
    ]


def highlight_segments(text: str, highlights: list[Any]) -> list[tuple[str, str | None]]:
    """Split ``text`` into (piece, category or None) for colouring.

    The API defangs the text *and* the phrases, so the original character offsets no longer
    fit; each phrase is found again in order instead. Phrases that cannot be found are skipped.
    """
    ordered = sorted(
        (h for h in highlights if isinstance(h, list | tuple) and len(h) >= 4),
        key=lambda h: h[2],
    )
    segments: list[tuple[str, str | None]] = []
    cursor = 0
    lowered = text.lower()
    for category, phrase, *_ in ordered:
        phrase = str(phrase)
        index = lowered.find(phrase.lower(), cursor)
        if index < 0:
            # Line breaks may have been collapsed in the phrase; try the words one by one.
            first = phrase.split()[0].lower() if phrase.split() else ""
            index = lowered.find(first, cursor) if first else -1
            if index < 0:
                continue
            phrase = text[index : index + len(first)]
        if index > cursor:
            segments.append((text[cursor:index], None))
        segments.append((text[index : index + len(phrase)], str(category)))
        cursor = index + len(phrase)
    if cursor < len(text):
        segments.append((text[cursor:], None))
    return segments


def screenshot_url(value: str | None) -> str | None:
    """A urlscan.io screenshot link as a real https URL; anything else stays unusable."""
    if not value or not value.startswith(SCREENSHOT_HOSTS):
        return None
    live = value.replace("hxxps://", "https://").replace("[.]", ".")
    return live if live.startswith("https://urlscan.io/") else None


def url_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in raw(report, "urls").get("urls") or []:
        services = {r.get("service"): r.get("status") for r in row.get("reputation") or []}
        rows.append(
            {
                "url": row.get("defanged") or row.get("url"),
                "visible text": ", ".join(row.get("visible_texts") or []),
                "source": ", ".join(row.get("sources") or []),
                "verdict": row.get("reputation_verdict") or "not checked",
                **{f"{k}": v for k, v in services.items() if k},
                "final url": row.get("final_url"),
                "flags": ", ".join(row.get("flags") or []),
                "_screenshot": screenshot_url(row.get("screenshot_url")),
            }
        )
    return rows


def attachment_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in raw(report, "attachments").get("attachments") or []:
        sandbox = row.get("sandbox") or {}
        rows.append(
            {
                "file": row.get("safe_name") or row.get("filename"),
                "inside": row.get("parent") or "",
                "type": row.get("detected_type"),
                "size": row.get("size"),
                "reputation": row.get("reputation_verdict") or "not checked",
                "static findings": ", ".join(row.get("flags") or []),
                "sandbox": (
                    f"{sandbox.get('sandbox')}: {sandbox.get('verdict')}"
                    if sandbox.get("status") == "done"
                    else sandbox.get("reason") or sandbox.get("status") or ""
                ),
                "md5": row.get("md5"),
                "sha256": row.get("sha256"),
                "inline": bool(row.get("inline")),
                "_name": row.get("filename") or row.get("safe_name"),
            }
        )
    return rows


def archive_tree(rows: list[dict[str, Any]]) -> list[str]:
    """Indented lines showing which file came out of which archive."""
    children: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        children.setdefault(row["inside"] or "", []).append(row)
    lines: list[str] = []
    seen: set[int] = set()

    def walk(parent: str, depth: int) -> None:
        for row in children.get(parent, []):
            if id(row) in seen:
                continue
            seen.add(id(row))
            lines.append(f"{'    ' * depth}- {row['file']} ({row['type'] or 'unknown'})")
            walk(row.get("_name") or row["file"], depth + 1)

    walk("", 0)
    return lines


def filter_iocs(
    iocs: list[dict[str, Any]], types: list[str] | None = None, verdicts: list[str] | None = None
) -> list[dict[str, Any]]:
    return [
        {
            "type": i.get("type"),
            "value": i.get("defanged") or i.get("value"),
            "verdict": i.get("verdict") or "unknown",
            "source": i.get("source_module"),
            "context": i.get("context"),
        }
        for i in iocs
        if (not types or i.get("type") in types)
        and (not verdicts or (i.get("verdict") or "unknown") in verdicts)
    ]


def mitre_by_tactic(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for technique in report.get("mitre") or []:
        for tactic in technique.get("tactics") or ["other"]:
            grouped.setdefault(tactic, []).append(technique)
    return dict(sorted(grouped.items()))


def findings_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for module, result in (report.get("results") or {}).items():
        for finding in (result or {}).get("findings") or []:
            rows.append(
                {
                    "severity": finding.get("severity"),
                    "points": finding.get("score", 0),
                    "finding": finding.get("title"),
                    "module": module,
                    "id": finding.get("id"),
                    "mitre": ", ".join(finding.get("mitre") or []),
                    "_description": finding.get("description"),
                    "_evidence": finding.get("evidence") or {},
                }
            )
    return sorted(
        rows,
        key=lambda r: (
            SEVERITY_ORDER.index(r["severity"]) if r["severity"] in SEVERITY_ORDER else 9,
            -(r["points"] or 0),
        ),
    )
