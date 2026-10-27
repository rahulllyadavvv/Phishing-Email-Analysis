"""Report view model: everything the HTML template shows, gathered from an AnalysisReport.

The template never digs into analyzer internals; this module does, and returns plain dicts and
lists. Values that must not be defanged are wrapped in ``Plain``; links in ``Link`` (only
allowed hosts become clickable). Everything else is defanged at render time.
"""

from __future__ import annotations

import json
from typing import Any

from phishlens.models import AnalysisReport, AnalyzerResult, CaseType, Finding
from phishlens.parser.received import originating_external_ip
from phishlens.reporting.safe import Link, Plain

__all__ = ["SEVERITY_ORDER", "build_view"]

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
MODULE_TITLES = {
    "header": "Header authentication",
    "domain": "Sender and domain",
    "tone": "Body analysis",
    "urls": "URLs",
    "attachments": "Attachments",
    "artifacts": "Hidden artifacts",
    "nested": "Forwarded emails",
}


def _result(report: AnalysisReport, name: str) -> AnalyzerResult:
    return report.results.get(name) or AnalyzerResult(module=name, skipped=True)


def _evidence_text(evidence: dict[str, Any]) -> str:
    if not evidence:
        return ""
    text = json.dumps(evidence, indent=1, ensure_ascii=False, default=str)
    return text if len(text) <= 4000 else text[:4000] + "\n..."


def _finding_row(finding: Finding) -> dict[str, Any]:
    return {
        "id": Plain(finding.id),
        "module": Plain(finding.module),
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "score": finding.score,
        "evidence": _evidence_text(finding.evidence),
        "mitre": [Link(_mitre_url(t), t) for t in finding.mitre],
    }


def _mitre_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/")


def _email_overview(report: AnalysisReport) -> dict[str, Any] | None:
    email = report.email
    if email is None:
        return None
    header = _result(report, "header")
    origin = (header.raw.get("spf") or {}).get("ip") or originating_external_ip(
        email.received_chain
    )

    def addresses(items: list) -> list[str]:
        return [f"{a.display_name} <{a.address}>" if a.display_name else a.address for a in items]

    return {
        "from": addresses(email.from_addrs),
        "to": addresses(email.to),
        "cc": addresses(email.cc),
        "subject": email.subject,
        "date": email.date.isoformat() if email.date else None,
        "message_id": email.message_id,
        "return_path": email.return_path.address if email.return_path else None,
        "reply_to": addresses(email.reply_to),
        "originating_ip": origin,
        "attachments": len(email.attachments),
        "urls": len(email.urls),
        "nested": len(email.nested_emails),
    }


def _file_overview(report: AnalysisReport) -> dict[str, Any] | None:
    info = report.file_info
    if info is None:
        return None
    return {
        "filename": Plain(info.filename),
        "size": info.size,
        "detected_type": Plain(info.detected_type or "unknown"),
        "md5": Plain(info.md5),
        "sha1": Plain(info.sha1),
        "sha256": Plain(info.sha256),
    }


def _auth(report: AnalysisReport) -> dict[str, Any]:
    raw = _result(report, "header").raw
    dmarc = raw.get("dmarc") or {}
    arc = raw.get("arc") or {}
    return {
        "summary": raw.get("auth_summary") or [],
        "dmarc_policy": dmarc.get("policy"),
        "dmarc_record_domain": dmarc.get("record_domain"),
        "arc": {
            "chain": arc.get("chain"),
            "sealer": arc.get("sealer"),
            "trusted": arc.get("trusted"),
        },
        "verdict": {
            "verdict": (raw.get("header_verdict") or {}).get("verdict"),
            "reason": (raw.get("header_verdict") or {}).get("reason"),
        },
        "spf": raw.get("spf") or {},
    }


def _received(report: AnalysisReport) -> list[dict[str, Any]]:
    if report.email is None:
        return []
    return [
        {
            "hop": index,
            "from_host": hop.from_host,
            "by_host": hop.by_host,
            "ip": hop.ip,
            "timestamp": hop.timestamp.isoformat() if hop.timestamp else None,
        }
        for index, hop in enumerate(report.email.received_chain, start=1)
    ]


def _domain(report: AnalysisReport) -> dict[str, Any]:
    raw = _result(report, "domain").raw
    identity = raw.get("identity") or {}
    ages = [
        {
            "domain": domain,
            "status": info.get("status"),
            "registered": info.get("registered"),
            "age_days": info.get("age_days"),
            "registrar": info.get("registrar"),
        }
        for domain, info in (raw.get("domain_age") or {}).items()
    ]
    lookalikes = [
        {
            "domain": domain,
            "brand": m.get("brand"),
            "legitimate": m.get("legitimate_domain"),
            "kind": m.get("kind"),
        }
        for domain, matches in (raw.get("lookalikes") or {}).items()
        for m in matches
    ]
    return {
        "table": raw.get("domain_table") or [],
        "lookalikes": lookalikes,
        "ages": ages,
        "identity": {
            "sender_domain": identity.get("sender_domain"),
            "authenticated": identity.get("authenticated"),
            "claims": [
                {"brand": brand, "where": ", ".join(sources)}
                for brand, sources in (identity.get("claimed_brands") or {}).items()
            ],
        },
    }


def _tone(report: AnalysisReport) -> list[dict[str, Any]]:
    tone = _result(report, "tone")
    rows = []
    for finding in tone.findings:
        matches = finding.evidence.get("matches")
        if not isinstance(matches, list):
            continue
        rows.append(
            {
                "title": finding.title,
                "severity": finding.severity.value,
                "snippets": [m.get("snippet") or m.get("phrase") for m in matches][:5],
            }
        )
    return rows


def _urls(report: AnalysisReport) -> list[dict[str, Any]]:
    rows = []
    for row in _result(report, "urls").raw.get("urls") or []:
        screenshot = row.get("screenshot_url")
        rows.append(
            {
                "url": row.get("defanged") or row.get("url"),
                "visible": ", ".join(row.get("visible_texts") or []),
                "sources": ", ".join(row.get("sources") or []),
                "verdict": row.get("reputation_verdict") or "not checked",
                "services": [
                    f"{r['service']}: {r['status']}" for r in row.get("reputation") or []
                ],
                "final_url": row.get("final_url"),
                "screenshot": Link(screenshot, "screenshot") if screenshot else None,
                "flags": ", ".join(row.get("flags") or []),
            }
        )
    return rows


def _attachments(report: AnalysisReport) -> list[dict[str, Any]]:
    rows = []
    for row in _result(report, "attachments").raw.get("attachments") or []:
        sandbox = row.get("sandbox") or {}
        if sandbox.get("status") == "done":
            sandbox_text = f"{sandbox.get('sandbox')}: {sandbox.get('verdict')}"
        elif sandbox:
            sandbox_text = sandbox.get("reason") or sandbox.get("status") or ""
        else:
            sandbox_text = ""
        rows.append(
            {
                "name": Plain(row.get("safe_name") or row.get("filename") or ""),
                "parent": Plain(row.get("parent") or ""),
                "type": Plain(row.get("detected_type") or ""),
                "size": row.get("size"),
                "md5": Plain(row.get("md5") or ""),
                "sha256": Plain(row.get("sha256") or ""),
                "verdict": row.get("reputation_verdict") or "not checked",
                "flags": Plain(", ".join(row.get("flags") or [])),
                "sandbox": sandbox_text,
                "inline": bool(row.get("inline")),
            }
        )
    return rows


def _module_findings(report: AnalysisReport, name: str) -> list[dict[str, Any]]:
    return [_finding_row(f) for f in _result(report, name).findings]


def build_view(
    report: AnalysisReport,
    summary: list[str] | None = None,
    recommendations: list[str] | None = None,
) -> dict[str, Any]:
    verdict = report.verdict
    is_file = report.case_type == CaseType.FILE
    findings = sorted(
        (f for r in report.results.values() for f in r.findings),
        key=lambda f: (SEVERITY_ORDER.index(f.severity.value), -f.score, f.id),
    )
    module_scores = []
    if verdict is not None:
        module_scores = [
            {"module": MODULE_TITLES.get(name, name), "score": score}
            for name, score in verdict.module_scores.items()
            if not _result(report, name).skipped  # analyzers that did not run are left out
        ]
    return {
        "case": {
            "id": Plain(report.case_id),
            "type": report.case_type.value,
            "created": report.created_at.strftime("%Y-%m-%d %H:%M UTC"),
            "label": verdict.label.value if verdict else "unknown",
            "score": verdict.total_score if verdict else 0,
            "confidence": round((verdict.confidence if verdict else 0) * 100),
            "overrides": ", ".join(verdict.overrides_applied) if verdict else "",
        },
        "is_file": is_file,
        "summary": summary or [],
        "recommendations": recommendations or [],
        "email": _email_overview(report),
        "file": _file_overview(report),
        "auth": _auth(report),
        "auth_findings": _module_findings(report, "header"),
        "received": _received(report),
        "domain": _domain(report),
        "domain_findings": _module_findings(report, "domain"),
        "tone": _tone(report),
        "urls": _urls(report),
        "url_findings": _module_findings(report, "urls"),
        "attachments": _attachments(report),
        "attachment_findings": _module_findings(report, "attachments"),
        "artifacts": _module_findings(report, "artifacts"),
        "tracking_domains": _result(report, "artifacts").raw.get("tracking_domains") or [],
        "nested": _module_findings(report, "nested"),
        "iocs": [
            {
                "type": Plain(i.type.value),
                "value": i.defanged or i.value,
                "verdict": i.verdict or "unknown",
                "source": i.source_module,
                "context": i.context,
            }
            for i in report.iocs
        ],
        "mitre": [
            {
                "id": Link(t.url or _mitre_url(t.id), t.id),
                "name": t.name,
                "tactics": ", ".join(t.tactics),
                "triggered_by": Plain(", ".join(t.triggered_by)),
            }
            for t in report.mitre
        ],
        "module_scores": module_scores,
        "findings": [_finding_row(f) for f in findings],
        "errors": [f"{m}: {e}" for m, r in report.results.items() for e in r.errors],
        "footer": {
            "version": Plain(report.tool_version or "unknown"),
            "used": ", ".join(report.services_used) or "none",
            "not_configured": ", ".join(report.services_not_configured) or "none",
        },
    }
