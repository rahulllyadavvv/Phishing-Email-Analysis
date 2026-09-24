"""Analysis pipeline: raw email -> analyzers -> IOCs -> MITRE ATT&CK -> verdict -> report.

``analyze_email(raw_bytes)`` runs, in order:

1. ``parse_email``;
2. the header analyzer, then concurrently: domain -> tone (tone needs the domain result to
   skip brands the domain analyzer already reported), artifacts and attachments. Each gets
   ``context`` with the results so far;
3. the URL analyzer on the email's URLs plus URLs extracted by attachments and artifacts;
4. forwarded (``message/rfc822``) emails, analyzed the same way up to
   ``NESTED_EMAIL_MAX_DEPTH``; their findings are collected in a ``nested`` result, each marked
   ``evidence["nested"] = "nested:<n>"``;
5. IOC extraction, MITRE ATT&CK mapping (technique IDs are also written to the findings),
   scoring;
6. an ``AnalysisReport``.

``analyze_file(raw_bytes, filename)`` handles a standalone file: the attachment analyzer
(``analyze_files``), the URL analyzer on URLs found inside it, IOCs, MITRE and scoring with the
file thresholds; the email-only analyzers are marked skipped ("not an email").
``analyze_input(raw_bytes, filename)`` routes by content (``ingest.load_input``): anything that
is really an email (.eml, or .msg converted to RFC 822) goes to ``analyze_email``.

Every analyzer runs with a timeout (``ANALYZER_TIMEOUT_SECONDS``; the attachment analyzer uses
``ATTACHMENT_TIMEOUT_SECONDS`` because it may wait for a sandbox). An analyzer that fails or
times out is recorded as an error result and the pipeline carries on. ``progress_cb(module,
status)`` (plain function or coroutine) receives ``pending``/``running``/``done``/``error``
(and ``skipped`` for the email-only analyzers in a file case).
``network=False`` runs everything offline (no DNS, no HTTP, no LLM).
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from phishlens import __version__
from phishlens.analyzers import artifacts, attachments, domain, header, tone, urls
from phishlens.config import SERVICE_FIELDS, get_settings
from phishlens.enrichment.network import network_enabled, offline
from phishlens.ingest.loader import load_input
from phishlens.ioc.extract import VERDICT_ORDER, extract_iocs
from phishlens.mapping.mitre import map_findings
from phishlens.models import (
    IOC,
    AnalysisReport,
    AnalyzerResult,
    CaseType,
    Finding,
    MitreTechnique,
    ParsedEmail,
)
from phishlens.parser import parse_email
from phishlens.parser.attachments import make_attachment
from phishlens.scoring import get_scorer

__all__ = [
    "EMAIL_MODULES",
    "FILE_SKIPPED_MODULES",
    "ProgressCallback",
    "analyze_email",
    "analyze_file",
    "analyze_input",
    "merge_iocs",
    "run_analyzer",
]

EMAIL_MODULES = ("header", "domain", "tone", "artifacts", "attachments", "urls")
FILE_SKIPPED_MODULES = ("header", "domain", "tone", "artifacts")
NOT_AN_EMAIL = "not an email"
ProgressCallback = Callable[[str, str], Any]


class _Progress:
    def __init__(self, callback: ProgressCallback | None) -> None:
        self.callback = callback

    async def __call__(self, module: str, status: str) -> None:
        if self.callback is None:
            return
        try:
            outcome = self.callback(module, status)
            if inspect.isawaitable(outcome):
                await outcome
        except Exception:
            pass  # a broken progress display must never break the analysis


async def run_analyzer(
    name: str,
    call: Callable[[], Awaitable[AnalyzerResult]],
    timeout: float,
    progress: _Progress | None = None,
) -> AnalyzerResult:
    """Run one analyzer with a timeout; failures become an error result."""
    progress = progress or _Progress(None)
    await progress(name, "running")
    try:
        result = await asyncio.wait_for(call(), timeout=timeout)
    except TimeoutError:
        result = AnalyzerResult(module=name, errors=[f"timed out after {timeout:g}s"])
        await progress(name, "error")
        return result
    except Exception as exc:  # analyzers should never raise; this is the last safety net
        result = AnalyzerResult(module=name, errors=[f"crashed: {type(exc).__name__}: {exc}"])
        await progress(name, "error")
        return result
    await progress(name, "done")
    return result


async def _analyze_parsed(
    email: ParsedEmail, progress: _Progress, depth: int
) -> tuple[dict[str, AnalyzerResult], list[IOC]]:
    settings = get_settings()
    timeout = settings.analyzer_timeout_seconds
    network = network_enabled()
    for name in EMAIL_MODULES:
        await progress(name, "pending")

    results: dict[str, AnalyzerResult] = {}
    results["header"] = await run_analyzer(
        "header", lambda: header.analyze(email), timeout, progress
    )

    async def domain_then_tone() -> None:
        context = {"header": results["header"]}
        results["domain"] = await run_analyzer(
            "domain", lambda: domain.analyze(email, context), timeout, progress
        )
        tone_context = {**context, "domain": results["domain"]}
        results["tone"] = await run_analyzer(
            "tone", lambda: tone.analyze(email, tone_context), timeout, progress
        )

    async def run_artifacts() -> None:
        results["artifacts"] = await run_analyzer(
            "artifacts", lambda: artifacts.analyze(email), timeout, progress
        )

    async def run_attachments() -> None:
        results["attachments"] = await run_analyzer(
            "attachments",
            lambda: attachments.analyze(email, reputation=network, sandbox=network),
            settings.attachment_timeout_seconds,
            progress,
        )

    await asyncio.gather(domain_then_tone(), run_artifacts(), run_attachments())

    extra = [ref for name in ("attachments", "artifacts") for ref in results[name].extracted_urls]
    results["urls"] = await run_analyzer(
        "urls",
        lambda: urls.analyze(email, dict(results), extra_urls=extra, reputation=network),
        timeout,
        progress,
    )
    iocs = extract_iocs(email, results)

    if email.nested_emails and depth < settings.nested_email_max_depth:
        await progress("nested", "running")
        nested_findings: list[Finding] = []
        described = []
        for index, nested in enumerate(email.nested_emails, start=1):
            nested_results, nested_iocs = await _analyze_parsed(
                nested, _Progress(None), depth + 1
            )
            label = f"nested:{index}"
            described.append(
                {
                    "nested": label,
                    "subject": nested.subject,
                    "from": nested.from_addrs[0].address if nested.from_addrs else None,
                    "errors": {n: r.errors for n, r in nested_results.items() if r.errors},
                }
            )
            for result in nested_results.values():
                for finding in result.findings:
                    nested_findings.append(
                        finding.model_copy(
                            update={
                                "module": f"nested.{finding.module}",
                                "evidence": {"nested": label, **finding.evidence},
                            }
                        )
                    )
            iocs = merge_iocs(iocs, nested_iocs)
        results["nested"] = AnalyzerResult(
            module="nested", findings=nested_findings, raw={"emails": described}
        )
        await progress("nested", "done")
    return results, iocs


def merge_iocs(first: list[IOC], second: list[IOC]) -> list[IOC]:
    """Combine two IOC lists: same (type, value) merges sources/contexts, worst verdict wins."""
    merged: dict[tuple[str, str], IOC] = {(i.type.value, i.value): i for i in first}
    for ioc in second:
        key = (ioc.type.value, ioc.value)
        existing = merged.get(key)
        if existing is None:
            merged[key] = ioc
            continue
        verdicts = [v for v in (existing.verdict, ioc.verdict) if v in VERDICT_ORDER]
        merged[key] = existing.model_copy(
            update={
                "source_module": _join(existing.source_module, ioc.source_module, ", "),
                "context": _join(existing.context, ioc.context, "; "),
                "verdict": min(verdicts, key=VERDICT_ORDER.index) if verdicts else "unknown",
            }
        )
    return sorted(merged.values(), key=lambda i: (i.type.value, i.value))


def _join(a: str, b: str, sep: str) -> str:
    parts = [p for p in a.split(sep) if p] + [p for p in b.split(sep) if p]
    return sep.join(dict.fromkeys(parts))


def _tag_mitre(results: dict[str, AnalyzerResult], techniques: list[MitreTechnique]) -> None:
    by_finding: dict[str, list[str]] = {}
    for technique in techniques:
        for finding_id in technique.triggered_by:
            by_finding.setdefault(finding_id, []).append(technique.id)
    for result in results.values():
        for finding in result.findings:
            if finding.id in by_finding:
                finding.mitre = sorted(by_finding[finding.id])


def _services() -> tuple[list[str], list[str]]:
    if not network_enabled():
        return [], sorted(SERVICE_FIELDS)
    configured = get_settings().configured_services()
    used = sorted(name for name, on in configured.items() if on)
    return used, sorted(name for name, on in configured.items() if not on)


def build_report(
    case_id: str,
    case_type: CaseType,
    results: dict[str, AnalyzerResult],
    iocs: list[IOC],
    email: ParsedEmail | None = None,
    file_info: Any = None,
) -> AnalysisReport:
    """IOCs are given; this maps MITRE techniques, scores and assembles the report."""
    all_findings = [f for r in results.values() for f in r.findings]
    techniques = map_findings(all_findings)
    _tag_mitre(results, techniques)
    verdict = get_scorer().score(results, case_type.value)
    used, missing = _services()
    return AnalysisReport(
        case_id=case_id,
        case_type=case_type,
        email=email,
        file_info=file_info,
        results=results,
        iocs=iocs,
        mitre=techniques,
        verdict=verdict,
        services_used=used,
        services_not_configured=missing,
        tool_version=__version__,
    )


async def analyze_email(
    raw_bytes: bytes,
    progress_cb: ProgressCallback | None = None,
    *,
    network: bool = True,
    case_id: str | None = None,
) -> AnalysisReport:
    """Analyze one email (raw RFC 822 bytes) and return the full report. Never raises for a
    problem inside an analyzer; parsing itself never raises either."""
    case_id = case_id or uuid.uuid4().hex
    progress = _Progress(progress_cb)
    with offline(not network):
        email = parse_email(raw_bytes)
        results, iocs = await _analyze_parsed(email, progress, depth=0)
        await progress("scoring", "running")
        report = build_report(case_id, CaseType.EMAIL, results, iocs, email=email)
        await progress("scoring", "done")
    return report


async def analyze_file(
    raw_bytes: bytes,
    filename: str,
    progress_cb: ProgressCallback | None = None,
    *,
    network: bool = True,
    case_id: str | None = None,
) -> AnalysisReport:
    """Analyze one standalone file (not an email). Never raises for analyzer problems."""
    case_id = case_id or uuid.uuid4().hex
    progress = _Progress(progress_cb)
    settings = get_settings()
    with offline(not network):
        net = network_enabled()
        file = make_attachment(filename or "upload.bin", raw_bytes)
        results: dict[str, AnalyzerResult] = {}
        for name in FILE_SKIPPED_MODULES:
            results[name] = AnalyzerResult(
                module=name, skipped=True, raw={"skipped_reason": NOT_AN_EMAIL}
            )
            await progress(name, "skipped")
        await progress("attachments", "pending")
        await progress("urls", "pending")
        results["attachments"] = await run_analyzer(
            "attachments",
            lambda: attachments.analyze_files([file], case_id, reputation=net, sandbox=net),
            settings.attachment_timeout_seconds,
            progress,
        )
        extracted = results["attachments"].extracted_urls
        no_email = ParsedEmail()
        results["urls"] = await run_analyzer(
            "urls",
            lambda: urls.analyze(no_email, dict(results), extra_urls=extracted, reputation=net),
            settings.analyzer_timeout_seconds,
            progress,
        )
        rows = results["attachments"].raw.get("attachments") or [{}]
        detected = rows[0].get("detected_type")
        file_info = file.model_copy(update={"detected_type": detected})
        iocs = extract_iocs(None, results)
        await progress("scoring", "running")
        report = build_report(case_id, CaseType.FILE, results, iocs, file_info=file_info)
        await progress("scoring", "done")
    return report


async def analyze_input(
    raw_bytes: bytes,
    filename: str | None = None,
    progress_cb: ProgressCallback | None = None,
    *,
    network: bool = True,
    case_id: str | None = None,
) -> AnalysisReport:
    """Route by content: emails (.eml, or .msg converted to RFC 822) to ``analyze_email``,
    everything else to ``analyze_file``. Raises ``LoaderError`` for oversize or broken .msg
    input (checked before any analysis)."""
    kind, data = load_input(raw_bytes, filename)
    if kind == "email":
        return await analyze_email(data, progress_cb, network=network, case_id=case_id)
    return await analyze_file(
        data, filename or "upload.bin", progress_cb, network=network, case_id=case_id
    )
