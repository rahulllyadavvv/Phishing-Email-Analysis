"""Attachment analyzer: unpacking, real file types and filename tricks (static only).

Every attachment is identified by content (``filetype.detect_type``), and archives are unpacked
in memory (``archives.unpack``) within the ``ARCHIVE_*`` limits shared by the whole email.
Encrypted archives are tried with passwords found in the email body (``data/password_hints.yaml``)
and the analyst convention ``infected``. Every file, top-level or extracted, is hashed and
checked for type mismatches, double extensions, bidirectional control characters,
whitespace-padded extensions and high-risk types.

Hash reputation (``reputation=True``): every non-empty file's SHA-256 goes through
``lookup.hash_reputation`` (MalwareBazaar -> VirusTotal). A known-malicious file gets
``attachment_known_malicious`` and is marked ``deep_analysis_skipped``, so the later content and
sandbox stages leave it alone: the verdict is already certain.

Content analysis (files not skipped above): Office and RTF files go through
``office.analyze_office`` (macros, XLM, remote templates, external links, embedded objects,
encryption). URLs found inside files are returned in ``extracted_urls`` (source "attachment").

Nothing is executed, opened or rendered. ``raw["attachments"]`` has one row per file and
``raw["archive_events"]`` what happened while unpacking. Findings are grouped per ID.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from bs4 import BeautifulSoup

from phishlens.analyzers.archives import Budget, PasswordCandidate, unpack
from phishlens.analyzers.filetype import BIDI_CONTROLS, detect_type, filename_checks
from phishlens.analyzers.office import analyze_office, is_office_type
from phishlens.config import get_settings
from phishlens.data_loader import password_hints
from phishlens.enrichment.lookup import hash_reputation
from phishlens.models import (
    AnalyzerResult,
    Attachment,
    EnrichmentResult,
    EnrichmentStatus,
    Finding,
    ParsedEmail,
    Severity,
    UrlRef,
    UrlSource,
)

MODULE = "attachments"

__all__ = ["DEFAULT_PASSWORDS", "MODULE", "analyze", "body_passwords", "prepare_files"]

# Tried after the body candidates: the usual password for shared malware samples.
DEFAULT_PASSWORDS = ("infected",)
_STRIP = "\"'“”‘’()[]{}<>:;,.!?*`"
MAX_CONCURRENT_LOOKUPS = 4
STATUS_ORDER = ("malicious", "suspicious", "clean", "unknown", "error", "not_configured")

# finding id -> (severity, title, description)
FINDINGS: dict[str, tuple[Severity, str, str]] = {
    "type_mismatch": (
        Severity.HIGH,
        "File content does not match its name",
        "The file's real type (from its content) is a risky type hidden behind another name "
        "or declared type.",
    ),
    "double_extension": (
        Severity.HIGH,
        "File name has a double extension",
        "A harmless-looking extension is placed before the real one (invoice.pdf.exe), and "
        "Windows hides the last one by default.",
    ),
    "rtlo_filename": (
        Severity.HIGH,
        "File name contains right-to-left override characters",
        "Invisible direction characters reverse part of the name so a dangerous extension "
        "reads like a harmless one.",
    ),
    "whitespace_padded_extension": (
        Severity.MEDIUM,
        "File name pads the extension with spaces",
        "Long runs of spaces push the real extension out of view in file dialogs.",
    ),
    "high_risk_file_type": (
        Severity.MEDIUM,
        "High-risk file type",
        "Files of this type can run code or are commonly used to deliver malware.",
    ),
    "archive_limit_exceeded": (
        Severity.MEDIUM,
        "Archive exceeds unpacking limits",
        "The archive is nested too deep, holds too many files or decompresses to too much "
        "data (possible zip bomb). It was only partly unpacked.",
    ),
    "encrypted_archive_password_in_body": (
        Severity.HIGH,
        "Encrypted archive with the password in the email",
        "The archive is password-protected so scanners cannot look inside, and the password "
        "is given in the message: a common malware delivery trick.",
    ),
    "attachment_known_malicious": (
        Severity.CRITICAL,
        "Attachment is known malware",
        "Threat-intelligence services identify this file (by its hash) as malicious.",
    ),
    "office_macro_autoexec": (
        Severity.HIGH,
        "Office macro runs automatically",
        "The document contains VBA macros that start on their own when it is opened.",
    ),
    "office_macro_suspicious_calls": (
        Severity.HIGH,
        "Office macro uses suspicious functions",
        "The macro code calls functions used to run programs, download files or hide "
        "activity (Shell, CreateObject, URLDownloadToFile, WScript, PowerShell, ...).",
    ),
    "xlm_macro": (
        Severity.HIGH,
        "Excel 4.0 (XLM) macros",
        "The workbook contains legacy Excel 4.0 macros, a favourite of malware because many "
        "tools do not inspect them.",
    ),
    "remote_template_injection": (
        Severity.HIGH,
        "Document loads a remote template",
        "The document points to a template on the internet that Office downloads when it "
        "opens: a way to fetch malicious macros after the file has passed the filters.",
    ),
    "office_external_link": (
        Severity.MEDIUM,
        "Document links to external content",
        "The document refers to external objects or files that Office may load when opened.",
    ),
    "rtf_embedded_object": (
        Severity.MEDIUM,
        "RTF document contains embedded objects",
        "Embedded OLE objects in RTF files are a common exploit vehicle (for example the "
        "Equation Editor, CVE-2017-11882).",
    ),
    "encrypted_office_document": (
        Severity.MEDIUM,
        "Password-protected Office document",
        "The document is encrypted, which hides its content from mail filters.",
    ),
    "encrypted_archive_unopened": (
        Severity.HIGH,
        "Encrypted archive could not be opened",
        "The archive is password-protected and none of the candidate passwords worked, so its "
        "content could not be checked.",
    ),
}


def safe_name(filename: str) -> str:
    """The filename with bidirectional control characters made visible (``<U+202E>``)."""
    return "".join(f"<U+{ord(ch):04X}>" if ch in BIDI_CONTROLS else ch for ch in filename)


def body_passwords(email: ParsedEmail) -> list[str]:
    """Password candidates from the text and HTML bodies, in order of appearance."""
    hints = password_hints()
    text = email.text_body
    if email.html_body:
        text += "\n" + BeautifulSoup(email.html_body, "html.parser").get_text(" ")
    skip = set(hints.stopwords) | set(hints.hints)
    found: list[tuple[int, str]] = []
    for hint in hints.hints:
        pattern = re.compile(r"(?<!\w)" + re.escape(hint) + r"(?!\w)", re.IGNORECASE)
        for match in pattern.finditer(text):
            # The first real token after the hint word is the candidate ("is", "for the file"
            # and similar filler words are skipped).
            for token in text[match.end() : match.end() + 200].split()[: hints.max_tokens]:
                token = token.strip(_STRIP)
                if not token or token.lower() in skip:
                    continue
                if 3 <= len(token) <= 64:
                    found.append((match.start(), token))
                break
    candidates: list[str] = []
    for _, token in sorted(found):
        if token not in candidates:
            candidates.append(token)
    return candidates


def _budget() -> Budget:
    settings = get_settings()
    return Budget(
        max_depth=settings.archive_max_depth,
        max_files=settings.archive_max_files,
        max_total_bytes=int(settings.archive_max_total_mb * 1024 * 1024),
        file_timeout=settings.archive_file_timeout_seconds,
    )


async def prepare_files(
    attachments: list[Attachment], passwords: list[str]
) -> tuple[list[Attachment], list[dict[str, Any]]]:
    """Identify every attachment and unpack archives. Returns all files (top-level first,
    each followed by what was extracted from it) and the unpacking events."""
    candidates = [PasswordCandidate(p, "body") for p in passwords]
    candidates += [PasswordCandidate(p, "default") for p in DEFAULT_PASSWORDS if p not in passwords]
    budget = _budget()
    files: list[Attachment] = []
    events: list[dict[str, Any]] = []
    for attachment in attachments:
        top = attachment.model_copy(
            update={"detected_type": attachment.detected_type or detect_type(attachment.data)}
        )
        files.append(top)
        unpacked = await asyncio.to_thread(unpack, top, candidates, budget)
        files.extend(unpacked.files)
        events.extend(unpacked.events)
    return files, events


def _row(file: Attachment, flags: list[str]) -> dict[str, Any]:
    return {
        "filename": file.filename,
        "safe_name": safe_name(file.filename),
        "parent": file.parent,
        "depth": file.depth,
        "declared_type": file.declared_type,
        "detected_type": file.detected_type,
        "size": file.size,
        "md5": file.md5,
        "sha1": file.sha1,
        "sha256": file.sha256,
        "flags": flags,
    }


def _add_findings(result: AnalyzerResult, grouped: dict[str, list[dict[str, Any]]]) -> None:
    for finding_id, entries in grouped.items():
        severity, title, description = FINDINGS[finding_id]
        result.findings.append(
            Finding(
                id=finding_id,
                module=MODULE,
                title=title,
                description=description,
                severity=severity,
                evidence={"files": entries, "count": len(entries)},
            )
        )


def _static_file_checks(
    files: list[Attachment], events: list[dict[str, Any]], result: AnalyzerResult
) -> None:
    grouped: dict[str, list[dict[str, Any]]] = {}
    rows = []
    for file in files:
        flags = filename_checks(file.filename, file.detected_type, file.declared_type)
        rows.append(_row(file, [flag for flag, _ in flags]))
        for flag, details in flags:
            grouped.setdefault(flag, []).append(
                {"file": safe_name(file.filename), "sha256": file.sha256, **details}
            )
    result.raw["attachments"] = rows

    for event in events:
        kind = event["event"]
        entry = {k: v for k, v in event.items() if k != "event"}
        entry["archive"] = safe_name(event["archive"])
        if kind == "limit":
            grouped.setdefault("archive_limit_exceeded", []).append(entry)
        elif kind == "encrypted_opened" and event.get("source") == "body":
            grouped.setdefault("encrypted_archive_password_in_body", []).append(entry)
        elif kind == "encrypted_unopened":
            grouped.setdefault("encrypted_archive_unopened", []).append(entry)
        elif kind == "error":
            result.errors.append(f"unpack: {entry['archive']}: {event['detail']}")
    result.raw["archive_events"] = [
        {**e, "archive": safe_name(e["archive"])} for e in events
    ]
    _add_findings(result, grouped)


def _families(results: list[EnrichmentResult]) -> list[str]:
    names: list[str] = []
    for r in results:
        if r.status != EnrichmentStatus.MALICIOUS:
            continue
        label = r.details.get("signature") or (
            (r.details.get("popular_threat_classification") or {}).get("suggested_threat_label")
        )
        if label and str(label) not in names:
            names.append(str(label))
    return names


def _summary(result: EnrichmentResult) -> dict[str, Any]:
    return {
        "service": result.service,
        "status": result.status.value,
        "detections": result.detections,
        "total_engines": result.total_engines,
        "cached": result.cached,
        "link": result.link,
        "error": result.error,
    }


async def _check_reputation(result: AnalyzerResult) -> None:
    rows = result.raw.get("attachments", [])
    hashes = list(dict.fromkeys(r["sha256"] for r in rows if r["size"] > 0))
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_LOOKUPS)

    async def lookup(sha256: str) -> list[EnrichmentResult]:
        async with semaphore:
            return await hash_reputation(sha256)

    answers = dict(zip(hashes, await asyncio.gather(*(lookup(h) for h in hashes)), strict=True))
    malicious: list[dict[str, Any]] = []
    for row in rows:
        results = answers.get(row["sha256"], [])
        row["reputation"] = [_summary(r) for r in results]
        statuses = {r.status.value for r in results}
        row["reputation_verdict"] = next((s for s in STATUS_ORDER if s in statuses), None)
        row["deep_analysis_skipped"] = row["reputation_verdict"] == "malicious"
        if row["deep_analysis_skipped"]:
            row["skip_reason"] = "known malicious by hash reputation"
            malicious.append(
                {
                    "file": row["safe_name"],
                    "sha256": row["sha256"],
                    "parent": row["parent"],
                    "services": [
                        r.service for r in results if r.status == EnrichmentStatus.MALICIOUS
                    ],
                    "detections": {
                        r.service: f"{r.detections}/{r.total_engines}"
                        for r in results
                        if r.total_engines
                    },
                    "families": _families(results),
                    "links": [r.link for r in results if r.link],
                }
            )
    if malicious:
        _add_findings(result, {"attachment_known_malicious": malicious})


async def _check_content(
    files: list[Attachment], passwords: list[str], result: AnalyzerResult
) -> None:
    """Deep static analysis per file type (Office/RTF for now), skipping known-bad files."""
    rows = result.raw.get("attachments", [])
    grouped: dict[str, list[dict[str, Any]]] = {}
    seen_urls = {ref.url for ref in result.extracted_urls}
    for file, row in zip(files, rows, strict=True):
        if row.get("deep_analysis_skipped") or not is_office_type(file.detected_type):
            continue
        report = await asyncio.to_thread(
            analyze_office, file.filename, file.data, file.detected_type, passwords
        )
        row["office"] = report.info
        for error in report.errors:
            result.errors.append(f"office: {row['safe_name']}: {error}")
        for flag, details in report.flags:
            row["flags"].append(flag)
            grouped.setdefault(flag, []).append(
                {"file": row["safe_name"], "sha256": file.sha256, **details}
            )
        for url in report.urls:
            if url not in seen_urls:
                seen_urls.add(url)
                result.extracted_urls.append(UrlRef(url=url, source=UrlSource.ATTACHMENT))
    _add_findings(result, grouped)


async def analyze(
    email: ParsedEmail,
    context: dict[str, AnalyzerResult] | None = None,
    reputation: bool = True,
) -> AnalyzerResult:
    """Analyze the email's attachments. Never raises; errors go into ``errors``.

    ``reputation=False`` skips the hash lookups (no network at all).
    """
    start = time.perf_counter()
    result = AnalyzerResult(module=MODULE)
    if not email.attachments:
        result.skipped = True
        result.raw["attachments"] = []
        return result
    files: list[Attachment] = []
    passwords: list[str] = []
    try:
        passwords = body_passwords(email)
        result.raw["password_candidates"] = passwords
        files, events = await prepare_files(list(email.attachments), passwords)
        _static_file_checks(files, events, result)
    except Exception as exc:
        result.errors.append(f"attachments: {type(exc).__name__}: {exc}")
    if reputation:
        try:
            await _check_reputation(result)
        except Exception as exc:
            result.errors.append(f"reputation: {type(exc).__name__}: {exc}")
    if files:
        try:
            await _check_content(files, passwords, result)
        except Exception as exc:
            result.errors.append(f"content: {type(exc).__name__}: {exc}")
    result.duration_ms = int((time.perf_counter() - start) * 1000)
    return result
