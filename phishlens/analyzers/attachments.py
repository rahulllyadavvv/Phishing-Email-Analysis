"""Attachment analyzer: unpacking, identification, reputation, static content analysis,
sandbox gating and quarantine.

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
encryption); PDFs through ``documents.analyze_pdf`` (JavaScript, automatic and launch actions,
embedded files, links, QR codes in images); HTML and SVG through ``documents.analyze_html``
(HTML smuggling, credential forms, SVG script, obfuscation). URLs found inside files are
returned in ``extracted_urls`` (source "attachment", or "qr_code" for decoded QR codes).
Executables go through ``binaries.analyze_pe``, shortcuts through ``binaries.analyze_lnk`` and
images through ``binaries.analyze_image`` (QR codes). Every file is scanned with the YARA rules.
Inline images (``email.inline_images``) get only the YARA and QR checks: no reputation lookups
and no filename findings, since mails are full of harmless inline logos.

Sandbox (``sandbox=True``): a file goes to the configured external sandbox (CAPE first, then
Hybrid Analysis) only when hash reputation had no verdict and the file is high-risk or has a
medium+ static finding; every other file records why it was skipped. Sandbox verdicts add
``sandbox_malicious`` / ``sandbox_suspicious``; a clean run never removes static findings.
Network indicators and dropped hashes are collected in ``raw["sandbox_iocs"]``.

Quarantine: every analyzed file is stored in ``<QUARANTINE_DIR>/<case>/files.zip`` (AES,
password "infected"), named by SHA-256 with a ``manifest.json``.

``analyze_files(files, case_id)`` runs the same stages for standalone file cases.

Nothing is executed, opened or rendered on this host. ``raw["attachments"]`` has one row per
file and ``raw["archive_events"]`` what happened while unpacking. Findings are grouped per ID.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

import pyzipper
from bs4 import BeautifulSoup

from phishlens.analyzers.archives import Budget, PasswordCandidate, unpack
from phishlens.analyzers.binaries import analyze_image, analyze_lnk, analyze_pe, yara_scan
from phishlens.analyzers.documents import (
    ContentReport,
    analyze_html,
    analyze_pdf,
    is_html_type,
    is_pdf_type,
)
from phishlens.analyzers.filetype import (
    BIDI_CONTROLS,
    category_of_mime,
    detect_type,
    filename_checks,
)
from phishlens.analyzers.office import analyze_office, is_office_type
from phishlens.config import get_settings
from phishlens.data_loader import password_hints
from phishlens.enrichment import base as enrichment_base
from phishlens.enrichment.lookup import hash_reputation
from phishlens.enrichment.sandbox import CapeClient, HybridAnalysisClient, SandboxClient
from phishlens.models import (
    AnalyzerResult,
    Attachment,
    EnrichmentResult,
    EnrichmentStatus,
    Finding,
    ParsedEmail,
    SandboxReport,
    Severity,
    UrlRef,
    UrlSource,
)

MODULE = "attachments"

__all__ = [
    "DEFAULT_PASSWORDS",
    "MODULE",
    "QUARANTINE_PASSWORD",
    "analyze",
    "analyze_files",
    "body_passwords",
    "prepare_files",
    "quarantine",
]

# Tried after the body candidates: the usual password for shared malware samples.
DEFAULT_PASSWORDS = ("infected",)
_STRIP = "\"'“”‘’()[]{}<>:;,.!?*`"
MAX_CONCURRENT_LOOKUPS = 4
MAX_SANDBOX_PER_CASE = 5
QUARANTINE_PASSWORD = "infected"
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
    "pdf_javascript": (
        Severity.HIGH,
        "PDF contains JavaScript",
        "Legitimate documents rarely need JavaScript; in attachments it is used for exploits "
        "and redirects.",
    ),
    "pdf_auto_action": (
        Severity.HIGH,
        "PDF runs an action automatically",
        "The PDF triggers an action when it is opened or a page is shown (/OpenAction, /AA).",
    ),
    "pdf_launch_action": (
        Severity.CRITICAL,
        "PDF tries to launch a program",
        "A /Launch action asks the reader to start a program or open a file.",
    ),
    "pdf_embedded_file": (
        Severity.MEDIUM,
        "PDF carries embedded files",
        "Files hidden inside the PDF can be extracted and opened by the reader.",
    ),
    "html_smuggling": (
        Severity.CRITICAL,
        "HTML smuggling",
        "The HTML file builds a file in the browser from embedded data and offers it as a "
        "download, bypassing mail filters that scan attachments.",
    ),
    "credential_form_attachment": (
        Severity.HIGH,
        "Attachment contains a login form",
        "A local HTML page with a password field or a form sending data to a website is a "
        "classic credential-phishing attachment.",
    ),
    "svg_script": (
        Severity.HIGH,
        "SVG image contains script",
        "The image carries JavaScript or event handlers, used to redirect or run code when "
        "it is opened in a browser.",
    ),
    "obfuscated_script": (
        Severity.MEDIUM,
        "Obfuscated script",
        "The script hides its behaviour (eval, unescape, long encoded strings).",
    ),
    "pe_executable_attachment": (
        Severity.HIGH,
        "Windows executable attached",
        "The file is a Windows program. Legitimate senders almost never email executables.",
    ),
    "pe_packed": (
        Severity.MEDIUM,
        "Executable is packed or encrypted",
        "Packer section names or very high entropy show the program's code is compressed or "
        "encrypted, which hides it from scanners.",
    ),
    "lnk_suspicious_command": (
        Severity.CRITICAL,
        "Shortcut runs a suspicious command",
        "The shortcut starts a script host, a Windows tool abused by malware, or something on "
        "a remote path when it is opened.",
    ),
    "qr_code_url": (
        Severity.MEDIUM,
        "Image contains a QR code",
        "A QR code sends the victim to a link on their phone, outside the protection of the "
        "mail filter (quishing).",
    ),
    "yara_match": (
        Severity.HIGH,
        "YARA rule matched",
        "A file matches one or more YARA rules.",
    ),
    "sandbox_malicious": (
        Severity.CRITICAL,
        "Sandbox detonation: malicious",
        "The file behaved maliciously when run in an external sandbox.",
    ),
    "sandbox_suspicious": (
        Severity.MEDIUM,
        "Sandbox detonation: suspicious",
        "The file showed suspicious behaviour when run in an external sandbox.",
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
    files: list[Attachment],
    events: list[dict[str, Any]],
    result: AnalyzerResult,
    inline: set[int] | None = None,
) -> None:
    inline = inline or set()
    grouped: dict[str, list[dict[str, Any]]] = {}
    rows = []
    for index, file in enumerate(files):
        if index in inline:
            rows.append({**_row(file, []), "inline": True})
            continue
        flags = filename_checks(file.filename, file.detected_type, file.declared_type)
        rows.append({**_row(file, [flag for flag, _ in flags]), "inline": False})
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
    hashes = list(
        dict.fromkeys(r["sha256"] for r in rows if r["size"] > 0 and not r.get("inline"))
    )
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


def _content_analysis(
    file: Attachment, passwords: list[str]
) -> tuple[str, ContentReport] | None:
    """Run the static analyzer for the file's type. Returns (section name, report)."""
    mime = file.detected_type
    if is_office_type(mime):
        return "office", analyze_office(file.filename, file.data, mime, passwords)
    if is_pdf_type(mime):
        return "pdf", analyze_pdf(file.data)
    if is_html_type(mime):
        return "html", analyze_html(file.data, mime)
    category = category_of_mime(mime)
    if category == "executable" and file.data[:2] == b"MZ":
        return "pe", analyze_pe(file.data)
    if category == "shortcut":
        return "lnk", analyze_lnk(file.data)
    if category == "image":
        return "image", analyze_image(file.data)
    return None


async def _check_content(
    files: list[Attachment], passwords: list[str], result: AnalyzerResult
) -> None:
    """Deep static analysis per file type, skipping files already known to be malicious."""
    rows = result.raw.get("attachments", [])
    grouped: dict[str, list[dict[str, Any]]] = {}
    seen_urls = {ref.url for ref in result.extracted_urls}

    def add_url(url: str, source: UrlSource) -> None:
        if url not in seen_urls:
            seen_urls.add(url)
            result.extracted_urls.append(UrlRef(url=url, source=source))

    yara_hits: list[dict[str, Any]] = []
    yara_errors: list[str] = []
    for file, row in zip(files, rows, strict=True):
        if row.get("deep_analysis_skipped"):
            continue
        matches, errors = await asyncio.to_thread(yara_scan, file.data)
        yara_errors += [e for e in errors if e not in yara_errors]
        if matches:
            row["flags"].append("yara_match")
            row["yara"] = matches
            yara_hits += [
                {"file": row["safe_name"], "sha256": file.sha256, **m} for m in matches
            ]
        if row.get("inline") and category_of_mime(file.detected_type) != "image":
            continue
        analysis = await asyncio.to_thread(_content_analysis, file, passwords)
        if analysis is None:
            continue
        section, report = analysis
        row[section] = report.info
        for error in report.errors:
            result.errors.append(f"{section}: {row['safe_name']}: {error}")
        for flag, details in report.flags:
            row["flags"].append(flag)
            grouped.setdefault(flag, []).append(
                {"file": row["safe_name"], "sha256": file.sha256, **details}
            )
        for url in report.urls:
            add_url(url, UrlSource.ATTACHMENT)
        for url in report.qr_urls:
            add_url(url, UrlSource.QR_CODE)
    _add_findings(result, grouped)
    result.errors.extend(yara_errors)
    if yara_hits:
        order = ["info", "low", "medium", "high", "critical"]
        worst = max(
            (h["severity"] if h["severity"] in order else "high" for h in yara_hits),
            key=order.index,
        )
        _, title, description = FINDINGS["yara_match"]
        result.findings.append(
            Finding(
                id="yara_match",
                module=MODULE,
                title=title,
                description=description,
                severity=Severity(worst),
                evidence={"files": yara_hits, "count": len(yara_hits)},
            )
        )


# --- Sandbox -------------------------------------------------------------------------------------

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_NO_REPUTATION_VERDICT = frozenset({None, "unknown", "error", "not_configured"})


def _sandbox_client() -> SandboxClient | None:
    """The configured sandbox: CAPE (normally self-hosted) first, then Hybrid Analysis."""
    for client_class in (CapeClient, HybridAnalysisClient):
        client = client_class()
        if client.enabled:
            return client
    return None


def _sandbox_reason(row: dict[str, Any]) -> str | None:
    """Why this file should NOT go to the sandbox (None means: submit it)."""
    if row.get("inline"):
        return "inline image"
    if row.get("deep_analysis_skipped"):
        return "already known malicious"
    if row.get("reputation_verdict") not in _NO_REPUTATION_VERDICT:
        return f"hash reputation already {row['reputation_verdict']}"
    risky = any(
        flag in FINDINGS
        and _SEVERITY_ORDER.index(FINDINGS[flag][0]) >= _SEVERITY_ORDER.index(Severity.MEDIUM)
        for flag in row["flags"]
    )
    if not risky:
        return "no high-risk type or medium+ static finding"
    return None


async def _run_sandbox(client: SandboxClient, file: Attachment) -> SandboxReport:
    submitted = await client.submit(file.data, file.filename)
    if isinstance(submitted, SandboxReport):
        return submitted
    settings = get_settings()
    waited = 0.0
    while True:
        report = await client.get_report(submitted)
        if report.status != "pending":
            return report
        if waited >= settings.sandbox_max_wait_seconds:
            return report.model_copy(
                update={
                    "status": "error",
                    "error": f"no report after {settings.sandbox_max_wait_seconds:g}s",
                }
            )
        await enrichment_base._sleep(settings.sandbox_poll_seconds)
        waited += settings.sandbox_poll_seconds


async def _check_sandbox(files: list[Attachment], result: AnalyzerResult) -> None:
    rows = result.raw.get("attachments", [])
    client = _sandbox_client()
    candidates: list[tuple[Attachment, dict[str, Any]]] = []
    for file, row in zip(files, rows, strict=True):
        reason = "no sandbox configured" if client is None else _sandbox_reason(row)
        if reason is None and len(candidates) >= MAX_SANDBOX_PER_CASE:
            reason = f"limit of {MAX_SANDBOX_PER_CASE} sandbox submissions reached"
        if reason is None:
            candidates.append((file, row))
        else:
            row["sandbox"] = {"status": "skipped", "reason": reason}
    if client is None or not candidates:
        return
    grouped: dict[str, list[dict[str, Any]]] = {}
    iocs: dict[str, list[str]] = {"domains": [], "ips": [], "urls": [], "dropped_hashes": []}
    async with client:
        for file, row in candidates:
            report = await _run_sandbox(client, file)
            row["sandbox"] = report.model_dump(mode="json")
            if report.status != "done":
                if report.status == "error":
                    result.errors.append(f"sandbox: {row['safe_name']}: {report.error}")
                continue
            for key, values in (
                ("domains", report.network_domains),
                ("ips", report.network_ips),
                ("urls", report.network_urls),
                ("dropped_hashes", report.dropped_hashes),
            ):
                iocs[key] += [v for v in values if v not in iocs[key]]
            entry = {
                "file": row["safe_name"],
                "sha256": file.sha256,
                "sandbox": report.sandbox,
                "score": report.score,
                "signatures": report.signatures[:20],
                "link": report.link,
            }
            if report.verdict == EnrichmentStatus.MALICIOUS:
                row["flags"].append("sandbox_malicious")
                grouped.setdefault("sandbox_malicious", []).append(entry)
            elif report.verdict == EnrichmentStatus.SUSPICIOUS:
                row["flags"].append("sandbox_suspicious")
                grouped.setdefault("sandbox_suspicious", []).append(entry)
            # A clean sandbox run is recorded in the row only; static findings stay.
    result.raw["sandbox_iocs"] = iocs
    _add_findings(result, grouped)


# --- Quarantine ----------------------------------------------------------------------------------


def quarantine(files: list[Attachment], case_key: str) -> str | None:
    """Store every file in ``<QUARANTINE_DIR>/<case_key>/files.zip`` (AES, password
    "infected"). Entries are named by SHA-256; ``manifest.json`` maps them to the original
    names. Returns the zip path, or None when quarantine is disabled."""
    settings = get_settings()
    if not settings.quarantine_enabled or not files:
        return None
    folder = Path(settings.quarantine_dir) / re.sub(r"[^A-Za-z0-9_-]", "_", case_key)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "files.zip"
    manifest = []
    with pyzipper.AESZipFile(
        path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as archive:
        archive.setpassword(QUARANTINE_PASSWORD.encode())
        written: set[str] = set()
        for file in files:
            manifest.append(
                {
                    "entry": file.sha256,
                    "filename": file.filename,
                    "parent": file.parent,
                    "depth": file.depth,
                    "detected_type": file.detected_type,
                    "size": file.size,
                    "md5": file.md5,
                    "sha1": file.sha1,
                    "sha256": file.sha256,
                }
            )
            if file.sha256 not in written:
                written.add(file.sha256)
                archive.writestr(file.sha256, file.data)
        archive.writestr("manifest.json", json.dumps(manifest, indent=2))
    return str(path)


# --- Entry points --------------------------------------------------------------------------------


async def _run(
    result: AnalyzerResult,
    attachments: list[Attachment],
    inline_images: list[Attachment],
    passwords: list[str],
    case_key: str,
    reputation: bool,
    sandbox: bool,
) -> None:
    files: list[Attachment] = []
    try:
        result.raw["password_candidates"] = passwords
        files, events = await prepare_files(attachments, passwords)
        inline = [
            image.model_copy(
                update={"detected_type": image.detected_type or detect_type(image.data)}
            )
            for image in inline_images
        ]
        inline_indexes = set(range(len(files), len(files) + len(inline)))
        files += inline
        _static_file_checks(files, events, result, inline_indexes)
    except Exception as exc:
        result.errors.append(f"attachments: {type(exc).__name__}: {exc}")
    stages: list[tuple[str, Any]] = []
    if reputation:
        stages.append(("reputation", lambda: _check_reputation(result)))
    if files:
        stages.append(("content", lambda: _check_content(files, passwords, result)))
        if sandbox:
            stages.append(("sandbox", lambda: _check_sandbox(files, result)))
    for name, stage in stages:
        try:
            await stage()
        except Exception as exc:
            result.errors.append(f"{name}: {type(exc).__name__}: {exc}")
    try:
        result.raw["quarantine_path"] = await asyncio.to_thread(quarantine, files, case_key)
    except Exception as exc:
        result.errors.append(f"quarantine: {type(exc).__name__}: {exc}")


def _case_key(email: ParsedEmail) -> str:
    if email.sha256:
        return email.sha256
    digest = hashlib.sha256("".join(a.sha256 for a in email.attachments).encode())
    return digest.hexdigest()


async def analyze(
    email: ParsedEmail,
    context: dict[str, AnalyzerResult] | None = None,
    reputation: bool = True,
    sandbox: bool = True,
    case_id: str | None = None,
) -> AnalyzerResult:
    """Analyze the email's attachments. Never raises; errors go into ``errors``.

    ``case_id`` names the quarantine folder (default: the email's SHA-256).

    ``reputation=False`` skips the hash lookups and ``sandbox=False`` the sandbox (with both
    off, nothing leaves this host).
    """
    start = time.perf_counter()
    result = AnalyzerResult(module=MODULE)
    if not email.attachments and not email.inline_images:
        result.skipped = True
        result.raw["attachments"] = []
        return result
    try:
        passwords = body_passwords(email)
    except Exception as exc:
        passwords = []
        result.errors.append(f"passwords: {type(exc).__name__}: {exc}")
    await _run(
        result,
        list(email.attachments),
        list(email.inline_images),
        passwords,
        case_id or _case_key(email),
        reputation,
        sandbox,
    )
    result.duration_ms = int((time.perf_counter() - start) * 1000)
    return result


async def analyze_files(
    files: list[Attachment],
    case_id: str,
    passwords: list[str] | None = None,
    reputation: bool = True,
    sandbox: bool = True,
) -> AnalyzerResult:
    """Analyze standalone files (a file case, no email). Same stages as ``analyze``; the
    quarantine folder is ``case_id``. Never raises."""
    start = time.perf_counter()
    result = AnalyzerResult(module=MODULE)
    if not files:
        result.skipped = True
        result.raw["attachments"] = []
        return result
    await _run(result, list(files), [], list(passwords or []), case_id, reputation, sandbox)
    result.duration_ms = int((time.perf_counter() - start) * 1000)
    return result
