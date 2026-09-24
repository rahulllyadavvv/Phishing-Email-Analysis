"""Attachment analyzer: unpacking, real file types and filename tricks (static only).

Every attachment is identified by content (``filetype.detect_type``), and archives are unpacked
in memory (``archives.unpack``) within the ``ARCHIVE_*`` limits shared by the whole email.
Encrypted archives are tried with passwords found in the email body (``data/password_hints.yaml``)
and the analyst convention ``infected``. Every file, top-level or extracted, is hashed and
checked for type mismatches, double extensions, bidirectional control characters,
whitespace-padded extensions and high-risk types.

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
from phishlens.config import get_settings
from phishlens.data_loader import password_hints
from phishlens.models import AnalyzerResult, Attachment, Finding, ParsedEmail, Severity

MODULE = "attachments"

__all__ = ["DEFAULT_PASSWORDS", "MODULE", "analyze", "body_passwords", "prepare_files"]

# Tried after the body candidates: the usual password for shared malware samples.
DEFAULT_PASSWORDS = ("infected",)
_STRIP = "\"'“”‘’()[]{}<>:;,.!?*`"

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


async def analyze(
    email: ParsedEmail, context: dict[str, AnalyzerResult] | None = None
) -> AnalyzerResult:
    """Analyze the email's attachments. Never raises; errors go into ``errors``."""
    start = time.perf_counter()
    result = AnalyzerResult(module=MODULE)
    if not email.attachments:
        result.skipped = True
        result.raw["attachments"] = []
        return result
    try:
        passwords = body_passwords(email)
        result.raw["password_candidates"] = passwords
        files, events = await prepare_files(list(email.attachments), passwords)
        _static_file_checks(files, events, result)
    except Exception as exc:
        result.errors.append(f"attachments: {type(exc).__name__}: {exc}")
    result.duration_ms = int((time.perf_counter() - start) * 1000)
    return result
