"""Real file type detection and filename tricks (helpers for the attachment analyzer).

``detect_type(data)`` returns a MIME type from the content: libmagic (python-magic) when it is
installed, otherwise the signature table in ``data/file_types.yaml``. Zip files are refined to
the Office Open XML type they contain (and flagged as macro-enabled when they hold a
``vbaProject.bin``). Nothing is executed or rendered: only bytes are inspected.

``filename_checks`` finds type mismatches, double extensions, right-to-left override and other
bidirectional control characters, whitespace-padded extensions and high-risk file types.
"""

from __future__ import annotations

import io
import re
import zipfile
from functools import cache
from typing import Any

from phishlens.config import get_settings
from phishlens.data_loader import file_types

__all__ = [
    "BIDI_CONTROLS",
    "RISKY_CATEGORIES",
    "category_of_mime",
    "detect_type",
    "extension",
    "filename_checks",
    "libmagic_available",
]

BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩")
# Categories whose presence under another name is a type_mismatch.
RISKY_CATEGORIES = frozenset(
    {"executable", "script", "archive", "disk_image", "html", "shortcut", "onenote", "office_macro"}
)
# A representative extension per category, to check detected types against the high-risk list.
CATEGORY_EXTENSION = {
    "executable": "exe",
    "shortcut": "lnk",
    "disk_image": "iso",
    "onenote": "one",
    "html": "html",
    "office_macro": "docm",
}

_MIME_CATEGORIES: dict[str, str] = {
    "application/x-dosexec": "executable",
    "application/x-msdownload": "executable",
    "application/vnd.microsoft.portable-executable": "executable",
    "application/x-executable": "executable",
    "application/x-sharedlib": "executable",
    "application/x-mach-binary": "executable",
    "application/java-vm": "executable",
    "application/x-msi": "executable",
    "application/zip": "archive",
    "application/x-7z-compressed": "archive",
    "application/x-rar": "archive",
    "application/vnd.rar": "archive",
    "application/gzip": "archive",
    "application/x-gzip": "archive",
    "application/x-tar": "archive",
    "application/x-bzip2": "archive",
    "application/x-xz": "archive",
    "application/vnd.ms-cab-compressed": "archive",
    "application/x-iso9660-image": "disk_image",
    "text/html": "html",
    "image/svg+xml": "html",
    "application/x-ms-shortcut": "shortcut",
    "application/onenote": "onenote",
    "application/javascript": "script",
    "text/javascript": "script",
    "application/x-sh": "script",
    "text/x-shellscript": "script",
    "application/pdf": "document",
    "text/rtf": "document",
    "application/rtf": "document",
    "application/msword": "document",
    "application/x-ole-storage": "document",
    "application/vnd.ms-excel": "document",
    "application/vnd.ms-powerpoint": "document",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "document",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "document",
    "application/vnd.ms-word.document.macroenabled.12": "office_macro",
    "application/vnd.ms-excel.sheet.macroenabled.12": "office_macro",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12": "office_macro",
}

_OOXML = {
    "word/": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-word.document.macroenabled.12",
    ),
    "xl/": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel.sheet.macroenabled.12",
    ),
    "ppt/": (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.ms-powerpoint.presentation.macroenabled.12",
    ),
}
_WS_PADDED_RE = re.compile(r"[\s -​　]{3,}\.[^.\s]{1,6}$|\.[^.\s]{1,6}[\s​]+$")


@cache
def _magic() -> Any:
    try:
        import magic

        return magic.Magic(mime=True)
    except (ImportError, OSError):  # python-magic without the libmagic system library
        return None


def libmagic_available() -> bool:
    return _magic() is not None


def _sniff(data: bytes) -> str:
    table = file_types()
    for signature in table.signatures:
        end = signature.offset + len(signature.magic)
        if data[signature.offset : end] == signature.magic:
            return signature.mime
    head = data[:2048].lower()
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        return "application/octet-stream"
    for marker in table.text_markers:
        if any(m in text for m in marker.markers):
            return marker.mime
    return "text/plain" if text.isprintable() or text.strip() else "application/octet-stream"


def _refine_zip(data: bytes, mime: str) -> str:
    """Tell Office Open XML files apart from plain zips (with or without macros)."""
    try:
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError):
        return mime
    if "[Content_Types].xml" not in names:
        return mime
    has_macro = any(n.lower().endswith("vbaproject.bin") for n in names)
    for prefix, (plain, macro) in _OOXML.items():
        if any(n.startswith(prefix) for n in names):
            return macro if has_macro else plain
    return mime


def detect_type(data: bytes) -> str:
    """The MIME type of ``data`` from its content."""
    if not data:
        return "application/x-empty"
    checker = _magic()
    mime = None
    if checker is not None:
        try:
            mime = str(checker.from_buffer(data[:65536])).lower()
        except Exception:
            mime = None
    mime = mime or _sniff(data)
    if mime in ("application/zip", "application/octet-stream") and data[:2] == b"PK":
        mime = _refine_zip(data, "application/zip")
    return mime


def category_of_mime(mime: str | None) -> str | None:
    if not mime:
        return None
    mime = mime.lower().split(";")[0].strip()
    if mime in _MIME_CATEGORIES:
        return _MIME_CATEGORIES[mime]
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("text/"):
        return "text"
    return None


def extension(filename: str) -> str:
    """The last extension of ``filename``, lowercased, without the dot ("" when none)."""
    name = filename.strip().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    name = "".join(ch for ch in name if ch not in BIDI_CONTROLS)
    return name.rsplit(".", 1)[1].strip().lower() if "." in name else ""


def filename_checks(
    filename: str, detected_type: str | None, declared_type: str | None = None
) -> list[tuple[str, dict[str, Any]]]:
    """Return ``(finding_id, details)`` pairs for one file."""
    flags: list[tuple[str, dict[str, Any]]] = []
    table = file_types()
    high_risk = set(get_settings().high_risk_extensions)
    ext = extension(filename)
    ext_category = table.category_of_extension(ext) if ext else None
    detected_category = category_of_mime(detected_type)

    if detected_category in RISKY_CATEGORIES and detected_category != ext_category:
        flags.append(
            (
                "type_mismatch",
                {
                    "extension": ext or None,
                    "claims": ext_category,
                    "declared_type": declared_type,
                    "detected_type": detected_type,
                    "actual": detected_category,
                },
            )
        )

    bare = "".join(ch for ch in filename if ch not in BIDI_CONTROLS)
    parts = [p.strip().lower() for p in bare.split(".")]
    if len(parts) >= 3 and parts[-1] in high_risk and parts[-2] in table.decoy_extensions:
        flags.append(("double_extension", {"shown_as": parts[-2], "real": parts[-1]}))

    bidi = sorted({f"U+{ord(ch):04X}" for ch in filename if ch in BIDI_CONTROLS})
    if bidi:
        flags.append(("rtlo_filename", {"characters": bidi, "without_controls": bare}))

    if _WS_PADDED_RE.search(filename):
        flags.append(("whitespace_padded_extension", {"extension": ext}))

    risky_by_type = CATEGORY_EXTENSION.get(detected_category or "") in high_risk
    if ext in high_risk or risky_by_type:
        flags.append(
            (
                "high_risk_file_type",
                {"extension": ext or None, "detected_type": detected_type},
            )
        )
    return flags
