"""Static analysis of Office (OLE2 and OOXML) and RTF files (helper for the attachment analyzer).

Nothing is opened in Office or executed: oletools and msoffcrypto parse the bytes.

- Encrypted documents are decrypted in memory with the email's password candidates (plus
  Excel's built-in default "VelvetSweatshop", often abused so a file opens without a prompt).
- olevba: VBA macros, auto-exec triggers, suspicious keywords and IOCs; mraptor's verdict;
  Excel 4.0 (XLM) macros.
- OOXML relationships: an external ``attachedTemplate`` is remote template injection (the
  template, with its macros, is downloaded when the document opens); other external objects,
  frames and links are reported too. Hyperlink targets become extracted URLs.
- Embedded objects: OOXML ``embeddings/`` parts and OLE native streams are listed in the report.
- RTF: embedded objects via rtfobj (Equation Editor objects are called out: CVE-2017-11882).

``analyze_office(file_bytes, passwords)`` returns an ``OfficeReport`` with ``(finding_id,
details)`` pairs, the URLs found, and descriptive data for ``raw``.
"""

from __future__ import annotations

import io
import logging
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree

import msoffcrypto
from oletools import olevba, rtfobj
from oletools.mraptor import MacroRaptor

__all__ = [
    "DEFAULT_OFFICE_PASSWORDS",
    "OFFICE_MIME_PREFIXES",
    "OfficeReport",
    "analyze_office",
    "is_office_type",
]

# Quiet the oletools loggers: parse problems are reported through the result, not the log.
for _name in ("olevba", "mraptor", "rtfobj", "oleobj", "olefile", "msoffcrypto"):
    logging.getLogger(_name).setLevel(logging.CRITICAL)

DEFAULT_OFFICE_PASSWORDS = ("VelvetSweatshop",)
OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
MAX_RELS_BYTES = 1024 * 1024
OFFICE_MIME_PREFIXES = (
    "application/msword",
    "application/vnd.ms-",
    "application/vnd.openxmlformats-officedocument",
    "application/x-ole-storage",
    "application/cdfv2",
)
RTF_TYPES = frozenset({"text/rtf", "application/rtf"})
# Keywords the plan singles out; olevba's other "Suspicious" keywords are reported as well.
KEY_SUSPICIOUS = ("Shell", "CreateObject", "URLDownloadToFile", "WScript", "PowerShell")
_REL_NS = "{http://schemas.openxmlformats.org/package/2006/relationships}"
_EXTERNAL_LINK_TYPES = (
    "oleobject",
    "frame",
    "subdocument",
    "package",
    "externallinkpath",
    "externallink",
    "control",
)
_URL_RE = re.compile(rb"https?://[^\s\"'<>\\}{)]+", re.IGNORECASE)


@dataclass
class OfficeReport:
    flags: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def add_url(self, url: str) -> None:
        url = url.strip()
        if url.lower().startswith(("http://", "https://", "ftp://")) and url not in self.urls:
            self.urls.append(url)


def is_office_type(mime: str | None) -> bool:
    mime = (mime or "").lower()
    return mime.startswith(OFFICE_MIME_PREFIXES) or mime in RTF_TYPES


# --- Encryption ----------------------------------------------------------------------------------


def _decrypt(data: bytes, passwords: list[str], report: OfficeReport) -> bytes:
    """Return decrypted bytes when ``data`` is an encrypted Office file and a password works."""
    try:
        office = msoffcrypto.OfficeFile(io.BytesIO(data))
        encrypted = office.is_encrypted()
    except Exception:
        return data  # not an Office container msoffcrypto understands
    if not encrypted:
        return data
    for source, candidates in (("body", passwords), ("default", DEFAULT_OFFICE_PASSWORDS)):
        for password in candidates:
            try:
                office = msoffcrypto.OfficeFile(io.BytesIO(data))
                office.load_key(password=password)
                out = io.BytesIO()
                office.decrypt(out)
            except Exception:
                continue
            report.flags.append(
                ("encrypted_office_document", {"decrypted": True, "password_source": source})
            )
            report.info["decrypted_with"] = source
            return out.getvalue()
    report.flags.append(("encrypted_office_document", {"decrypted": False}))
    report.info["decrypted_with"] = None
    return data


# --- Macros ---------------------------------------------------------------------------------------


def _scan_macros(filename: str, data: bytes) -> dict[str, Any]:
    """Run olevba (and mraptor) on the bytes. Returns a plain dict; tests replace this."""
    parser = olevba.VBA_Parser(filename or "document", data=data)
    try:
        has_vba = bool(parser.detect_vba_macros())
        xlm = bool(parser.detect_xlm_macros())
        analysis = (parser.analyze_macros() or []) if (has_vba or xlm) else []
        code = parser.get_vba_code_all_modules() if has_vba else ""
    finally:
        parser.close()
    mraptor = None
    if code:
        raptor = MacroRaptor(code)
        raptor.scan()
        mraptor = {
            "suspicious": bool(raptor.suspicious),
            "autoexec": bool(raptor.autoexec),
            "write": bool(raptor.write),
            "execute": bool(raptor.execute),
        }
    return {
        "vba": has_vba,
        "xlm": xlm,
        "analysis": [(str(t), str(k), str(d)) for t, k, d in analysis],
        "mraptor": mraptor,
    }


def _macro_flags(scan: dict[str, Any], report: OfficeReport) -> None:
    by_type: dict[str, list[str]] = {}
    for kind, keyword, _ in scan["analysis"]:
        values = by_type.setdefault(kind, [])
        if keyword not in values:
            values.append(keyword)
    report.info["macros"] = {
        "vba": scan["vba"],
        "xlm": scan["xlm"],
        "mraptor": scan["mraptor"],
        "keywords": by_type,
    }
    for ioc in by_type.get("IOC", []):
        report.add_url(ioc)
    autoexec = by_type.get("AutoExec", [])
    if scan["vba"] and autoexec:
        report.flags.append(("office_macro_autoexec", {"triggers": autoexec}))
    suspicious = by_type.get("Suspicious", [])
    if scan["vba"] and suspicious:
        key = [k for k in suspicious if any(s.lower() in k.lower() for s in KEY_SUSPICIOUS)]
        report.flags.append(
            (
                "office_macro_suspicious_calls",
                {"keywords": suspicious, "key_calls": key, "mraptor": scan["mraptor"]},
            )
        )
    if scan["xlm"]:
        report.flags.append(("xlm_macro", {"keywords": by_type.get("Suspicious", [])}))


# --- OOXML relationships and embeddings -------------------------------------------------------


def _ooxml_parts(data: bytes, report: OfficeReport) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError):
        return
    with archive:
        names = archive.namelist()
        embedded = [n for n in names if "/embeddings/" in n]
        if embedded:
            report.info["embedded_objects"] = embedded
        external: list[dict[str, str]] = []
        for name in names:
            if not name.endswith(".rels"):
                continue
            info = archive.getinfo(name)
            if info.file_size > MAX_RELS_BYTES:
                report.errors.append(f"{name}: relationships part too large, skipped")
                continue
            try:
                root = ElementTree.fromstring(archive.read(name))
            except ElementTree.ParseError as exc:
                report.errors.append(f"{name}: {exc}")
                continue
            for rel in root.iter(f"{_REL_NS}Relationship"):
                if rel.get("TargetMode", "").lower() != "external":
                    continue
                rel_type = rel.get("Type", "").rsplit("/", 1)[-1]
                target = rel.get("Target", "")
                external.append({"part": name, "type": rel_type, "target": target})
                report.add_url(target)
        report.info["external_relationships"] = external
    for rel in external:
        kind = rel["type"].lower()
        details = {"type": rel["type"], "target": rel["target"], "part": rel["part"]}
        if kind == "attachedtemplate":
            report.flags.append(("remote_template_injection", details))
        elif kind in _EXTERNAL_LINK_TYPES:
            report.flags.append(("office_external_link", details))


def _ole_embedded(data: bytes, report: OfficeReport) -> None:
    """List OLE native streams (embedded packages) in an OLE2 document."""
    import olefile

    if not data.startswith(OLE_MAGIC):
        return
    with olefile.OleFileIO(io.BytesIO(data)) as ole:
        streams = ["/".join(s) for s in ole.listdir()]
    native = [s for s in streams if s.lower().endswith("\x01ole10native")]
    if native:
        report.info["embedded_objects"] = native


# --- RTF -----------------------------------------------------------------------------------------


def _rtf(data: bytes, report: OfficeReport) -> None:
    parser = rtfobj.RtfObjParser(data)
    parser.parse()
    objects = []
    for obj in parser.objects:
        class_name = obj.class_name.decode("latin-1", "replace") if obj.class_name else None
        filename = obj.filename if isinstance(obj.filename, str) else (
            obj.filename.decode("latin-1", "replace") if obj.filename else None
        )
        objects.append(
            {
                "class_name": class_name,
                "is_ole": bool(obj.is_ole),
                "is_package": bool(obj.is_package),
                "filename": filename,
                "equation_editor": bool(class_name and class_name.lower().startswith("equation")),
            }
        )
    report.info["rtf_objects"] = objects
    if objects:
        report.flags.append(("rtf_embedded_object", {"objects": objects}))
    for match in _URL_RE.finditer(data):
        report.add_url(match.group(0).decode("latin-1"))


# --- Entry point ---------------------------------------------------------------------------------


def analyze_office(
    filename: str, data: bytes, mime: str | None, passwords: list[str]
) -> OfficeReport:
    """Analyze one Office or RTF file. Never raises: problems go to ``report.errors``."""
    report = OfficeReport()
    if (mime or "").lower() in RTF_TYPES:
        try:
            _rtf(data, report)
        except Exception as exc:
            report.errors.append(f"rtf: {type(exc).__name__}: {exc}")
        return report
    data = _decrypt(data, passwords, report)
    steps = (
        ("macros", lambda: _macro_flags(_scan_macros(filename, data), report)),
        ("ooxml", lambda: _ooxml_parts(data, report)),
        ("ole", lambda: _ole_embedded(data, report)),
    )
    for name, step in steps:
        try:
            step()
        except Exception as exc:
            report.errors.append(f"{name}: {type(exc).__name__}: {exc}")
    return report
