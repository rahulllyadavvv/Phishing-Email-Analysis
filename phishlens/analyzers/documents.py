"""Static analysis of PDF, HTML and SVG files (helpers for the attachment analyzer).

Nothing is rendered, displayed or executed: PDFs are parsed with pypdf (object tree only), HTML
and SVG are parsed as text with BeautifulSoup and regular expressions.

PDF: JavaScript, automatic actions (/OpenAction with an action, /AA), /Launch, embedded files,
/URI links, and QR codes in embedded images (when zbar is installed).

HTML/SVG: HTML smuggling (a file built in the browser from an embedded blob and offered as a
download), credential forms (password fields, forms posting elsewhere), scripts in SVG images,
and obfuscated script. Links, form targets and redirects are collected as URLs.
"""

from __future__ import annotations

import io
import re
from typing import Any

from bs4 import BeautifulSoup
from pypdf import PdfReader
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject

from phishlens.analyzers.office import OfficeReport as ContentReport
from phishlens.analyzers.qr import decode_qr, qr_available

__all__ = ["ContentReport", "analyze_html", "analyze_pdf", "is_html_type", "is_pdf_type"]

MAX_PDF_NODES = 50_000
MAX_QR_PAGES = 20
MAX_QR_IMAGES = 50
LONG_BASE64 = 200  # characters; a string this long inside script is a hidden payload
HTML_TYPES = frozenset({"text/html", "image/svg+xml", "application/xhtml+xml"})

_URL_ATTRS = ("href", "src", "action", "data", "xlink:href", "formaction")
_B64_RE = re.compile(rf"[A-Za-z0-9+/]{{{LONG_BASE64},}}={{0,2}}")
_HEX_ESCAPES_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}|(?:%[0-9a-fA-F]{2}){40,}")
_JS_URL_RE = re.compile(
    r"""(?:location(?:\.href)?|window\.open)\s*(?:=|\()\s*["'](https?://[^"']+)["']""",
    re.IGNORECASE,
)
_META_REFRESH_RE = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.IGNORECASE)
_SMUGGLING = {
    "blob": re.compile(r"new\s+Blob\s*\(|msSaveOrOpenBlob|msSaveBlob", re.IGNORECASE),
    "object_url": re.compile(r"createObjectURL|msSaveOrOpenBlob|msSaveBlob", re.IGNORECASE),
    "download": re.compile(
        r"\.download\s*=|\bdownload\s*=|\.setAttribute\(\s*['\"]download", re.IGNORECASE
    ),
    # Old Edge/IE API that saves a blob to disk by itself (blob + object URL + download in one).
    "ms_save": re.compile(r"msSaveOrOpenBlob|msSaveBlob", re.IGNORECASE),
    "decode": re.compile(r"\batob\s*\(|Uint8Array|fromCharCode", re.IGNORECASE),
}
_OBFUSCATION = {
    "eval": re.compile(r"\beval\s*\("),
    "unescape": re.compile(r"\bunescape\s*\("),
    "function_constructor": re.compile(r"\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"]"),
    "document_write": re.compile(r"document\.write\s*\("),
}


def is_pdf_type(mime: str | None) -> bool:
    return (mime or "").lower() == "application/pdf"


def is_html_type(mime: str | None) -> bool:
    return (mime or "").lower() in HTML_TYPES


# --- PDF -----------------------------------------------------------------------------------------


def _walk_pdf(reader: PdfReader) -> tuple[dict[str, list[Any]], list[str]]:
    """Visit every object reachable from the trailer. Returns key -> values and URIs."""
    seen_refs: set[tuple[int, int]] = set()
    keys: dict[str, list[Any]] = {}
    uris: list[str] = []
    stack: list[Any] = [reader.trailer]
    nodes = 0
    while stack and nodes < MAX_PDF_NODES:
        node = stack.pop()
        nodes += 1
        if isinstance(node, IndirectObject):
            ref = (node.idnum, node.generation)
            if ref in seen_refs:
                continue
            seen_refs.add(ref)
            try:
                node = node.get_object()
            except Exception:
                continue
        if isinstance(node, DictionaryObject):
            for key, value in node.items():
                keys.setdefault(str(key), []).append(value)
                if key == "/URI":
                    try:
                        uri = value.get_object()
                        uris.append(str(uri))
                    except Exception:
                        pass
                stack.append(value)
        elif isinstance(node, ArrayObject):
            stack.extend(node)
    return keys, uris


def _action_type(value: Any) -> str | None:
    try:
        obj = value.get_object() if isinstance(value, IndirectObject) else value
    except Exception:
        return None
    if isinstance(obj, DictionaryObject) and "/S" in obj:
        return str(obj["/S"])
    return None


def _pdf_qr(reader: PdfReader, report: ContentReport) -> None:
    if not qr_available():
        report.info["qr_decoding"] = "unavailable (zbar not installed)"
        return
    decoded = 0
    for page in list(reader.pages)[:MAX_QR_PAGES]:
        try:
            images = list(page.images)
        except Exception:
            continue
        for image in images:
            if decoded >= MAX_QR_IMAGES:
                return
            decoded += 1
            for text in decode_qr(image.data):
                if text not in report.qr_urls:
                    report.qr_urls.append(text)


def analyze_pdf(data: bytes) -> ContentReport:
    """Static PDF analysis. Never raises: problems go to ``report.errors``."""
    report = ContentReport()
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            report.info["encrypted"] = True
            if not reader.decrypt(""):
                report.errors.append("pdf: encrypted with a user password, not analyzed")
                return report
        keys, uris = _walk_pdf(reader)
    except Exception as exc:
        report.errors.append(f"pdf: {type(exc).__name__}: {exc}")
        return report

    report.info["pages"] = len(reader.pages)
    actions: list[str] = []
    for value in keys.get("/OpenAction", []):
        action = _action_type(value)
        if action:  # a plain destination (page + zoom) is harmless
            actions.append(f"OpenAction:{action}")
    for value in keys.get("/AA", []):
        try:
            triggers = value.get_object()
        except Exception:
            continue
        if isinstance(triggers, DictionaryObject):
            actions += [f"AA{k}:{_action_type(v) or '?'}" for k, v in triggers.items()]
    action_types = {
        str(v) for s in keys.get("/S", []) for v in [s] if isinstance(s, NameObject)
    }
    has_js = "/JS" in keys or "/JavaScript" in keys or "/JavaScript" in action_types
    if has_js:
        report.flags.append(("pdf_javascript", {"keys": sorted(k for k in ("/JS", "/JavaScript")
                                                                  if k in keys)}))
    if actions:
        report.flags.append(("pdf_auto_action", {"actions": actions}))
    if "/Launch" in keys or "/Launch" in action_types:
        targets = [str(v) for v in keys.get("/F", [])][:10]
        report.flags.append(("pdf_launch_action", {"targets": targets}))
    if "/EmbeddedFile" in keys or "/EmbeddedFiles" in keys:
        try:
            names = list(reader.attachments)
        except Exception:
            names = []
        report.flags.append(("pdf_embedded_file", {"names": names}))
        report.info["embedded_files"] = names
    for uri in uris:
        report.add_url(uri)
    _pdf_qr(reader, report)
    return report


# --- HTML / SVG ---------------------------------------------------------------------------------


def _decode_text(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def analyze_html(data: bytes, mime: str | None = None) -> ContentReport:
    """Static HTML/SVG analysis. Never raises: problems go to ``report.errors``."""
    report = ContentReport()
    try:
        text = _decode_text(data)
        soup = BeautifulSoup(text, "html.parser")
    except Exception as exc:
        report.errors.append(f"html: {type(exc).__name__}: {exc}")
        return report
    scripts = "\n".join(s.get_text() for s in soup.find_all("script"))
    handlers = " ".join(
        str(value)
        for tag in soup.find_all(True)
        for name, value in tag.attrs.items()
        if name.lower().startswith("on")
    )
    code = scripts + "\n" + handlers
    is_svg = (mime or "").lower() == "image/svg+xml" or soup.find("svg") is not None

    smuggling = [name for name, rx in _SMUGGLING.items() if rx.search(code)]
    large_payload = bool(_B64_RE.search(code))
    if large_payload:
        smuggling.append("large_encoded_payload")
    if "ms_save" in smuggling or (
        "blob" in smuggling
        and "object_url" in smuggling
        and ("download" in smuggling or large_payload or "decode" in smuggling)
    ):
        report.flags.append(("html_smuggling", {"patterns": smuggling}))

    forms = soup.find_all("form")
    password_fields = soup.find_all("input", attrs={"type": re.compile("^password$", re.I)})
    external_actions = [
        str(f.get("action")) for f in forms
        if str(f.get("action") or "").lower().startswith(("http://", "https://"))
    ]
    if password_fields or external_actions:
        report.flags.append(
            (
                "credential_form_attachment",
                {
                    "password_fields": len(password_fields),
                    "form_actions": external_actions,
                },
            )
        )

    if is_svg and (scripts.strip() or handlers.strip() or "javascript:" in text.lower()):
        report.flags.append(("svg_script", {"script_tags": len(soup.find_all("script")),
                                            "event_handlers": bool(handlers.strip())}))

    obfuscation = [name for name, rx in _OBFUSCATION.items() if rx.search(code)]
    if large_payload:
        obfuscation.append("long_base64")
    if _HEX_ESCAPES_RE.search(code):
        obfuscation.append("hex_escapes")
    if obfuscation:
        report.flags.append(("obfuscated_script", {"techniques": obfuscation}))

    for tag in soup.find_all(True):
        for attr in _URL_ATTRS:
            value = tag.get(attr)
            if isinstance(value, str):
                report.add_url(value)
        if tag.name == "meta" and str(tag.get("http-equiv", "")).lower() == "refresh":
            match = _META_REFRESH_RE.search(str(tag.get("content", "")))
            if match:
                report.add_url(match.group(1))
    for match in _JS_URL_RE.finditer(code):
        report.add_url(match.group(1))
    report.info["forms"] = len(forms)
    report.info["scripts"] = len(soup.find_all("script"))
    return report
