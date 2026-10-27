"""Write a case's reports: HTML, PDF, JSON, IOC CSV, STIX bundle, or all of them in one zip.

Files are named ``<case_id>_<verdict>.<ext>`` (``.html``, ``.pdf``, ``.json``, ``.csv``,
``.stix.json``, ``.zip``). The PDF is rendered by WeasyPrint from the same HTML (page numbers
and repeated table headers come from the template's print CSS); WeasyPrint's URL fetcher is
replaced by one that refuses everything, so rendering never touches the network.

WeasyPrint needs system libraries (Pango). When they are missing, the PDF is skipped with a
reason instead of failing the whole export.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

from phishlens.ioc.export import to_csv, to_stix_bundle
from phishlens.models import AnalysisReport
from phishlens.reporting.html import render_html

__all__ = [
    "FORMATS",
    "GeneratedReports",
    "PdfUnavailableError",
    "generate_report",
    "pdf_available",
    "render_pdf",
]

FORMATS = ("html", "pdf", "json", "csv", "stix", "zip")
EXTENSIONS = {
    "html": "html",
    "pdf": "pdf",
    "json": "json",
    "csv": "csv",
    "stix": "stix.json",
    "zip": "zip",
}


class PdfUnavailableError(RuntimeError):
    """WeasyPrint or its system libraries are not installed."""


@dataclass
class GeneratedReports:
    """``paths``: format -> written file. ``skipped``: format -> reason it was not written."""

    paths: dict[str, Path] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)


@cache
def _weasyprint() -> Any:
    try:
        import weasyprint
    except (ImportError, OSError) as exc:
        return exc
    return weasyprint


def pdf_available() -> bool:
    return not isinstance(_weasyprint(), Exception)


def _no_fetch(url: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    raise ValueError(f"external resources are not loaded in reports: {url[:60]}")


def render_pdf(html: str) -> bytes:
    """PDF bytes for ``html``. Raises ``PdfUnavailableError`` without WeasyPrint."""
    module = _weasyprint()
    if isinstance(module, Exception):
        raise PdfUnavailableError(
            "WeasyPrint cannot load its system libraries (install Pango; see "
            "docs/SETUP_NOTES.md)"
        )
    return module.HTML(string=html, url_fetcher=_no_fetch).write_pdf()


def _name(report: AnalysisReport, fmt: str) -> str:
    label = report.verdict.label.value if report.verdict else "unscored"
    return f"{report.case_id}_{label}.{EXTENSIONS[fmt]}"


def _content(report: AnalysisReport, fmt: str, html: str) -> bytes:
    if fmt == "html":
        return html.encode("utf-8")
    if fmt == "pdf":
        return render_pdf(html)
    if fmt == "json":
        return report.model_dump_json(indent=2).encode("utf-8")
    if fmt == "csv":
        return to_csv(report.iocs).encode("utf-8")
    if fmt == "stix":
        bundle = to_stix_bundle(report.iocs, report_name=f"PhishLens case {report.case_id}")
        return bundle.serialize(pretty=True).encode("utf-8")
    raise ValueError(f"unknown format: {fmt}")


def generate_report(
    report: AnalysisReport, formats: list[str] | tuple[str, ...], out_dir: str | Path
) -> GeneratedReports:
    """Write the requested formats to ``out_dir``. Unknown formats raise ValueError; a format
    that cannot be produced here (PDF without WeasyPrint) is listed in ``skipped``."""
    unknown = [f for f in formats if f not in FORMATS]
    if unknown:
        raise ValueError(f"unknown format(s): {', '.join(unknown)}")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    result = GeneratedReports()
    html = render_html(report)
    contents: dict[str, bytes] = {}
    wanted = [f for f in FORMATS if f in formats]
    members = [f for f in FORMATS if f != "zip"] if "zip" in wanted else []
    for fmt in dict.fromkeys([*wanted, *members]):
        if fmt == "zip":
            continue
        try:
            contents[fmt] = _content(report, fmt, html)
        except PdfUnavailableError as exc:
            result.skipped[fmt] = str(exc)
    for fmt in wanted:
        path = out / _name(report, fmt)
        if fmt == "zip":
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for member, data in contents.items():
                    archive.writestr(_name(report, member), data)
        elif fmt in contents:
            path.write_bytes(contents[fmt])
        else:
            continue
        result.paths[fmt] = path
    return result
