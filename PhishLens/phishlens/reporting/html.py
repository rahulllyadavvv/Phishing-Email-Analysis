"""Render an AnalysisReport as a self-contained HTML page (``templates/report.html``).

The Jinja environment autoescapes everything and uses ``safe.finalize``, which defangs every
value it outputs; only ``Plain`` values (shown unchanged) and ``Link`` values to allowed hosts
(MITRE ATT&CK, urlscan.io) escape defanging.
"""

from __future__ import annotations

from functools import cache

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from phishlens.models import AnalysisReport
from phishlens.reporting.safe import finalize
from phishlens.reporting.view import build_view

__all__ = ["render_html"]


@cache
def _environment() -> Environment:
    return Environment(
        loader=PackageLoader("phishlens.reporting", "templates"),
        autoescape=select_autoescape(["html"]),
        finalize=finalize,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(
    report: AnalysisReport,
    summary: list[str] | None = None,
    recommendations: list[str] | None = None,
) -> str:
    """The report as HTML. ``summary`` / ``recommendations`` default to ``build_summary`` /
    ``build_recommendations``."""
    from phishlens.reporting.summary import build_recommendations, build_summary

    if summary is None:
        summary = build_summary(report)
    if recommendations is None:
        recommendations = build_recommendations(report)
    template = _environment().get_template("report.html")
    return template.render(**build_view(report, summary, recommendations))
