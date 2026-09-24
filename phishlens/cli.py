"""PhishLens command-line interface (entry point ``phishlens``).

Commands:

- ``phishlens analyze <path> [--format json,csv,stix] [--out reports/] [--no-network]``:
  analyzes an email (.eml/.msg) or any other file (routed by content), shows live per-module
  progress and a summary, and writes the requested report formats.
- ``phishlens analyze-file <path>``: the same, but always treats the input as a standalone file.
- ``phishlens check-config``: which services and optional components are available. Key values
  are never printed.

Everything shown is defanged; finding titles are used as reasons (they carry no indicator
values).
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phishlens import __version__
from phishlens.config import get_settings
from phishlens.ingest.loader import LoaderError, max_input_bytes
from phishlens.ioc.export import to_csv, to_stix_bundle
from phishlens.models import AnalysisReport
from phishlens.pipeline import analyze_file, analyze_input

app = typer.Typer(
    name="phishlens",
    help="Automated phishing email analysis (static analysis only; nothing is executed).",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.callback()
def _setup(
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show library log messages")
    ] = False,
) -> None:
    """Problems are shown in the summary; library log lines only with --verbose."""
    logging.basicConfig(
        level=logging.INFO if verbose else logging.CRITICAL,
        format="%(levelname)s %(name)s: %(message)s",
        force=True,
    )

SUPPORTED_FORMATS = ("json", "csv", "stix")
LATER_FORMATS = ("html", "pdf")
LABEL_STYLE = {"clean": "bold green", "suspicious": "bold yellow", "malicious": "bold red"}
STATUS_STYLE = {
    "pending": "dim",
    "running": "cyan",
    "done": "green",
    "error": "red",
    "skipped": "dim",
}
MODULE_ORDER = ("header", "domain", "tone", "artifacts", "attachments", "urls", "nested", "scoring")


class _ProgressView:
    """A live table of module statuses fed by the pipeline's progress callback."""

    def __init__(self) -> None:
        self.statuses: dict[str, str] = {}

    def update(self, module: str, status: str) -> None:
        self.statuses[module] = status

    def render(self) -> Table:
        table = Table(show_header=False, box=None, padding=(0, 1))
        for module in sorted(self.statuses, key=_module_rank):
            status = self.statuses[module]
            table.add_row(module, Text(status, style=STATUS_STYLE.get(status, "")))
        return table


def _module_rank(module: str) -> int:
    return MODULE_ORDER.index(module) if module in MODULE_ORDER else len(MODULE_ORDER)


def _parse_formats(value: str) -> list[str]:
    formats = [f.strip().lower() for f in value.split(",") if f.strip()]
    unknown = [f for f in formats if f not in SUPPORTED_FORMATS + LATER_FORMATS]
    if unknown:
        raise typer.BadParameter(
            f"unknown format(s): {', '.join(unknown)} "
            f"(choose from {', '.join(SUPPORTED_FORMATS + LATER_FORMATS)})"
        )
    return formats or ["json"]


def _write_reports(report: AnalysisReport, formats: list[str], out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for fmt in formats:
        if fmt in LATER_FORMATS:
            console.print(f"[yellow]{fmt.upper()} reports are not available yet; skipped.[/]")
            continue
        if fmt == "json":
            path = out / f"{report.case_id}.json"
            path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        elif fmt == "csv":
            path = out / f"{report.case_id}.iocs.csv"
            path.write_text(to_csv(report.iocs), encoding="utf-8")
        else:
            path = out / f"{report.case_id}.stix.json"
            bundle = to_stix_bundle(report.iocs, report_name=f"PhishLens case {report.case_id}")
            path.write_text(bundle.serialize(pretty=True), encoding="utf-8")
        written.append(path)
    return written


def _summary(report: AnalysisReport) -> Panel:
    verdict = report.verdict
    assert verdict is not None
    label = verdict.label.value
    header = Text()
    header.append(label.upper(), style=LABEL_STYLE.get(label, "bold"))
    header.append(f"   score {verdict.total_score}/100   confidence {verdict.confidence:.0%}")
    if verdict.overrides_applied:
        header.append(f"\noverrides: {', '.join(verdict.overrides_applied)}", style="dim")

    reasons = Table(title="Top findings", title_justify="left", box=None, padding=(0, 1))
    reasons.add_column("severity")
    reasons.add_column("points", justify="right")
    reasons.add_column("finding")
    for finding in verdict.top_findings:
        reasons.add_row(finding.severity.value, str(finding.score), finding.title)
    if not verdict.top_findings:
        reasons.add_row("-", "0", "no findings")

    counts: dict[str, int] = {}
    for ioc in report.iocs:
        counts[ioc.verdict or "unknown"] = counts.get(ioc.verdict or "unknown", 0) + 1
    ioc_line = Text(
        f"IOCs: {len(report.iocs)}"
        + (" (" + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) + ")" if counts else "")
    )
    mitre = Table(title="MITRE ATT&CK", title_justify="left", box=None, padding=(0, 1))
    for technique in report.mitre:
        mitre.add_row(technique.id, technique.name)
    if not report.mitre:
        mitre.add_row("-", "no techniques mapped")

    errors = [f"{m}: {e}" for m, r in report.results.items() for e in r.errors]
    parts: list = [header, reasons, ioc_line, mitre]
    if errors:
        parts.append(Text("Errors:\n" + "\n".join(errors[:10]), style="red"))
    if report.services_not_configured:
        parts.append(
            Text("Not configured: " + ", ".join(report.services_not_configured), style="dim")
        )
    subject = report.email.subject if report.email else (
        report.file_info.filename if report.file_info else ""
    )
    title = f"PhishLens {report.case_type.value} case"
    return Panel(Group(*parts), title=title, subtitle=subject[:80] or None, expand=False)


def _run(path: Path, formats: str, out: Path, no_network: bool, force_file: bool) -> None:
    wanted = _parse_formats(formats)
    if not path.is_file():
        console.print(f"[red]No such file: {path}[/]")
        raise typer.Exit(1)
    if path.stat().st_size > max_input_bytes():
        console.print(f"[red]{path.name} is larger than MAX_INPUT_SIZE_MB.[/]")
        raise typer.Exit(1)
    data = path.read_bytes()
    view = _ProgressView()

    async def go() -> AnalysisReport:
        network = not no_network
        if force_file:
            return await analyze_file(data, path.name, view.update, network=network)
        return await analyze_input(data, path.name, view.update, network=network)

    try:
        with Live(view.render(), console=console, refresh_per_second=8, transient=True) as live:

            async def refresh_loop(task: asyncio.Task) -> None:
                while not task.done():
                    live.update(view.render())
                    await asyncio.sleep(0.1)

            async def main() -> AnalysisReport:
                task = asyncio.create_task(go())
                await refresh_loop(task)
                return await task

            report = asyncio.run(main())
    except LoaderError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from None
    console.print(_summary(report))
    for written in _write_reports(report, wanted, out):
        console.print(f"Saved {written}")


@app.command()
def analyze(
    path: Annotated[Path, typer.Argument(help="Email (.eml/.msg) or any file to analyze")],
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Comma-separated: json, csv, stix (html, pdf later)"),
    ] = "json",
    out: Annotated[Path, typer.Option("--out", "-o", help="Folder for the reports")] = Path(
        "reports"
    ),
    no_network: Annotated[
        bool, typer.Option("--no-network", help="No DNS, reputation, sandbox or LLM calls")
    ] = False,
) -> None:
    """Analyze an email or a file (routed automatically by content)."""
    _run(path, format, out, no_network, force_file=False)


@app.command("analyze-file")
def analyze_file_command(
    path: Annotated[Path, typer.Argument(help="File to analyze as a standalone file")],
    format: Annotated[str, typer.Option("--format", "-f", help="Comma-separated formats")] = "json",
    out: Annotated[Path, typer.Option("--out", "-o", help="Folder for the reports")] = Path(
        "reports"
    ),
    no_network: Annotated[bool, typer.Option("--no-network")] = False,
) -> None:
    """Analyze a file as a standalone file, even if it looks like an email."""
    _run(path, format, out, no_network, force_file=True)


@app.command("check-config")
def check_config() -> None:
    """Show which services and optional components are available (never key values)."""
    from phishlens.analyzers.filetype import libmagic_available
    from phishlens.analyzers.qr import qr_available
    from phishlens.analyzers.tone_ml import configured_classifiers
    from phishlens.mapping.mitre import ATTACK_DATA_PATH

    settings = get_settings()
    services = Table(title=f"PhishLens {__version__}: services", title_justify="left")
    services.add_column("service")
    services.add_column("status")
    for name, enabled in settings.configured_services().items():
        services.add_row(name, "[green]enabled[/]" if enabled else "[dim]not configured[/]")
    console.print(services)

    components = Table(title="Components and options", title_justify="left")
    components.add_column("component")
    components.add_column("status")
    flags = {
        "libmagic (file types)": libmagic_available(),
        "zbar (QR codes)": qr_available(),
        "MITRE ATT&CK data": ATTACK_DATA_PATH.is_file(),
        "tone ML classifiers": bool(configured_classifiers()),
        "VirusTotal uploads (UPLOAD_FILES_TO_VT)": settings.upload_files_to_vt,
        "Hybrid Analysis uploads": settings.upload_files_to_hybrid_analysis,
        "trusted Authentication-Results servers": bool(settings.trusted_authserv_ids),
    }
    for name, ok in flags.items():
        components.add_row(name, "[green]yes[/]" if ok else "[dim]no[/]")
    components.add_row("scorer", settings.scorer)
    console.print(components)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
