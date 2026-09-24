"""Evaluate PhishLens on a labelled folder of emails.

    python scripts/evaluate.py samples/eval/ --labels samples/eval/labels.csv
    python scripts/evaluate.py tests/fixtures --labels tests/fixtures/eval_labels.csv --no-network

The labels CSV has the columns ``filename``, ``label`` (``phishing`` or ``legit``) and,
optionally, ``manual_verdict`` (``clean`` / ``suspicious`` / ``malicious``, or
``phishing`` / ``legit``) and ``notes``. Every labelled file is analyzed with
``analyze_input``; *Suspicious* counts as phishing unless ``--suspicious-as legit``.

Output: confusion matrix, precision, recall, F1, false positive rate, average processing time,
how often each module's findings appear in correct and wrong verdicts, agreement with
``manual_verdict`` and the misclassified emails with their top findings. ``--tune`` re-scores
the saved results with a grid of threshold pairs (no new analysis) to show the
precision/recall trade-off. An HTML report (charts as embedded PNGs) and a JSON file with the
numbers are written to ``reports/evaluation/``.

``--no-network`` makes no network calls at all; ``--cached-only`` keeps DNS but answers
threat-intel lookups only from the enrichment cache (no new API calls or uploads). Nothing is
executed or rendered: the analysis is the same static pipeline the CLI and API use.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import io
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment

from phishlens import __version__
from phishlens.enrichment.network import cache_only
from phishlens.models import AnalysisReport
from phishlens.pipeline import analyze_input
from phishlens.reporting.safe import Plain, finalize
from phishlens.scoring.rule_scorer import RuleScorer
from phishlens.scoring.weights import Thresholds, scoring_config

PHISHING, LEGIT = "phishing", "legit"
VERDICTS = ("clean", "suspicious", "malicious")
DEFAULT_OUT = Path("reports") / "evaluation"


# --- data ---------------------------------------------------------------------------------------


@dataclass
class Sample:
    filename: str
    label: str
    manual_verdict: str | None = None
    notes: str = ""


@dataclass
class Outcome:
    filename: str
    label: str
    verdict: str | None
    score: int | None
    predicted: str | None
    seconds: float
    manual_verdict: str | None = None
    top_findings: list[str] = field(default_factory=list)
    modules_with_findings: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def correct(self) -> bool:
        return self.predicted == self.label


def load_labels(path: Path) -> list[Sample]:
    """Read the labels CSV. Raises ``ValueError`` for a missing column or an unknown label."""
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        missing = {"filename", "label"} - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"{path}: missing column(s) {', '.join(sorted(missing))}")
        samples = []
        for line, row in enumerate(reader, start=2):
            label = (row.get("label") or "").strip().lower()
            if label not in (PHISHING, LEGIT):
                raise ValueError(f"{path}:{line}: label must be phishing or legit, got {label!r}")
            manual = (row.get("manual_verdict") or "").strip().lower() or None
            if manual and manual not in (*VERDICTS, PHISHING, LEGIT):
                raise ValueError(f"{path}:{line}: unknown manual_verdict {manual!r}")
            samples.append(
                Sample(row["filename"].strip(), label, manual, (row.get("notes") or "").strip())
            )
    return samples


def binary(verdict: str | None, suspicious_as: str = PHISHING) -> str | None:
    """Map a verdict (or a phishing/legit label) to phishing/legit."""
    if verdict in (PHISHING, LEGIT) or verdict is None:
        return verdict
    if verdict == "suspicious":
        return suspicious_as
    return PHISHING if verdict == "malicious" else LEGIT


# --- running ------------------------------------------------------------------------------------


async def analyze_one(path: Path, network: bool) -> tuple[AnalysisReport | None, float, str]:
    start = time.perf_counter()
    try:
        report = await analyze_input(path.read_bytes(), path.name, network=network)
    except Exception as exc:  # a broken sample must not stop the evaluation
        return None, time.perf_counter() - start, f"{type(exc).__name__}: {exc}"
    return report, time.perf_counter() - start, ""


def outcome_for(
    sample: Sample,
    report: AnalysisReport | None,
    seconds: float,
    error: str = "",
    suspicious_as: str = PHISHING,
) -> Outcome:
    verdict = report.verdict if report else None
    label = verdict.label.value if verdict else None
    modules = sorted(
        name for name, result in (report.results if report else {}).items()
        if any(f.score > 0 for f in result.findings)
    )
    return Outcome(
        filename=sample.filename,
        label=sample.label,
        verdict=label,
        score=verdict.total_score if verdict else None,
        predicted=binary(label, suspicious_as),
        seconds=seconds,
        manual_verdict=sample.manual_verdict,
        top_findings=[f.title for f in verdict.top_findings] if verdict else [],
        modules_with_findings=modules,
        error=error or (None if verdict else "no verdict"),
    )


async def run(
    folder: Path,
    samples: list[Sample],
    *,
    network: bool = True,
    cached_only: bool = False,
    suspicious_as: str = PHISHING,
    progress: Any = None,
) -> tuple[list[Outcome], dict[str, AnalysisReport]]:
    """Analyze every sample; returns the outcomes and the reports (for threshold tuning)."""
    outcomes: list[Outcome] = []
    reports: dict[str, AnalysisReport] = {}
    with cache_only(cached_only):
        for index, sample in enumerate(samples, start=1):
            path = folder / sample.filename
            if not path.is_file():
                outcomes.append(outcome_for(sample, None, 0.0, "file not found", suspicious_as))
            else:
                report, seconds, error = await analyze_one(path, network)
                if report is not None:
                    reports[sample.filename] = report
                outcomes.append(outcome_for(sample, report, seconds, error, suspicious_as))
            if progress:
                progress(index, len(samples), outcomes[-1])
    return outcomes, reports


# --- metrics ------------------------------------------------------------------------------------


def confusion(pairs: list[tuple[str, str | None]]) -> dict[str, int]:
    """TP/FP/TN/FN from (label, predicted) pairs; failed analyses are left out."""
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for label, predicted in pairs:
        if predicted is None:
            continue
        if predicted == PHISHING:
            counts["tp" if label == PHISHING else "fp"] += 1
        else:
            counts["fn" if label == PHISHING else "tn"] += 1
    return counts


def _ratio(a: int, b: int) -> float | None:
    return a / b if b else None


def rates(counts: dict[str, int]) -> dict[str, float | None]:
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": _ratio(fp, fp + tn),
        "accuracy": _ratio(tp + tn, tp + fp + tn + fn),
    }


def module_contribution(outcomes: list[Outcome]) -> list[dict[str, Any]]:
    """Per module: in how many correct and wrong verdicts it had findings with points."""
    rows: dict[str, dict[str, Any]] = {}
    for outcome in outcomes:
        if outcome.predicted is None:
            continue
        for module in outcome.modules_with_findings:
            row = rows.setdefault(module, {"module": module, "correct": 0, "wrong": 0})
            row["correct" if outcome.correct else "wrong"] += 1
    for row in rows.values():
        row["share_correct"] = _ratio(row["correct"], row["correct"] + row["wrong"])
    return sorted(rows.values(), key=lambda r: (-(r["correct"] + r["wrong"]), r["module"]))


def manual_agreement(outcomes: list[Outcome], suspicious_as: str = PHISHING) -> dict[str, Any]:
    """Agreement with ``manual_verdict``: exact label when the manual verdict is a label,
    phishing/legit otherwise."""
    compared = agreed = 0
    for outcome in outcomes:
        if not outcome.manual_verdict or outcome.verdict is None:
            continue
        compared += 1
        if outcome.manual_verdict in VERDICTS:
            agreed += outcome.manual_verdict == outcome.verdict
        else:
            agreed += outcome.manual_verdict == binary(outcome.verdict, suspicious_as)
    return {"compared": compared, "agreed": agreed, "rate": _ratio(agreed, compared)}


def summarize(outcomes: list[Outcome], suspicious_as: str = PHISHING) -> dict[str, Any]:
    counts = confusion([(o.label, o.predicted) for o in outcomes])
    analyzed = [o for o in outcomes if o.predicted is not None]
    return {
        "samples": len(outcomes),
        "analyzed": len(analyzed),
        "failed": len(outcomes) - len(analyzed),
        "confusion": counts,
        **rates(counts),
        "avg_seconds": (
            sum(o.seconds for o in analyzed) / len(analyzed) if analyzed else None
        ),
        "verdicts": {v: sum(o.verdict == v for o in outcomes) for v in VERDICTS},
        "modules": module_contribution(outcomes),
        "manual_agreement": manual_agreement(outcomes, suspicious_as),
        "misclassified": [asdict(o) for o in outcomes if o.predicted and not o.correct],
        "errors": [{"filename": o.filename, "error": o.error} for o in outcomes if o.error],
    }


# --- threshold tuning ---------------------------------------------------------------------------


def threshold_grid(step: int = 5) -> list[tuple[int, int]]:
    return [
        (suspicious, malicious)
        for suspicious in range(step, 100, step)
        for malicious in range(suspicious + step, 101, step)
    ]


def tune(
    reports: dict[str, AnalysisReport],
    labels: dict[str, str],
    suspicious_as: str = PHISHING,
    grid: list[tuple[int, int]] | None = None,
) -> list[dict[str, Any]]:
    """Re-score the saved results for every (suspicious, malicious) pair. The pair applies to
    every case type; override rules still apply. No analyzer runs again."""
    base = scoring_config()
    rows = []
    for suspicious, malicious in grid or threshold_grid():
        pair = Thresholds(suspicious=suspicious, malicious=malicious)
        scorer = RuleScorer(
            base.model_copy(update={"thresholds": dict.fromkeys(base.thresholds, pair)})
        )
        pairs = []
        for name, report in reports.items():
            results = {k: r.model_copy(deep=True) for k, r in report.results.items()}
            verdict = scorer.score(results, report.case_type.value)
            pairs.append((labels[name], binary(verdict.label.value, suspicious_as)))
        counts = confusion(pairs)
        rows.append({"suspicious": suspicious, "malicious": malicious, **counts, **rates(counts)})
    return rows


def best_pairs(rows: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    """Best F1 first; ties go to the lower false positive rate, then the higher thresholds."""
    return sorted(
        rows,
        key=lambda r: (
            -(r["f1"] or 0),
            r["false_positive_rate"] if r["false_positive_rate"] is not None else 1,
            -r["suspicious"],
            -r["malicious"],
        ),
    )[:limit]


# --- charts and HTML ----------------------------------------------------------------------------


def _png(figure: Any) -> str:
    import matplotlib.pyplot as plt

    buffer = io.BytesIO()
    figure.savefig(buffer, format="png", dpi=110, bbox_inches="tight")
    plt.close(figure)
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


def charts(summary: dict[str, Any], tuning: list[dict[str, Any]] | None) -> dict[str, str]:
    """Charts as PNG data URIs (matplotlib, headless)."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out: dict[str, str] = {}
    c = summary["confusion"]
    fig, ax = plt.subplots(figsize=(3.6, 3.2))
    grid = [[c["tp"], c["fn"]], [c["fp"], c["tn"]]]
    ax.imshow(grid, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, grid[i][j], ha="center", va="center", fontsize=14)
    ax.set_xticks([0, 1], ["phishing", "legit"])
    ax.set_yticks([0, 1], ["phishing", "legit"])
    ax.set_xlabel("predicted")
    ax.set_ylabel("actual")
    out["confusion"] = _png(fig)

    modules = summary["modules"]
    if modules:
        fig, ax = plt.subplots(figsize=(6, 0.4 * len(modules) + 1))
        names = [m["module"] for m in modules]
        ax.barh(names, [m["correct"] for m in modules], color="#1d7a46", label="correct")
        ax.barh(names, [m["wrong"] for m in modules], left=[m["correct"] for m in modules],
                color="#b3261e", label="wrong")
        ax.invert_yaxis()
        ax.set_xlabel("verdicts where the module had findings")
        ax.legend(loc="lower right")
        out["modules"] = _png(fig)

    points = [r for r in tuning or [] if r["precision"] is not None and r["recall"] is not None]
    if points:
        fig, ax = plt.subplots(figsize=(5, 4))
        ax.scatter([r["recall"] for r in points], [r["precision"] for r in points],
                   c=[r["suspicious"] for r in points], cmap="viridis", s=18)
        for r in best_pairs(points, 3):
            ax.annotate(f"{r['suspicious']}/{r['malicious']}", (r["recall"], r["precision"]),
                        fontsize=8, xytext=(4, 4), textcoords="offset points")
        ax.set_xlabel("recall")
        ax.set_ylabel("precision")
        ax.set_xlim(-0.02, 1.02)
        ax.set_ylim(-0.02, 1.02)
        ax.set_title("threshold pairs (colour: suspicious threshold)")
        out["tuning"] = _png(fig)
    return out


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>PhishLens evaluation</title>
<style>
body{font-family:system-ui,sans-serif;margin:24px auto;max-width:1000px;color:#1f2733;
padding:0 16px}
table{border-collapse:collapse;width:100%;margin:8px 0 20px;font-size:14px}
th,td{border-bottom:1px solid #e3e6ec;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f4f6f9}.metrics{display:flex;flex-wrap:wrap;gap:12px}
.metric{border:1px solid #e3e6ec;border-radius:8px;padding:10px 14px;min-width:120px}
.metric b{display:block;font-size:22px}.muted{color:#5d6778;font-size:13px}
</style></head><body>
<h1>PhishLens evaluation</h1>
<p class="muted">{{ generated }} · PhishLens {{ version }} · {{ s.samples }} samples
({{ s.analyzed }} analyzed, {{ s.failed }} failed) · mode: {{ mode }} ·
suspicious counted as {{ suspicious_as }}</p>
<div class="metrics">
{% for name, value in metrics %}<div class="metric">{{ name }}<b>{{ value }}</b></div>{% endfor %}
</div>
<h2>Confusion matrix</h2>
<img src="{{ charts.confusion }}" alt="confusion matrix">
<table><tr><th></th><th>predicted phishing</th><th>predicted legit</th></tr>
<tr><th>phishing</th><td>{{ s.confusion.tp }} (TP)</td><td>{{ s.confusion.fn }} (FN)</td></tr>
<tr><th>legit</th><td>{{ s.confusion.fp }} (FP)</td><td>{{ s.confusion.tn }} (TN)</td></tr></table>
<p class="muted">Verdicts: {% for v, n in s.verdicts.items() %}{{ v }} {{ n }}{% if not loop.last %}
· {% endif %}{% endfor %}</p>
<h2>Module contribution</h2>
{% if charts.modules %}<img src="{{ charts.modules }}" alt="module contribution">{% endif %}
<table><tr><th>module</th><th>in correct verdicts</th><th>in wrong verdicts</th>
<th>share correct</th></tr>
{% for m in s.modules %}<tr><td>{{ m.module }}</td><td>{{ m.correct }}</td><td>{{ m.wrong }}</td>
<td>{{ pct(m.share_correct) }}</td></tr>{% else %}<tr><td colspan="4">No findings.</td></tr>
{% endfor %}</table>
<h2>Agreement with manual verdicts</h2>
<p>{% if s.manual_agreement.compared %}{{ s.manual_agreement.agreed }} of
{{ s.manual_agreement.compared }} ({{ pct(s.manual_agreement.rate) }}){% else %}No manual
verdicts given.{% endif %}</p>
<h2>Misclassified</h2>
<table><tr><th>file</th><th>label</th><th>verdict</th><th>score</th><th>top findings</th></tr>
{% for o in s.misclassified %}<tr><td>{{ o.filename }}</td><td>{{ o.label }}</td>
<td>{{ o.verdict }}</td><td>{{ o.score }}</td><td>{{ o.top_findings | join("; ") }}</td></tr>
{% else %}<tr><td colspan="5">None.</td></tr>{% endfor %}</table>
{% if s.errors %}<h2>Errors</h2><table><tr><th>file</th><th>error</th></tr>
{% for e in s.errors %}<tr><td>{{ e.filename }}</td><td>{{ e.error }}</td></tr>{% endfor %}
</table>{% endif %}
{% if tuning %}<h2>Threshold tuning</h2>
<p class="muted">Every (suspicious, malicious) pair re-scores the saved results; override rules
still apply. Current thresholds: {{ current }}.</p>
{% if charts.tuning %}<img src="{{ charts.tuning }}" alt="precision/recall trade-off">{% endif %}
<table><tr><th>suspicious</th><th>malicious</th><th>precision</th><th>recall</th><th>F1</th>
<th>FPR</th><th>TP</th><th>FP</th><th>TN</th><th>FN</th></tr>
{% for r in tuning %}<tr{% if r.current %} style="font-weight:600;background:#fdf0d8"{% endif %}>
<td>{{ r.suspicious }}{% if r.current %} (current){% endif %}</td><td>{{ r.malicious }}</td>
<td>{{ pct(r.precision) }}</td><td>{{ pct(r.recall) }}</td><td>{{ pct(r.f1) }}</td>
<td>{{ pct(r.false_positive_rate) }}</td><td>{{ r.tp }}</td><td>{{ r.fp }}</td><td>{{ r.tn }}</td>
<td>{{ r.fn }}</td></tr>{% endfor %}</table>{% endif %}
</body></html>
"""


def tuning_table(rows: list[dict[str, Any]], current: Thresholds) -> list[dict[str, Any]]:
    """The 15 best pairs, plus the current (email) thresholds marked with ``current``."""
    table = [dict(r) for r in best_pairs(rows, 15)]
    now = next(
        (r for r in rows
         if (r["suspicious"], r["malicious"]) == (current.suspicious, current.malicious)),
        None,
    )
    if now is not None:
        match = next((r for r in table if r["suspicious"] == now["suspicious"]
                      and r["malicious"] == now["malicious"]), None)
        if match is None:
            table.append(match := dict(now))
        match["current"] = True
    return table


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


def render_html(
    summary: dict[str, Any],
    tuning: list[dict[str, Any]] | None = None,
    *,
    mode: str = "network",
    suspicious_as: str = PHISHING,
) -> str:
    """The HTML report. Every string goes through the report ``finalize`` hook (escaped and
    defanged); only the embedded chart images are passed through as they are."""
    env = Environment(autoescape=True, finalize=finalize)
    env.globals["pct"] = pct
    thresholds = scoring_config().thresholds
    metrics = [
        ("Precision", pct(summary["precision"])),
        ("Recall", pct(summary["recall"])),
        ("F1", pct(summary["f1"])),
        ("False positive rate", pct(summary["false_positive_rate"])),
        ("Accuracy", pct(summary["accuracy"])),
        ("Avg time / email",
         "n/a" if summary["avg_seconds"] is None else f"{summary['avg_seconds']:.2f}s"),
    ]
    return env.from_string(TEMPLATE).render(
        s=summary,
        metrics=metrics,
        charts={k: Plain(v) for k, v in charts(summary, tuning).items()},
        tuning=tuning_table(tuning, thresholds["email"]) if tuning else None,
        current=", ".join(f"{k} {t.suspicious}/{t.malicious}" for k, t in thresholds.items()),
        generated=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        version=__version__,
        mode=mode,
        suspicious_as=suspicious_as,
    )


# --- CLI ----------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate PhishLens on labelled emails")
    parser.add_argument("folder", type=Path, help="folder with the emails")
    parser.add_argument("--labels", type=Path, required=True, help="labels CSV")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output folder")
    parser.add_argument("--limit", type=int, default=None, help="evaluate only the first N")
    network = parser.add_mutually_exclusive_group()
    network.add_argument("--no-network", action="store_true", help="no network calls at all")
    network.add_argument("--cached-only", action="store_true",
                         help="threat-intel answers from the cache only (no new API calls)")
    parser.add_argument("--suspicious-as", choices=[PHISHING, LEGIT], default=PHISHING,
                        help="how a Suspicious verdict counts (default: phishing)")
    parser.add_argument("--tune", action="store_true",
                        help="also try threshold pairs and show the precision/recall trade-off")
    parser.add_argument("--tune-step", type=int, default=5, help="grid step for --tune")
    args = parser.parse_args(argv)

    try:
        samples = load_labels(args.labels)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.limit is not None:
        samples = samples[: max(0, args.limit)]
    if not samples:
        print("error: no samples to evaluate", file=sys.stderr)
        return 2

    def progress(index: int, total: int, outcome: Outcome) -> None:
        mark = "ok " if outcome.correct else ("ERR" if outcome.predicted is None else "MIS")
        print(f"[{index}/{total}] {mark} {outcome.filename}: {outcome.verdict or outcome.error}",
              file=sys.stderr)

    outcomes, reports = asyncio.run(
        run(
            args.folder,
            samples,
            network=not args.no_network,
            cached_only=args.cached_only,
            suspicious_as=args.suspicious_as,
            progress=progress,
        )
    )
    summary = summarize(outcomes, args.suspicious_as)
    labels = {s.filename: s.label for s in samples}
    tuning = (
        tune(reports, labels, args.suspicious_as, threshold_grid(max(1, args.tune_step)))
        if args.tune
        else None
    )
    mode = "no network" if args.no_network else ("cache only" if args.cached_only else "network")

    args.out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    html_path = args.out / f"evaluation_{stamp}.html"
    json_path = args.out / f"evaluation_{stamp}.json"
    html_path.write_text(
        render_html(summary, tuning, mode=mode, suspicious_as=args.suspicious_as), "utf-8"
    )
    json_path.write_text(
        json.dumps({"summary": summary, "tuning": tuning, "mode": mode}, indent=2, default=str),
        "utf-8",
    )
    c = summary["confusion"]
    print(f"TP {c['tp']}  FP {c['fp']}  TN {c['tn']}  FN {c['fn']}  "
          f"precision {pct(summary['precision'])}  recall {pct(summary['recall'])}  "
          f"F1 {pct(summary['f1'])}  FPR {pct(summary['false_positive_rate'])}")
    print(f"Report: {html_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
