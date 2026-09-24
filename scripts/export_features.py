"""Turn saved AnalysisReport JSON files into a feature CSV for training a learned scorer.

One row per report: case_id, case_type, one column per finding ID (its points under the current
weights), module scores (``module:<name>``) and a ``label`` column.

Labels come from ``--labels``, a CSV with columns ``case_id,label`` (label: clean / suspicious /
malicious, or 0/1). Reports without a label get an empty label, unless ``--use-verdict`` is
given, which uses each report's own verdict (weak labels: a model trained on them only learns
to copy the rule scorer).

Usage:
    python scripts/export_features.py reports/ --out features.csv [--labels labels.csv]
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from phishlens.models import AnalysisReport
from phishlens.scoring.features import feature_columns, features


def load_labels(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not {"case_id", "label"} <= set(reader.fieldnames or []):
            raise ValueError("labels CSV needs columns case_id,label")
        return {row["case_id"].strip(): row["label"].strip() for row in reader}


def report_files(inputs: list[Path]) -> list[Path]:
    files: list[Path] = []
    for item in inputs:
        files += sorted(item.rglob("*.json")) if item.is_dir() else [item]
    return files


def export(inputs: list[Path], out: Path, labels: dict[str, str], use_verdict: bool) -> int:
    columns = feature_columns()
    rows = 0
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["case_id", "case_type", *columns, "label"])
        for path in report_files(inputs):
            try:
                report = AnalysisReport.model_validate_json(path.read_text(encoding="utf-8"))
            except ValueError:
                print(f"skipped (not an AnalysisReport): {path}", file=sys.stderr)
                continue
            row = features(report.results)
            label = labels.get(report.case_id, "")
            if not label and use_verdict and report.verdict is not None:
                label = report.verdict.label.value
            writer.writerow(
                [report.case_id, report.case_type.value, *(row[c] for c in columns), label]
            )
            rows += 1
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export scorer features from saved reports")
    parser.add_argument("inputs", nargs="+", type=Path, help="report JSON files or folders")
    parser.add_argument("--out", type=Path, default=Path("features.csv"))
    parser.add_argument("--labels", type=Path, help="CSV with columns case_id,label")
    parser.add_argument(
        "--use-verdict", action="store_true", help="use each report's verdict as its label"
    )
    args = parser.parse_args(argv)
    try:
        count = export(args.inputs, args.out, load_labels(args.labels), args.use_verdict)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {count} rows to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
