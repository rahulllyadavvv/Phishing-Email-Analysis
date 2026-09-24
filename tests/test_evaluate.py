"""Tests for scripts/evaluate.py (the fake internet from conftest, no real network)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from phishlens.scoring.weights import scoring_config

SCRIPT = Path(__file__).parent.parent / "scripts" / "evaluate.py"
FIXTURES = Path(__file__).parent / "fixtures"
LABELS = FIXTURES / "eval_labels.csv"


def _load():
    spec = importlib.util.spec_from_file_location("evaluate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["evaluate"] = module
    spec.loader.exec_module(module)
    return module


ev = _load()


def _outcome(label: str, verdict: str | None, modules=(), manual=None):
    return ev.Outcome(
        filename=f"{label}-{verdict}.eml", label=label, verdict=verdict, score=0,
        predicted=ev.binary(verdict), seconds=0.5, manual_verdict=manual,
        modules_with_findings=list(modules),
    )


def test_load_labels(tmp_path: Path) -> None:
    samples = ev.load_labels(LABELS)
    assert len(samples) == 14 and samples[0].filename == "clean_newsletter.eml"
    assert samples[0].label == "legit" and samples[1].manual_verdict == "malicious"
    bad = tmp_path / "bad.csv"
    bad.write_text("filename,label\na.eml,spam\n")
    with pytest.raises(ValueError, match="phishing or legit"):
        ev.load_labels(bad)
    bad.write_text("name,label\n")
    with pytest.raises(ValueError, match="missing column"):
        ev.load_labels(bad)


def test_binary_mapping() -> None:
    assert ev.binary("suspicious") == "phishing"
    assert ev.binary("suspicious", "legit") == "legit"
    assert ev.binary("malicious") == "phishing" and ev.binary("clean") == "legit"
    assert ev.binary(None) is None


def test_metrics() -> None:
    outcomes = [
        _outcome("phishing", "malicious", ["header", "urls"], manual="malicious"),
        _outcome("phishing", "suspicious", ["tone"], manual="malicious"),
        _outcome("phishing", "clean", ["header"], manual="phishing"),
        _outcome("legit", "suspicious", ["header"]),
        _outcome("legit", "clean"),
        _outcome("legit", None),  # failed analysis: not counted
    ]
    summary = ev.summarize(outcomes)
    assert summary["confusion"] == {"tp": 2, "fp": 1, "tn": 1, "fn": 1}
    assert summary["precision"] == pytest.approx(2 / 3)
    assert summary["recall"] == pytest.approx(2 / 3)
    assert summary["f1"] == pytest.approx(2 / 3)
    assert summary["false_positive_rate"] == 0.5
    assert summary["failed"] == 1 and summary["avg_seconds"] == 0.5
    header = next(m for m in summary["modules"] if m["module"] == "header")
    assert (header["correct"], header["wrong"]) == (1, 2)
    assert summary["manual_agreement"] == {"compared": 3, "agreed": 1, "rate": pytest.approx(1 / 3)}
    assert len(summary["misclassified"]) == 2
    assert ev.rates({"tp": 0, "fp": 0, "tn": 0, "fn": 0})["precision"] is None


def test_threshold_grid() -> None:
    grid = ev.threshold_grid(25)
    assert (25, 50) in grid and (25, 100) in grid and all(s < m <= 100 for s, m in grid)


def _expected_miss(name: str) -> bool:
    from phishlens.analyzers import qr

    return name == "qr_code.eml" and not qr.qr_available()


async def test_run_on_fixtures(world) -> None:
    samples = ev.load_labels(LABELS)
    outcomes, reports = await ev.run(FIXTURES, samples, network=True)
    wrong = [o.filename for o in outcomes if not o.correct and not _expected_miss(o.filename)]
    assert wrong == []
    assert len(reports) == 14 and all(o.seconds > 0 for o in outcomes)

    # Re-scoring with today's thresholds gives the same verdicts as the analysis.
    current = scoring_config().thresholds["email"]
    labels = {s.filename: s.label for s in samples}
    (row,) = ev.tune(reports, labels, grid=[(current.suspicious, current.malicious)])
    assert {k: row[k] for k in ("tp", "fp", "tn", "fn")} == ev.summarize(outcomes)["confusion"]
    # A very high bar turns most phishing into misses.
    (strict,) = ev.tune(reports, labels, grid=[(95, 100)])
    assert strict["fn"] > row["fn"]


async def test_cached_only_makes_no_new_calls(world, respx_mock) -> None:
    samples = [s for s in ev.load_labels(LABELS) if s.filename == "eicar_attachment.eml"]
    outcomes, _ = await ev.run(FIXTURES, samples, cached_only=True)
    assert outcomes[0].verdict is not None
    assert respx_mock.calls.call_count == 0  # no MalwareBazaar, RDAP, ... requests
    fresh, _ = await ev.run(FIXTURES, samples)
    assert respx_mock.calls.call_count > 0 and fresh[0].verdict == "malicious"


def test_missing_file_is_an_error_not_a_crash(tmp_path: Path) -> None:
    labels = tmp_path / "labels.csv"
    labels.write_text("filename,label\nnope.eml,phishing\n")
    out = tmp_path / "out"
    assert ev.main([str(tmp_path), "--labels", str(labels), "--no-network", "--out",
                    str(out)]) == 0
    data = json.loads(next(out.glob("*.json")).read_text())
    assert data["summary"]["errors"] == [{"filename": "nope.eml", "error": "file not found"}]


def test_main_writes_html_and_json(tmp_path: Path) -> None:
    out = tmp_path / "evaluation"
    code = ev.main([str(FIXTURES), "--labels", str(LABELS), "--no-network", "--limit", "5",
                    "--tune", "--tune-step", "10", "--out", str(out)])
    assert code == 0
    html = next(out.glob("evaluation_*.html")).read_text()
    data = json.loads(next(out.glob("evaluation_*.json")).read_text())
    assert data["summary"]["samples"] == 5 and data["mode"] == "no network"
    assert data["tuning"] and "Threshold tuning" in html and "(current)" in html
    assert html.count("data:image/png;base64,") == 3
    assert "Confusion matrix" in html and "Module contribution" in html
    assert "http://" not in html and "https://" not in html  # nothing clickable or live


def test_main_rejects_bad_labels(tmp_path: Path, capsys) -> None:
    assert ev.main([str(tmp_path), "--labels", str(tmp_path / "missing.csv")]) == 2
    assert "error" in capsys.readouterr().err
