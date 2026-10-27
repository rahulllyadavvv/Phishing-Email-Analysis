"""Tests for scripts/train_tone_model.py (the parts that need no ML libraries)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "train_tone_model.py"
spec = importlib.util.spec_from_file_location("train_tone_model", SCRIPT)
tm = importlib.util.module_from_spec(spec)
sys.modules["train_tone_model"] = tm  # dataclasses look their module up here
spec.loader.exec_module(tm)


def _write(tmp_path: Path, rows: list[tuple[str, str]], header: str = "text,label") -> Path:
    import csv

    path = tmp_path / "data.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header.split(","))
        writer.writerows(rows)
    return path


def test_clean_text() -> None:
    assert tm.clean_text("<p>Verify <b>now</b></p>\n\n") == "Verify now"
    assert tm.clean_text("pay​pal   login\n") == "paypal login"
    assert tm.clean_text("5 < 6 and plain text") == "5 < 6 and plain text"


def test_load_csv_cleans_and_deduplicates(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        [
            ("Verify your account", "1"),
            ("verify   your account", "1"),  # different case: kept
            ("Verify your account", "1"),  # exact duplicate
            ("   ", "0"),
            ("Lunch at noon?", "0"),
            ("multi\nline, with \"quotes\"", "0"),
        ],
    )
    examples, dropped = tm.load_csv(path)
    assert [e.label for e in examples] == [1, 1, 0, 0]
    assert dropped == {"empty": 1, "duplicate": 1}
    assert examples[-1].text == 'multi line, with "quotes"'


@pytest.mark.parametrize(
    ("rows", "header", "message"),
    [
        ([("x", "1")], "body,label", "missing column"),
        ([("x", "yes")], "text,label", "label must be 0 or 1"),
    ],
)
def test_load_csv_rejects_bad_input(tmp_path, rows, header, message) -> None:
    with pytest.raises(ValueError, match=message):
        tm.load_csv(_write(tmp_path, rows, header))


def test_stratified_split_keeps_balance_and_is_deterministic() -> None:
    examples = [tm.Example(f"p{i}", 1) for i in range(30)] + [
        tm.Example(f"l{i}", 0) for i in range(70)
    ]
    train, val, test = tm.stratified_split(examples, 0.1, 0.2, seed=7)
    assert (len(train), len(val), len(test)) == (70, 10, 20)
    assert sum(e.label for e in test) == 6 and sum(e.label for e in val) == 3
    assert {e.text for e in train} | {e.text for e in val} | {e.text for e in test} == {
        e.text for e in examples
    }
    again = tm.stratified_split(examples, 0.1, 0.2, seed=7)
    assert [e.text for e in again[2]] == [e.text for e in test]


def test_small_classes_still_reach_every_split() -> None:
    examples = [tm.Example(f"p{i}", 1) for i in range(3)] + [
        tm.Example(f"l{i}", 0) for i in range(3)
    ]
    train, val, test = tm.stratified_split(examples, 0.1, 0.1, seed=1)
    for part in (train, val, test):
        assert {e.label for e in part} == {0, 1}


def test_binary_metrics() -> None:
    metrics = tm.binary_metrics([1, 1, 1, 0, 0, 0], [1, 1, 0, 0, 0, 1])
    assert metrics["confusion_matrix"] == [[2, 1], [1, 2]]
    assert metrics["precision"] == metrics["recall"] == metrics["f1"] == pytest.approx(0.6667)
    assert metrics["accuracy"] == pytest.approx(0.6667)
    assert tm.binary_metrics([0, 0], [0, 0])["f1"] == 0.0


def test_main_reports_bad_csv(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    path = _write(tmp_path, [("only phishing", "1"), ("more phishing", "1")])
    pytest.importorskip("transformers")
    assert tm.main(["--csv", str(path), "--output", str(tmp_path / "out")]) == 1
    assert "both phishing (1) and legitimate (0)" in capsys.readouterr().err


def test_parse_args_defaults() -> None:
    args = tm.parse_args(["--csv", "x.csv"])
    assert (args.model, args.epochs, args.batch_size, args.max_length) == (
        "distilbert-base-uncased",
        3,
        16,
        256,
    )
    assert args.output == "models/tone"
