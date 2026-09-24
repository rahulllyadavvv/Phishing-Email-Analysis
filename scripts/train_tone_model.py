"""Fine-tune a phishing text classifier for the tone analyzer (TONE_MODEL_PATH).

Input: a CSV with columns ``text,label`` (1 = phishing, 0 = legitimate). Text is cleaned (HTML
stripped, zero-width characters removed, whitespace collapsed), empty rows and duplicates are
dropped, and the data is split into stratified train / validation / test sets. The model
(default ``distilbert-base-uncased``) is fine-tuned with the Hugging Face ``Trainer``; the best
epoch (by validation F1) is kept. Precision, recall, F1 and the confusion matrix on the test set
are printed and written to ``metrics.json`` next to the saved model and tokenizer.

Needs the optional ``ml`` dependencies: ``pip install -e ".[ml]"``.

Usage:
    python scripts/train_tone_model.py --csv data.csv [--output models/tone] [--epochs 3]
        [--batch-size 16] [--max-length 256] [--model distilbert-base-uncased]
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup

ZERO_WIDTH_RE = re.compile("[​‌‍⁠﻿­᠎]")
HTML_HINT_RE = re.compile(r"<\s*(html|body|div|p|br|table|a|span)\b", re.IGNORECASE)


@dataclass
class Example:
    text: str
    label: int


def clean_text(text: str) -> str:
    """Strip HTML, remove zero-width characters and collapse whitespace."""
    if HTML_HINT_RE.search(text):
        text = BeautifulSoup(text, "html.parser").get_text(" ")
    text = ZERO_WIDTH_RE.sub("", text)
    return " ".join(text.split())


def load_csv(path: Path) -> tuple[list[Example], dict[str, int]]:
    """Read ``text,label`` rows. Returns the cleaned, de-duplicated examples and counts of
    what was dropped. Raises ValueError for a missing column or a label other than 0/1."""
    csv.field_size_limit(sys.maxsize)
    examples: list[Example] = []
    seen: set[str] = set()
    dropped = {"empty": 0, "duplicate": 0}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = {"text", "label"} - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV is missing column(s): {', '.join(sorted(missing))}")
        for line, row in enumerate(reader, start=2):
            label = str(row["label"]).strip()
            if label not in ("0", "1"):
                raise ValueError(f"line {line}: label must be 0 or 1, got {label!r}")
            text = clean_text(row["text"] or "")
            if not text:
                dropped["empty"] += 1
                continue
            if text in seen:
                dropped["duplicate"] += 1
                continue
            seen.add(text)
            examples.append(Example(text, int(label)))
    return examples, dropped


def stratified_split(
    examples: list[Example], val_size: float, test_size: float, seed: int
) -> tuple[list[Example], list[Example], list[Example]]:
    """Split each class separately so all three sets keep the class balance. Each set gets at
    least one example of a class when that class has 3 or more examples."""
    rng = random.Random(seed)
    train: list[Example] = []
    val: list[Example] = []
    test: list[Example] = []
    for label in (0, 1):
        group = [e for e in examples if e.label == label]
        rng.shuffle(group)
        n_test = round(len(group) * test_size)
        n_val = round(len(group) * val_size)
        if len(group) >= 3:
            n_test, n_val = max(1, n_test), max(1, n_val)
        test += group[:n_test]
        val += group[n_test : n_test + n_val]
        train += group[n_test + n_val :]
    for part in (train, val, test):
        rng.shuffle(part)
    return train, val, test


def binary_metrics(labels: list[int], predictions: list[int]) -> dict[str, Any]:
    """Precision, recall and F1 for the phishing class (1), accuracy and confusion matrix."""
    tp = sum(1 for y, p in zip(labels, predictions, strict=True) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(labels, predictions, strict=True) if y == 0 and p == 1)
    fn = sum(1 for y, p in zip(labels, predictions, strict=True) if y == 1 and p == 0)
    tn = sum(1 for y, p in zip(labels, predictions, strict=True) if y == 0 and p == 0)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    total = len(labels)
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
        "support": total,
        # rows = true label (0, 1), columns = predicted label (0, 1)
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def train(args: argparse.Namespace) -> dict[str, Any]:
    """Fine-tune, evaluate on the test split and save everything to ``args.output``."""
    import numpy as np
    import torch
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
    )

    examples, dropped = load_csv(Path(args.csv))
    labels_present = {e.label for e in examples}
    if labels_present != {0, 1}:
        raise ValueError("the CSV needs both phishing (1) and legitimate (0) examples")
    train_set, val_set, test_set = stratified_split(
        examples, args.val_size, args.test_size, args.seed
    )
    if not val_set or not test_set:
        raise ValueError("too few examples for a validation and a test split")

    torch.manual_seed(args.seed)
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model,
        num_labels=2,
        id2label={0: "legitimate", 1: "phishing"},
        label2id={"legitimate": 0, "phishing": 1},
    )

    class TextDataset(torch.utils.data.Dataset):
        def __init__(self, rows: list[Example]) -> None:
            self.encodings = tokenizer(
                [r.text for r in rows],
                truncation=True,
                max_length=args.max_length,
                padding="max_length",
            )
            self.labels = [r.label for r in rows]

        def __len__(self) -> int:
            return len(self.labels)

        def __getitem__(self, index: int) -> dict[str, Any]:
            item = {k: torch.tensor(v[index]) for k, v in self.encodings.items()}
            item["labels"] = torch.tensor(self.labels[index])
            return item

    def compute_metrics(prediction: Any) -> dict[str, float]:
        predicted = np.argmax(prediction.predictions, axis=-1).tolist()
        scores = binary_metrics(prediction.label_ids.tolist(), predicted)
        return {k: v for k, v in scores.items() if isinstance(v, float)}

    output = Path(args.output)
    training_args = TrainingArguments(
        output_dir=str(output / "checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        save_total_limit=1,
        seed=args.seed,
        logging_steps=10,
        report_to=[],
    )
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=TextDataset(train_set),
        eval_dataset=TextDataset(val_set),
        compute_metrics=compute_metrics,
    )
    trainer.train()

    raw = trainer.predict(TextDataset(test_set))
    predicted = np.argmax(raw.predictions, axis=-1).tolist()
    metrics = {
        "test": binary_metrics([e.label for e in test_set], predicted),
        "splits": {"train": len(train_set), "validation": len(val_set), "test": len(test_set)},
        "dropped": dropped,
        "base_model": args.model,
        "params": {
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "max_length": args.max_length,
            "learning_rate": args.learning_rate,
            "seed": args.seed,
        },
    }
    output.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(output))
    tokenizer.save_pretrained(str(output))
    (output / "metrics.json").write_text(json.dumps(metrics, indent=2))
    shutil.rmtree(output / "checkpoints", ignore_errors=True)  # the best model is saved above
    return metrics


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--csv", required=True, help="CSV with columns text,label")
    parser.add_argument("--output", default="models/tone", help="folder for model + metrics")
    parser.add_argument("--model", default="distilbert-base-uncased", help="base model")
    parser.add_argument("--epochs", type=float, default=3)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--learning-rate", type=float, default=5e-5)
    parser.add_argument("--val-size", type=float, default=0.1)
    parser.add_argument("--test-size", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        metrics = train(args)
    except ImportError:
        print('Missing ML dependencies: pip install -e ".[ml]"', file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    test = metrics["test"]
    print(f"Test precision {test['precision']}  recall {test['recall']}  F1 {test['f1']}")
    print(f"Confusion matrix [[TN, FP], [FN, TP]]: {test['confusion_matrix']}")
    print(f"Saved model and metrics.json to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
