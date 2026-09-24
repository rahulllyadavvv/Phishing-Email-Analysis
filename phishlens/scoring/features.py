"""Feature vectors for learned scorers: one column per finding ID (its points) plus module
scores. Used by ``scripts/export_features.py`` and ``MLScorer``."""

from __future__ import annotations

from phishlens.models import AnalyzerResult
from phishlens.scoring.rule_scorer import finding_points
from phishlens.scoring.weights import ScoringConfig, scoring_config

__all__ = ["feature_columns", "features"]

MODULES = ("header", "domain", "urls", "attachments", "artifacts", "tone")


def feature_columns(config: ScoringConfig | None = None) -> list[str]:
    """Stable column order: every weighted finding ID, then ``module:<name>`` scores."""
    config = config or scoring_config()
    return sorted(config.weights) + [f"module:{m}" for m in MODULES]


def features(
    results: dict[str, AnalyzerResult], config: ScoringConfig | None = None
) -> dict[str, float]:
    """Summed finding points per finding ID and raw points per module (unknown IDs ignored)."""
    config = config or scoring_config()
    columns = feature_columns(config)
    row = dict.fromkeys(columns, 0.0)
    for name, result in results.items():
        module_total = 0.0
        for finding in result.findings:
            points = finding_points(finding, config)
            module_total += points
            if finding.id in row:
                row[finding.id] += points
        key = f"module:{name}"
        if key in row:
            row[key] += module_total
    return row
