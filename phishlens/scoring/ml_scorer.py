"""Placeholder for a learned scorer (``SCORER=ml``).

It loads a scikit-learn classifier saved with joblib at ``SCORER_MODEL_PATH`` as
``{"model": estimator, "features": [column names]}`` (columns from ``features.feature_columns``,
as written by ``scripts/export_features.py``). The rule scorer still computes module scores, top
findings and overrides; the model's phishing probability x 100 replaces the total score, and the
label is recomputed with the same thresholds (overrides still apply). When the model or
scikit-learn is missing, it falls back to the rule verdict and says so in
``overrides_applied``.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

from phishlens.config import get_settings
from phishlens.models import AnalyzerResult, Verdict, VerdictLabel
from phishlens.scoring.features import features
from phishlens.scoring.rule_scorer import CaseType, RuleScorer
from phishlens.scoring.weights import LABEL_ORDER

__all__ = ["MLScorer", "load_model"]

FALLBACK_NOTE = "ml_scorer_unavailable_used_rules"


@cache
def load_model(path: str) -> dict[str, Any] | None:
    if not Path(path).is_file():
        return None
    try:
        import joblib
    except ImportError:
        return None
    bundle = joblib.load(path)
    if not isinstance(bundle, dict) or "model" not in bundle or "features" not in bundle:
        return None
    return bundle


class MLScorer:
    name = "ml"

    def __init__(self, rules: RuleScorer | None = None) -> None:
        self.rules = rules or RuleScorer()

    def score(self, results: dict[str, AnalyzerResult], case_type: CaseType = "email") -> Verdict:
        verdict = self.rules.score(results, case_type)
        path = get_settings().scorer_model_path
        bundle = load_model(path) if path else None
        if bundle is None:
            return verdict.model_copy(
                update={"overrides_applied": [*verdict.overrides_applied, FALLBACK_NOTE]}
            )
        row = features(results, self.rules.config)
        vector = [[row.get(column, 0.0) for column in bundle["features"]]]
        probability = float(bundle["model"].predict_proba(vector)[0][1])
        total = round(probability * 100)
        label = self.rules.label_for(total, case_type)
        findings = [f for r in results.values() for f in r.findings]
        for _, forced_label in self.rules.fired_overrides(findings):
            if LABEL_ORDER.index(forced_label) > LABEL_ORDER.index(label):
                label = forced_label
        if label != "clean":
            total = max(total, getattr(self.rules.config.thresholds[case_type], label))
        return verdict.model_copy(update={"label": VerdictLabel(label), "total_score": total})
