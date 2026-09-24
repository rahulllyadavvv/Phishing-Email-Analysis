"""Scoring: turn analyzer results into a verdict.

``get_scorer()`` returns the configured scorer (``SCORER=rule`` or ``ml``); every scorer has
``score(results, case_type) -> Verdict``.
"""

from __future__ import annotations

from typing import Protocol

from phishlens.config import get_settings
from phishlens.models import AnalyzerResult, Verdict
from phishlens.scoring.ml_scorer import MLScorer
from phishlens.scoring.rule_scorer import CaseType, RuleScorer

__all__ = ["MLScorer", "RuleScorer", "Scorer", "get_scorer"]


class Scorer(Protocol):
    name: str

    def score(
        self, results: dict[str, AnalyzerResult], case_type: CaseType = "email"
    ) -> Verdict: ...


def get_scorer() -> Scorer:
    return MLScorer() if get_settings().scorer == "ml" else RuleScorer()
