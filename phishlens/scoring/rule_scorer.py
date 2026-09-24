"""Rule-based scorer: weighted findings, per-module caps, thresholds and override rules.

Each finding contributes points (``ScoringConfig.weight``), scaled for tone findings (how many
distinct phrases matched, up to the category cap), for ML findings (by probability) and cut
to the severity fallback for findings downgraded by a trusted ARC forward. A module's points
are capped, the total is clamped to 0-100 and mapped to a label with the case type's
thresholds. Override rules can force a minimum label (and raise the score to that label's
threshold). Every finding's ``score`` is set to its contribution.

Confidence is the share of analyzers that ran without errors (skipped ones do not count),
lowered for each key reputation service that is not configured.
"""

from __future__ import annotations

from typing import Literal

from phishlens.config import get_settings
from phishlens.models import AnalyzerResult, Finding, Verdict, VerdictLabel
from phishlens.scoring.weights import LABEL_ORDER, SEVERITIES, ScoringConfig, scoring_config

__all__ = ["CaseType", "RuleScorer", "finding_points"]

CaseType = Literal["email", "file"]
TOP_FINDINGS = 5


def finding_points(finding: Finding, config: ScoringConfig) -> float:
    """Points one finding contributes before module caps."""
    severity = finding.severity.value
    evidence = finding.evidence
    if evidence.get("downgraded_by"):
        return float(config.severity_fallback[severity])
    points = float(config.weight(finding.id, severity))
    counted, cap = evidence.get("counted"), evidence.get("cap")
    if isinstance(counted, int) and isinstance(cap, int) and cap > 0:
        points *= 0.5 + 0.5 * min(counted, cap) / cap
    probability = evidence.get("probability")
    if isinstance(probability, int | float) and 0 <= probability <= 1:
        points *= float(probability)
    return points


class RuleScorer:
    """The default scorer (``SCORER=rule``)."""

    name = "rule"

    def __init__(self, config: ScoringConfig | None = None) -> None:
        self.config = config or scoring_config()

    def label_for(self, total: int, case_type: CaseType) -> str:
        """The label for ``total`` with the case type's thresholds (before overrides)."""
        thresholds = self.config.thresholds[case_type]
        if total >= thresholds.malicious:
            return "malicious"
        if total >= thresholds.suspicious:
            return "suspicious"
        return "clean"

    def fired_overrides(self, findings: list[Finding]) -> list[tuple[str, str]]:
        """(override name, forced label) for every override rule that fires."""
        present = {f.id for f in findings}
        worst = max((SEVERITIES.index(f.severity.value) for f in findings), default=-1)
        fired = []
        for rule in self.config.overrides:
            if rule.any_of:
                hit = bool(present & set(rule.any_of))
            elif rule.all_of:
                hit = set(rule.all_of) <= present
            else:
                hit = worst >= SEVERITIES.index(rule.min_severity or "critical")
            if hit:
                fired.append((rule.name, rule.label))
        return fired

    def _confidence(self, results: dict[str, AnalyzerResult]) -> float:
        cfg = self.config.confidence
        ran = [r for r in results.values() if not r.skipped]
        share = sum(1 for r in ran if not r.errors) / len(ran) if ran else 1.0
        settings = get_settings()
        missing = sum(1 for s in cfg.key_services if not settings.is_enabled(s))
        penalty = min(cfg.max_service_penalty, missing * cfg.penalty_per_missing_service)
        return round(max(cfg.minimum, min(1.0, share - penalty)), 2)

    def score(self, results: dict[str, AnalyzerResult], case_type: CaseType = "email") -> Verdict:
        contributions: list[tuple[float, Finding]] = []
        module_scores: dict[str, int] = {}
        for name, result in results.items():
            raw = 0.0
            for finding in result.findings:
                points = finding_points(finding, self.config)
                finding.score = round(points)
                contributions.append((points, finding))
                raw += points
            cap = self.config.module_caps.get(name)
            module_scores[name] = round(min(raw, cap) if cap is not None else raw)
        total = max(0, min(100, sum(module_scores.values())))
        label = self.label_for(total, case_type)

        applied = []
        thresholds = self.config.thresholds[case_type]
        for name, forced in self.fired_overrides([f for _, f in contributions]):
            applied.append(name)
            if LABEL_ORDER.index(forced) > LABEL_ORDER.index(label):
                label = forced
            floor = getattr(thresholds, label) if label != "clean" else 0
            total = max(total, floor)

        top = sorted(contributions, key=lambda c: (-c[0], c[1].id))[:TOP_FINDINGS]
        return Verdict(
            label=VerdictLabel(label),
            total_score=total,
            confidence=self._confidence(results),
            module_scores=module_scores,
            top_findings=[f.model_copy() for points, f in top if points > 0],
            overrides_applied=applied,
        )

