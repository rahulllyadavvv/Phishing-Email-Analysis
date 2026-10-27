"""Scoring configuration (``data/weights.yaml``), loaded once and validated."""

from __future__ import annotations

from functools import cache
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from phishlens.data_loader import load_yaml

__all__ = ["LABEL_ORDER", "SEVERITIES", "Override", "ScoringConfig", "scoring_config"]

SEVERITIES = ("info", "low", "medium", "high", "critical")
LABEL_ORDER = ("clean", "suspicious", "malicious")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Thresholds(_Model):
    suspicious: int
    malicious: int

    @model_validator(mode="after")
    def _ordered(self) -> Thresholds:
        if not 0 < self.suspicious < self.malicious <= 100:
            raise ValueError("thresholds must satisfy 0 < suspicious < malicious <= 100")
        return self


class Override(_Model):
    name: str
    label: Literal["suspicious", "malicious"]
    any_of: tuple[str, ...] = ()
    all_of: tuple[str, ...] = ()
    min_severity: Literal["low", "medium", "high", "critical"] | None = None

    @model_validator(mode="after")
    def _one_condition(self) -> Override:
        given = sum(bool(x) for x in (self.any_of, self.all_of, self.min_severity))
        if given != 1:
            raise ValueError(
                f"override {self.name}: give exactly one of any_of/all_of/min_severity"
            )
        return self


class ConfidenceConfig(_Model):
    key_services: tuple[str, ...] = ()
    penalty_per_missing_service: float = 0.1
    max_service_penalty: float = 0.3
    minimum: float = 0.1


class ScoringConfig(_Model):
    severity_fallback: dict[str, int]
    module_caps: dict[str, int] = {}
    thresholds: dict[Literal["email", "file"], Thresholds]
    overrides: tuple[Override, ...] = ()
    confidence: ConfidenceConfig = ConfidenceConfig()
    weights: dict[str, int | dict[str, int]] = {}

    @field_validator("severity_fallback")
    @classmethod
    def _all_severities(cls, value: dict[str, int]) -> dict[str, int]:
        missing = set(SEVERITIES) - set(value)
        if missing:
            raise ValueError(f"severity_fallback misses {sorted(missing)}")
        return value

    @field_validator("weights")
    @classmethod
    def _known_severities(cls, value: dict[str, int | dict[str, int]]) -> dict:
        for finding_id, weight in value.items():
            if isinstance(weight, dict) and set(weight) - set(SEVERITIES):
                raise ValueError(f"{finding_id}: unknown severity in {sorted(weight)}")
        return value

    def weight(self, finding_id: str, severity: str) -> int:
        """Points for one finding before scaling."""
        weight = self.weights.get(finding_id)
        if isinstance(weight, int):
            return weight
        if isinstance(weight, dict) and severity in weight:
            return weight[severity]
        return self.severity_fallback[severity]


@cache
def scoring_config() -> ScoringConfig:
    return ScoringConfig.model_validate(load_yaml("weights.yaml"))
