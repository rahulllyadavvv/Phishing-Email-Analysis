"""Optional machine-learning layer for the tone analyzer.

``ToneClassifier`` is the interface: ``classify(text)`` returns a ``ToneScore`` with the
probability that the text is phishing, an optional rationale and extra details. Two
implementations, both disabled unless configured:

- ``LocalTransformerClassifier``: a Hugging Face text-classification model in
  ``TONE_MODEL_PATH`` (optional ``ml`` dependencies: transformers + torch). Runs locally.
- ``LLMClassifier``: Claude via ``enrichment.llm.assess_tone`` (``LLM_TONE_ENABLED`` +
  ``LLM_API_KEY``). Sends the email text to a third party.

``configured_classifiers()`` returns the ones that can run; with nothing configured the tone
analyzer simply skips this layer.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any, Protocol

from phishlens.config import get_settings
from phishlens.enrichment import llm

__all__ = [
    "LLMClassifier",
    "LocalTransformerClassifier",
    "ToneClassifier",
    "ToneScore",
    "configured_classifiers",
]

# Labels a fine-tuned model may use for the phishing and the legitimate class.
PHISHING_LABELS = frozenset({"label_1", "1", "phishing", "phish", "spam", "malicious"})
LEGIT_LABELS = frozenset({"label_0", "0", "legitimate", "legit", "ham", "benign", "safe"})


@dataclass
class ToneScore:
    probability: float
    rationale: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class ToneClassifier(Protocol):
    name: str

    async def classify(self, text: str) -> ToneScore: ...


@cache
def _pipeline(model_path: str) -> Any:
    from transformers import pipeline  # optional dependency

    return pipeline("text-classification", model=model_path, tokenizer=model_path, top_k=None)


class LocalTransformerClassifier:
    """A fine-tuned Hugging Face model (for example from scripts/train_tone_model.py)."""

    name = "local_model"

    def __init__(self, model_path: str) -> None:
        self.model_path = model_path

    @staticmethod
    def available(model_path: str | None) -> bool:
        if not model_path or not Path(model_path).is_dir():
            return False
        try:
            import torch  # noqa: F401
            import transformers  # noqa: F401
        except ImportError:
            return False
        return True

    def _run(self, text: str) -> ToneScore:
        scores = _pipeline(self.model_path)(text, truncation=True)
        if scores and isinstance(scores[0], list):
            scores = scores[0]
        by_label = {str(s["label"]).lower(): float(s["score"]) for s in scores}
        phishing = [v for k, v in by_label.items() if k in PHISHING_LABELS]
        legit = [v for k, v in by_label.items() if k in LEGIT_LABELS]
        if phishing:
            probability = phishing[0]
        elif legit:
            probability = 1.0 - legit[0]
        else:
            raise ValueError(f"model labels not recognised: {sorted(by_label)}")
        return ToneScore(probability, details={"labels": by_label, "model": self.model_path})

    async def classify(self, text: str) -> ToneScore:
        return await asyncio.to_thread(self._run, text)


class LLMClassifier:
    """Claude tone assessment. The probability is the strongest pressure score / 10."""

    name = "llm"

    async def classify(self, text: str) -> ToneScore:
        assessment, meta = await llm.assess_tone(text)
        strongest = max(assessment.urgency, assessment.greed, assessment.fear)
        return ToneScore(
            probability=strongest / 10,
            rationale=assessment.rationale,
            details={**assessment.model_dump(), **meta},
        )


def configured_classifiers() -> list[ToneClassifier]:
    settings = get_settings()
    classifiers: list[ToneClassifier] = []
    if LocalTransformerClassifier.available(settings.tone_model_path):
        classifiers.append(LocalTransformerClassifier(str(settings.tone_model_path)))
    if llm.llm_enabled():
        classifiers.append(LLMClassifier())
    return classifiers
