"""Tests for phishlens.scoring (rule scorer, config, features, ML placeholder, export)."""

from __future__ import annotations

import csv
import importlib.util
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from phishlens.config import get_settings
from phishlens.models import AnalysisReport, AnalyzerResult, Finding, Severity
from phishlens.scoring import MLScorer, RuleScorer, get_scorer
from phishlens.scoring.features import feature_columns, features
from phishlens.scoring.rule_scorer import finding_points
from phishlens.scoring.weights import Override, ScoringConfig, scoring_config

KEYS = ("VIRUSTOTAL_API_KEY", "GOOGLE_SAFEBROWSING_API_KEY", "ABUSECH_API_KEY")


@pytest.fixture(autouse=True)
def all_key_services(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure the key services so confidence is only about analyzer errors by default."""
    for key in KEYS:
        monkeypatch.setenv(key, "fake")
    monkeypatch.delenv("SCORER", raising=False)
    monkeypatch.delenv("SCORER_MODEL_PATH", raising=False)
    get_settings.cache_clear()


def _f(finding_id: str, severity: str = "high", **evidence) -> Finding:
    return Finding(
        id=finding_id, module="m", title=finding_id, severity=Severity(severity), evidence=evidence
    )


def _results(**modules: list[Finding]) -> dict[str, AnalyzerResult]:
    return {name: AnalyzerResult(module=name, findings=f) for name, f in modules.items()}


def _score(case_type: str = "email", **modules: list[Finding]):
    return RuleScorer().score(_results(**modules), case_type)


# --- Config --------------------------------------------------------------------------------------


def test_every_finding_id_in_the_code_has_a_weight() -> None:
    """Each analyzer's findings are weighted explicitly (not just the severity fallback)."""
    import re

    ids = set()
    for path in Path("phishlens").rglob("*.py"):
        text = path.read_text()
        ids |= set(re.findall(r'^\s{4}"([a-z0-9]+(?:_[a-z0-9]+)+)": \(\s*$', text, re.M))
        ids |= set(re.findall(r'_finding\(\s*"([a-z0-9_]+)"', text))
        ids |= set(re.findall(r'flags\.append\(\s*\(\s*"([a-z0-9_]+)"', text))
    from phishlens.data_loader import lexicons

    ids |= {lexicon.finding_id for lexicon in lexicons().values()}
    from phishlens.analyzers.header import _WARNING_FINDINGS

    ids -= set(_WARNING_FINDINGS)  # parser warning codes, mapped to the finding IDs below
    ids |= {finding_id for finding_id, _, _ in _WARNING_FINDINGS.values()}
    assert ids, "no finding IDs found"
    assert ids <= set(scoring_config().weights), sorted(ids - set(scoring_config().weights))


def test_weight_lookup() -> None:
    config = scoring_config()
    assert config.weight("auth_but_unaligned", "critical") == 45
    assert config.weight("brand_impersonation", "medium") == 15
    assert config.weight("brand_impersonation", "low") == 5  # missing in the map: fallback
    assert config.weight("never_heard_of_it", "critical") == 50


def test_invalid_config() -> None:
    base = scoring_config().model_dump()
    with pytest.raises(ValidationError):
        ScoringConfig.model_validate({**base, "severity_fallback": {"low": 5}})
    with pytest.raises(ValidationError):
        ScoringConfig.model_validate(
            {**base, "thresholds": {"email": {"suspicious": 70, "malicious": 60}}}
        )
    with pytest.raises(ValidationError):
        Override(name="x", label="malicious")
    with pytest.raises(ValidationError):
        Override(name="x", label="malicious", any_of=["a"], min_severity="high")


# --- Points and scaling --------------------------------------------------------------------------


def test_tone_scaling_by_counted_matches() -> None:
    config = scoring_config()
    one = finding_points(_f("tone_urgency", "medium", counted=1, cap=5), config)
    full = finding_points(_f("tone_urgency", "medium", counted=5, cap=5), config)
    assert (one, full) == (pytest.approx(12 * 0.6), 12)


def test_ml_probability_scaling() -> None:
    finding = _f("ml_phishing_probability_high", "high", probability=0.9)
    points = finding_points(finding, scoring_config())
    assert points == pytest.approx(27)


def test_arc_downgraded_findings_use_the_low_fallback() -> None:
    config = scoring_config()
    normal = finding_points(_f("auth_but_unaligned", "critical"), config)
    downgraded = finding_points(
        _f("auth_but_unaligned", "low", downgraded_by="arc_trusted_forward"), config
    )
    assert (normal, downgraded) == (45, 5)
    verdict = _score(
        header=[
            _f("auth_but_unaligned", "low", downgraded_by="arc_trusted_forward"),
            _f("dmarc_fail", "low", downgraded_by="arc_trusted_forward"),
            _f("arc_trusted_forward", "info"),
        ]
    )
    assert verdict.label == "clean" and verdict.total_score == 10


# --- Thresholds and caps -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("case_type", "findings", "label", "score"),
    [
        ("email", [_f("replyto_mismatch", "medium"), _f("returnpath_mismatch", "low")],
         "clean", 20),
        ("email", [_f("display_name_brand_spoof")], "suspicious", 30),
        ("email", [_f("lookalike_domain"), _f("replyto_free_webmail")], "suspicious", 50),
        ("file", [_f("replyto_mismatch", "medium")], "clean", 15),
        ("file", [_f("display_name_brand_spoof")], "suspicious", 30),
    ],
)
def test_thresholds(case_type, findings, label, score) -> None:
    verdict = _score(case_type, domain=findings)
    assert (verdict.label, verdict.total_score) == (label, score)


def test_malicious_by_score_and_file_thresholds() -> None:
    findings = {"urls": [_f("link_text_mismatch"), _f("credential_keywords", "low")]}
    assert _score("email", **findings).total_score == 35
    assert _score("email", **findings).label == "suspicious"
    findings["tone"] = [_f("credential_request", "high", counted=5, cap=5)]
    findings["domain"] = [_f("replyto_free_webmail")]
    verdict = _score("email", **findings)
    assert (verdict.total_score, verdict.label) == (80, "malicious")
    edge = _score("email", urls=[_f("link_text_mismatch"), _f("brand_in_unrelated_domain")])
    assert (edge.total_score, edge.label) == (60, "malicious")  # the threshold is inclusive
    attachments = [_f("double_extension"), _f("high_risk_file_type", "medium")]
    assert _score("file", attachments=attachments).label == "malicious"  # 55 >= 50
    assert _score("email", attachments=attachments).label == "suspicious"


def test_module_caps_and_total_clamp() -> None:
    verdict = _score(
        artifacts=[_f("script_in_body"), _f("hidden_text"), _f("encoded_link"), _f("meta_refresh")],
        attachments=[_f("attachment_known_malicious", "critical"), _f("double_extension")],
    )
    assert verdict.module_scores["artifacts"] == 25  # 70 raw, capped
    assert verdict.module_scores["attachments"] == 70  # 110 raw, capped
    assert verdict.total_score == 95
    huge = _score(**{m: [_f("auth_but_unaligned", "critical")] * 3 for m in
                     ("header", "domain", "urls", "attachments")})
    assert huge.total_score == 100


def test_top_findings_and_scores_are_set() -> None:
    findings = [_f("tracking_pixel", "low"), _f("lookalike_domain"), _f("spf_none", "low")]
    verdict = _score(domain=findings)
    assert [f.id for f in verdict.top_findings] == [
        "lookalike_domain",
        "spf_none",
        "tracking_pixel",
    ]
    assert verdict.top_findings[0].score == 35
    assert findings[1].score == 35  # written back to the analyzer's finding
    many = _score(urls=[_f(f"x{i}_id") for i in range(8)])
    assert len(many.top_findings) == 5


# --- Overrides -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("module", "finding", "name"),
    [
        ("attachments", _f("attachment_known_malicious", "critical"), "known_malicious_attachment"),
        ("urls", _f("url_known_malicious", "critical"), "known_malicious_url"),
        ("attachments", _f("sandbox_malicious", "critical"), "sandbox_malicious"),
        ("attachments", _f("html_smuggling", "critical"), "html_smuggling"),
    ],
)
def test_single_finding_overrides_force_malicious(module, finding, name) -> None:
    for case_type in ("email", "file"):
        verdict = RuleScorer().score(
            {module: AnalyzerResult(module=module, findings=[finding])}, case_type
        )
        assert verdict.label == "malicious"
        assert name in verdict.overrides_applied
        threshold = scoring_config().thresholds[case_type].malicious
        assert verdict.total_score >= threshold


def test_combination_override_needs_both() -> None:
    both = _score(
        header=[_f("auth_but_unaligned", "critical")],
        domain=[_f("brand_impersonation", "high")],
    )
    assert both.label == "malicious" and "spoofed_brand" in both.overrides_applied
    assert both.total_score == 80  # 45 + 35, above the threshold, so it is kept
    one = _score(header=[_f("auth_but_unaligned", "high")])
    assert "spoofed_brand" not in one.overrides_applied


def test_any_critical_finding_is_at_least_suspicious() -> None:
    verdict = _score(domain=[_f("brand_impersonation", "critical")])
    assert verdict.label == "suspicious" and verdict.total_score >= 30
    assert verdict.overrides_applied == ["critical_finding"]
    low = _score(domain=[_f("brand_impersonation", "medium")])
    assert low.label == "clean" and low.overrides_applied == []


def test_override_never_lowers_a_label() -> None:
    verdict = _score(
        header=[_f("auth_but_unaligned", "critical"), _f("dmarc_fail")],
        tone=[_f("credential_request", counted=5, cap=5)],
    )
    assert verdict.label == "malicious" and "critical_finding" in verdict.overrides_applied


# --- Confidence ----------------------------------------------------------------------------------


def test_confidence_from_errors_and_skips() -> None:
    results = {
        "header": AnalyzerResult(module="header"),
        "domain": AnalyzerResult(module="domain", errors=["rdap: timeout"]),
        "attachments": AnalyzerResult(module="attachments", skipped=True),
        "urls": AnalyzerResult(module="urls"),
        "tone": AnalyzerResult(module="tone"),
    }
    assert RuleScorer().score(results).confidence == 0.75  # 3 of 4 ran cleanly
    assert RuleScorer().score({}).confidence == 1.0


def test_confidence_drops_for_missing_services(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VIRUSTOTAL_API_KEY")
    get_settings.cache_clear()
    assert RuleScorer().score(_results(header=[])).confidence == 0.9
    for key in KEYS:
        monkeypatch.delenv(key, raising=False)
    get_settings.cache_clear()
    assert RuleScorer().score(_results(header=[])).confidence == 0.7  # penalty capped at 0.3
    results = {"a": AnalyzerResult(module="a", errors=["x"])}
    assert RuleScorer().score(results).confidence == 0.1  # floor


# --- Features, ML placeholder, scorer selection -------------------------------------------------


def test_features() -> None:
    row = features(_results(domain=[_f("lookalike_domain"), _f("lookalike_domain")],
                            tone=[_f("unknown_thing", "low")]))
    assert row["lookalike_domain"] == 70
    assert row["module:domain"] == 70 and row["module:tone"] == 5
    assert list(row) == feature_columns()


def test_scorer_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    assert isinstance(get_scorer(), RuleScorer)
    monkeypatch.setenv("SCORER", "ml")
    get_settings.cache_clear()
    assert isinstance(get_scorer(), MLScorer)
    monkeypatch.setenv("SCORER", "neural")
    with pytest.raises(ValueError):
        get_settings.cache_clear() or get_settings()


def test_ml_scorer_falls_back_without_model() -> None:
    verdict = MLScorer().score(_results(domain=[_f("lookalike_domain")]))
    assert verdict.total_score == 35
    assert verdict.overrides_applied == ["ml_scorer_unavailable_used_rules"]


def test_ml_scorer_with_model(monkeypatch: pytest.MonkeyPatch) -> None:
    from phishlens.scoring import ml_scorer

    class FakeModel:
        def predict_proba(self, rows):
            assert len(rows[0]) == 2
            return [[0.1, 0.9]]

    monkeypatch.setattr(
        ml_scorer, "load_model",
        lambda path: {"model": FakeModel(), "features": ["lookalike_domain", "module:domain"]},
    )
    monkeypatch.setenv("SCORER_MODEL_PATH", "/models/scorer.joblib")
    get_settings.cache_clear()
    verdict = MLScorer().score(_results(domain=[_f("lookalike_domain")]))
    assert (verdict.label, verdict.total_score) == ("malicious", 90)


# --- export_features script ----------------------------------------------------------------------

SCRIPT = Path(__file__).parent.parent / "scripts" / "export_features.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("export_features", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["export_features"] = module
    spec.loader.exec_module(module)
    return module


def test_export_features(tmp_path: Path) -> None:
    script = _load_script()
    results = _results(domain=[_f("lookalike_domain")])
    verdict = RuleScorer().score(results)
    for case_id in ("case-a", "case-b"):
        report = AnalysisReport(
            case_id=case_id, case_type="email", results=results, verdict=verdict
        )
        (tmp_path / f"{case_id}.json").write_text(report.model_dump_json())
    (tmp_path / "junk.json").write_text("{}")
    labels = tmp_path / "labels.csv"
    labels.write_text("case_id,label\ncase-a,malicious\n")
    out = tmp_path / "features.csv"
    assert script.main([str(tmp_path), "--out", str(out), "--labels", str(labels)]) == 0
    rows = list(csv.DictReader(out.open()))
    assert [(r["case_id"], r["label"]) for r in rows] == [("case-a", "malicious"), ("case-b", "")]
    assert float(rows[0]["lookalike_domain"]) == 35
    assert script.main([str(tmp_path), "--out", str(out), "--use-verdict"]) == 0
    assert [r["label"] for r in csv.DictReader(out.open())] == ["suspicious", "suspicious"]
