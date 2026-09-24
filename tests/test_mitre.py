"""Tests for phishlens.mapping.mitre."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from phishlens.mapping import mitre
from phishlens.mapping.mitre import MitreRule, map_findings, mitre_rules, technique_url
from phishlens.models import Finding

HAVE_DATA = mitre.ATTACK_DATA_PATH.is_file()
needs_data = pytest.mark.skipif(
    not HAVE_DATA, reason="ATT&CK data not downloaded (python scripts/update_attack_data.py)"
)


@pytest.fixture(autouse=True)
def fresh_rules():
    """Reload the rules each test; the (large) ATT&CK data stays cached across tests."""
    mitre.mitre_rules.cache_clear()
    mitre.technique_info.cache_clear()
    yield
    mitre.mitre_rules.cache_clear()
    mitre.technique_info.cache_clear()


def _f(finding_id: str, **evidence) -> Finding:
    return Finding(id=finding_id, module="test", title=finding_id, evidence=evidence)


def _ids(techniques) -> dict:
    return {t.id: t for t in techniques}


def test_attachment_findings() -> None:
    techniques = _ids(map_findings([_f("attachment_known_malicious"), _f("office_macro_autoexec")]))
    assert set(techniques) == {"T1204.002", "T1566.001"}
    t = techniques["T1566.001"]
    assert t.triggered_by == ["attachment_known_malicious", "office_macro_autoexec"]
    assert t.url == "https://attack.mitre.org/techniques/T1566/001"
    assert "initial-access" in t.tactics
    assert "Spearphishing Attachment" in t.name


def test_link_credential_and_impersonation() -> None:
    techniques = _ids(
        map_findings(
            [
                _f("link_text_mismatch"),
                _f("urlscan_login_page_on_unrelated_domain"),
                _f("brand_impersonation"),
                _f("html_smuggling"),
                _f("remote_template_injection"),
                _f("double_extension"),
                _f("rtlo_filename"),
                _f("office_macro_suspicious_calls"),
                _f("obfuscated_script"),
            ]
        )
    )
    assert {
        "T1566.002", "T1204.001", "T1598.003", "T1684.001", "T1027.006", "T1221",
        "T1036.007", "T1036.002", "T1059.005", "T1027",
    } <= set(techniques)


def test_combination_rule_needs_all_parts() -> None:
    assert "T1583.001" not in _ids(map_findings([_f("lookalike_domain")]))
    assert "T1583.001" not in _ids(map_findings([_f("domain_age_under_30_days")]))
    both = _ids(map_findings([_f("lookalike_domain"), _f("domain_age_under_30_days")]))
    assert both["T1583.001"].triggered_by == ["domain_age_under_30_days", "lookalike_domain"]
    younger = _ids(map_findings([_f("lookalike_domain"), _f("domain_age_under_7_days")]))
    assert "T1583.001" in younger


def test_evidence_filter_for_disk_images() -> None:
    iso = _f("high_risk_file_type", files=[{"file": "invoice.iso", "extension": "iso"}])
    exe = _f("high_risk_file_type", files=[{"file": "setup.exe", "extension": "exe"}])
    assert "T1553.005" in _ids(map_findings([iso]))
    assert "T1553.005" not in _ids(map_findings([exe]))


def test_no_findings_no_techniques() -> None:
    assert map_findings([]) == []
    assert map_findings([_f("tracking_pixel"), _f("missing_date")]) == []


def test_fallback_without_attack_data(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(mitre, "ATTACK_DATA_PATH", tmp_path / "missing.json")
    mitre.attack_data.cache_clear()
    try:
        [t] = map_findings([_f("remote_template_injection")])
    finally:
        mitre.attack_data.cache_clear()
    assert (t.id, t.name, t.tactics) == ("T1221", "Template Injection", ["stealth"])
    assert t.url == "https://attack.mitre.org/techniques/T1221"


def test_rule_validation() -> None:
    with pytest.raises(ValidationError):
        MitreRule(techniques=["T12"], any_of=["x"])
    with pytest.raises(ValidationError):
        MitreRule(techniques=["T1566"])  # no condition
    with pytest.raises(ValidationError):
        MitreRule(techniques=["T1566"], any_of=["a"], all_of=[["b"]])
    rule = MitreRule(techniques=["T1566"], all_of=["a", ["b", "c"]])
    assert rule.all_of == (("a",), ("b", "c"))


def test_technique_url() -> None:
    assert technique_url("T1566") == "https://attack.mitre.org/techniques/T1566"
    assert technique_url("T1566.001") == "https://attack.mitre.org/techniques/T1566/001"


def test_every_rule_technique_has_a_fallback() -> None:
    rules = mitre_rules()
    used = {t for rule in rules.rules for t in rule.techniques}
    assert used <= set(rules.techniques)


@needs_data
def test_every_technique_exists_in_attack_data() -> None:
    data = mitre.attack_data()
    rules = mitre_rules()
    used = {t for rule in rules.rules for t in rule.techniques}
    for technique_id in sorted(used):
        obj = data.get_object_by_attack_id(technique_id, "attack-pattern")
        assert obj is not None, f"{technique_id} not in ATT&CK data"
        assert not obj.get("revoked", False), f"{technique_id} is revoked"
        name, tactics, _ = mitre.technique_info(technique_id)
        assert name == rules.techniques[technique_id].name, technique_id
        assert set(tactics) == set(rules.techniques[technique_id].tactics), technique_id
