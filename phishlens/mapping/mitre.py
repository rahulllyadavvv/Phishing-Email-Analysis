"""MITRE ATT&CK mapping: findings -> techniques (rules in ``data/mitre_rules.yaml``).

``map_findings(findings)`` evaluates every rule (``any_of`` / ``all_of`` with alternatives, and
optional evidence filters) and returns one ``MitreTechnique`` per technique, listing the
findings that triggered it. Names, tactics and URLs come from the local ATT&CK Enterprise data
(``data/mitre/enterprise-attack.json``, read with mitreattack-python) when it has been
downloaded, else from the fallback table in the rules file.
"""

from __future__ import annotations

import re
from functools import cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from phishlens.data_loader import DATA_DIR, load_yaml
from phishlens.models import Finding, MitreTechnique

__all__ = [
    "ATTACK_DATA_PATH",
    "MitreRule",
    "attack_data",
    "clear_cache",
    "map_findings",
    "mitre_rules",
    "technique_info",
    "technique_url",
]

ATTACK_DATA_PATH = DATA_DIR / "mitre" / "enterprise-attack.json"
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class MitreRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    techniques: tuple[str, ...]
    any_of: tuple[str, ...] = ()
    all_of: tuple[tuple[str, ...], ...] = ()
    evidence: dict[str, tuple[str, ...]] = {}

    @field_validator("techniques")
    @classmethod
    def _valid_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        bad = [t for t in value if not _TECHNIQUE_RE.match(t)]
        if bad or not value:
            raise ValueError(f"invalid technique IDs: {bad or 'none given'}")
        return value

    @field_validator("all_of", mode="before")
    @classmethod
    def _alternatives(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [tuple(v) if isinstance(v, list) else (v,) for v in value]
        return value

    @field_validator("evidence", mode="before")
    @classmethod
    def _lower_values(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: tuple(str(v).lower() for v in vs) for k, vs in value.items()}
        return value

    @model_validator(mode="after")
    def _has_condition(self) -> MitreRule:
        if bool(self.any_of) == bool(self.all_of):
            raise ValueError("a rule needs exactly one of any_of / all_of")
        return self


class _TechniqueFallback(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    tactics: tuple[str, ...] = ()


class _RulesFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rules: tuple[MitreRule, ...]
    techniques: dict[str, _TechniqueFallback] = {}


@cache
def mitre_rules() -> _RulesFile:
    return _RulesFile.model_validate(load_yaml("mitre_rules.yaml"))


@cache
def attack_data(path: str | None = None) -> Any:
    """The loaded ATT&CK data (``MitreAttackData``) or None when the file is missing."""
    file = Path(path) if path else ATTACK_DATA_PATH
    if not file.is_file():
        return None
    from mitreattack.stix20 import MitreAttackData

    return MitreAttackData(stix_filepath=str(file))


def clear_cache() -> None:
    mitre_rules.cache_clear()
    attack_data.cache_clear()


def technique_url(technique_id: str) -> str:
    """The technique page, in the same form as the ATT&CK data (no trailing slash)."""
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/")


@cache
def technique_info(technique_id: str) -> tuple[str, tuple[str, ...], str]:
    """(name, tactics, url) from the ATT&CK data, else from the fallback table."""
    data = attack_data()
    if data is not None:
        obj = data.get_object_by_attack_id(technique_id, "attack-pattern")
        if obj is not None:
            tactics = tuple(
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            )
            url = next(
                (
                    ref.get("url")
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack" and ref.get("url")
                ),
                technique_url(technique_id),
            )
            name = obj["name"]
            parent_id = technique_id.split(".")[0]
            if "." in technique_id:
                parent = data.get_object_by_attack_id(parent_id, "attack-pattern")
                if parent is not None and not name.startswith(parent["name"]):
                    name = f"{parent['name']}: {name}"
            return name, tactics, url
    fallback = mitre_rules().techniques.get(technique_id)
    if fallback is not None:
        return fallback.name, fallback.tactics, technique_url(technique_id)
    return technique_id, (), technique_url(technique_id)


def _evidence_matches(finding: Finding, wanted: dict[str, tuple[str, ...]]) -> bool:
    if not wanted:
        return True
    entries = [finding.evidence]
    for key in ("files", "urls"):
        value = finding.evidence.get(key)
        if isinstance(value, list):
            entries += [e for e in value if isinstance(e, dict)]
    return any(
        str(entry.get(field, "")).lower() in values
        for entry in entries
        for field, values in wanted.items()
    )


def _fired(rule: MitreRule, by_id: dict[str, list[Finding]]) -> list[str]:
    """IDs of the findings that make ``rule`` fire (empty when it does not)."""
    if rule.any_of:
        return [
            fid
            for fid in rule.any_of
            if any(_evidence_matches(f, rule.evidence) for f in by_id.get(fid, []))
        ]
    triggered: list[str] = []
    for alternatives in rule.all_of:
        present = [fid for fid in alternatives if fid in by_id]
        if not present:
            return []
        triggered += present
    return triggered


def map_findings(findings: list[Finding]) -> list[MitreTechnique]:
    """Techniques indicated by ``findings``, each with the findings that triggered it,
    ordered by technique ID."""
    by_id: dict[str, list[Finding]] = {}
    for finding in findings:
        by_id.setdefault(finding.id, []).append(finding)
    triggered: dict[str, list[str]] = {}
    for rule in mitre_rules().rules:
        fired = _fired(rule, by_id)
        if not fired:
            continue
        for technique_id in rule.techniques:
            ids = triggered.setdefault(technique_id, [])
            ids += [f for f in fired if f not in ids]
    techniques = []
    for technique_id in sorted(triggered):
        name, tactics, url = technique_info(technique_id)
        techniques.append(
            MitreTechnique(
                id=technique_id,
                name=name,
                tactics=list(tactics),
                url=url,
                triggered_by=sorted(triggered[technique_id]),
            )
        )
    return techniques
