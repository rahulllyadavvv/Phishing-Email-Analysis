"""Tests for phishlens.ioc.export (CSV, JSON, STIX 2.1)."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

import pytest
import stix2
from stix2patterns.validator import run_validator

from phishlens.ioc.export import CSV_COLUMNS, indicator_pattern, to_csv, to_json, to_stix_bundle
from phishlens.models import IOC, IOCType

WHEN = datetime(2026, 9, 7, 9, 0, tzinfo=UTC)


def _ioc(kind: IOCType, value: str, verdict: str = "unknown", defanged: str | None = None) -> IOC:
    return IOC(
        type=kind,
        value=value,
        defanged=defanged or value,
        source_module="urls, text",
        verdict=verdict,
        context="link (html_href); host of link",
    )


IOCS = [
    _ioc(IOCType.URL, "http://evil.test/o'brien?a=1", "malicious", "hxxp://evil[.]test/o'brien?a=1"),
    _ioc(IOCType.DOMAIN, "evil.test", "suspicious", "evil[.]test"),
    _ioc(IOCType.IP, "203.0.113.9", "malicious", "203[.]0[.]113[.]9"),
    _ioc(IOCType.IP, "2001:db8::1", "suspicious"),
    _ioc(IOCType.EMAIL, "bad@evil.test", "malicious", "bad[@]evil[.]test"),
    _ioc(IOCType.SHA256, "a" * 64, "malicious"),
    _ioc(IOCType.SHA1, "b" * 40, "suspicious"),
    _ioc(IOCType.MD5, "c" * 32, "malicious"),
    _ioc(IOCType.FILENAME, "invoice.pdf.exe", "suspicious"),
    _ioc(IOCType.DOMAIN, "cdn.example.test", "unknown"),
    _ioc(IOCType.SHA256, "d" * 64, "clean"),
    _ioc(IOCType.EMAIL, "news@example.test", "unknown"),
]


def test_csv() -> None:
    text = to_csv(IOCS)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert tuple(rows[0]) == CSV_COLUMNS
    assert rows[0] == {
        "type": "url",
        "value": "http://evil.test/o'brien?a=1",
        "defanged": "hxxp://evil[.]test/o'brien?a=1",
        "verdict": "malicious",
        "source": "urls, text",
        "context": "link (html_href); host of link",
    }
    assert len(rows) == len(IOCS)


def test_json() -> None:
    data = json.loads(to_json(IOCS))
    assert len(data) == len(IOCS)
    assert data[4]["defanged"] == "bad[@]evil[.]test"


@pytest.mark.parametrize("ioc", [i for i in IOCS], ids=lambda i: f"{i.type.value}-{i.value[:12]}")
def test_every_pattern_is_valid(ioc: IOC) -> None:
    assert run_validator(indicator_pattern(ioc)) == [], indicator_pattern(ioc)


def test_pattern_shapes_and_escaping() -> None:
    assert indicator_pattern(IOCS[0]) == r"[url:value = 'http://evil.test/o\'brien?a=1']"
    assert indicator_pattern(IOCS[2]).startswith("[ipv4-addr:value")
    assert indicator_pattern(IOCS[3]).startswith("[ipv6-addr:value")
    assert indicator_pattern(IOCS[5]) == f"[file:hashes.'SHA-256' = '{'a' * 64}']"
    assert indicator_pattern(IOCS[8]) == "[file:name = 'invoice.pdf.exe']"


def test_stix_bundle_parses_back_and_is_complete() -> None:
    bundle = to_stix_bundle(IOCS, report_name="Case 42", timestamp=WHEN)
    parsed = stix2.parse(bundle.serialize(pretty=True), allow_custom=False)
    by_type: dict[str, list] = {}
    for obj in parsed.objects:
        by_type.setdefault(obj.type, []).append(obj)

    indicators = by_type["indicator"]
    assert len(indicators) == 9  # malicious + suspicious only
    for indicator in indicators:
        assert run_validator(indicator.pattern) == []
        assert indicator.pattern_type == "stix"
        assert indicator.labels[0] in ("malicious", "suspicious")
        expected = "malicious-activity" if indicator.labels[0] == "malicious" else (
            "anomalous-activity"
        )
        assert indicator.indicator_types == [expected]
        assert "http://" not in indicator.name  # names use the defanged form
    [observed] = by_type["observed-data"]
    assert len(observed.object_refs) == 3  # unknown/clean IOCs as observables
    assert {o.type for o in by_type["domain-name"] + by_type["file"]} == {"domain-name", "file"}
    [report] = by_type["report"]
    assert report.name == "Case 42"
    assert set(report.object_refs) == {i.id for i in indicators} | {observed.id}
    [identity] = by_type["identity"]
    assert all(o.created_by_ref == identity.id for o in indicators + [observed, report])


def test_stix_exclude_others() -> None:
    bundle = to_stix_bundle(IOCS, others="exclude", timestamp=WHEN)
    types = {o.type for o in bundle.objects}
    assert "observed-data" not in types and "domain-name" not in types
    assert types == {"identity", "indicator", "report"}


def test_stix_empty_and_benign_only() -> None:
    assert [o.type for o in to_stix_bundle([], timestamp=WHEN).objects] == ["identity"]
    benign = to_stix_bundle([IOCS[9]], others="exclude", timestamp=WHEN)
    assert [o.type for o in benign.objects] == ["identity"]


def test_stix_bundle_is_deterministic_for_a_timestamp() -> None:
    first = to_stix_bundle(IOCS, timestamp=WHEN)
    second = to_stix_bundle(IOCS, timestamp=WHEN)
    observables = lambda b: sorted(o.id for o in b.objects if o.type in ("domain-name", "file"))  # noqa: E731
    assert observables(first) == observables(second)  # SCO ids are content-derived
