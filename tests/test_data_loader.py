"""Tests for phishlens.data_loader."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from phishlens import data_loader


@pytest.fixture(autouse=True)
def fresh_cache():
    data_loader.clear_cache()
    yield
    data_loader.clear_cache()


def test_esp_file_parses() -> None:
    esps = data_loader.esps()
    assert len(esps) >= 6
    names = {e.name for e in esps}
    assert {"SendGrid", "Amazon SES", "Mailgun", "SparkPost"} <= names
    for esp in esps:
        assert esp.domains
        assert all(d == d.lower() and not d.endswith(".") for d in esp.domains)


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("sendgrid.net", "SendGrid"),
        ("em1234.Bounces.SendGrid.net.", "SendGrid"),
        ("mcsv.net", "Mailchimp / Mandrill"),
        ("us-east-1.amazonses.com", "Amazon SES"),
        ("notsendgrid.net", None),
        ("example.com", None),
        ("", None),
        (None, None),
    ],
)
def test_esp_for_domain(domain: str | None, expected: str | None) -> None:
    esp = data_loader.esp_for_domain(domain)
    assert (esp.name if esp else None) == expected


def test_load_yaml_is_cached(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "x.yaml").write_text("a: 1\n")
    monkeypatch.setattr(data_loader, "DATA_DIR", tmp_path)
    first = data_loader.load_yaml("x.yaml")
    (tmp_path / "x.yaml").write_text("a: 2\n")
    assert data_loader.load_yaml("x.yaml") is first
    data_loader.clear_cache()
    assert data_loader.load_yaml("x.yaml") == {"a": 2}


def test_invalid_esp_file_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "esp_domains.yaml").write_text("esps:\n  - name: NoDomains\n")
    monkeypatch.setattr(data_loader, "DATA_DIR", tmp_path)
    with pytest.raises(ValidationError):
        data_loader.esps()


def test_brand_registry_parses() -> None:
    registry = data_loader.brand_registry()
    assert len(registry.brands) >= 30
    names = {b.name for b in registry.brands}
    assert {"Microsoft", "PayPal", "State Bank of India", "Income Tax Department"} <= names
    assert registry.organization.domains == ()
    for brand in registry.brands:
        assert brand.keywords and brand.legitimate_domains
        assert all(k == k.lower() for k in brand.keywords)
        assert all("." in d and d == d.lower() for d in brand.legitimate_domains)


def test_no_domain_belongs_to_two_brands() -> None:
    seen: dict[str, str] = {}
    for brand in data_loader.brands():
        for domain in brand.legitimate_domains:
            assert domain not in seen, f"{domain} in {seen.get(domain)} and {brand.name}"
            seen[domain] = brand.name


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("accounts.google.com", "Google"),
        ("PayPal.com.", "PayPal"),
        ("sbi.co.in", "State Bank of India"),
        ("paypal-secure.test", None),
        ("", None),
    ],
)
def test_brand_for_domain(domain: str, expected: str | None) -> None:
    brand = data_loader.brand_for_domain(domain)
    assert (brand.name if brand else None) == expected


def test_free_webmail_risky_tlds_and_shorteners() -> None:
    assert data_loader.is_free_webmail("gmail.com")
    assert data_loader.is_free_webmail("Proton.Me")
    assert not data_loader.is_free_webmail("company.example")
    assert data_loader.is_risky_tld("zetatech.xyz")
    assert data_loader.is_risky_tld("evil.ZIP.")
    assert not data_loader.is_risky_tld("example.com")
    assert not data_loader.is_risky_tld("")
    assert data_loader.is_shortener("bit.ly")
    assert not data_loader.is_shortener("notbit.ly")
    assert all("." not in t for t in data_loader.risky_tlds())


def test_invalid_brand_file_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "brand_registry.yaml").write_text(
        "brands:\n  - name: Empty\n    keywords: []\n    legitimate_domains: [x.test]\n"
    )
    monkeypatch.setattr(data_loader, "DATA_DIR", tmp_path)
    with pytest.raises(ValidationError):
        data_loader.brand_registry()


def test_every_data_file_has_an_extension_comment() -> None:
    for path in data_loader.DATA_DIR.glob("*.yaml"):
        assert path.read_text().startswith("#"), path.name


def test_confusables_file_parses() -> None:
    table = data_loader.confusables()
    assert table.characters["0"] == "o"
    assert table.characters["а"] == "a"  # Cyrillic a
    assert table.sequences["rn"] == "m"
    assert all(len(k) == 1 for k in table.characters)


def test_generic_labels() -> None:
    assert {"office", "live"} <= set(data_loader.brand_registry().generic_labels)
