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
