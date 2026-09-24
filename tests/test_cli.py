"""Tests for the Typer CLI (phishlens.cli). All runs use --no-network or mocked services."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from phishlens.cli import app
from phishlens.config import get_settings

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


@pytest.fixture(autouse=True)
def wide_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "140")


def _run(*args: str):
    return runner.invoke(app, list(args))


def test_analyze_spoof_prints_verdict_and_reasons(tmp_path: Path) -> None:
    result = _run(
        "analyze", str(FIXTURES / "spoof_unaligned.eml"), "--no-network", "--out", str(tmp_path)
    )
    assert result.exit_code == 0, result.output
    assert "SUSPICIOUS" in result.output or "MALICIOUS" in result.output
    assert "Impersonates Microsoft" in result.output or "Display name" in result.output
    assert "Top findings" in result.output and "IOCs:" in result.output
    [report_file] = tmp_path.glob("*.json")
    report = json.loads(report_file.read_text())
    assert report["case_type"] == "email" and report["verdict"]["label"] in (
        "suspicious",
        "malicious",
    )


def test_all_formats_and_later_formats(tmp_path: Path) -> None:
    result = _run(
        "analyze", str(FIXTURES / "link_mismatch.eml"), "--no-network",
        "--format", "json,csv,stix,html", "--out", str(tmp_path),
    )
    assert result.exit_code == 0, result.output
    assert "HTML reports are not available yet" in result.output
    names = sorted(p.name.split(".", 1)[1] for p in tmp_path.iterdir())
    assert names == ["iocs.csv", "json", "stix.json"]
    stix = json.loads(next(tmp_path.glob("*.stix.json")).read_text())
    assert stix["type"] == "bundle"
    assert "hxxp://paypal-secure-login[.]example" in result.output or "MALICIOUS" in result.output


def test_output_is_defanged(tmp_path: Path) -> None:
    result = _run(
        "analyze", str(FIXTURES / "link_mismatch.eml"), "--no-network", "--out", str(tmp_path)
    )
    assert "http://paypal-secure-login.example" not in result.output
    assert "paypal-secure-login.example" not in result.output


def test_analyze_file_forces_file_mode(tmp_path: Path) -> None:
    result = _run(
        "analyze-file", str(FIXTURES / "clean_newsletter.eml"), "--no-network",
        "--out", str(tmp_path),
    )
    assert result.exit_code == 0, result.output
    assert "file case" in result.output
    report = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert report["case_type"] == "file"


def test_plain_file_is_routed_to_file_mode(tmp_path: Path) -> None:
    sample = tmp_path / "notes.txt"
    sample.write_text("Agenda for Tuesday.\n")
    result = _run("analyze", str(sample), "--no-network", "--out", str(tmp_path / "out"))
    assert result.exit_code == 0 and "CLEAN" in result.output


def test_bad_inputs() -> None:
    assert _run("analyze", "/no/such/file.eml", "--no-network").exit_code == 1
    bad_format = _run("analyze", str(FIXTURES / "zip_attachment.eml"), "--format", "docx")
    assert bad_format.exit_code != 0
    assert "unknown format" in bad_format.output


def test_too_large(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAX_INPUT_SIZE_MB", "0.0001")
    get_settings.cache_clear()
    result = _run("analyze", str(FIXTURES / "zip_attachment.eml"), "--no-network")
    assert result.exit_code == 1 and "larger than MAX_INPUT_SIZE_MB" in result.output


def test_check_config_never_prints_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "super-secret-vt-key")
    get_settings.cache_clear()
    result = _run("check-config")
    assert result.exit_code == 0
    assert "virustotal" in result.output and "enabled" in result.output
    assert "not configured" in result.output
    assert "super-secret-vt-key" not in result.output
    assert "MITRE ATT&CK data" in result.output


def test_help() -> None:
    result = _run("--help")
    assert result.exit_code == 0
    assert "analyze-file" in result.output and "check-config" in result.output
