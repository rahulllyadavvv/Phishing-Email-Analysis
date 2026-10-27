"""Tests for phishlens.reporting.summary (fixtures 2, 6 and 14 in the fake internet)."""

from __future__ import annotations

from pathlib import Path

from phishlens import pipeline
from phishlens.models import AnalysisReport, AnalyzerResult, CaseType, Verdict
from phishlens.reporting.html import render_html
from phishlens.reporting.summary import build_recommendations, build_summary

FIXTURES = Path(__file__).parent / "fixtures"


async def _report(name: str) -> AnalysisReport:
    return await pipeline.analyze_email((FIXTURES / name).read_bytes())


def _text(sentences: list[str]) -> str:
    return " ".join(sentences)


async def test_fixture_2_spoof_summary(world) -> None:
    report = await _report("spoof_unaligned.eml")
    summary = build_summary(report)
    assert 3 <= len(summary) <= 5
    assert summary[0].startswith("PhishLens rates this email as Malicious")
    text = _text(summary)
    assert "claims to be from Microsoft" in text
    assert "authenticated by zetatech[.]xyz" in text and "microsoft[.]com" in text
    assert text.count("zetatech[.]xyz") == 1  # the separate authentication sentence is merged
    actions = _text(build_recommendations(report))
    assert "Do not block microsoft[.]com itself" in actions
    assert "Block the " in actions and "Block sender domain" not in actions
    assert "Report the impersonation to Microsoft" in actions
    assert "reset their password" in actions


async def test_fixture_6_lookalike_summary(world) -> None:
    text = _text(build_summary(await _report("lookalike_domain.eml")))
    assert "lookalike domain micros0ft-support[.]example" in text
    assert "imitates microsoft[.]com (combosquat)" in text
    assert "micros0ft-support.example" not in text  # defanged


async def test_fixture_14_eicar_summary(world) -> None:
    report = await _report("eicar_attachment.eml")
    summary = build_summary(report)
    assert 3 <= len(summary) <= 5
    text = _text(summary)
    assert "is known malware (EICAR-Test-File)" in text
    actions = _text(build_recommendations(report))
    assert "isolate the computer" in actions
    assert "sender domain and the" in actions  # not a brand domain: blocking it is fine


async def test_clean_email_has_no_actions(world) -> None:
    report = await _report("clean_newsletter.eml")
    assert build_recommendations(report) == []
    [sentence] = build_summary(report)
    assert "Clean" in sentence and "No significant" in sentence


def test_file_case_and_missing_verdict() -> None:
    report = AnalysisReport(
        case_id="x",
        case_type=CaseType.FILE,
        results={"attachments": AnalyzerResult(module="attachments")},
        verdict=Verdict(label="suspicious", total_score=30),
    )
    summary = build_summary(report)
    assert summary[0].startswith("PhishLens rates this file as Suspicious")
    actions = build_recommendations(report)
    assert actions[0].startswith("Do not click links, open attachments")
    assert not any("mailboxes" in a for a in actions)
    unscored = AnalysisReport(case_id="y", case_type=CaseType.EMAIL)
    assert build_summary(unscored) == ["This email has not been scored."]
    assert build_recommendations(unscored) == []


async def test_html_report_uses_summary_by_default(world) -> None:
    html = render_html(await _report("lookalike_domain.eml"))
    assert "imitates microsoft[.]com" in html
    assert "Report the impersonation to Microsoft" in html
