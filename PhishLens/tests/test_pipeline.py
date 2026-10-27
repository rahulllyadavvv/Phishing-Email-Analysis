"""End-to-end tests for phishlens.pipeline with all network mocked (a small fake "internet").

DNS: every fixture's envelope (Return-Path) domain publishes an SPF record authorizing the IP
that delivered it, matching the fixtures' own Authentication-Results headers; microsoft.com and
paypal.com publish DMARC p=reject; every From domain has an MX. HTTP: MalwareBazaar knows the
EICAR test file, URLhaus knows nothing, RDAP answers 404. No real network is used (the
``no_network`` guard in conftest makes sure of that)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import yaml

from phishlens import pipeline
from phishlens.analyzers import header, qr
from phishlens.config import get_settings
from phishlens.models import AnalyzerResult, CaseType

FIXTURES = Path(__file__).parent / "fixtures"
LABELS = yaml.safe_load((FIXTURES / "labels.yaml").read_text())


def _expected(name: str) -> str:
    return LABELS[name]["verdict"]


@pytest.mark.parametrize("name", sorted(LABELS))
async def test_every_fixture_gets_its_expected_verdict(world, name: str) -> None:
    if name == "qr_code.eml" and not qr.qr_available():
        pytest.skip("the QR payload can only be judged with zbar installed")
    report = await pipeline.analyze_email((FIXTURES / name).read_bytes())
    verdict = report.verdict
    assert verdict.label.value == _expected(name), (
        f"{name}: {verdict.total_score} {verdict.module_scores} "
        f"{[f.id for f in verdict.top_findings]} {verdict.overrides_applied}"
    )
    errors = {m: r.errors for m, r in report.results.items() if r.errors}
    assert errors == {}, errors


async def test_report_contents_for_the_spoof(world) -> None:
    report = await pipeline.analyze_email((FIXTURES / "spoof_unaligned.eml").read_bytes())
    assert report.case_type == CaseType.EMAIL and len(report.case_id) == 32
    assert report.email is not None and report.email.subject.startswith("Unusual sign-in")
    assert set(report.results) == set(pipeline.EMAIL_MODULES)
    assert "spoofed_brand" in report.verdict.overrides_applied
    assert {"T1566", "T1684.001"} <= {t.id for t in report.mitre}
    auth = next(f for f in report.results["header"].findings if f.id == "auth_but_unaligned")
    assert auth.mitre == ["T1566"] and auth.score == 45
    assert "abusech" in report.services_used and "virustotal" in report.services_not_configured
    assert report.tool_version
    assert any(i.value == "zetatech.xyz" and i.verdict == "suspicious" for i in report.iocs)
    assert "raw_bytes" not in report.model_dump_json()  # never serialized


async def test_nested_email_findings(world) -> None:
    report = await pipeline.analyze_email((FIXTURES / "forwarded_nested.eml").read_bytes())
    nested = report.results["nested"]
    assert nested.raw["emails"][0]["nested"] == "nested:1"
    assert nested.raw["emails"][0]["from"] == "account-security@microsoft.com"
    assert nested.findings and all(f.evidence["nested"] == "nested:1" for f in nested.findings)
    assert {f.module for f in nested.findings} <= {f"nested.{m}" for m in pipeline.EMAIL_MODULES}
    assert any(i.value == "http://account-review.zetatech.example/verify" for i in report.iocs)


async def test_offline_mode_makes_no_calls(world) -> None:
    report = await pipeline.analyze_email(
        (FIXTURES / "eicar_attachment.eml").read_bytes(), network=False
    )
    assert world.calls.call_count == 0
    assert report.results["header"].raw["spf"]["skipped_reason"] == "offline"
    assert report.services_used == []
    row = report.results["attachments"].raw["attachments"][0]
    assert "reputation" not in row


async def test_progress_callback(world) -> None:
    events: list[tuple[str, str]] = []

    async def progress(module: str, status: str) -> None:
        events.append((module, status))

    await pipeline.analyze_email((FIXTURES / "clean_newsletter.eml").read_bytes(), progress)
    for module in pipeline.EMAIL_MODULES:
        statuses = [s for m, s in events if m == module]
        assert statuses == ["pending", "running", "done"], (module, statuses)
    assert events[-1] == ("scoring", "done")
    assert events.index(("header", "done")) < events.index(("domain", "running"))
    assert events.index(("domain", "done")) < events.index(("tone", "running"))


async def test_failing_and_slow_analyzers_do_not_stop_the_pipeline(
    world, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def crash(email):
        raise RuntimeError("header exploded")

    async def slow(email, context=None):
        await asyncio.sleep(5)

    monkeypatch.setattr(header, "analyze", crash)
    monkeypatch.setattr(pipeline.artifacts, "analyze", slow)
    monkeypatch.setenv("ANALYZER_TIMEOUT_SECONDS", "0.2")
    get_settings.cache_clear()
    events: list[tuple[str, str]] = []
    report = await pipeline.analyze_email(
        (FIXTURES / "link_mismatch.eml").read_bytes(), lambda m, s: events.append((m, s))
    )
    assert report.results["header"].errors == ["crashed: RuntimeError: header exploded"]
    assert report.results["artifacts"].errors == ["timed out after 0.2s"]
    assert ("artifacts", "error") in events and ("header", "error") in events
    assert report.verdict.label.value == "malicious"  # the other analyzers still decide
    assert report.verdict.confidence < 1.0


async def test_broken_progress_callback_is_ignored(world) -> None:
    def broken(module: str, status: str) -> None:
        raise RuntimeError("display crashed")

    report = await pipeline.analyze_email((FIXTURES / "zip_attachment.eml").read_bytes(), broken)
    assert report.verdict is not None


def test_merge_iocs() -> None:
    from phishlens.models import IOC, IOCType

    a = [IOC(type=IOCType.DOMAIN, value="x.test", source_module="email", verdict="unknown",
             context="From domain")]
    b = [IOC(type=IOCType.DOMAIN, value="x.test", source_module="urls", verdict="suspicious",
             context="host of link"),
         IOC(type=IOCType.IP, value="203.0.113.1", verdict="unknown")]
    merged = pipeline.merge_iocs(a, b)
    assert [(i.value, i.verdict, i.source_module, i.context) for i in merged] == [
        ("x.test", "suspicious", "email, urls", "From domain; host of link"),
        ("203.0.113.1", "unknown", "", ""),
    ]


async def test_run_analyzer_directly() -> None:
    async def ok() -> AnalyzerResult:
        return AnalyzerResult(module="x")

    assert (await pipeline.run_analyzer("x", ok, 1)).errors == []
