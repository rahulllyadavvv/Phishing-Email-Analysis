"""Tests for phishlens.enrichment.sandbox. HTTP is mocked with respx; keys are fake; the
"files" are harmless bytes."""

from __future__ import annotations

import httpx
import pytest
import respx

from phishlens.config import get_settings
from phishlens.enrichment.sandbox import HA_API_URL, CapeClient, HybridAnalysisClient
from phishlens.models import EnrichmentStatus, SandboxReport

HA_KEY = "fake-ha-key"
CAPE = "https://cape.lab.test"
FILE = b"harmless test bytes"
SHA256 = "d" * 64


@pytest.fixture(autouse=True)
def sandbox_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "HYBRID_ANALYSIS_API_KEY",
        "UPLOAD_FILES_TO_HYBRID_ANALYSIS",
        "CAPE_BASE_URL",
        "CAPE_API_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()


def _configure(monkeypatch: pytest.MonkeyPatch, **env: str) -> None:
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()


# --- Hybrid Analysis -----------------------------------------------------------------------------


@pytest.mark.respx(assert_all_called=False)
async def test_ha_not_configured_does_nothing(respx_mock) -> None:
    route = respx_mock.post(url__startswith=HA_API_URL).respond(200, json={"job_id": "1"})
    async with HybridAnalysisClient() as ha:
        submitted = await ha.submit(FILE, "a.bin")
        report = await ha.get_report("1")
    assert isinstance(submitted, SandboxReport) and submitted.status == "not_configured"
    assert report.status == "not_configured"
    assert route.call_count == 0


@pytest.mark.respx(assert_all_called=False)
async def test_ha_upload_needs_its_own_opt_in(respx_mock, monkeypatch) -> None:
    _configure(monkeypatch, HYBRID_ANALYSIS_API_KEY=HA_KEY)
    route = respx_mock.post(f"{HA_API_URL}/submit/file").respond(200, json={"job_id": "1"})
    async with HybridAnalysisClient() as ha:
        submitted = await ha.submit(FILE, "a.bin")
    assert submitted.status == "not_configured"
    assert "UPLOAD_FILES_TO_HYBRID_ANALYSIS" in submitted.error
    assert route.call_count == 0


@respx.mock
async def test_ha_submit_and_report(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(
        monkeypatch, HYBRID_ANALYSIS_API_KEY=HA_KEY, UPLOAD_FILES_TO_HYBRID_ANALYSIS="true"
    )
    submit = respx.post(f"{HA_API_URL}/submit/file").respond(
        201, json={"job_id": "job-9", "sha256": SHA256}
    )
    respx.get(f"{HA_API_URL}/report/job-9/summary").respond(
        200,
        json={
            "state": "SUCCESS",
            "verdict": "malicious",
            "threat_score": 95,
            "sha256": SHA256,
            "environment_id": 160,
            "processes": [{"name": "invoice.exe"}, {"name": "powershell.exe"}],
            "domains": ["c2.bad.test"],
            "hosts": ["203.0.113.66", "203.0.113.66"],
            "extracted_urls": ["http://c2.bad.test/gate.php"],
            "extracted_files": [{"sha256": "e" * 64}],
            "signatures": [{"name": "Contacts a C2 server"}],
        },
    )
    async with HybridAnalysisClient() as ha:
        task_id = await ha.submit(FILE, "invoice.exe")
        report = await ha.get_report(task_id)
    assert task_id == "job-9"
    request = submit.calls.last.request
    assert request.headers["api-key"] == HA_KEY
    assert request.headers["user-agent"] == "Falcon Sandbox"
    assert b"harmless test bytes" in request.content and b"160" in request.content
    assert report.status == "done"
    assert report.verdict == EnrichmentStatus.MALICIOUS and report.score == 95
    assert report.processes == ["invoice.exe", "powershell.exe"]
    assert report.network_ips == ["203.0.113.66"]
    assert report.network_urls == ["http://c2.bad.test/gate.php"]
    assert report.dropped_hashes == ["e" * 64]
    assert report.signatures == ["Contacts a C2 server"]
    assert report.link == f"https://www.hybrid-analysis.com/sample/{SHA256}/160"


@pytest.mark.parametrize(
    ("body", "status", "verdict"),
    [
        ({"state": "IN_PROGRESS"}, "pending", EnrichmentStatus.UNKNOWN),
        ({"state": "ERROR"}, "error", EnrichmentStatus.UNKNOWN),
        ({"state": "SUCCESS", "verdict": "no specific threat"}, "done", EnrichmentStatus.CLEAN),
        ({"state": "SUCCESS", "verdict": "suspicious"}, "done", EnrichmentStatus.SUSPICIOUS),
    ],
)
@respx.mock
async def test_ha_report_states(monkeypatch, body: dict, status: str, verdict) -> None:
    _configure(monkeypatch, HYBRID_ANALYSIS_API_KEY=HA_KEY)
    respx.get(f"{HA_API_URL}/report/j/summary").respond(200, json=body)
    async with HybridAnalysisClient() as ha:
        report = await ha.get_report("j")
    assert (report.status, report.verdict) == (status, verdict)


@respx.mock
async def test_ha_errors_never_raise_or_leak_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, HYBRID_ANALYSIS_API_KEY=HA_KEY)
    respx.get(f"{HA_API_URL}/report/j/summary").respond(403)
    async with HybridAnalysisClient() as ha:
        report = await ha.get_report("j")
    assert report.status == "error" and report.error == "report failed: HTTP 403"
    assert HA_KEY not in report.model_dump_json()


# --- CAPE ----------------------------------------------------------------------------------------


CAPE_REPORT = {
    "malscore": 8.5,
    "behavior": {"processes": [{"process_name": "doc.exe"}]},
    "network": {
        "domains": [{"domain": "drop.bad.test"}],
        "hosts": [{"ip": "198.51.100.23"}, "198.51.100.24"],
        "http": [{"uri": "http://drop.bad.test/p.bin"}],
    },
    "dropped": [{"sha256": "f" * 64}],
    "signatures": [{"name": "injection_createremotethread"}],
}


@respx.mock
async def test_cape_submit_poll_and_report(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, CAPE_BASE_URL=CAPE + "/", CAPE_API_TOKEN="cape-token")
    submit = respx.post(f"{CAPE}/apiv2/tasks/create/file/").respond(
        200, json={"error": False, "data": {"task_ids": [42]}}
    )
    view = respx.get(f"{CAPE}/apiv2/tasks/view/42/")
    view.side_effect = [
        httpx.Response(200, json={"data": {"status": "running"}}),
        httpx.Response(200, json={"data": {"status": "reported"}}),
    ]
    respx.get(f"{CAPE}/apiv2/tasks/get/report/42/json/").respond(200, json=CAPE_REPORT)
    async with CapeClient() as cape:
        task_id = await cape.submit(FILE, "doc.exe")
        pending = await cape.get_report(task_id)
        report = await cape.get_report(task_id)
    assert task_id == "42"
    assert submit.calls.last.request.headers["authorization"] == "Token cape-token"
    assert pending.status == "pending"
    assert report.status == "done"
    assert report.verdict == EnrichmentStatus.MALICIOUS and report.score == 85.0
    assert report.processes == ["doc.exe"]
    assert report.network_domains == ["drop.bad.test"]
    assert report.network_ips == ["198.51.100.23", "198.51.100.24"]
    assert report.network_urls == ["http://drop.bad.test/p.bin"]
    assert report.dropped_hashes == ["f" * 64]
    assert report.signatures == ["injection_createremotethread"]
    assert report.link == f"{CAPE}/analysis/42/"


@pytest.mark.parametrize(
    ("malscore", "verdict"),
    [
        (7, EnrichmentStatus.MALICIOUS),
        (4, EnrichmentStatus.SUSPICIOUS),
        (1, EnrichmentStatus.CLEAN),
    ],
)
@respx.mock
async def test_cape_malscore_mapping(monkeypatch, malscore: float, verdict) -> None:
    _configure(monkeypatch, CAPE_BASE_URL=CAPE)
    respx.get(f"{CAPE}/apiv2/tasks/view/1/").respond(200, json={"data": {"status": "reported"}})
    respx.get(f"{CAPE}/apiv2/tasks/get/report/1/json/").respond(200, json={"malscore": malscore})
    async with CapeClient() as cape:
        report = await cape.get_report("1")
    assert report.verdict == verdict
    assert "authorization" not in respx.calls.last.request.headers


@respx.mock
async def test_cape_failed_task_and_submit_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, CAPE_BASE_URL=CAPE)
    respx.get(f"{CAPE}/apiv2/tasks/view/5/").respond(
        200, json={"data": {"status": "failed_analysis"}}
    )
    respx.post(f"{CAPE}/apiv2/tasks/create/file/").respond(
        200, json={"error": True, "error_value": "file too big"}
    )
    async with CapeClient() as cape:
        report = await cape.get_report("5")
        submitted = await cape.submit(FILE, "x.bin")
    assert report.status == "error" and report.error == "CAPE task failed_analysis"
    assert submitted.status == "error" and submitted.error == "submit failed: file too big"


async def test_cape_not_configured() -> None:
    async with CapeClient() as cape:
        assert (await cape.get_report("1")).status == "not_configured"
        assert (await cape.submit(FILE, "x")).status == "not_configured"
