"""External sandbox clients (dynamic analysis happens there, never on this host).

``SandboxClient`` is the common interface: ``submit(data, filename)`` returns a task id (or a
``SandboxReport`` explaining why nothing was submitted) and ``get_report(task_id)`` returns a
normalized ``SandboxReport`` (``status`` ``pending`` while the sandbox is still working).
Neither client does anything unless configured; both use the base client's rate limiting,
retries and secret scrubbing. Reports are not cached (they change until finished).

- ``HybridAnalysisClient``: Falcon Sandbox API v2. Submitting uploads the file to a public third
  party, so it also needs ``UPLOAD_FILES_TO_HYBRID_ANALYSIS=true``.
- ``CapeClient``: a CAPEv2 instance at ``CAPE_BASE_URL`` (optional ``CAPE_API_TOKEN``).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from phishlens.enrichment.base import BaseClient, EnrichmentError, redact
from phishlens.models import EnrichmentStatus, SandboxReport

__all__ = ["HA_API_URL", "CapeClient", "HybridAnalysisClient", "SandboxClient"]

HA_API_URL = "https://www.hybrid-analysis.com/api/v2"
HA_SITE_URL = "https://www.hybrid-analysis.com/sample"

# Hybrid Analysis verdict -> normalized status.
_HA_VERDICTS = {
    "malicious": EnrichmentStatus.MALICIOUS,
    "suspicious": EnrichmentStatus.SUSPICIOUS,
    "no specific threat": EnrichmentStatus.CLEAN,
    "whitelisted": EnrichmentStatus.CLEAN,
    "no verdict": EnrichmentStatus.UNKNOWN,
}
_HA_PENDING = frozenset({"IN_QUEUE", "IN_PROGRESS"})

# CAPE malscore (0-10) thresholds.
CAPE_MALICIOUS_SCORE = 7.0
CAPE_SUSPICIOUS_SCORE = 4.0
_CAPE_DONE = frozenset({"reported"})
_CAPE_FAILED = frozenset({"failed_analysis", "failed_processing", "failed_reporting"})


def _unique(values: Any) -> list[str]:
    out: list[str] = []
    for value in values:
        text = str(value).strip() if value is not None else ""
        if text and text not in out:
            out.append(text)
    return out


class SandboxClient(BaseClient, ABC):
    """Common interface of sandbox clients."""

    def _report(self, **fields: Any) -> SandboxReport:
        return SandboxReport(sandbox=self.service, **fields)

    def _not_configured(self, reason: str | None = None) -> SandboxReport:
        return self._report(status="not_configured", error=reason)

    def _failed(self, task_id: str | None, exc: Exception) -> SandboxReport:
        message = str(exc) if isinstance(exc, EnrichmentError) else type(exc).__name__
        return self._report(task_id=task_id, status="error", error=redact(message, self.settings))

    async def submit(self, data: bytes, filename: str) -> str | SandboxReport:
        """Submit a file. Returns the task id, or a report with status not_configured/error."""
        if not self.enabled:
            return self._not_configured()
        blocked = self._submit_blocked()
        if blocked:
            return self._not_configured(blocked)
        try:
            return await self._submit(data, filename)
        except Exception as exc:
            return self._failed(None, exc)

    async def get_report(self, task_id: str) -> SandboxReport:
        """Fetch the normalized report for ``task_id``. Never raises."""
        if not self.enabled:
            return self._not_configured()
        try:
            return await self._get_report(task_id)
        except Exception as exc:
            return self._failed(task_id, exc)

    def _submit_blocked(self) -> str | None:
        """A reason submission is not allowed even though the service is configured."""
        return None

    @abstractmethod
    async def _submit(self, data: bytes, filename: str) -> str: ...

    @abstractmethod
    async def _get_report(self, task_id: str) -> SandboxReport: ...


class HybridAnalysisClient(SandboxClient):
    service = "hybrid_analysis"

    def _headers(self) -> dict[str, str]:
        key = self.settings.hybrid_analysis_api_key
        # Hybrid Analysis rejects requests without this exact User-Agent.
        return {
            "api-key": key.get_secret_value() if key else "",
            "User-Agent": "Falcon Sandbox",
            "Accept": "application/json",
        }

    def _submit_blocked(self) -> str | None:
        if not self.settings.upload_files_to_hybrid_analysis:
            return "uploads disabled (UPLOAD_FILES_TO_HYBRID_ANALYSIS=false)"
        return None

    async def _submit(self, data: bytes, filename: str) -> str:
        response = await self.request(
            "POST",
            f"{HA_API_URL}/submit/file",
            headers=self._headers(),
            data={"environment_id": str(self.settings.hybrid_analysis_environment_id)},
            files={"file": (filename, data)},
        )
        if response.status_code not in (200, 201):
            raise EnrichmentError(f"submit failed: HTTP {response.status_code}")
        job_id = response.json().get("job_id")
        if not job_id:
            raise EnrichmentError("submit response had no job_id")
        return str(job_id)

    async def _get_report(self, task_id: str) -> SandboxReport:
        response = await self.request(
            "GET", f"{HA_API_URL}/report/{task_id}/summary", headers=self._headers()
        )
        if response.status_code == 404:
            return self._report(task_id=task_id, status="pending")
        if response.status_code != 200:
            raise EnrichmentError(f"report failed: HTTP {response.status_code}")
        data = response.json()
        state = str(data.get("state") or "")
        if state in _HA_PENDING:
            return self._report(task_id=task_id, status="pending")
        if state == "ERROR":
            return self._report(task_id=task_id, status="error", error="sandbox analysis failed")
        sha256 = data.get("sha256")
        environment = data.get("environment_id")
        verdict = str(data.get("verdict") or "").lower()
        return self._report(
            task_id=task_id,
            verdict=_HA_VERDICTS.get(verdict, EnrichmentStatus.UNKNOWN),
            score=data.get("threat_score"),
            processes=_unique(p.get("name") for p in data.get("processes") or []),
            network_domains=_unique(data.get("domains") or []),
            network_ips=_unique(data.get("hosts") or []),
            network_urls=_unique(data.get("extracted_urls") or []),
            dropped_hashes=_unique(f.get("sha256") for f in data.get("extracted_files") or []),
            signatures=_unique(s.get("name") for s in data.get("signatures") or []),
            link=f"{HA_SITE_URL}/{sha256}/{environment}" if sha256 and environment else None,
        )


class CapeClient(SandboxClient):
    service = "cape"

    @property
    def base_url(self) -> str:
        return (self.settings.cape_base_url or "").rstrip("/")

    def _headers(self) -> dict[str, str]:
        token = self.settings.cape_api_token
        return {"Authorization": f"Token {token.get_secret_value()}"} if token else {}

    async def _submit(self, data: bytes, filename: str) -> str:
        response = await self.request(
            "POST",
            f"{self.base_url}/apiv2/tasks/create/file/",
            headers=self._headers(),
            files={"file": (filename, data)},
        )
        if response.status_code != 200:
            raise EnrichmentError(f"submit failed: HTTP {response.status_code}")
        body = response.json()
        task_ids = (body.get("data") or {}).get("task_ids") or []
        if body.get("error") or not task_ids:
            raise EnrichmentError(f"submit failed: {body.get('error_value') or 'no task id'}")
        return str(task_ids[0])

    async def _get_report(self, task_id: str) -> SandboxReport:
        view = await self.request(
            "GET", f"{self.base_url}/apiv2/tasks/view/{task_id}/", headers=self._headers()
        )
        if view.status_code != 200:
            raise EnrichmentError(f"task view failed: HTTP {view.status_code}")
        status = str((view.json().get("data") or {}).get("status") or "")
        if status in _CAPE_FAILED:
            return self._report(task_id=task_id, status="error", error=f"CAPE task {status}")
        if status not in _CAPE_DONE:
            return self._report(task_id=task_id, status="pending")
        response = await self.request(
            "GET",
            f"{self.base_url}/apiv2/tasks/get/report/{task_id}/json/",
            headers=self._headers(),
        )
        if response.status_code != 200:
            raise EnrichmentError(f"report failed: HTTP {response.status_code}")
        report = response.json()
        malscore = float(report.get("malscore") or 0)
        if malscore >= CAPE_MALICIOUS_SCORE:
            verdict = EnrichmentStatus.MALICIOUS
        elif malscore >= CAPE_SUSPICIOUS_SCORE:
            verdict = EnrichmentStatus.SUSPICIOUS
        else:
            verdict = EnrichmentStatus.CLEAN
        network = report.get("network") or {}
        hosts = network.get("hosts") or []
        return self._report(
            task_id=task_id,
            verdict=verdict,
            score=round(malscore * 10, 1),
            processes=_unique(
                p.get("process_name") for p in (report.get("behavior") or {}).get("processes") or []
            ),
            network_domains=_unique(d.get("domain") for d in network.get("domains") or []),
            network_ips=_unique(h.get("ip") if isinstance(h, dict) else h for h in hosts),
            network_urls=_unique(h.get("uri") for h in network.get("http") or []),
            dropped_hashes=_unique(f.get("sha256") for f in report.get("dropped") or []),
            signatures=_unique(s.get("name") for s in report.get("signatures") or []),
            link=f"{self.base_url}/analysis/{task_id}/",
        )
