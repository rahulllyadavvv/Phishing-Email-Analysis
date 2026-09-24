"""Header analyzer: email authentication results and header anomalies.

So far this covers ``Authentication-Results`` headers. Each one is parsed with ``authres`` and
kept only when its authserv-id is listed in ``TRUSTED_AUTHSERV_IDS``, because any sender can add
an ``Authentication-Results`` header of their own. An untrusted header gets a
``forged_auth_results_header`` finding. When the trust list is empty the forgery check is skipped
(no receiving server is known), and every header is recorded as untrusted.

``raw["auth_results"]`` lists every header (trusted or not) and ``raw["trusted_auth_results"]``
the method results from trusted headers only, for the SPF/DKIM/DMARC checks that follow.
"""

from __future__ import annotations

import time
from typing import Any

import authres

from phishlens.config import get_settings
from phishlens.models import AnalyzerResult, Finding, ParsedEmail, Severity

MODULE = "header"


def _parse_auth_results(value: str) -> dict[str, Any]:
    """Parse one Authentication-Results header value into a plain dict."""
    entry: dict[str, Any] = {"raw": value, "authserv_id": None, "results": [], "parse_error": None}
    try:
        header = authres.AuthenticationResultsHeader.parse_value(value)
    except Exception as exc:
        entry["parse_error"] = f"{type(exc).__name__}: {exc}"
        return entry
    entry["authserv_id"] = (header.authserv_id or "").lower() or None
    entry["results"] = [
        {
            "method": result.method,
            "result": result.result,
            "properties": {f"{p.type}.{p.name}": p.value for p in result.properties},
        }
        for result in header.results
    ]
    return entry


def _check_auth_results(email: ParsedEmail, result: AnalyzerResult) -> None:
    trusted_ids = set(get_settings().trusted_authserv_ids)
    entries = [_parse_auth_results(value) for value in email.auth_results_headers]
    for entry in entries:
        entry["trusted"] = entry["authserv_id"] in trusted_ids
    result.raw["auth_results"] = entries
    result.raw["trusted_authserv_ids_configured"] = bool(trusted_ids)
    result.raw["trusted_auth_results"] = [
        r for entry in entries if entry["trusted"] for r in entry["results"]
    ]
    if not trusted_ids:
        return
    for entry in entries:
        if entry["trusted"]:
            continue
        authserv_id = entry["authserv_id"] or "unparseable"
        result.findings.append(
            Finding(
                id="forged_auth_results_header",
                module=MODULE,
                title="Authentication-Results header from an untrusted server",
                description=(
                    f"An Authentication-Results header claims to come from '{authserv_id}', "
                    "which is not one of the trusted receiving servers. Senders can add these "
                    "headers themselves to fake passing SPF/DKIM/DMARC results."
                ),
                severity=Severity.MEDIUM,
                evidence={"header": entry["raw"], "authserv_id": entry["authserv_id"]},
            )
        )


async def analyze(email: ParsedEmail) -> AnalyzerResult:
    """Analyze the email's headers. Never raises; errors go into ``AnalyzerResult.errors``."""
    start = time.perf_counter()
    result = AnalyzerResult(module=MODULE)
    try:
        _check_auth_results(email, result)
    except Exception as exc:
        result.errors.append(f"auth_results: {type(exc).__name__}: {exc}")
    result.duration_ms = int((time.perf_counter() - start) * 1000)
    return result
