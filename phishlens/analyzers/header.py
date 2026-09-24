"""Header analyzer: email authentication results and header anomalies.

So far this covers ``Authentication-Results`` headers. Each one is parsed with ``authres`` and
kept only when its authserv-id is listed in ``TRUSTED_AUTHSERV_IDS``, because any sender can add
an ``Authentication-Results`` header of their own. An untrusted header gets a
``forged_auth_results_header`` finding. When the trust list is empty the forgery check is skipped
(no receiving server is known), and every header is recorded as untrusted.

``raw["auth_results"]`` lists every header (trusted or not) and ``raw["trusted_auth_results"]``
the method results from trusted headers only, for the SPF/DKIM/DMARC checks that follow.

SPF is evaluated by PhishLens itself (``phishlens.enrichment.spf_check``) for the originating
external IP from the Received chain, using the Return-Path domain or, when there is none, the HELO
name of that hop. The outcome is in ``raw["spf"]``.

Every DKIM-Signature is verified (``phishlens.enrichment.dkim_check``) and described in
``raw["dkim"]``. Besides pass/fail, signature quality is checked on the valid signatures: an
``l=`` body length, From/Subject/To left out of ``h=``, and an old ``t=`` (possible replay).
"""

from __future__ import annotations

import ipaddress
import re
import time
from datetime import UTC, datetime
from typing import Any

import authres

from phishlens.config import get_settings
from phishlens.enrichment.dkim_check import DkimSignature, verify_dkim
from phishlens.enrichment.spf_check import check_spf
from phishlens.models import AnalyzerResult, Finding, ParsedEmail, ReceivedHop, Severity
from phishlens.parser.received import originating_external_ip

MODULE = "header"

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")

# SPF result -> (finding id, severity, title). pass and neutral produce no finding.
_SPF_FINDINGS: dict[str, tuple[str, Severity, str]] = {
    "fail": ("spf_fail", Severity.HIGH, "SPF fail: sending server not authorized"),
    "softfail": ("spf_softfail", Severity.MEDIUM, "SPF softfail: sending server not authorized"),
    "none": ("spf_none", Severity.LOW, "No SPF record for the sending domain"),
    "temperror": ("spf_error", Severity.LOW, "SPF could not be evaluated (temporary error)"),
    "permerror": ("spf_error", Severity.LOW, "SPF could not be evaluated (broken record)"),
}

# A valid DKIM signature should cover these headers; otherwise they can be changed freely.
CRITICAL_SIGNED_HEADERS = ("from", "subject", "to")


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


def _helo_for(chain: list[ReceivedHop], ip: str) -> str:
    """HELO name of the newest hop from ``ip``, or "" when it is missing or not a host name."""
    for hop in reversed(chain):
        if hop.ip == ip:
            helo = (hop.from_host or "").strip().rstrip(".").lower()
            return helo if _HOSTNAME_RE.match(helo) else ""
    return ""


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


async def _check_spf(email: ParsedEmail, result: AnalyzerResult) -> None:
    ip = originating_external_ip(email.received_chain, get_settings().trusted_internal_hosts)
    if ip is None or not _is_ip(ip):
        result.raw["spf"] = {"result": None, "skipped_reason": "no_originating_ip"}
        return
    mail_from = email.return_path.address if email.return_path else ""
    helo = _helo_for(email.received_chain, ip)
    if not mail_from and not helo:
        result.raw["spf"] = {"result": None, "ip": ip, "skipped_reason": "no_identity"}
        return

    check = await check_spf(ip, mail_from, helo)
    result.raw["spf"] = check.to_dict()
    if check.result not in _SPF_FINDINGS:
        return
    finding_id, severity, title = _SPF_FINDINGS[check.result]
    if check.result == "none":
        description = f"'{check.domain}' publishes no SPF record, so any server can send as it."
    elif finding_id == "spf_error":
        description = f"SPF for '{check.domain}' returned {check.result}: {check.explanation}"
    else:
        description = (
            f"SPF for '{check.domain}' ({check.identity}) does not authorize the sending IP "
            f"{check.ip}. The message may not come from where it claims."
        )
    result.findings.append(
        Finding(
            id=finding_id,
            module=MODULE,
            title=title,
            description=description,
            severity=severity,
            evidence={
                "result": check.result,
                "ip": check.ip,
                "domain": check.domain,
                "identity": check.identity,
                "explanation": check.explanation,
            },
        )
    )


def _delivery_time(email: ParsedEmail) -> datetime:
    """When the message was delivered: newest Received timestamp, else Date, else now."""
    for hop in reversed(email.received_chain):
        if hop.timestamp is not None:
            return hop.timestamp
    return email.date or datetime.now(UTC)


def _sig_summary(sig: DkimSignature, **extra: Any) -> dict[str, Any]:
    return {"domain": sig.domain, "selector": sig.selector, **extra}


def _dkim_finding(
    finding_id: str, severity: Severity, title: str, description: str, signatures: list
) -> Finding:
    return Finding(
        id=finding_id,
        module=MODULE,
        title=title,
        description=description,
        severity=severity,
        evidence={"signatures": signatures},
    )


async def _check_dkim(email: ParsedEmail, result: AnalyzerResult) -> None:
    has_signature = any(name.lower() == "dkim-signature" for name, _ in email.headers)
    if has_signature and not email.raw_bytes:
        result.raw["dkim"] = {"signatures": [], "skipped_reason": "no_raw_message"}
        return
    signatures = await verify_dkim(email.raw_bytes) if has_signature else []
    delivered = _delivery_time(email)
    max_age_days = get_settings().dkim_max_age_days
    result.raw["dkim"] = {
        "signatures": [s.to_dict() for s in signatures],
        "delivery_time": delivered.isoformat(),
    }
    findings = result.findings

    if not signatures:
        findings.append(
            Finding(
                id="dkim_none",
                module=MODULE,
                title="No DKIM signature",
                description="The message carries no DKIM signature, so its content and sender "
                "domain are not cryptographically vouched for.",
                severity=Severity.LOW,
            )
        )
        return

    valid = [s for s in signatures if s.valid]
    invalid = [s for s in signatures if s.status in ("fail", "permerror")]
    if invalid:
        findings.append(
            _dkim_finding(
                "dkim_invalid",
                Severity.LOW if valid else Severity.MEDIUM,
                "DKIM signature does not verify",
                "A DKIM signature failed verification: the message was changed after signing, "
                "or the signature or key is broken.",
                [_sig_summary(s, status=s.status, error=s.error) for s in invalid],
            )
        )

    with_length = [s for s in valid if s.body_length is not None]
    if with_length:
        findings.append(
            _dkim_finding(
                "dkim_body_length_tag",
                Severity.MEDIUM,
                "DKIM signature covers only part of the body (l= tag)",
                "The signature uses l=, so content appended after the signed length is not "
                "covered and could have been added by anyone.",
                [_sig_summary(s, body_length=s.body_length) for s in with_length],
            )
        )

    unsigned = [
        _sig_summary(s, missing=missing)
        for s in valid
        if (missing := [h for h in CRITICAL_SIGNED_HEADERS if h not in s.signed_headers])
    ]
    if unsigned:
        findings.append(
            _dkim_finding(
                "dkim_unsigned_critical_headers",
                Severity.MEDIUM,
                "DKIM signature does not cover key headers",
                "A valid signature leaves From, Subject or To out of h=, so those headers "
                "could be changed without breaking it.",
                unsigned,
            )
        )

    stale: list[dict[str, Any]] = []
    for sig in signatures:
        if sig.status == "expired":
            stale.append(_sig_summary(sig, reason="expired", expiration=sig.expiration))
        elif sig.valid and sig.timestamp is not None:
            age_days = (delivered.timestamp() - sig.timestamp) / 86400
            if age_days > max_age_days:
                stale.append(
                    _sig_summary(
                        sig, reason="old", timestamp=sig.timestamp, age_days=round(age_days, 1)
                    )
                )
    if stale:
        findings.append(
            _dkim_finding(
                "dkim_expired_or_old",
                Severity.MEDIUM,
                "DKIM signature expired or much older than delivery",
                f"A signature is past its x= expiry or was made more than {max_age_days:g} "
                "days before delivery, which can mean an old signed message is being replayed.",
                stale,
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
    try:
        await _check_spf(email, result)
    except Exception as exc:
        result.errors.append(f"spf: {type(exc).__name__}: {exc}")
    try:
        await _check_dkim(email, result)
    except Exception as exc:
        result.errors.append(f"dkim: {type(exc).__name__}: {exc}")
    result.duration_ms = int((time.perf_counter() - start) * 1000)
    return result
