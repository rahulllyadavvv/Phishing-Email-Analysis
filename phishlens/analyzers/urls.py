"""URL analyzer. Static checks only here: nothing is fetched, the URL strings are parsed.

Input: ``email.urls`` plus extra ``UrlRef``s from other analyzers (attachments, QR codes, ...)
passed in by the pipeline. URLs are deduplicated; each unique URL gets one row in
``raw["urls"]`` with its defanged form, sources, visible texts and the static flags it raised.
Findings are grouped by ID (one finding per ID, listing the URLs) so the scorer counts each kind
of problem once per email.

URLs on ``data/url_allowlist.yaml`` domains are marked ``allowlisted``: they are skipped for
reputation lookups, but the static checks below still apply to them.

Reputation (``reputation=True``, the default): every other unique http(s)/ftp URL goes through
``lookup.url_reputation`` (Safe Browsing -> URLhaus -> VirusTotal), concurrently. URLs that no
service had a verdict for are then sent to urlscan.io (at most ``MAX_URLSCAN_PER_EMAIL``), which
visits the page in its own browser. NOTHING is ever fetched from this host.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from typing import Any
from urllib.parse import urlsplit

from phishlens.analyzers.domain import check_lookalike, decode_idn
from phishlens.data_loader import (
    brand_for_domain,
    is_risky_tld,
    is_shortener,
    is_url_allowlisted,
    url_credential_keywords,
)
from phishlens.enrichment.lookup import url_reputation
from phishlens.enrichment.urlscan import UrlscanClient
from phishlens.ioc.defang import defang_domain, defang_url
from phishlens.models import (
    AnalyzerResult,
    EnrichmentResult,
    EnrichmentStatus,
    Finding,
    ParsedEmail,
    Severity,
    UrlRef,
)
from phishlens.parser.headers import org_domain

MODULE = "urls"

__all__ = ["MODULE", "analyze", "static_checks", "urlscan_scan"]

REPUTATION_SCHEMES = frozenset({"http", "https", "ftp"})
MAX_CONCURRENT_LOOKUPS = 4
MAX_URLSCAN_PER_EMAIL = 5
# Worst first: the overall reputation of a URL is the first of these any service returned.
STATUS_ORDER = (
    EnrichmentStatus.MALICIOUS,
    EnrichmentStatus.SUSPICIOUS,
    EnrichmentStatus.CLEAN,
    EnrichmentStatus.UNKNOWN,
    EnrichmentStatus.ERROR,
    EnrichmentStatus.NOT_CONFIGURED,
)
NO_VERDICT = frozenset(
    {EnrichmentStatus.UNKNOWN, EnrichmentStatus.ERROR, EnrichmentStatus.NOT_CONFIGURED}
)

MAX_SUBDOMAIN_LEVELS = 3  # more labels than this in front of the registered domain is odd
SCRIPT_SCHEMES = frozenset({"data", "javascript", "vbscript"})

# finding id -> (severity, title, description)
FINDINGS: dict[str, tuple[Severity, str, str]] = {
    "link_text_mismatch": (
        Severity.HIGH,
        "Link text shows a different domain than the real link",
        "The visible text of a link names one domain, but clicking it goes to another.",
    ),
    "ip_address_url": (
        Severity.MEDIUM,
        "Link points to a raw IP address",
        "Legitimate services link to domain names, not to bare (or disguised) IP addresses.",
    ),
    "url_shortener": (
        Severity.LOW,
        "Link uses a URL shortener",
        "A shortener hides the real destination of the link.",
    ),
    "at_sign_in_url": (
        Severity.HIGH,
        "Link contains an @ before the host",
        "Everything before the @ is ignored by browsers, so the link can show a trusted name "
        "while going somewhere else (http://trusted.com@evil.example/).",
    ),
    "excessive_subdomains": (
        Severity.LOW,
        "Link has an unusually deep subdomain",
        "Long subdomain chains are used to push a trusted-looking name to the front of the host.",
    ),
    "brand_in_unrelated_domain": (
        Severity.HIGH,
        "Link domain imitates a known brand",
        "The link's domain looks like a brand's domain but is not one of its real domains.",
    ),
    "risky_tld": (
        Severity.LOW,
        "Link uses a high-risk top-level domain",
        "The top-level domain is cheap and heavily used for phishing and malware.",
    ),
    "credential_keywords": (
        Severity.LOW,
        "Link path suggests a login or payment page",
        "Words like login, verify or account in the link point at a page asking for details.",
    ),
    "data_or_javascript_uri": (
        Severity.HIGH,
        "Link is a data: or javascript: URI",
        "The link carries its own content or script instead of pointing to a website, a common "
        "way to smuggle phishing pages past filters.",
    ),
    "punycode_url": (
        Severity.MEDIUM,
        "Link uses an internationalized (punycode) domain",
        "The domain contains non-Latin characters that can look like a familiar name.",
    ),
    "url_known_malicious": (
        Severity.CRITICAL,
        "Link is known to be malicious",
        "A threat-intelligence service lists this link as phishing or malware.",
    ),
    "url_suspicious_reputation": (
        Severity.MEDIUM,
        "Link has a suspicious reputation",
        "A threat-intelligence service rates this link as suspicious.",
    ),
    "urlscan_login_page_on_unrelated_domain": (
        Severity.HIGH,
        "Link opens a login page on an unrelated domain",
        "urlscan.io found a password field on the page, which is not on the sender's domain "
        "or a known brand's domain.",
    ),
    "redirect_to_different_domain": (
        Severity.MEDIUM,
        "Link redirects to a different domain",
        "The link ends up on another domain than the one it shows, which hides the real "
        "destination.",
    ),
}

_VISIBLE_DOMAIN_RE = re.compile(
    r"(?:[a-z][a-z0-9+.-]*://)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})(?![a-z0-9-])"
)
_OBFUSCATED_IP_RE = re.compile(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}")


def _safe_text(text: str | None) -> str | None:
    """Defang whatever domain-like parts a visible link text contains."""
    if text is None:
        return None
    return defang_url(text) if "://" in text else defang_domain(text)


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(_OBFUSCATED_IP_RE.fullmatch(host))  # decimal / hex / octal IP forms


def _keyword_patterns() -> list[tuple[str, re.Pattern[str]]]:
    return [
        (kw, re.compile(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])"))
        for kw in url_credential_keywords()
    ]


def static_checks(url: str, visible_texts: list[str]) -> dict[str, Any]:
    """Run the static checks on one URL. Returns the row fields plus ``flags`` (finding ids)
    and per-flag ``details``."""
    flags: list[str] = []
    details: dict[str, Any] = {}
    info: dict[str, Any] = {"scheme": None, "host": None, "registered_domain": None}
    try:
        parts = urlsplit(url.strip())
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").rstrip(".").lower()
    except ValueError as exc:
        return {**info, "flags": flags, "details": details, "parse_error": str(exc)}
    info["scheme"] = scheme or None
    if scheme in SCRIPT_SCHEMES:
        flags.append("data_or_javascript_uri")
        return {**info, "flags": flags, "details": details}
    if not host:
        return {**info, "flags": flags, "details": details}

    ip_host = _is_ip_host(host)
    registered = host if ip_host else (org_domain(host) or host)
    info.update(host=host, registered_domain=registered)

    for text in visible_texts:
        match = _VISIBLE_DOMAIN_RE.search(text.lower())
        if match and org_domain(match.group(1)) != registered:
            flags.append("link_text_mismatch")
            details["link_text_mismatch"] = {
                "visible_domain": defang_domain(match.group(1)),
                "actual_domain": defang_domain(registered),
            }
            break
    if ip_host:
        flags.append("ip_address_url")
    if "@" in parts.netloc:
        flags.append("at_sign_in_url")
    if not ip_host:
        if is_shortener(host):
            flags.append("url_shortener")
        subdomain_levels = host.count(".") - registered.count(".")
        if subdomain_levels > MAX_SUBDOMAIN_LEVELS:
            flags.append("excessive_subdomains")
            details["excessive_subdomains"] = {"levels": subdomain_levels}
        matches = check_lookalike(host)
        if matches:
            flags.append("brand_in_unrelated_domain")
            details["brand_in_unrelated_domain"] = {
                "brands": sorted({m.brand for m in matches}),
                "matches": [
                    {
                        **m.to_dict(),
                        "domain": defang_domain(m.domain),
                        "decoded": defang_domain(m.decoded),
                    }
                    for m in matches
                ],
            }
        if is_risky_tld(host):
            flags.append("risky_tld")
        if not host.isascii() or any(label.startswith("xn--") for label in host.split(".")):
            flags.append("punycode_url")
            details["punycode_url"] = {
                "decoded": defang_domain(decode_idn(host)),
                "lookalike": bool(matches),
            }
    path_query = f"{parts.path}?{parts.query}".lower()
    found = [kw for kw, pattern in _keyword_patterns() if pattern.search(path_query)]
    if found:
        flags.append("credential_keywords")
        details["credential_keywords"] = {"keywords": found}
    return {**info, "flags": flags, "details": details}


def _unique_refs(refs: list[UrlRef]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for ref in refs:
        url = ref.url.strip()
        if not url:
            continue
        row = rows.setdefault(url, {"sources": [], "visible_texts": []})
        if ref.source.value not in row["sources"]:
            row["sources"].append(ref.source.value)
        if ref.visible_text and ref.visible_text not in row["visible_texts"]:
            row["visible_texts"].append(ref.visible_text)
    return rows


def _add_findings(result: AnalyzerResult, grouped: dict[str, list[dict[str, Any]]]) -> None:
    for finding_id, entries in grouped.items():
        severity, title, description = FINDINGS[finding_id]
        if finding_id == "punycode_url" and any(e.get("lookalike") for e in entries):
            severity = Severity.HIGH
        result.findings.append(
            Finding(
                id=finding_id,
                module=MODULE,
                title=title,
                description=description,
                severity=severity,
                evidence={"urls": entries, "count": len(entries)},
            )
        )


def _check_urls(refs: list[UrlRef], result: AnalyzerResult) -> None:
    rows = []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for url, seen in _unique_refs(refs).items():
        checks = static_checks(url, seen["visible_texts"])
        row = {
            "url": url,
            "defanged": defang_url(url),
            "visible_texts": [_safe_text(t) for t in seen["visible_texts"]],
            "sources": seen["sources"],
            "allowlisted": bool(checks["host"]) and is_url_allowlisted(checks["host"]),
            **checks,
        }
        rows.append(row)
        for flag in checks["flags"]:
            entry = {"url": row["defanged"], **checks["details"].get(flag, {})}
            grouped.setdefault(flag, []).append(entry)
    result.raw["urls"] = rows
    _add_findings(result, grouped)


async def urlscan_scan(url: str) -> EnrichmentResult:
    """Scan one URL with urlscan.io (reusing a recent scan when there is one)."""
    async with UrlscanClient() as client:
        return await client.scan(url)


def _overall(statuses: set[str]) -> str:
    """The worst status in ``statuses`` (see ``STATUS_ORDER``); ``unknown`` when empty."""
    return next((s.value for s in STATUS_ORDER if s.value in statuses), "unknown")


def _summary(result: EnrichmentResult) -> dict[str, Any]:
    """A report-friendly view of one service result (no raw query; links kept)."""
    return {
        "service": result.service,
        "status": result.status.value,
        "detections": result.detections,
        "total_engines": result.total_engines,
        "cached": result.cached,
        "link": result.link,
        "error": result.error,
    }


def _needs_reputation(row: dict[str, Any]) -> bool:
    return (
        not row["allowlisted"]
        and row.get("scheme") in REPUTATION_SCHEMES
        and bool(row.get("host"))
    )


async def _check_reputation(email: ParsedEmail, result: AnalyzerResult) -> None:
    rows = [r for r in result.raw.get("urls", []) if _needs_reputation(r)]
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_LOOKUPS)

    async def reputation(row: dict[str, Any]) -> list[EnrichmentResult]:
        async with semaphore:
            return await url_reputation(row["url"])

    lookups = await asyncio.gather(*(reputation(r) for r in rows))
    grouped: dict[str, list[dict[str, Any]]] = {}
    unscanned: list[dict[str, Any]] = []
    for row, results in zip(rows, lookups, strict=True):
        row["reputation"] = [_summary(r) for r in results]
        if all(r.status in NO_VERDICT for r in results):
            unscanned.append(row)

    to_scan = unscanned[:MAX_URLSCAN_PER_EMAIL]
    scans = await asyncio.gather(*(urlscan_scan(r["url"]) for r in to_scan))
    from_domain = email.from_addrs[0].org_domain if email.from_addrs else ""
    for row, scan in zip(to_scan, scans, strict=True):
        row["reputation"].append(_summary(scan))
        if scan.status in (EnrichmentStatus.ERROR, EnrichmentStatus.NOT_CONFIGURED):
            continue
        details = scan.details
        final_url = details.get("final_url")
        row["final_url"] = defang_url(final_url) if final_url else None
        row["screenshot_url"] = details.get("screenshot_url")
        row["urlscan_link"] = scan.link
        row["login_form"] = details.get("login_form")
        final_host = (urlsplit(final_url).hostname or "").lower() if final_url else ""
        final_registered = org_domain(final_host) if final_host else ""
        if final_registered and final_registered != row["registered_domain"]:
            grouped.setdefault("redirect_to_different_domain", []).append(
                {
                    "url": row["defanged"],
                    "final_url": row["final_url"],
                    "final_domain": defang_domain(final_registered),
                }
            )
        if (
            details.get("login_form")
            and final_registered
            and final_registered != from_domain
            and brand_for_domain(final_registered) is None
        ):
            grouped.setdefault("urlscan_login_page_on_unrelated_domain", []).append(
                {
                    "url": row["defanged"],
                    "final_url": row["final_url"],
                    "screenshot_url": row["screenshot_url"],
                }
            )

    for row in rows:
        verdict = _overall({r["status"] for r in row["reputation"]})
        row["reputation_verdict"] = verdict
        flagged_by = [r["service"] for r in row["reputation"] if r["status"] == verdict]
        entry = {"url": row["defanged"], "services": flagged_by}
        if verdict == EnrichmentStatus.MALICIOUS:
            grouped.setdefault("url_known_malicious", []).append(entry)
        elif verdict == EnrichmentStatus.SUSPICIOUS:
            grouped.setdefault("url_suspicious_reputation", []).append(entry)
    for row in result.raw.get("urls", []):
        row.setdefault("reputation", [])
        row.setdefault("reputation_verdict", None)
    _add_findings(result, grouped)



async def analyze(
    email: ParsedEmail,
    context: dict[str, AnalyzerResult] | None = None,
    extra_urls: list[UrlRef] | None = None,
    reputation: bool = True,
) -> AnalyzerResult:
    """Analyze the email's URLs (plus ``extra_urls``). Never raises.

    ``reputation=False`` runs the static checks only (no network at all).
    """
    start = time.perf_counter()
    result = AnalyzerResult(module=MODULE)
    try:
        _check_urls(list(email.urls) + list(extra_urls or []), result)
    except Exception as exc:
        result.errors.append(f"static: {type(exc).__name__}: {exc}")
    if reputation:
        try:
            await _check_reputation(email, result)
        except Exception as exc:
            result.errors.append(f"reputation: {type(exc).__name__}: {exc}")
    result.duration_ms = int((time.perf_counter() - start) * 1000)
    return result
