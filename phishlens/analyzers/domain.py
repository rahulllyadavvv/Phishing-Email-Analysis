"""Domain analyzer: sender domain consistency, display-name brand spoofing and lookalikes.

The organizational domains of From, Return-Path, Reply-To and Sender are compared. A Reply-To
that points elsewhere (especially to free webmail) is a classic way to receive the victim's
answer while showing a trusted From. The display name is searched for brand keywords from
``data/brand_registry.yaml``; a brand name shown over an address that is not one of the brand's
domains (or is free webmail) is display-name spoofing.

``raw["domain_table"]`` has one row per sender address for the report.
"""

from __future__ import annotations

import re
import time
from functools import cache
from typing import Any

from phishlens.data_loader import (
    Brand,
    BrandRegistry,
    brand_for_domain,
    brand_registry,
    domain_matches,
    esp_for_domain,
    is_free_webmail,
    is_risky_tld,
)
from phishlens.models import Address, AnalyzerResult, Finding, ParsedEmail, Severity

MODULE = "domain"

__all__ = ["MODULE", "BrandMention", "analyze", "find_brand_mentions"]


class BrandMention:
    """A brand keyword found in some text."""

    __slots__ = ("brand", "keyword")

    def __init__(self, brand: Brand, keyword: str) -> None:
        self.brand = brand
        self.keyword = keyword

    def __repr__(self) -> str:
        return f"BrandMention({self.brand.name!r}, {self.keyword!r})"


def _keyword_pattern(keyword: str) -> str:
    words = [re.escape(w) for w in keyword.split()]
    return r"(?<![a-z0-9])" + r"[\s\-_.]*".join(words) + r"(?![a-z0-9])"


@cache
def _brand_patterns(
    registry: BrandRegistry,
) -> tuple[tuple[Brand, tuple[tuple[str, re.Pattern[str]], ...]], ...]:
    """Compiled keyword patterns, cached per registry (a reloaded registry recompiles)."""
    entries = list(registry.brands)
    org = registry.organization
    if org.name.strip() and org.domains:
        entries.append(
            Brand(name=org.name, keywords=(org.name.lower(),), legitimate_domains=org.domains)
        )
    return tuple(
        (brand, tuple((kw, re.compile(_keyword_pattern(kw))) for kw in brand.keywords))
        for brand in entries
    )


def find_brand_mentions(text: str) -> list[BrandMention]:
    """Return the brands whose keywords appear in ``text`` as whole words (one per brand).

    The user's organization (``organization`` in the brand registry) is included as a brand
    when it has a name and domains.
    """
    lowered = text.lower()
    mentions = []
    for brand, patterns in _brand_patterns(brand_registry()):
        for keyword, pattern in patterns:
            if pattern.search(lowered):
                mentions.append(BrandMention(brand, keyword))
                break
    return mentions


def _row(role: str, addr: Address, from_addr: Address | None) -> dict[str, Any]:
    brand = brand_for_domain(addr.domain)
    esp = esp_for_domain(addr.domain)
    return {
        "role": role,
        "address": addr.address,
        "display_name": addr.display_name,
        "domain": addr.domain,
        "org_domain": addr.org_domain,
        "free_webmail": is_free_webmail(addr.domain),
        "risky_tld": is_risky_tld(addr.domain),
        "brand": brand.name if brand else None,
        "esp": esp.name if esp else None,
        "matches_from": bool(from_addr) and addr.org_domain == from_addr.org_domain,
    }


def _finding(
    finding_id: str, severity: Severity, title: str, description: str, evidence: dict
) -> Finding:
    return Finding(
        id=finding_id,
        module=MODULE,
        title=title,
        description=description,
        severity=severity,
        evidence=evidence,
    )


def _check_consistency(email: ParsedEmail, result: AnalyzerResult) -> None:
    from_addr = email.from_addrs[0] if email.from_addrs else None
    rows = [_row("from", a, from_addr) for a in email.from_addrs]
    if email.return_path:
        rows.append(_row("return_path", email.return_path, from_addr))
    rows += [_row("reply_to", a, from_addr) for a in email.reply_to]
    if email.sender:
        rows.append(_row("sender", email.sender, from_addr))
    result.raw["domain_table"] = rows
    if from_addr is None or not from_addr.domain:
        return

    rp = email.return_path
    if rp and rp.domain and rp.org_domain != from_addr.org_domain:
        esp = esp_for_domain(rp.domain)
        result.findings.append(
            _finding(
                "returnpath_mismatch",
                Severity.INFO if esp else Severity.LOW,
                "Return-Path domain differs from From",
                f"Bounces go to '{rp.domain}', not to the From domain '{from_addr.domain}'."
                + (f" That is the bulk email service {esp.name}, which is common." if esp else ""),
                {
                    "from_domain": from_addr.domain,
                    "return_path_domain": rp.domain,
                    "esp": esp.name if esp else None,
                },
            )
        )

    from_is_webmail = is_free_webmail(from_addr.domain)
    for reply in email.reply_to:
        if not reply.domain or reply.address.lower() == from_addr.address.lower():
            continue
        evidence = {
            "from": from_addr.address,
            "reply_to": reply.address,
            "reply_to_domain": reply.domain,
        }
        if reply.org_domain != from_addr.org_domain:
            result.findings.append(
                _finding(
                    "replyto_mismatch",
                    Severity.MEDIUM,
                    "Reply-To points to a different domain",
                    f"Replies go to '{reply.address}' instead of the From domain "
                    f"'{from_addr.domain}', so an answer would reach someone else.",
                    evidence,
                )
            )
        if is_free_webmail(reply.domain):
            result.findings.append(
                _finding(
                    "replyto_free_webmail",
                    Severity.MEDIUM if from_is_webmail else Severity.HIGH,
                    "Reply-To is a free webmail address",
                    f"Replies go to the free webmail address '{reply.address}'"
                    + (
                        ""
                        if from_is_webmail
                        else f" although the message claims to come from '{from_addr.domain}'"
                    )
                    + ".",
                    {**evidence, "from_is_free_webmail": from_is_webmail},
                )
            )


def _check_display_name(email: ParsedEmail, result: AnalyzerResult) -> None:
    for addr in email.from_addrs:
        if not addr.display_name:
            continue
        for mention in find_brand_mentions(addr.display_name):
            webmail = is_free_webmail(addr.domain)
            legit = domain_matches(addr.domain, mention.brand.legitimate_domains)
            if legit and not webmail:
                continue
            reason = "a free webmail address" if webmail else "not one of the brand's domains"
            result.findings.append(
                _finding(
                    "display_name_brand_spoof",
                    Severity.HIGH,
                    f"Display name claims {mention.brand.name}",
                    f"The sender is shown as '{addr.display_name}', but the address "
                    f"'{addr.address}' is {reason}.",
                    {
                        "brand": mention.brand.name,
                        "keyword": mention.keyword,
                        "display_name": addr.display_name,
                        "address": addr.address,
                        "domain": addr.domain,
                        "free_webmail": webmail,
                        "legitimate_domains": list(mention.brand.legitimate_domains),
                    },
                )
            )


async def analyze(email: ParsedEmail) -> AnalyzerResult:
    """Analyze sender domains. Never raises; errors go into ``AnalyzerResult.errors``."""
    start = time.perf_counter()
    result = AnalyzerResult(module=MODULE)
    for name, check in (("consistency", _check_consistency), ("display_name", _check_display_name)):
        try:
            check(email, result)
        except Exception as exc:
            result.errors.append(f"{name}: {type(exc).__name__}: {exc}")
    result.duration_ms = int((time.perf_counter() - start) * 1000)
    return result
