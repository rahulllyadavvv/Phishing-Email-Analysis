"""DMARC record discovery and parsing (RFC 7489 6.3 and 6.6.3), through our cached DNS helper.

The record is looked up at ``_dmarc.<From domain>``. When there is none and the From domain is a
subdomain, the organizational domain's record is used instead, and its ``sp=`` policy (default
``p=``) applies. Only the tags PhishLens needs are interpreted; the rest are kept in ``tags``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from phishlens.enrichment import dns as dns_helper

__all__ = ["DmarcRecord", "fetch_dmarc", "parse_dmarc"]

POLICIES = frozenset({"none", "quarantine", "reject"})
MISSING = frozenset({"nxdomain", "no_answer"})


@dataclass
class DmarcRecord:
    """The DMARC policy that applies to a From domain.

    ``found`` is False when neither the From domain nor its organizational domain publishes a
    record. ``error`` is set when a lookup failed for another reason (e.g. a timeout), in which
    case the policy is unknown. ``policy`` is the effective policy for the From domain: ``sp``
    when the record came from the organizational domain, otherwise ``p``.
    """

    domain: str
    found: bool = False
    record_domain: str | None = None
    record: str | None = None
    p: str | None = None
    sp: str | None = None
    adkim: str = "r"
    aspf: str = "r"
    pct: int = 100
    policy: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_dmarc(record: str) -> tuple[dict[str, str], list[str]]:
    """Split a DMARC record into lowercased tag names and stripped values, plus warnings."""
    tags: dict[str, str] = {}
    warnings: list[str] = []
    for part in record.split(";"):
        if not part.strip():
            continue
        name, sep, value = part.partition("=")
        if not sep:
            warnings.append(f"ignored malformed tag: {part.strip()}")
            continue
        tags.setdefault(name.strip().lower(), value.strip())
    return tags, warnings


def _apply(result: DmarcRecord, record: str, record_domain: str) -> None:
    tags, warnings = parse_dmarc(record)
    result.found, result.record, result.record_domain = True, record, record_domain
    result.tags, result.warnings = tags, warnings

    p = tags.get("p", "").lower()
    if p not in POLICIES:
        # RFC 7489 6.6.3: an invalid or missing p= is treated as p=none (when rua= is present;
        # we are lenient and always do so, and note it).
        warnings.append(f"invalid or missing p= ({p or 'absent'}), treated as none")
        p = "none"
    sp = tags.get("sp", "").lower()
    if sp and sp not in POLICIES:
        warnings.append(f"invalid sp= ({sp}), using p=")
        sp = ""
    result.p, result.sp = p, sp or None
    for tag in ("adkim", "aspf"):
        mode = tags.get(tag, "r").lower()
        if mode not in ("r", "s"):
            warnings.append(f"invalid {tag}= ({mode}), using relaxed")
            mode = "r"
        setattr(result, tag, mode)
    pct = tags.get("pct", "100")
    if pct.isdigit() and 0 <= int(pct) <= 100:
        result.pct = int(pct)
    else:
        warnings.append(f"invalid pct= ({pct}), using 100")
    from_org = record_domain != result.domain
    result.policy = (result.sp or result.p) if from_org else result.p


async def _lookup(domain: str) -> tuple[list[str], str | None]:
    """Return the DMARC records at ``_dmarc.<domain>`` and a lookup error, if any."""
    answer = await dns_helper.txt(f"_dmarc.{domain}")
    if answer.error in MISSING:
        return [], None
    if answer.error:
        return [], answer.error
    return [r for r in answer.records if r.strip().lower().startswith("v=dmarc1")], None


async def fetch_dmarc(from_domain: str, org_domain: str) -> DmarcRecord:
    """Find and parse the DMARC policy for ``from_domain``. Never raises."""
    from_domain, org_domain = from_domain.lower(), (org_domain or from_domain).lower()
    result = DmarcRecord(domain=from_domain)
    candidates = [from_domain] + ([org_domain] if org_domain != from_domain else [])
    for domain in candidates:
        records, error = await _lookup(domain)
        if error:
            result.error = f"DNS {error} for _dmarc.{domain}"
            return result
        if len(records) > 1:
            # RFC 7489 6.6.3: more than one record means no policy applies.
            result.warnings.append(f"{len(records)} DMARC records at _dmarc.{domain}, ignored")
            return result
        if records:
            _apply(result, records[0], domain)
            return result
    return result
