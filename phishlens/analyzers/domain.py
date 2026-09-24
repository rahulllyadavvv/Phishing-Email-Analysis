"""Domain analyzer: sender domain consistency, display-name brand spoofing and lookalikes.

The organizational domains of From, Return-Path, Reply-To and Sender are compared. A Reply-To
that points elsewhere (especially to free webmail) is a classic way to receive the victim's
answer while showing a trusted From. The display name is searched for brand keywords from
``data/brand_registry.yaml``; a brand name shown over an address that is not one of the brand's
domains (or is free webmail) is display-name spoofing.

``check_lookalike(domain)`` (also used by the URL analyzer) compares a domain with every brand's
legitimate domains: homoglyphs and IDN/punycode (via the "skeleton" built from
``data/confusables.yaml``), typos (Damerau-Levenshtein on skeletons), combosquatting (a brand
label plus other words), TLD swaps and a brand used as a subdomain of another domain.

Identity binding (``bind_identity``) ties it together: every brand the message claims to be
(display name, lookalike domain, subject; later also the body) must match the domain the message
actually authenticated as. The header analyzer's result is needed for that and comes in through
the optional ``context`` argument of ``analyze`` (module name -> ``AnalyzerResult``).

``raw["domain_table"]`` has one row per sender address for the report.
"""

from __future__ import annotations

import re
import time
import unicodedata
from dataclasses import asdict, dataclass
from functools import cache
from typing import Any

from rapidfuzz.distance import DamerauLevenshtein

from phishlens.data_loader import (
    Brand,
    BrandRegistry,
    brand_for_domain,
    brand_registry,
    confusables,
    domain_matches,
    esp_for_domain,
    is_free_webmail,
    is_risky_tld,
)
from phishlens.models import Address, AnalyzerResult, Finding, ParsedEmail, Severity
from phishlens.parser.headers import org_domain

MODULE = "domain"

__all__ = [
    "MODULE",
    "BrandMention",
    "ClaimedBrand",
    "LookalikeMatch",
    "SenderIdentity",
    "analyze",
    "bind_identity",
    "check_lookalike",
    "decode_idn",
    "find_brand_mentions",
    "sender_identity",
    "skeleton",
]

# Claim sources that on their own are weak (a newsletter may mention a brand in its subject).
WEAK_CLAIM_SOURCES = frozenset({"subject", "body"})

# Strongest kind first; used to keep one match per brand.
LOOKALIKE_KINDS = ("homoglyph", "typosquat", "combosquat", "tld_swap", "brand_in_subdomain")
MIN_TYPO_LABEL = 6  # shorter brand labels only match via homoglyphs (too many real words)
MIN_SUBSTRING_LABEL = 6  # shorter labels are only matched as a whole hyphen-separated token
MIN_LABEL = 3


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


@dataclass(frozen=True)
class LookalikeMatch:
    """A domain that imitates one of a brand's legitimate domains."""

    domain: str
    decoded: str
    brand: str
    legitimate_domain: str
    kind: str
    distance: int = 0
    token: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def decode_idn(domain: str) -> str:
    """Decode punycode (``xn--``) labels to Unicode; labels that fail to decode are kept."""
    labels = []
    for label in domain.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def skeleton(text: str) -> str:
    """Reduce ``text`` to its lookalike skeleton (``paypa1`` and ``paypal`` give the same)."""
    table = confusables()
    text = unicodedata.normalize("NFKC", text.lower())
    out = "".join(table.characters.get(ch, ch) for ch in text)
    for sequence, replacement in table.sequences.items():
        out = out.replace(sequence, replacement)
    return out


def _split(domain: str) -> tuple[str, str, str]:
    """Return ``(subdomain, label, suffix)`` for an ASCII domain."""
    registered = org_domain(domain) or domain
    label, _, suffix = registered.partition(".")
    subdomain = domain[: -len(registered)].rstrip(".") if domain != registered else ""
    return subdomain, label, suffix


@dataclass(frozen=True)
class _Target:
    brand: str
    domain: str
    label: str
    suffix: str
    skeleton: str
    generic: bool = False


@cache
def _targets(registry: BrandRegistry) -> tuple[_Target, ...]:
    targets = []
    for brand in registry.brands:
        for legit in brand.legitimate_domains:
            _, label, suffix = _split(legit)
            if len(label) >= MIN_LABEL:
                generic = label in registry.generic_labels
                targets.append(
                    _Target(brand.name, legit, label, suffix, skeleton(label), generic)
                )
    return tuple(targets)


def _typo_threshold(label: str) -> int:
    if len(label) < MIN_TYPO_LABEL:
        return 0
    return 2 if len(label) >= 9 else 1


def _match_label(label: str, target: _Target) -> tuple[str, int] | None:
    """Compare one label (or hyphen token) with a brand label: exact, homoglyph or typo."""
    if label == target.label:
        return "exact", 0
    label_skeleton = skeleton(label)
    if label_skeleton == target.skeleton:
        return "homoglyph", 0
    limit = _typo_threshold(target.label)
    if limit:
        distance = DamerauLevenshtein.distance(label_skeleton, target.skeleton)
        if distance <= limit:
            return "typosquat", distance
    return None


def _match(domain: str, decoded: str, target: _Target) -> LookalikeMatch | None:
    subdomain, label, suffix = _split(domain)
    unicode_label = decode_idn(label)

    def found(kind: str, distance: int = 0, token: str | None = None) -> LookalikeMatch:
        return LookalikeMatch(
            domain, decoded, target.brand, target.domain, kind, distance, token
        )

    if target.generic:
        # Everyday words: only a disguised copy of the whole label counts.
        homoglyph = unicode_label != target.label and skeleton(unicode_label) == target.skeleton
        return found("homoglyph") if homoglyph else None

    whole = _match_label(unicode_label, target)
    if whole:
        kind, distance = whole
        if kind == "exact":
            return found("tld_swap") if suffix != target.suffix else None
        return found(kind, distance)

    tokens = [t for t in re.split(r"[-_]+", unicode_label) if t]
    if len(tokens) > 1:
        for token in tokens:
            if _match_label(token, target):
                return found("combosquat", token=token)
    if len(target.label) >= MIN_SUBSTRING_LABEL and target.skeleton in skeleton(unicode_label):
        return found("combosquat", token=target.label)

    if subdomain:
        sub_tokens = set(re.split(r"[.\-_]+", decode_idn(subdomain)))
        if target.domain in subdomain or (
            len(target.label) >= 4 and target.label in sub_tokens
        ):
            return found("brand_in_subdomain", token=target.label)
    return None


def check_lookalike(domain: str) -> list[LookalikeMatch]:
    """Return lookalike matches for ``domain``, at most one per brand (the strongest kind).

    Accepts ASCII/punycode or Unicode domains. A domain that is (a subdomain of) any brand's
    legitimate domain returns no matches.
    """
    domain = domain.strip().rstrip(".").lower()
    if not domain or "." not in domain:
        return []
    try:
        ascii_domain = domain.encode("idna").decode("ascii") if not domain.isascii() else domain
    except UnicodeError:
        ascii_domain = domain
    registry = brand_registry()
    if any(domain_matches(ascii_domain, b.legitimate_domains) for b in registry.brands):
        return []
    decoded = decode_idn(ascii_domain)
    best: dict[str, LookalikeMatch] = {}
    for target in _targets(registry):
        match = _match(ascii_domain, decoded, target)
        if match is None:
            continue
        current = best.get(match.brand)
        rank = (LOOKALIKE_KINDS.index(match.kind), match.distance)
        if current is None or rank < (LOOKALIKE_KINDS.index(current.kind), current.distance):
            best[match.brand] = match
    return sorted(best.values(), key=lambda m: (LOOKALIKE_KINDS.index(m.kind), m.brand))


def _is_idn(domain: str) -> bool:
    return not domain.isascii() or any(label.startswith("xn--") for label in domain.split("."))


def _check_lookalikes(email: ParsedEmail, result: AnalyzerResult) -> None:
    roles: dict[str, list[str]] = {}
    addresses = [("from", a) for a in email.from_addrs]
    if email.return_path:
        addresses.append(("return_path", email.return_path))
    addresses += [("reply_to", a) for a in email.reply_to]
    if email.sender:
        addresses.append(("sender", email.sender))
    for role, addr in addresses:
        if addr.domain and role not in roles.setdefault(addr.domain, []):
            roles[addr.domain].append(role)

    lookalikes: dict[str, list[dict[str, Any]]] = {}
    for sender_domain, domain_roles in roles.items():
        matches = check_lookalike(sender_domain)
        if matches:
            lookalikes[sender_domain] = [m.to_dict() for m in matches]
            brands_text = ", ".join(sorted({m.brand for m in matches}))
            result.findings.append(
                _finding(
                    "lookalike_domain",
                    Severity.HIGH,
                    f"Lookalike domain imitating {brands_text}",
                    f"'{matches[0].decoded}' ({', '.join(domain_roles)}) imitates "
                    f"'{matches[0].legitimate_domain}' ({matches[0].kind}).",
                    {
                        "domain": sender_domain,
                        "decoded": matches[0].decoded,
                        "roles": domain_roles,
                        "matches": lookalikes[sender_domain],
                    },
                )
            )
        if _is_idn(sender_domain):
            decoded = decode_idn(sender_domain)
            result.findings.append(
                _finding(
                    "punycode_domain",
                    Severity.HIGH if matches else Severity.MEDIUM,
                    "Internationalized (punycode) sender domain",
                    f"'{sender_domain}' is an internationalized domain shown as '{decoded}'."
                    + (" It imitates a known brand." if matches else ""),
                    {"domain": sender_domain, "decoded": decoded, "roles": domain_roles},
                )
            )
    result.raw["lookalikes"] = lookalikes


@dataclass(frozen=True)
class ClaimedBrand:
    """A brand the message claims to be, and where it was claimed (display_name, lookalike,
    subject, body)."""

    brand: Brand
    sources: tuple[str, ...]


@dataclass(frozen=True)
class SenderIdentity:
    """The domain the message speaks for. ``authenticated`` is True when DMARC aligned, False
    when it did not, and None when no header analysis was available."""

    domain: str
    authenticated: bool | None


def sender_identity(
    email: ParsedEmail, context: dict[str, AnalyzerResult] | None = None
) -> SenderIdentity | None:
    """Build the sender identity from the From domain and the header analyzer's auth summary."""
    if not email.from_addrs or not email.from_addrs[0].domain:
        return None
    header = (context or {}).get("header")
    summary = header.raw.get("auth_summary") if header else None
    dmarc_row = next((r for r in summary or [] if r.get("mechanism") == "dmarc"), None)
    authenticated = bool(dmarc_row["aligned"]) if dmarc_row else None
    return SenderIdentity(email.from_addrs[0].domain, authenticated)


def bind_identity(
    claimed_brands: list[ClaimedBrand],
    identity: SenderIdentity,
    *,
    lookalike_domains: frozenset[str] = frozenset(),
    new_domains: frozenset[str] = frozenset(),
) -> list[Finding]:
    """Return a ``brand_impersonation`` finding for every claimed brand the sender is not.

    The sender is the brand when its domain is one of the brand's legitimate domains (not free
    webmail) and it is not known to be unauthenticated. Severity: high; critical when the sender
    domain is a lookalike or newly registered; medium when the brand was only claimed in the
    subject or body.
    """
    findings = []
    domain = identity.domain
    for claim in claimed_brands:
        legit = domain_matches(domain, claim.brand.legitimate_domains) is not None
        if legit and not is_free_webmail(domain) and identity.authenticated is not False:
            continue
        is_lookalike = domain in lookalike_domains
        is_new = domain in new_domains
        if is_lookalike or is_new:
            severity = Severity.CRITICAL
        elif set(claim.sources) <= WEAK_CLAIM_SOURCES:
            severity = Severity.MEDIUM
        else:
            severity = Severity.HIGH
        if legit and not is_free_webmail(domain):
            why = f"uses {claim.brand.name}'s domain '{domain}' but did not authenticate as it"
        else:
            why = f"comes from '{domain}', which is not a {claim.brand.name} domain"
        findings.append(
            _finding(
                "brand_impersonation",
                severity,
                f"Impersonates {claim.brand.name}",
                f"The message presents itself as {claim.brand.name} "
                f"({', '.join(claim.sources)}) but {why}.",
                {
                    "brand": claim.brand.name,
                    "claimed_in": list(claim.sources),
                    "sender_domain": domain,
                    "authenticated": identity.authenticated,
                    "lookalike": is_lookalike,
                    "newly_registered": is_new,
                    "legitimate_domains": list(claim.brand.legitimate_domains),
                },
            )
        )
    return findings


def _claimed_brands(email: ParsedEmail, result: AnalyzerResult) -> list[ClaimedBrand]:
    sources: dict[str, tuple[Brand, list[str]]] = {}

    def claim(brand: Brand, source: str) -> None:
        entry = sources.setdefault(brand.name, (brand, []))
        if source not in entry[1]:
            entry[1].append(source)

    for addr in email.from_addrs:
        for mention in find_brand_mentions(addr.display_name):
            claim(mention.brand, "display_name")
    by_name = {b.name: b for b in brand_registry().brands}
    for matches in result.raw.get("lookalikes", {}).values():
        for match in matches:
            if match["brand"] in by_name:
                claim(by_name[match["brand"]], "lookalike")
    for mention in find_brand_mentions(email.subject):
        claim(mention.brand, "subject")
    return [ClaimedBrand(brand, tuple(where)) for brand, where in sources.values()]


def _check_identity(
    email: ParsedEmail, result: AnalyzerResult, context: dict[str, AnalyzerResult] | None
) -> None:
    identity = sender_identity(email, context)
    claims = _claimed_brands(email, result)
    result.raw["identity"] = {
        "sender_domain": identity.domain if identity else None,
        "authenticated": identity.authenticated if identity else None,
        "claimed_brands": {c.brand.name: list(c.sources) for c in claims},
    }
    if identity is None or not claims:
        return
    result.findings.extend(
        bind_identity(
            claims,
            identity,
            lookalike_domains=frozenset(result.raw.get("lookalikes", {})),
            new_domains=frozenset(result.raw.get("new_domains", [])),
        )
    )


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


async def analyze(
    email: ParsedEmail, context: dict[str, AnalyzerResult] | None = None
) -> AnalyzerResult:
    """Analyze sender domains. Never raises; errors go into ``AnalyzerResult.errors``.

    ``context`` maps module names to earlier results; the ``header`` result is used for identity
    binding. Without it, a brand domain's authentication is treated as unknown.
    """
    start = time.perf_counter()
    result = AnalyzerResult(module=MODULE)
    checks = (
        ("consistency", _check_consistency),
        ("display_name", _check_display_name),
        ("lookalike", _check_lookalikes),
        ("identity", lambda e, r: _check_identity(e, r, context)),
    )
    for name, check in checks:
        try:
            check(email, result)
        except Exception as exc:
            result.errors.append(f"{name}: {type(exc).__name__}: {exc}")
    result.duration_ms = int((time.perf_counter() - start) * 1000)
    return result
