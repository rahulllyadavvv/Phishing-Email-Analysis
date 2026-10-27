"""Plain-English executive summary and recommended actions (templates, no LLM).

``build_summary(report)`` gives 3-5 sentences: the verdict, then the strongest evidence, one
sentence per kind of evidence, taken from templates per finding ID and filled with the actual
values (brand, authenticated domain, domain age, lookalike target, file name, ...). Findings
are considered in order of their points.

``build_recommendations(report)`` gives the actions that fit the verdict and the findings
(nothing for a clean verdict).

Every value is defanged; the sentences are safe for the CLI, the API and reports.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from phishlens.data_loader import brand_for_domain
from phishlens.models import AnalysisReport, CaseType, Finding, IOCType
from phishlens.parser.headers import org_domain
from phishlens.reporting.safe import defang_text

__all__ = ["build_recommendations", "build_summary"]

MAX_EVIDENCE_SENTENCES = 4


def _first(entries: Any) -> dict[str, Any]:
    if isinstance(entries, list) and entries and isinstance(entries[0], dict):
        return entries[0]
    return {}


def _quoted(finding: Finding, limit: int = 2) -> str:
    phrases = [m.get("phrase") for m in finding.evidence.get("matches", []) if m.get("phrase")]
    return ", ".join(f'"{p}"' for p in phrases[:limit])


class _Context:
    """Lookups the templates need across findings."""

    def __init__(self, report: AnalysisReport) -> None:
        self.report = report
        self.findings = {f.id: f for r in report.results.values() for f in r.findings}
        domain = report.results.get("domain")
        self.ages = (domain.raw.get("domain_age") or {}) if domain else {}

    def age_days(self, domain: str | None) -> float | None:
        if not domain:
            return None
        for key in (domain, org_domain(domain) or domain):
            age = (self.ages.get(key) or {}).get("age_days")
            if isinstance(age, int | float) and age >= 0:
                return age
        return None

    def age_phrase(self, domain: str | None) -> str:
        age = self.age_days(domain)
        if age is None:
            return ""
        days = int(age)
        return f", a domain registered {days} day{'s' if days != 1 else ''} ago"

    def authenticated_domain(self) -> str | None:
        auth = self.findings.get("auth_but_unaligned")
        if auth is None:
            return None
        domains = auth.evidence.get("dkim_domains") or []
        return auth.evidence.get("spf_domain") or (domains[0] if domains else None)


def _brand_impersonation(f: Finding, ctx: _Context) -> str:
    brand = f.evidence.get("brand", "a known brand")
    sender = f.evidence.get("sender_domain")
    authenticated_as = ctx.authenticated_domain()
    if authenticated_as:
        return (
            f"The email claims to be from {brand}, but it was authenticated by "
            f"{authenticated_as}{ctx.age_phrase(authenticated_as)}, not by {sender}."
        )
    if f.evidence.get("lookalike"):
        return (
            f"The email claims to be from {brand}, but it comes from the lookalike domain "
            f"{sender}{ctx.age_phrase(sender)}."
        )
    return (
        f"The email claims to be from {brand}, but it comes from "
        f"{sender}{ctx.age_phrase(sender)}."
    )


def _auth_but_unaligned(f: Finding, ctx: _Context) -> str:
    domain = ctx.authenticated_domain() or "another domain"
    return (
        f"The message passed email authentication only for {domain}, not for the sender "
        f"domain {f.evidence.get('from_domain')} shown in From."
    )


def _lookalike(f: Finding, ctx: _Context) -> str:
    match = _first(f.evidence.get("matches"))
    decoded = f.evidence.get("decoded") or f.evidence.get("domain")
    return (
        f"The sender domain {decoded} imitates {match.get('legitimate_domain', 'a brand domain')}"
        f" ({match.get('kind', 'lookalike')}){ctx.age_phrase(f.evidence.get('domain'))}."
    )


def _display_name(f: Finding, ctx: _Context) -> str:
    return (
        f'The sender is displayed as "{f.evidence.get("display_name")}", but the real address is '
        f"{f.evidence.get('address')}."
    )


def _link_mismatch(f: Finding, ctx: _Context) -> str:
    entry = _first(f.evidence.get("urls"))
    return (
        f"A link shows {entry.get('visible_domain', 'one address')} but actually leads to "
        f"{entry.get('actual_domain', 'another domain')}."
    )


def _brand_url(f: Finding, ctx: _Context) -> str:
    entry = _first(f.evidence.get("urls"))
    brands = ", ".join(entry.get("brands", [])) or "a known brand"
    return f"The link {entry.get('url', '')} uses a domain made to look like {brands}."


def _url_malicious(f: Finding, ctx: _Context) -> str:
    entry = _first(f.evidence.get("urls"))
    services = ", ".join(entry.get("services", [])) or "threat intelligence"
    count = f.evidence.get("count", 1)
    subject = "A link" if count == 1 else f"{count} links"
    return (
        f"{subject} in the message ({entry.get('url', '')}) is listed as malicious by "
        f"{services}."
    )


def _login_page(f: Finding, ctx: _Context) -> str:
    entry = _first(f.evidence.get("urls"))
    return (
        f"The link opens a login page at {entry.get('final_url') or entry.get('url')}, which "
        "does not belong to the sender or the brand it names."
    )


def _attachment_malicious(f: Finding, ctx: _Context) -> str:
    entry = _first(f.evidence.get("files"))
    families = ", ".join(entry.get("families", []))
    known = f"known malware ({families})" if families else "known malware"
    sources = ", ".join(entry.get("services", [])) or "threat intelligence"
    return f"The attachment {entry.get('file', '')} is {known} according to {sources}."


def _file_sentence(template: str) -> Callable[[Finding, _Context], str]:
    def build(f: Finding, ctx: _Context) -> str:
        entry = _first(f.evidence.get("files"))
        name = entry.get("file") or entry.get("archive") or "the file"
        return template.format(**{**entry, "file": name})

    return build


def _tone(label: str) -> Callable[[Finding, _Context], str]:
    def build(f: Finding, ctx: _Context) -> str:
        quoted = _quoted(f)
        return f"The text {label}{f' ({quoted})' if quoted else ''}."

    return build


def _sandbox(f: Finding, ctx: _Context) -> str:
    entry = _first(f.evidence.get("files"))
    return (
        f"Run in an external sandbox ({entry.get('sandbox')}), {entry.get('file')} behaved "
        "maliciously."
    )


def _domain_age(f: Finding, ctx: _Context) -> str:
    return (
        f"The domain {f.evidence.get('domain')} was registered only "
        f"{int(f.evidence.get('age_days') or 0)} days before the message arrived."
    )


TEMPLATES: dict[str, Callable[[Finding, _Context], str]] = {
    "attachment_known_malicious": _attachment_malicious,
    "sandbox_malicious": _sandbox,
    "url_known_malicious": _url_malicious,
    "html_smuggling": _file_sentence(
        "The attachment {file} builds and offers a file inside the browser (HTML smuggling)."
    ),
    "brand_impersonation": _brand_impersonation,
    "auth_but_unaligned": _auth_but_unaligned,
    "lookalike_domain": _lookalike,
    "display_name_brand_spoof": _display_name,
    "urlscan_login_page_on_unrelated_domain": _login_page,
    "link_text_mismatch": _link_mismatch,
    "brand_in_unrelated_domain": _brand_url,
    "lnk_suspicious_command": _file_sentence(
        "The shortcut {file} starts a command when opened ({arguments})."
    ),
    "double_extension": _file_sentence(
        "The attachment {file} hides its real type behind a double extension."
    ),
    "type_mismatch": _file_sentence(
        "The attachment {file} is really a different kind of file ({actual}) than its name says."
    ),
    "rtlo_filename": _file_sentence(
        "The attachment name {file} uses invisible characters to disguise its extension."
    ),
    "encrypted_archive_password_in_body": _file_sentence(
        "The attachment {file} is a password-protected archive with the password in the "
        "message, a common way to slip past scanners."
    ),
    "office_macro_autoexec": _file_sentence(
        "The document {file} contains macros that run automatically when it is opened."
    ),
    "remote_template_injection": _file_sentence(
        "The document {file} loads a template from the internet when it is opened."
    ),
    "pdf_launch_action": _file_sentence("The PDF {file} tries to launch a program."),
    "credential_form_attachment": _file_sentence(
        "The attachment {file} contains a login form that sends what is typed elsewhere."
    ),
    "domain_age_under_7_days": _domain_age,
    "domain_age_under_30_days": _domain_age,
    "multiple_from_headers": lambda f, ctx: (
        "The message has several From headers, a trick to confuse filters and mail clients."
    ),
    "replyto_free_webmail": lambda f, ctx: (
        f"Replies would go to the free webmail address {f.evidence.get('reply_to')} instead of "
        "the sender."
    ),
    "credential_request": _tone("asks the reader to log in, verify an account or share a code"),
    "payment_request": _tone("asks for a payment or new bank details"),
    "tone_urgency": _tone("pushes the reader to act immediately"),
    "tone_fear": _tone("threatens consequences if the reader does not act"),
    "secrecy_request": _tone("asks the reader to keep the request secret"),
    "hidden_text": lambda f, ctx: (
        "The message contains hidden text meant to fool spam filters."
    ),
    "qr_code_url": lambda f, ctx: (
        "An image contains a QR code, which sends the reader to a link on their phone."
    ),
}


def _verdict_sentence(report: AnalysisReport) -> str:
    verdict = report.verdict
    subject = "file" if report.case_type == CaseType.FILE else "email"
    if verdict is None:
        return f"This {subject} has not been scored."
    label = verdict.label.value
    base = (
        f"PhishLens rates this {subject} as {label.capitalize()} "
        f"(score {verdict.total_score}/100, confidence {round(verdict.confidence * 100)}%)."
    )
    if label == "clean":
        return base + " No significant phishing or malware indicators were found."
    return base


def build_summary(report: AnalysisReport) -> list[str]:
    """3-5 sentences: the verdict and the strongest evidence."""
    ctx = _Context(report)
    findings = sorted(
        (f for r in report.results.values() for f in r.findings),
        key=lambda f: (-f.score, f.id),
    )
    sentences = [_verdict_sentence(report)]
    used: set[str] = set()
    present = {f.id for f in findings}
    # A finding whose point another sentence already makes (the brand sentence names the
    # authenticated domain).
    covered_by = {"auth_but_unaligned": "brand_impersonation"}
    for finding in findings:
        if len(sentences) > MAX_EVIDENCE_SENTENCES:
            break
        template = TEMPLATES.get(finding.id)
        if template is None or finding.id in used or finding.score <= 0:
            continue
        if covered_by.get(finding.id) in present:
            continue
        try:
            sentence = template(finding, ctx)
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        used.add(finding.id)
        sentences.append(sentence)
    if len(sentences) < 3 and report.verdict is not None and report.verdict.label.value != "clean":
        count = sum(1 for r in report.results.values() for _ in r.findings)
        sentences.append(f"{count} findings contributed to this verdict; see the details below.")
    return [defang_text(s) for s in sentences]


def build_recommendations(report: AnalysisReport) -> list[str]:
    """Actions that fit the verdict and the findings; none for a clean verdict."""
    verdict = report.verdict
    if verdict is None or verdict.label.value == "clean":
        return []
    ids = {f.id for r in report.results.values() for f in r.findings}
    bad_iocs = [i for i in report.iocs if i.verdict in ("malicious", "suspicious")]
    is_email = report.case_type == CaseType.EMAIL
    has_links = bool(report.results.get("urls") and report.results["urls"].raw.get("urls"))
    has_files = bool(
        report.results.get("attachments")
        and report.results["attachments"].raw.get("attachments")
    )
    malicious = verdict.label.value == "malicious"
    actions: list[str] = []

    if malicious:
        from_addrs = report.email.from_addrs if report.email else []
        sender = from_addrs[0].domain if from_addrs else ""
        forged_brand = brand_for_domain(sender) if sender else None
        target = "sender domain and the " if is_email and not forged_brand else "the "
        count = f"{len(bad_iocs)} " if bad_iocs else ""
        actions.append(
            f"Block {target}{count}malicious or suspicious indicators (see the IOC table) on "
            "the mail gateway, web proxy, DNS filter and EDR."
        )
        if forged_brand:
            actions.append(
                f"Do not block {sender} itself: it belongs to {forged_brand.name} and was forged "
                "by the sender."
            )
        if is_email:
            actions.append(
                "Search all mailboxes for this message (same sender, subject or links) and "
                "remove it."
            )
    else:
        actions.append(
            "Do not click links, open attachments or reply until the message is verified."
        )
        if is_email:
            actions.append(
                "Confirm with the claimed sender through a known channel (phone or a saved "
                "contact), not by replying to this message."
            )
    credential_signals = {"credential_request", "urlscan_login_page_on_unrelated_domain",
                          "credential_form_attachment", "brand_impersonation"}
    if has_links and (malicious or ids & credential_signals):
        actions.append(
            "If anyone clicked a link and entered details: reset their password, sign out all "
            "sessions, and check MFA devices and mailbox forwarding rules."
        )
    file_signals = {"attachment_known_malicious", "sandbox_malicious", "office_macro_autoexec",
                    "html_smuggling", "lnk_suspicious_command", "pdf_launch_action",
                    "double_extension", "type_mismatch", "pe_executable_attachment"}
    if has_files and ids & file_signals:
        actions.append(
            "If anyone opened the attachment: isolate the computer from the network and run a "
            "full EDR scan before reconnecting it."
        )
    if "payment_request" in ids:
        actions.append(
            "Do not make any payment or change bank details; confirm the request with the "
            "finance contact through a known channel."
        )
    brands = sorted(
        {
            f.evidence.get("brand")
            for r in report.results.values()
            for f in r.findings
            if f.id in ("brand_impersonation", "display_name_brand_spoof")
            and f.evidence.get("brand")
        }
    )
    if brands:
        actions.append(
            f"Report the impersonation to {', '.join(brands)} through their phishing-report "
            "channel."
        )
    if malicious and any(i.type in (IOCType.URL, IOCType.DOMAIN) for i in bad_iocs):
        actions.append(
            "Report the malicious links to Google Safe Browsing and the hosting provider's "
            "abuse contact so they are taken down."
        )
    if is_email:
        actions.append(
            "If a user reported this message, thank them: early reports limit the damage."
        )
    return [defang_text(a) for a in actions]
