"""IOC extraction: collect indicators from the parsed email and every analyzer result.

Sources:

- Sender addresses (From, Reply-To, Return-Path, Sender) and their domains.
- Received hop IPs, skipping private/reserved addresses and ``TRUSTED_INTERNAL_HOSTS``; the
  originating external IP is marked as such.
- Every URL (email body, ``extracted_urls`` of all analyzers, the URL analyzer's rows) and its
  host (domain or IP).
- Tracking-pixel domains (artifacts analyzer).
- Attachment names and MD5/SHA-1/SHA-256 hashes, including files unpacked from archives
  (inline images are left out: they are logos, not indicators).
- Sandbox network indicators and dropped-file hashes.
- As a safety net, iocextract finds URLs and IPv4 addresses in the free text: the text and HTML
  bodies and model rationales.

IOCs are deduplicated by ``(type, value)``: sources and contexts are merged, and the verdict is
the worst one found (malicious > suspicious > clean > unknown). Verdicts come from reputation
results, sandbox verdicts and related findings. Every IOC carries a defanged form.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import iocextract
from bs4 import BeautifulSoup

from phishlens.config import get_settings
from phishlens.ioc.defang import defang_domain, defang_email, defang_ip, defang_url, refang
from phishlens.models import IOC, AnalyzerResult, IOCType, ParsedEmail
from phishlens.parser.headers import org_domain
from phishlens.parser.received import is_internal_ip, originating_external_ip

__all__ = ["VERDICT_ORDER", "canonical_url", "extract_iocs"]

VERDICT_ORDER = ("malicious", "suspicious", "clean", "unknown")
TYPE_ORDER = [
    IOCType.URL,
    IOCType.DOMAIN,
    IOCType.IP,
    IOCType.EMAIL,
    IOCType.SHA256,
    IOCType.SHA1,
    IOCType.MD5,
    IOCType.FILENAME,
]
URL_SCHEMES = ("http://", "https://", "ftp://")

# Static findings strong enough to call the flagged URL / file suspicious on their own.
SUSPICIOUS_URL_FLAGS = frozenset(
    {
        "link_text_mismatch",
        "at_sign_in_url",
        "brand_in_unrelated_domain",
        "data_or_javascript_uri",
        "redirect_to_different_domain",
        "urlscan_login_page_on_unrelated_domain",
    }
)
SUSPICIOUS_FILE_FLAGS = frozenset(
    {
        "type_mismatch",
        "double_extension",
        "rtlo_filename",
        "html_smuggling",
        "credential_form_attachment",
        "office_macro_autoexec",
        "office_macro_suspicious_calls",
        "xlm_macro",
        "remote_template_injection",
        "pdf_launch_action",
        "pdf_javascript",
        "lnk_suspicious_command",
        "yara_match",
        "sandbox_suspicious",
    }
)
# Findings whose evidence names a sender domain that should be treated as suspicious.
SUSPICIOUS_DOMAIN_FINDINGS = frozenset(
    {
        "lookalike_domain",
        "brand_impersonation",
        "domain_age_under_7_days",
        "domain_age_under_30_days",
    }
)


def _verdict(value: str | None) -> str:
    return value if value in ("malicious", "suspicious", "clean") else "unknown"


def _worst(*verdicts: str) -> str:
    return min(verdicts, key=VERDICT_ORDER.index)


@dataclass
class _Entry:
    type: IOCType
    value: str
    sources: list[str] = field(default_factory=list)
    contexts: list[str] = field(default_factory=list)
    verdict: str = "unknown"


class _Collector:
    def __init__(self) -> None:
        self.entries: dict[tuple[IOCType, str], _Entry] = {}

    def add(
        self, kind: IOCType, value: str, source: str, context: str, verdict: str = "unknown"
    ) -> None:
        value = value.strip()
        if kind in (IOCType.DOMAIN, IOCType.EMAIL):
            value = value.lower().rstrip(".")
        elif kind in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            value = value.lower()
        if not value:
            return
        entry = self.entries.setdefault((kind, value), _Entry(kind, value))
        if source not in entry.sources:
            entry.sources.append(source)
        if context and context not in entry.contexts:
            entry.contexts.append(context)
        entry.verdict = _worst(entry.verdict, _verdict(verdict))

    def add_host(self, host: str, source: str, context: str, verdict: str = "unknown") -> None:
        host = host.strip("[]").lower().rstrip(".")
        if not host:
            return
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            self.add(IOCType.DOMAIN, host, source, context, verdict)
        else:
            if not is_internal_ip(str(ip)):
                self.add(IOCType.IP, str(ip), source, context, verdict)

    def add_url(self, url: str, source: str, context: str, verdict: str = "unknown") -> None:
        if not url.strip().lower().startswith(URL_SCHEMES):
            return
        url = canonical_url(url)
        self.add(IOCType.URL, url, source, context, verdict)
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            return
        # A domain inherits "suspicious" at most from one URL; the site may host other pages.
        host_verdict = "suspicious" if verdict in ("malicious", "suspicious") else "unknown"
        self.add_host(host, source, f"host of {context}", host_verdict)

    def iocs(self) -> list[IOC]:
        out = []
        for entry in self.entries.values():
            out.append(
                IOC(
                    type=entry.type,
                    value=entry.value,
                    defanged=_defang(entry.type, entry.value),
                    source_module=", ".join(entry.sources),
                    verdict=entry.verdict,
                    context="; ".join(entry.contexts),
                )
            )
        return sorted(out, key=lambda i: (TYPE_ORDER.index(i.type), i.value))


def canonical_url(url: str) -> str:
    """Lowercase scheme and host and give an empty path a "/", so trivially different spellings
    of one URL deduplicate. Path, query and fragment keep their case."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url.strip()
    if not parts.netloc:
        return url.strip()
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"  # IPv6 literal
    userinfo = parts.netloc.rsplit("@", 1)[0] + "@" if "@" in parts.netloc else ""
    try:
        port = f":{parts.port}" if parts.port is not None else ""
    except ValueError:
        return url.strip()
    netloc = f"{userinfo}{host}{port}"
    rebuilt = f"{parts.scheme.lower()}://{netloc}{parts.path or '/'}"
    if parts.query:
        rebuilt += f"?{parts.query}"
    if parts.fragment:
        rebuilt += f"#{parts.fragment}"
    return rebuilt


def _defang(kind: IOCType, value: str) -> str:
    if kind == IOCType.URL:
        return defang_url(value)
    if kind == IOCType.DOMAIN:
        return defang_domain(value)
    if kind == IOCType.IP:
        return defang_ip(value)
    if kind == IOCType.EMAIL:
        return defang_email(value)
    return value


# --- Collection per source -----------------------------------------------------------------------


def _suspicious_sender_domains(results: dict[str, AnalyzerResult]) -> set[str]:
    domains: set[str] = set()
    for result in results.values():
        for finding in result.findings:
            if finding.id not in SUSPICIOUS_DOMAIN_FINDINGS:
                continue
            for key in ("domain", "sender_domain"):
                value = finding.evidence.get(key)
                if isinstance(value, str):
                    domain = refang(value).lower()
                    domains |= {domain, org_domain(domain) or domain}
    return domains


def _email_iocs(
    email: ParsedEmail, results: dict[str, AnalyzerResult], collector: _Collector
) -> None:
    suspicious = _suspicious_sender_domains(results)
    header = results.get("header")
    spoofing = bool(header and (header.raw.get("dmarc") or {}).get("auth_but_unaligned"))
    roles = [("From", a) for a in email.from_addrs] + [("Reply-To", a) for a in email.reply_to]
    if email.return_path:
        roles.append(("Return-Path", email.return_path))
    if email.sender:
        roles.append(("Sender", email.sender))
    for role, addr in roles:
        if not addr.address or "@" not in addr.address:
            continue
        verdict = "suspicious" if (
            addr.domain in suspicious or addr.org_domain in suspicious
        ) else "unknown"
        collector.add(IOCType.EMAIL, addr.address, "email", f"{role} address", verdict)
        if addr.domain:
            collector.add(IOCType.DOMAIN, addr.domain, "email", f"{role} domain", verdict)
    if spoofing and email.return_path and email.return_path.domain:
        collector.add(
            IOCType.DOMAIN,
            email.return_path.domain,
            "header",
            "authenticated domain unaligned with From",
            "suspicious",
        )

    trusted = get_settings().trusted_internal_hosts
    origin = originating_external_ip(email.received_chain, trusted)
    for hop in email.received_chain:
        if not hop.ip or is_internal_ip(hop.ip):
            continue
        context = "originating IP (Received)" if hop.ip == origin else "Received hop IP"
        if hop.ip != origin and originating_external_ip([hop], trusted) is None:
            continue  # a trusted internal host
        collector.add(IOCType.IP, hop.ip, "header", context)
    for ref in email.urls:
        collector.add_url(ref.url, "email", f"URL in body ({ref.source.value})")


def _url_rows(results: dict[str, AnalyzerResult], collector: _Collector) -> None:
    urls = results.get("urls")
    if urls is None:
        return
    for row in urls.raw.get("urls", []):
        verdict = _verdict(row.get("reputation_verdict"))
        if verdict == "unknown" and SUSPICIOUS_URL_FLAGS & set(row.get("flags", [])):
            verdict = "suspicious"
        collector.add_url(row["url"], "urls", f"link ({', '.join(row['sources'])})", verdict)
        if row.get("final_url"):
            final = refang(row["final_url"])
            collector.add_url(final, "urls", "final URL after redirects", verdict)


def _extracted_urls(results: dict[str, AnalyzerResult], collector: _Collector) -> None:
    for name, result in results.items():
        for ref in result.extracted_urls:
            context = "QR code" if ref.source.value == "qr_code" else f"URL from {name}"
            collector.add_url(ref.url, name, context)


def _artifact_iocs(results: dict[str, AnalyzerResult], collector: _Collector) -> None:
    artifacts = results.get("artifacts")
    if artifacts is None:
        return
    for domain in artifacts.raw.get("tracking_domains", []):
        collector.add_host(refang(domain), "artifacts", "tracking pixel domain")


def _attachment_iocs(results: dict[str, AnalyzerResult], collector: _Collector) -> None:
    attachments = results.get("attachments")
    if attachments is None:
        return
    for row in attachments.raw.get("attachments", []):
        if row.get("inline"):
            continue
        verdict = _verdict(row.get("reputation_verdict"))
        sandbox = row.get("sandbox") or {}
        if sandbox.get("status") == "done":
            verdict = _worst(verdict, _verdict(sandbox.get("verdict")))
        if verdict == "unknown" and SUSPICIOUS_FILE_FLAGS & set(row.get("flags", [])):
            verdict = "suspicious"
        where = f" inside {row['parent']}" if row.get("parent") else ""
        collector.add(
            IOCType.FILENAME, row["safe_name"], "attachments", f"attachment{where}", verdict
        )
        for kind in (IOCType.SHA256, IOCType.SHA1, IOCType.MD5):
            if row.get(kind.value) and row.get("size", 0) > 0:
                collector.add(
                    kind, row[kind.value], "attachments", f"hash of {row['safe_name']}", verdict
                )
        if sandbox.get("status") == "done":
            network_verdict = "malicious" if sandbox.get("verdict") == "malicious" else "suspicious"
            for domain in sandbox.get("network_domains", []):
                collector.add_host(domain, "sandbox", "sandbox network domain", network_verdict)
            for ip in sandbox.get("network_ips", []):
                collector.add_host(ip, "sandbox", "sandbox network IP", network_verdict)
            for url in sandbox.get("network_urls", []):
                collector.add_url(url, "sandbox", "sandbox network URL", network_verdict)
            for sha256 in sandbox.get("dropped_hashes", []):
                collector.add(
                    IOCType.SHA256, sha256, "sandbox", "file dropped in sandbox", network_verdict
                )


def _free_text(email: ParsedEmail | None, results: dict[str, AnalyzerResult]) -> list[str]:
    texts = []
    if email is not None:
        texts.append(email.text_body)
        if email.html_body:
            texts.append(BeautifulSoup(email.html_body, "html.parser").get_text(" "))
    tone = results.get("tone")
    if tone is not None:
        for entry in (tone.raw.get("ml") or {}).values():
            if isinstance(entry, dict) and entry.get("rationale"):
                texts.append(str(entry["rationale"]))
    return [t for t in texts if t]


def _safety_net(
    email: ParsedEmail | None, results: dict[str, AnalyzerResult], collector: _Collector
) -> None:
    for text in _free_text(email, results):
        for url in iocextract.extract_urls(text, refang=True):
            collector.add_url(url.rstrip(".,;)"), "text", "URL found in message text")
        for ip in iocextract.extract_ipv4s(text, refang=True):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            collector.add_host(ip, "text", "IP address in message text")


def extract_iocs(
    email: ParsedEmail | None, results: dict[str, AnalyzerResult] | None = None
) -> list[IOC]:
    """All IOCs of a case, deduplicated, with verdicts and defanged values.

    ``email`` is None for a standalone file case. ``results`` maps module name to result.
    """
    results = results or {}
    collector = _Collector()
    if email is not None:
        _email_iocs(email, results, collector)
    _url_rows(results, collector)
    _extracted_urls(results, collector)
    _artifact_iocs(results, collector)
    _attachment_iocs(results, collector)
    _safety_net(email, results, collector)
    return collector.iocs()
