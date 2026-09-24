"""Shared data models for PhishLens.

These pydantic v2 models are the contracts between the parser, the analyzers, the
enrichment services, the scorer and the report writers. Every module reads and writes
these types, so changes here affect the whole pipeline.

Binary payloads (``Attachment.data`` and ``ParsedEmail.raw_bytes``) are excluded from
serialization, so ``model_dump_json()`` never contains raw file or email bytes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Severity of a finding, from informational to critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UrlSource(StrEnum):
    """Where a URL was found."""

    TEXT_BODY = "text_body"
    HTML_HREF = "html_href"
    HTML_SRC = "html_src"
    FORM_ACTION = "form_action"
    META_REFRESH = "meta_refresh"
    ATTACHMENT = "attachment"
    QR_CODE = "qr_code"
    ARTIFACT = "artifact"


class IOCType(StrEnum):
    """Kind of indicator of compromise."""

    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILENAME = "filename"


class CaseType(StrEnum):
    """What was submitted for analysis: an email or a standalone file."""

    EMAIL = "email"
    FILE = "file"


class VerdictLabel(StrEnum):
    """Final classification of a case."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class EnrichmentStatus(StrEnum):
    """Normalized verdict of one threat-intel lookup."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"
    ERROR = "error"
    NOT_CONFIGURED = "not_configured"


class _Model(BaseModel):
    """Base class for all PhishLens models."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Address(_Model):
    """An email address as found in a header such as From, To or Reply-To.

    ``domain`` is the full domain after the ``@`` (lowercased). ``org_domain`` is the
    registered (organizational) domain, e.g. ``example.co.uk`` for ``mail.example.co.uk``.
    """

    display_name: str = ""
    address: str
    domain: str = ""
    org_domain: str = ""


class ReceivedHop(_Model):
    """One parsed ``Received`` header. The chain is ordered oldest hop first (the reverse
    of the header order in the email). Fields that could not be parsed are ``None``; ``raw``
    always holds the original header value."""

    from_host: str | None = None
    by_host: str | None = None
    ip: str | None = None
    timestamp: datetime | None = None
    raw: str = ""


class UrlRef(_Model):
    """A URL discovered in the email or in an artifact.

    ``visible_text`` is the anchor text for HTML links (used to detect text/href
    mismatches) and ``None`` when there is no visible text.
    """

    url: str
    visible_text: str | None = None
    source: UrlSource


class Attachment(_Model):
    """A file attached to an email, extracted from an archive, or submitted directly.

    ``declared_type`` is the MIME type claimed by the email; ``detected_type`` is the type
    found by content sniffing. ``data`` holds the raw bytes and is never serialized.
    ``parent`` is the filename of the containing archive (``None`` for top-level files)
    and ``depth`` is the nesting level (0 for top-level files).
    """

    filename: str
    declared_type: str | None = None
    detected_type: str | None = None
    size: int = 0
    data: bytes = Field(default=b"", exclude=True, repr=False)
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    parent: str | None = None
    depth: int = 0


class ParsedEmail(_Model):
    """A fully parsed email message.

    ``headers`` keeps every header in original order as ``(name, value)`` pairs,
    including duplicates. ``raw_bytes`` holds the original message and is never
    serialized; ``sha256`` is the hash of those bytes. ``nested_emails`` holds
    ``message/rfc822`` parts (e.g. forwarded originals), parsed recursively.
    """

    headers: list[tuple[str, str]] = Field(default_factory=list)
    from_addrs: list[Address] = Field(default_factory=list)
    reply_to: list[Address] = Field(default_factory=list)
    return_path: Address | None = None
    sender: Address | None = None
    to: list[Address] = Field(default_factory=list)
    cc: list[Address] = Field(default_factory=list)
    subject: str = ""
    date: datetime | None = None
    message_id: str | None = None
    received_chain: list[ReceivedHop] = Field(default_factory=list)
    auth_results_headers: list[str] = Field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    urls: list[UrlRef] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
    inline_images: list[Attachment] = Field(default_factory=list)
    nested_emails: list[ParsedEmail] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)
    raw_bytes: bytes = Field(default=b"", exclude=True, repr=False)
    sha256: str = ""


class Finding(_Model):
    """A single observation produced by an analyzer.

    ``id`` is a stable snake_case identifier (e.g. ``"spf_pass_unaligned"``) used by the
    scorer, MITRE mapping and ML feature export, so never rename an existing id.
    ``score`` is the risk points this finding contributes (may be negative for
    reassuring signals). ``mitre`` lists ATT&CK technique IDs such as ``"T1566.001"``.
    """

    id: str = Field(pattern=r"^[a-z0-9]+(_[a-z0-9]+)*$")
    module: str
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    score: int = 0
    evidence: dict[str, Any] = Field(default_factory=dict)
    mitre: list[str] = Field(default_factory=list)


class AnalyzerResult(_Model):
    """Output of one analyzer module.

    Analyzers never raise: problems go into ``errors``. ``skipped`` is ``True`` when the
    module did not run (e.g. nothing to analyze or a service is not configured).
    ``raw`` holds module-specific data for report tables, and ``extracted_urls`` returns
    any new URLs the module discovered (e.g. from attachments or QR codes).
    """

    module: str
    findings: list[Finding] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    extracted_urls: list[UrlRef] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    skipped: bool = False
    duration_ms: int = 0


class EnrichmentResult(_Model):
    """Normalized result of one external lookup (VirusTotal, URLhaus, RDAP, ...).

    ``query`` is the normalized value that was looked up. ``detections`` / ``total_engines``
    are engine counts where the service has them (0 otherwise). ``details`` holds
    service-specific data, ``link`` a human-readable report URL, and ``error`` a message
    (with API keys removed) when ``status`` is ``error``.
    """

    service: str
    query: str
    status: EnrichmentStatus
    detections: int = 0
    total_engines: int = 0
    details: dict[str, Any] = Field(default_factory=dict)
    cached: bool = False
    link: str | None = None
    error: str | None = None


class IOC(_Model):
    """An indicator of compromise collected from the case.

    ``value`` is the original indicator, ``defanged`` is a safe-to-share form
    (e.g. ``hxxp://evil[.]com``). ``verdict`` is the reputation verdict if known.
    """

    type: IOCType
    value: str
    defanged: str = ""
    source_module: str = ""
    verdict: str | None = None
    context: str = ""


class MitreTechnique(_Model):
    """A MITRE ATT&CK technique triggered by one or more findings."""

    id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    url: str = ""
    triggered_by: list[str] = Field(default_factory=list)


class Verdict(_Model):
    """Final scored verdict for a case.

    ``total_score`` is 0-100. ``confidence`` is 0.0-1.0 and reflects how much of the
    analysis completed. ``module_scores`` maps module name to its score contribution.
    ``overrides_applied`` names any rules that forced the label regardless of score.
    """

    label: VerdictLabel
    total_score: int = Field(default=0, ge=0, le=100)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    module_scores: dict[str, int] = Field(default_factory=dict)
    top_findings: list[Finding] = Field(default_factory=list)
    overrides_applied: list[str] = Field(default_factory=list)


class AnalysisReport(_Model):
    """The complete result of analyzing one case, as written to JSON and rendered in reports.

    ``email`` is set for email cases and ``file_info`` for standalone file cases. Raw
    bytes are excluded from both, so ``model_dump_json()`` is safe to store and share.
    ``results`` maps module name to that module's ``AnalyzerResult``.
    """

    case_id: str
    case_type: CaseType
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    email: ParsedEmail | None = None
    file_info: Attachment | None = None
    results: dict[str, AnalyzerResult] = Field(default_factory=dict)
    iocs: list[IOC] = Field(default_factory=list)
    mitre: list[MitreTechnique] = Field(default_factory=list)
    verdict: Verdict | None = None
    services_used: list[str] = Field(default_factory=list)
    services_not_configured: list[str] = Field(default_factory=list)
    tool_version: str = ""
