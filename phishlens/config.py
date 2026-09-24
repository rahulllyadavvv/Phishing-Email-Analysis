"""Application settings loaded from environment variables and an optional `.env` file.

Every value has a safe default, so the tool runs with no `.env` at all. API keys are optional:
a missing key disables the matching service. Keys are stored as `SecretStr` so they never show
up in repr, logs or `model_dump()` output.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

CommaList = Annotated[list[str], NoDecode]
# "service=value,service=value" in the environment; parsed by validators below.
ServiceMap = Annotated[dict[str, str], NoDecode]

# Cache lifetime for enrichment results when ENRICHMENT_CACHE_TTL has no entry for a service.
DEFAULT_CACHE_TTL_SECONDS = 86400

# Conservative default rate limits: service -> (requests, per seconds). Override with
# ENRICHMENT_RATE_LIMITS to match your API tier.
DEFAULT_RATE_LIMITS: dict[str, tuple[int, float]] = {
    "virustotal": (4, 60.0),
    "abuseipdb": (1000, 86400.0),
    "hybrid_analysis": (5, 60.0),
    "urlscan": (60, 60.0),
    "rdap": (1, 1.0),
    "abusech": (10, 1.0),
    "google_safebrowsing": (10, 1.0),
    "cape": (10, 1.0),
}
FALLBACK_RATE_LIMIT: tuple[int, float] = (1, 1.0)

# Service name -> settings field that must be set for the service to be enabled.
SERVICE_FIELDS: dict[str, str] = {
    "virustotal": "virustotal_api_key",
    "abusech": "abusech_api_key",
    "google_safebrowsing": "google_safebrowsing_api_key",
    "urlscan": "urlscan_api_key",
    "abuseipdb": "abuseipdb_api_key",
    "hybrid_analysis": "hybrid_analysis_api_key",
    "cape": "cape_base_url",
    "llm": "llm_api_key",
}


class Settings(BaseSettings):
    """PhishLens configuration. Field names map to upper-case environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
        case_sensitive=False,
    )

    # Third-party API keys (optional; missing key disables the service).
    virustotal_api_key: SecretStr | None = None
    abusech_api_key: SecretStr | None = None
    google_safebrowsing_api_key: SecretStr | None = None
    urlscan_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    hybrid_analysis_api_key: SecretStr | None = None
    cape_base_url: str | None = None
    cape_api_token: SecretStr | None = None  # only if your CAPE instance requires a token
    llm_api_key: SecretStr | None = None

    # Safety: files are only uploaded to VirusTotal when explicitly enabled.
    upload_files_to_vt: bool = False
    # VirusTotal: this many engines flagging "malicious" makes the verdict malicious (fewer, or
    # any "suspicious" votes, make it suspicious).
    vt_malicious_threshold: int = Field(default=3, ge=1)
    # Safety: Hybrid Analysis is a public third-party sandbox, so file submission to it is
    # separately opt-in (hash searches are always allowed). CAPE is used whenever
    # CAPE_BASE_URL is set (normally your own instance).
    upload_files_to_hybrid_analysis: bool = False
    hybrid_analysis_environment_id: int = 160  # 160 = Windows 10 64-bit

    # API authentication for the FastAPI backend (None disables auth checks for local use).
    phishlens_api_key: SecretStr | None = None

    # Largest accepted input (email or file), in megabytes.
    max_input_size_mb: float = Field(default=25.0, gt=0)

    # Infrastructure.
    redis_url: str = "redis://localhost:6379/0"
    database_url: str = "sqlite:///phishlens.sqlite"

    # DNS helper: per-query timeout, cache lifetime, and the optional SQLite cache file.
    dns_timeout_seconds: float = Field(default=5.0, gt=0)
    dns_cache_ttl_seconds: int = Field(default=3600, ge=0)
    dns_sqlite_cache: bool = True
    dns_cache_path: str = "phishlens_dns_cache.sqlite"

    # urlscan.io: scan visibility (public / unlisted / private), how long to wait for a scan,
    # and how recent an existing scan of the same URL must be to reuse it instead of submitting.
    urlscan_visibility: str = "unlisted"
    urlscan_max_wait_seconds: float = Field(default=90.0, gt=0)
    urlscan_reuse_days: int = Field(default=7, ge=0)

    # Archive unpacking limits (zip bomb protection) and the file types treated as high risk.
    archive_max_depth: int = Field(default=3, ge=0)
    archive_max_files: int = Field(default=100, ge=1)
    archive_max_total_mb: float = Field(default=200.0, gt=0)
    archive_file_timeout_seconds: float = Field(default=10.0, gt=0)
    high_risk_extensions: CommaList = [
        "exe", "scr", "js", "jse", "vbs", "vbe", "wsf", "hta", "lnk", "iso", "img", "vhd",
        "vhdx", "one", "html", "htm", "svg", "docm", "xlsm", "pptm", "bat", "cmd", "ps1", "msi",
        "jar", "com", "pif", "cpl", "dll",
    ]

    # Tone ML layer: a local Hugging Face model folder (optional "ml" dependencies) and the
    # probability from which it raises a finding.
    tone_model_path: str | None = None
    ml_phishing_threshold: float = Field(default=0.8, ge=0, le=1)
    # LLM tone classifier: OFF unless enabled here AND LLM_API_KEY is set, because it sends the
    # email text to a third party (Anthropic). Needs the optional "llm" dependencies.
    llm_tone_enabled: bool = False
    llm_model: str = "claude-opus-5"

    # Pipeline: time limit per analyzer (seconds); the attachment analyzer gets its own, longer
    # limit because it may wait for a sandbox report.
    analyzer_timeout_seconds: float = Field(default=120.0, gt=0)
    attachment_timeout_seconds: float = Field(default=900.0, gt=0)
    nested_email_max_depth: int = Field(default=2, ge=0)

    # Scoring: "rule" (weights in data/weights.yaml) or "ml" (a scikit-learn model saved with
    # joblib at SCORER_MODEL_PATH; falls back to the rules when it cannot be loaded).
    scorer: str = "rule"
    scorer_model_path: str | None = None

    # Sandbox: how long to wait for a report and how often to poll.
    sandbox_max_wait_seconds: float = Field(default=300.0, gt=0)
    sandbox_poll_seconds: float = Field(default=15.0, gt=0)

    # Quarantine: every analyzed file is stored in <dir>/<case>/files.zip (password "infected").
    quarantine_enabled: bool = True
    quarantine_dir: str = "quarantine"

    # YARA rules folder (every *.yar / *.yara file is compiled); empty means data/yara.
    yara_rules_dir: str | None = None

    # Enrichment HTTP clients (phishlens/enrichment/base.py).
    enrichment_timeout_seconds: float = Field(default=15.0, gt=0)
    enrichment_max_retries: int = Field(default=3, ge=0)
    enrichment_cache: bool = True
    enrichment_cache_path: str = "phishlens_enrichment_cache.sqlite"
    # Per-service overrides: "virustotal=3600,rdap=604800" (seconds; 0 disables caching).
    enrichment_cache_ttl: ServiceMap = {}
    # Per-service overrides: "virustotal=500/60" (requests per seconds).
    enrichment_rate_limits: ServiceMap = {}

    # DKIM: a valid signature older than this (at delivery time) may be a replayed message.
    dkim_max_age_days: float = Field(default=7.0, gt=0)

    # Trust lists (comma-separated in the environment).
    trusted_authserv_ids: CommaList = []
    trusted_internal_hosts: CommaList = []
    trusted_arc_sealers: CommaList = []

    @field_validator(
        "trusted_authserv_ids",
        "trusted_internal_hosts",
        "trusted_arc_sealers",
        "high_risk_extensions",
        mode="before",
    )
    @classmethod
    def _split_comma_list(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip().lower() for item in value.split(",") if item.strip()]
        return value

    @field_validator("high_risk_extensions")
    @classmethod
    def _strip_dots(cls, value: list[str]) -> list[str]:
        return [ext.lstrip(".") for ext in value if ext.lstrip(".")]

    @field_validator("scorer")
    @classmethod
    def _check_scorer(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in ("rule", "ml"):
            raise ValueError("SCORER must be rule or ml")
        return value

    @field_validator("urlscan_visibility")
    @classmethod
    def _check_visibility(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in ("public", "unlisted", "private"):
            raise ValueError("URLSCAN_VISIBILITY must be public, unlisted or private")
        return value

    @field_validator("enrichment_cache_ttl", "enrichment_rate_limits", mode="before")
    @classmethod
    def _split_service_map(cls, value: object) -> object:
        if isinstance(value, str):
            pairs = {}
            for item in value.split(","):
                if not item.strip():
                    continue
                name, sep, setting = item.partition("=")
                if not sep or not name.strip() or not setting.strip():
                    raise ValueError(f"expected service=value, got {item.strip()!r}")
                pairs[name.strip().lower()] = setting.strip()
            return pairs
        return value

    @field_validator("enrichment_cache_ttl")
    @classmethod
    def _check_ttls(cls, value: dict[str, str]) -> dict[str, str]:
        for name, ttl in value.items():
            if not ttl.isdigit():
                raise ValueError(f"cache TTL for {name} must be whole seconds, got {ttl!r}")
        return value

    @field_validator("enrichment_rate_limits")
    @classmethod
    def _check_rates(cls, value: dict[str, str]) -> dict[str, str]:
        for name, rate in value.items():
            _parse_rate(name, rate)
        return value

    def cache_ttl(self, service: str) -> int:
        """Enrichment cache lifetime for ``service`` in seconds (0 = do not cache)."""
        ttl = self.enrichment_cache_ttl.get(service)
        return int(ttl) if ttl is not None else DEFAULT_CACHE_TTL_SECONDS

    def rate_limit(self, service: str) -> tuple[int, float]:
        """``(requests, per_seconds)`` allowed for ``service``."""
        if service in self.enrichment_rate_limits:
            return _parse_rate(service, self.enrichment_rate_limits[service])
        return DEFAULT_RATE_LIMITS.get(service, FALLBACK_RATE_LIMIT)

    def secret_values(self) -> list[str]:
        """Every configured secret, for scrubbing error messages. Never log the result."""
        values = []
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, SecretStr) and value.get_secret_value().strip():
                values.append(value.get_secret_value())
        return values

    @field_validator("cape_base_url", mode="before")
    @classmethod
    def _blank_to_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    def is_enabled(self, service: str) -> bool:
        """Return True when the named service has its key (or base URL) configured."""
        field = SERVICE_FIELDS.get(service)
        if field is None:
            raise KeyError(f"unknown service: {service}")
        value = getattr(self, field)
        if isinstance(value, SecretStr):
            return bool(value.get_secret_value().strip())
        return bool(value)

    def configured_services(self) -> dict[str, bool]:
        """Map every known service to whether it is enabled. Never exposes key values."""
        return {service: self.is_enabled(service) for service in SERVICE_FIELDS}


def _parse_rate(service: str, rate: str) -> tuple[int, float]:
    count, sep, seconds = rate.partition("/")
    try:
        parsed = int(count), float(seconds)
    except ValueError:
        parsed = (0, 0.0)
    if not sep or parsed[0] <= 0 or parsed[1] <= 0:
        raise ValueError(f"rate limit for {service} must look like 4/60, got {rate!r}")
    return parsed


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance (cached; call `cache_clear()` to reload)."""
    return Settings()
