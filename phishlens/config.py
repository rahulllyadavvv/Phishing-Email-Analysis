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
    llm_api_key: SecretStr | None = None

    # Safety: files are only uploaded to VirusTotal when explicitly enabled.
    upload_files_to_vt: bool = False

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

    # Trust lists (comma-separated in the environment).
    trusted_authserv_ids: CommaList = []
    trusted_internal_hosts: CommaList = []
    trusted_arc_sealers: CommaList = []

    @field_validator(
        "trusted_authserv_ids", "trusted_internal_hosts", "trusted_arc_sealers", mode="before"
    )
    @classmethod
    def _split_comma_list(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip().lower() for item in value.split(",") if item.strip()]
        return value

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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance (cached; call `cache_clear()` to reload)."""
    return Settings()
