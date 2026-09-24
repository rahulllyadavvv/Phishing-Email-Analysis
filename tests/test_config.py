from collections.abc import Iterator

import pytest

from phishlens.config import SERVICE_FIELDS, Settings, get_settings

ENV_VARS = [
    "VIRUSTOTAL_API_KEY",
    "ABUSECH_API_KEY",
    "GOOGLE_SAFEBROWSING_API_KEY",
    "URLSCAN_API_KEY",
    "ABUSEIPDB_API_KEY",
    "HYBRID_ANALYSIS_API_KEY",
    "CAPE_BASE_URL",
    "LLM_API_KEY",
    "UPLOAD_FILES_TO_VT",
    "PHISHLENS_API_KEY",
    "REDIS_URL",
    "DATABASE_URL",
    "DNS_TIMEOUT_SECONDS",
    "DNS_CACHE_TTL_SECONDS",
    "DNS_SQLITE_CACHE",
    "DNS_CACHE_PATH",
    "TRUSTED_AUTHSERV_IDS",
    "TRUSTED_INTERNAL_HOSTS",
    "TRUSTED_ARC_SEALERS",
]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path) -> Iterator[None]:
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    # Run from an empty directory so no real .env file is picked up.
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_defaults_without_env_file() -> None:
    settings = get_settings()
    assert settings.virustotal_api_key is None
    assert settings.cape_base_url is None
    assert settings.upload_files_to_vt is False
    assert settings.redis_url == "redis://localhost:6379/0"
    assert settings.database_url == "sqlite:///phishlens.sqlite"
    assert settings.trusted_authserv_ids == []
    assert settings.dns_timeout_seconds == 5.0
    assert settings.dns_cache_ttl_seconds == 3600
    assert settings.dns_sqlite_cache is True
    assert settings.dns_cache_path == "phishlens_dns_cache.sqlite"
    assert settings.dkim_max_age_days == 7.0
    assert settings.enrichment_timeout_seconds == 15.0
    assert settings.vt_malicious_threshold == 3
    assert settings.enrichment_max_retries == 3
    assert settings.enrichment_cache is True
    assert settings.cache_ttl("virustotal") == 86400
    assert settings.rate_limit("virustotal") == (4, 60.0)
    assert settings.rate_limit("unknown-service") == (1, 1.0)
    assert not any(settings.configured_services().values())


def test_dns_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DNS_TIMEOUT_SECONDS", "2.5")
    monkeypatch.setenv("DNS_CACHE_TTL_SECONDS", "0")
    monkeypatch.setenv("DNS_SQLITE_CACHE", "false")
    monkeypatch.setenv("DNS_CACHE_PATH", "cache/dns.sqlite")
    settings = Settings()
    assert settings.dns_timeout_seconds == 2.5
    assert settings.dns_cache_ttl_seconds == 0
    assert settings.dns_sqlite_cache is False
    assert settings.dns_cache_path == "cache/dns.sqlite"


def test_dkim_max_age_days(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DKIM_MAX_AGE_DAYS", "1.5")
    assert Settings().dkim_max_age_days == 1.5
    monkeypatch.setenv("DKIM_MAX_AGE_DAYS", "0")
    with pytest.raises(ValueError):
        Settings()


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()


def test_env_values_and_comma_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key-not-real")
    monkeypatch.setenv("CAPE_BASE_URL", "http://cape.test")
    monkeypatch.setenv("UPLOAD_FILES_TO_VT", "true")
    monkeypatch.setenv("TRUSTED_AUTHSERV_IDS", "mx.example.com, MX2.Example.com ,,")
    settings = Settings()
    assert settings.is_enabled("virustotal")
    assert settings.is_enabled("cape")
    assert not settings.is_enabled("urlscan")
    assert settings.upload_files_to_vt is True
    assert settings.trusted_authserv_ids == ["mx.example.com", "mx2.example.com"]


def test_empty_values_fall_back_to_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV_VARS:
        monkeypatch.setenv(name, "")
    settings = Settings()
    assert settings.upload_files_to_vt is False
    assert settings.redis_url == "redis://localhost:6379/0"
    assert not any(settings.configured_services().values())


def test_env_file_is_loaded(tmp_path) -> None:
    (tmp_path / ".env").write_text("URLSCAN_API_KEY=test-key-not-real\n")
    assert Settings().is_enabled("urlscan")


def test_keys_are_not_exposed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "super-secret-test-value")
    settings = Settings()
    assert "super-secret-test-value" not in repr(settings)
    assert "super-secret-test-value" not in str(settings.model_dump())
    assert "super-secret-test-value" not in str(settings.configured_services())


def test_unknown_service_raises() -> None:
    with pytest.raises(KeyError):
        Settings().is_enabled("nope")


def test_service_fields_exist() -> None:
    for field in SERVICE_FIELDS.values():
        assert field in Settings.model_fields


def test_enrichment_service_maps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENRICHMENT_CACHE_TTL", "VirusTotal=3600, rdap=0")
    monkeypatch.setenv("ENRICHMENT_RATE_LIMITS", "virustotal=500/60,urlscan=2/1.5")
    settings = Settings()
    assert settings.cache_ttl("virustotal") == 3600
    assert settings.cache_ttl("rdap") == 0
    assert settings.cache_ttl("urlscan") == 86400
    assert settings.rate_limit("virustotal") == (500, 60.0)
    assert settings.rate_limit("urlscan") == (2, 1.5)
    assert settings.rate_limit("abuseipdb") == (1000, 86400.0)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ENRICHMENT_CACHE_TTL", "virustotal=soon"),
        ("ENRICHMENT_CACHE_TTL", "virustotal"),
        ("ENRICHMENT_RATE_LIMITS", "virustotal=4"),
        ("ENRICHMENT_RATE_LIMITS", "virustotal=0/60"),
        ("ENRICHMENT_RATE_LIMITS", "virustotal=x/y"),
    ],
)
def test_invalid_service_maps(monkeypatch: pytest.MonkeyPatch, name: str, value: str) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        Settings()


def test_secret_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-secret")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "   ")
    assert Settings().secret_values() == ["vt-secret"]
