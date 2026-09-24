"""Cached, validated access to the YAML data files in ``data/``.

Each file is read once per process (``functools.cache``) and validated with pydantic, so a
broken data file fails loudly at first use instead of producing silent wrong results. Call
``clear_cache()`` after changing a file at runtime (tests do this).

Domain lookups (``esp_for_domain``, ``brand_for_domain``, ``is_free_webmail``, ...) match the
listed domain itself and any subdomain of it, case-insensitively and ignoring a trailing dot.
"""

from __future__ import annotations

from collections.abc import Iterable
from functools import cache
from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import BaseModel, BeforeValidator, ConfigDict, field_validator

__all__ = [
    "DATA_DIR",
    "Brand",
    "BrandRegistry",
    "Confusables",
    "Esp",
    "FileTypes",
    "PasswordHints",
    "Organization",
    "brand_for_domain",
    "brand_registry",
    "brands",
    "clear_cache",
    "confusables",
    "domain_matches",
    "esp_for_domain",
    "esps",
    "file_types",
    "free_webmail_domains",
    "is_free_webmail",
    "is_risky_tld",
    "is_shortener",
    "is_url_allowlisted",
    "load_yaml",
    "normalize_domain",
    "password_hints",
    "risky_tlds",
    "shortener_domains",
    "url_allowlist",
    "url_credential_keywords",
]

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def normalize_domain(domain: str | None) -> str:
    return (domain or "").strip().rstrip(".").lower()


def domain_matches(domain: str | None, candidates: Iterable[str]) -> str | None:
    """Return the candidate that ``domain`` equals or is a subdomain of, else ``None``."""
    domain = normalize_domain(domain)
    if not domain:
        return None
    for candidate in candidates:
        if domain == candidate or domain.endswith("." + candidate):
            return candidate
    return None


def _clean_list(value: Any) -> Any:
    if isinstance(value, list | tuple):
        return tuple(normalize_domain(str(v)) for v in value if str(v).strip())
    return value


# A tuple of lowercased, dot-stripped strings (domains or keywords), blanks dropped.
Names = Annotated[tuple[str, ...], BeforeValidator(_clean_list)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Esp(_Model):
    """An email service provider and the domains it signs or bounces with."""

    name: str
    domains: Names


class Brand(_Model):
    """A commonly impersonated brand. ``keywords`` are lowercase words or phrases."""

    name: str
    keywords: Names
    legitimate_domains: Names
    esp_domains: Names = ()

    @field_validator("keywords", "legitimate_domains")
    @classmethod
    def _not_empty(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("must not be empty")
        return value


class Organization(_Model):
    """The user's own organization (optional)."""

    name: str = ""
    domains: Names = ()


class BrandRegistry(_Model):
    organization: Organization = Organization()
    generic_labels: Names = ()
    brands: tuple[Brand, ...]


class _EspFile(_Model):
    esps: tuple[Esp, ...]


class _DomainList(_Model):
    domains: Names


class _TldList(_Model):
    tlds: tuple[str, ...]

    @field_validator("tlds", mode="before")
    @classmethod
    def _strip_dots(cls, value: Any) -> Any:
        if isinstance(value, list | tuple):
            return tuple(str(t).strip().strip(".").lower() for t in value if str(t).strip())
        return value


class Confusables(_Model):
    """Lookalike maps: ``sequences`` (multi-character, applied first) and ``characters``."""

    sequences: dict[str, str] = {}
    characters: dict[str, str]

    @field_validator("sequences", "characters", mode="before")
    @classmethod
    def _stringify(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): str(v).lower() for k, v in value.items()}
        return value

    @field_validator("characters")
    @classmethod
    def _single_characters(cls, value: dict[str, str]) -> dict[str, str]:
        bad = [k for k in value if len(k) != 1]
        if bad:
            raise ValueError(f"character keys must be one character: {bad}")
        return value


@cache
def load_yaml(name: str) -> Any:
    """Parse ``data/<name>`` and return the raw YAML content."""
    with (DATA_DIR / name).open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@cache
def esps() -> tuple[Esp, ...]:
    """All ESPs from ``data/esp_domains.yaml``."""
    return _EspFile.model_validate(load_yaml("esp_domains.yaml")).esps


@cache
def brand_registry() -> BrandRegistry:
    """Brands and the user's organization from ``data/brand_registry.yaml``."""
    return BrandRegistry.model_validate(load_yaml("brand_registry.yaml"))


def brands() -> tuple[Brand, ...]:
    return brand_registry().brands


@cache
def free_webmail_domains() -> frozenset[str]:
    return frozenset(_DomainList.model_validate(load_yaml("free_webmail.yaml")).domains)


@cache
def risky_tlds() -> frozenset[str]:
    return frozenset(_TldList.model_validate(load_yaml("risky_tlds.yaml")).tlds)


@cache
def shortener_domains() -> frozenset[str]:
    return frozenset(_DomainList.model_validate(load_yaml("shorteners.yaml")).domains)


class Signature(_Model):
    mime: str
    offset: int = 0
    magic: bytes

    @field_validator("magic", mode="before")
    @classmethod
    def _from_hex(cls, value: Any) -> Any:
        return bytes.fromhex(str(value)) if isinstance(value, str) else value


class TextMarker(_Model):
    mime: str
    markers: Names


class FileTypes(_Model):
    """File signatures, text markers and extension knowledge (``data/file_types.yaml``)."""

    signatures: tuple[Signature, ...]
    text_markers: tuple[TextMarker, ...] = ()
    extension_categories: dict[str, Names]
    decoy_extensions: Names = ()

    @field_validator("signatures", mode="before")
    @classmethod
    def _rename_hex(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [
                {**{k: v for k, v in item.items() if k != "hex"}, "magic": item["hex"]}
                if isinstance(item, dict) and "hex" in item
                else item
                for item in value
            ]
        return value

    def category_of_extension(self, ext: str) -> str | None:
        ext = ext.lower().lstrip(".")
        for category, extensions in self.extension_categories.items():
            if ext in extensions:
                return category
        return None


class PasswordHints(_Model):
    """Words introducing a password in an email body (``data/password_hints.yaml``)."""

    max_tokens: int = 6
    hints: Names
    stopwords: Names = ()


class _UrlKeywords(_Model):
    credential_keywords: Names


@cache
def file_types() -> FileTypes:
    return FileTypes.model_validate(load_yaml("file_types.yaml"))


@cache
def password_hints() -> PasswordHints:
    return PasswordHints.model_validate(load_yaml("password_hints.yaml"))


@cache
def url_allowlist() -> frozenset[str]:
    return frozenset(_DomainList.model_validate(load_yaml("url_allowlist.yaml")).domains)


@cache
def url_credential_keywords() -> tuple[str, ...]:
    return _UrlKeywords.model_validate(load_yaml("url_keywords.yaml")).credential_keywords


@cache
def confusables() -> Confusables:
    return Confusables.model_validate(load_yaml("confusables.yaml"))


def esp_for_domain(domain: str | None) -> Esp | None:
    """Return the ESP that ``domain`` belongs to, else ``None``."""
    for esp in esps():
        if domain_matches(domain, esp.domains):
            return esp
    return None


def brand_for_domain(domain: str | None) -> Brand | None:
    """Return the brand whose legitimate domains include ``domain``, else ``None``."""
    for brand in brands():
        if domain_matches(domain, brand.legitimate_domains):
            return brand
    return None


def is_free_webmail(domain: str | None) -> bool:
    return domain_matches(domain, free_webmail_domains()) is not None


def is_shortener(domain: str | None) -> bool:
    return domain_matches(domain, shortener_domains()) is not None


def is_url_allowlisted(domain: str | None) -> bool:
    return domain_matches(domain, url_allowlist()) is not None


def is_risky_tld(domain: str | None) -> bool:
    domain = normalize_domain(domain)
    return bool(domain) and domain.rsplit(".", 1)[-1] in risky_tlds()


def clear_cache() -> None:
    for fn in (load_yaml, esps, brand_registry, free_webmail_domains, risky_tlds,
               shortener_domains, confusables, url_allowlist, url_credential_keywords,
               file_types, password_hints):
        fn.cache_clear()
