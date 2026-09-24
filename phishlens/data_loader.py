"""Cached, validated access to the YAML data files in ``data/``.

Each file is read once per process (``functools.lru_cache``) and validated with pydantic, so a
broken data file fails loudly at first use instead of producing silent wrong results. Call
``clear_cache()`` after changing a file at runtime (tests do this).
"""

from __future__ import annotations

from functools import cache, lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, field_validator

__all__ = ["DATA_DIR", "Esp", "clear_cache", "esp_for_domain", "esps", "load_yaml"]

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Esp(_Model):
    """An email service provider and the domains it signs or bounces with."""

    name: str
    domains: tuple[str, ...]

    @field_validator("domains", mode="before")
    @classmethod
    def _normalize(cls, value: Any) -> Any:
        if isinstance(value, list | tuple):
            return tuple(str(d).strip().rstrip(".").lower() for d in value if str(d).strip())
        return value


class _EspFile(_Model):
    esps: tuple[Esp, ...]


@cache
def load_yaml(name: str) -> Any:
    """Parse ``data/<name>`` and return the raw YAML content."""
    with (DATA_DIR / name).open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@lru_cache(maxsize=1)
def esps() -> tuple[Esp, ...]:
    """All ESPs from ``data/esp_domains.yaml``."""
    return _EspFile.model_validate(load_yaml("esp_domains.yaml")).esps


def esp_for_domain(domain: str | None) -> Esp | None:
    """Return the ESP that ``domain`` belongs to (same domain or a subdomain), else ``None``."""
    domain = (domain or "").strip().rstrip(".").lower()
    if not domain:
        return None
    for esp in esps():
        if any(domain == d or domain.endswith("." + d) for d in esp.domains):
            return esp
    return None


def clear_cache() -> None:
    load_yaml.cache_clear()
    esps.cache_clear()
