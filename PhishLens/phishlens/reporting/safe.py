"""Output safety for rendered reports: defang everything, allow only approved links.

``defang_text`` defangs every URL, email address, IPv4 address and bare domain inside free
text (numbers such as ``0.75`` or versions such as ``1.2.3`` are left alone). The HTML
renderer applies it to *every* value it outputs, so an analyzer that forgot to defang cannot
leak a live indicator into a report.

Two wrappers opt out explicitly:

- ``Plain(text)``: shown as-is (still HTML-escaped), for values that are not indicators
  but contain dots (file names, MIME types, versions, hashes);
- ``Link(url, text)``: a clickable link, only for ``ALLOWED_LINK_HOSTS`` (MITRE ATT&CK pages
  and urlscan.io screenshots/results); any other URL is rendered as defanged text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from markupsafe import Markup, escape

from phishlens.ioc.defang import defang_domain, defang_email, defang_ip, defang_url

__all__ = ["ALLOWED_LINK_HOSTS", "Link", "Plain", "defang_text", "finalize", "is_allowed_link"]

ALLOWED_LINK_HOSTS = frozenset({"attack.mitre.org", "urlscan.io"})

_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?<![\w.\[])(?:\d{1,3}\.){3}\d{1,3}(?![\w.\]])")
_DOMAIN_RE = re.compile(
    r"(?<![\w@./\[-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}(?![\w\[-])",
    re.IGNORECASE,
)


def defang_text(text: str) -> str:
    """Defang every indicator in ``text``; already defanged parts stay as they are."""
    text = _URL_RE.sub(lambda m: defang_url(m.group(0)), text)
    text = _EMAIL_RE.sub(lambda m: defang_email(m.group(0)), text)
    text = _IPV4_RE.sub(lambda m: defang_ip(m.group(0)), text)
    return _DOMAIN_RE.sub(lambda m: defang_domain(m.group(0)), text)


@dataclass(frozen=True)
class Plain:
    """A value shown without defanging (still escaped)."""

    text: str

    def __str__(self) -> str:
        return self.text


def is_allowed_link(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    return parts.scheme == "https" and (
        host in ALLOWED_LINK_HOSTS or any(host.endswith("." + h) for h in ALLOWED_LINK_HOSTS)
    )


@dataclass(frozen=True)
class Link:
    """A link that is clickable only when its host is allowed."""

    url: str
    text: str = ""

    def __html__(self) -> str:
        label = escape(self.text or self.url)
        if is_allowed_link(self.url):
            return Markup(
                f'<a href="{escape(self.url)}" rel="noopener noreferrer">{label}</a>'
            )
        return str(escape(defang_text(self.text or self.url)))


def finalize(value: object) -> object:
    """Jinja ``finalize`` hook: defang every string, pass numbers, wrappers and None through."""
    if value is None:
        return ""
    if isinstance(value, Link):
        return Markup(value.__html__())
    if isinstance(value, Plain):
        return Markup(escape(value.text))
    if isinstance(value, Markup):
        return value
    if isinstance(value, bool | int | float):
        return value
    return defang_text(str(value))
