"""Defanging: make indicators safe to show (not clickable, not auto-linked).

- URLs: ``http`` -> ``hxxp`` (also https, ftp), dots in the host -> ``[.]``, and an ``@`` in the
  authority -> ``[@]``. Path and query are left readable.
- Domains and IPs: dots -> ``[.]`` (IPv6 colons are left alone).
- Email addresses: ``@`` -> ``[@]`` and dots in the domain -> ``[.]``.
- ``javascript:``, ``vbscript:`` and ``data:`` URIs: the colon becomes ``[:]``.

Defanging is idempotent: already defanged values come back unchanged.
"""

from __future__ import annotations

__all__ = ["defang_domain", "defang_email", "defang_ip", "defang_url"]

# Schemes whose colon is broken as "[:]" so the URI cannot be clicked or pasted into a browser.
_INERT_SCHEMES = frozenset({"javascript", "vbscript", "data"})
_SCHEMES = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps"}


def defang_domain(domain: str) -> str:
    return domain.replace("[.]", ".").replace(".", "[.]")


def defang_ip(ip: str) -> str:
    return defang_domain(ip)


def defang_email(address: str) -> str:
    local, sep, domain = address.replace("[@]", "@").rpartition("@")
    if not sep:
        return defang_domain(address)
    return f"{local}[@]{defang_domain(domain)}"


def _defang_scheme(scheme: str) -> str:
    return _SCHEMES.get(scheme.lower(), scheme)


def defang_url(url: str) -> str:
    """Defang a URL, including ``data:``, ``javascript:`` and ``mailto:`` URIs."""
    url = url.strip()
    scheme, sep, rest = url.partition("://")
    if sep:
        authority, slash, path = rest.partition("/")
        authority = defang_domain(authority.replace("[@]", "@").replace("@", "[@]"))
        return f"{_defang_scheme(scheme)}://{authority}{slash}{path}"
    prefix, colon, body = url.partition(":")
    lowered = prefix.lower()
    if colon and lowered in _INERT_SCHEMES:
        return f"{prefix}[:]{body}"
    if colon and lowered == "mailto":
        return f"{prefix}:{defang_email(body)}"
    head, slash, tail = url.partition("/")  # a bare host or host/path
    return defang_domain(head) + slash + tail
