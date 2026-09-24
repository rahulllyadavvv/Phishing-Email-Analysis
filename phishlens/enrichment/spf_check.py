"""SPF evaluation (RFC 7208) with pyspf, using PhishLens' cached DNS helper for every lookup.

pyspf is synchronous and does its DNS through the module-level function ``spf.DNSLookup``. This
module replaces that function with ``_lookup``, which sends each query back to the running event
loop and answers it with ``phishlens.enrichment.dns.resolve``, so SPF lookups share the DNS cache
and are mocked in tests like any other lookup. ``check_spf`` runs pyspf in a worker thread so the
event loop stays free to serve those queries.

``_lookup`` only uses the helper while ``check_spf`` is running (the event loop is passed through
a context variable). Any other pyspf use in the process falls back to pyspf's own resolver.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from typing import Any

import spf

from phishlens.enrichment import dns as dns_helper

__all__ = ["SPF_QUERY_SECONDS", "SpfCheck", "check_spf"]

# Total time allowed for one SPF evaluation, including every DNS lookup (RFC 7208 4.6.4).
SPF_QUERY_SECONDS = 20
EMPTY_ANSWERS = frozenset({"nxdomain", "no_answer"})

_loop: ContextVar[asyncio.AbstractEventLoop | None] = ContextVar("spf_dns_loop", default=None)
_original_lookup = spf.DNSLookup


@dataclass(frozen=True)
class SpfCheck:
    """Outcome of one SPF evaluation.

    ``result`` is one of pass, fail, softfail, neutral, none, temperror or permerror.
    ``identity`` is ``"mailfrom"`` or ``"helo"`` and ``domain`` is the domain SPF checked (the
    MAIL FROM domain, or the HELO name when there is no MAIL FROM).
    """

    result: str
    ip: str
    identity: str
    domain: str
    mail_from: str
    helo: str
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _convert(name: str, qtype: str, record: str) -> tuple[tuple[str, str], Any]:
    """Turn a helper record string into the ``((name, type), value)`` pair pyspf expects."""
    if qtype == "TXT":
        return (name, qtype), (record.encode("utf-8"),)
    if qtype == "MX":
        preference, _, exchange = record.partition(" ")
        return (name, qtype), (int(preference), exchange)
    return (name, qtype), record


def _lookup(name: str, qtype: str, strict: Any = True, timeout: float = 30) -> list:
    """Replacement for ``spf.DNSLookup`` that answers from our DNS helper."""
    loop = _loop.get()
    if loop is None:
        return _original_lookup(name, qtype, strict, timeout)
    if qtype not in dns_helper.SUPPORTED_TYPES:
        return []  # e.g. the obsolete type 99 SPF record, only queried in pyspf's harsh mode
    future = asyncio.run_coroutine_threadsafe(dns_helper.resolve(name, qtype), loop)
    try:
        answer = future.result(timeout=timeout + 1)
    except concurrent.futures.TimeoutError as exc:
        future.cancel()
        raise spf.TempError(f"DNS timeout looking up {name} {qtype}") from exc
    if answer.error in EMPTY_ANSWERS:
        return []
    if answer.error:
        raise spf.TempError(f"DNS {answer.error} looking up {name} {qtype}")
    return [_convert(name, qtype, record) for record in answer.records]


spf.DNSLookup = _lookup


def _run_query(ip: str, mail_from: str, helo: str) -> tuple[str, str]:
    try:
        result, _code, explanation = spf.query(
            i=ip, s=mail_from, h=helo, querytime=SPF_QUERY_SECONDS
        ).check()
    except spf.PermError as exc:
        return "permerror", str(exc)
    except spf.TempError as exc:
        return "temperror", str(exc)
    return str(result).lower(), str(explanation)


async def check_spf(ip: str, mail_from: str, helo: str) -> SpfCheck:
    """Evaluate SPF for ``ip`` sending as ``mail_from`` (or as ``helo`` when it is empty).

    Never raises: DNS failures give ``temperror``, broken records ``permerror``, and anything
    unexpected ``temperror`` with the error in ``explanation``.
    """
    mail_from = mail_from.strip()
    helo = helo.strip().rstrip(".").lower()
    identity = "mailfrom" if mail_from else "helo"
    domain = mail_from.rpartition("@")[2].lower() if mail_from else helo
    token = _loop.set(asyncio.get_running_loop())
    try:
        result, explanation = await asyncio.to_thread(_run_query, ip, mail_from, helo)
    except Exception as exc:
        result, explanation = "temperror", f"{type(exc).__name__}: {exc}"
    finally:
        _loop.reset(token)
    return SpfCheck(result, ip, identity, domain, mail_from, helo, explanation)
