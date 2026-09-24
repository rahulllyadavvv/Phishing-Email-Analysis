"""Parse ``Received`` headers into a chain of ``ReceivedHop`` objects.

Headers appear newest first in an email; the returned chain is ordered oldest to newest. For
each hop the HELO host after ``from``, the host after ``by``, the connecting IP (IPv4 or IPv6,
preferably from a bracketed part of the ``from`` clause) and the timestamp after the last ``;``
are extracted.

Parsing never raises on bad input. Problems are returned as ``"<code>: <detail>"`` warnings:
``received_no_ip`` (a hop with no parsable IP) and ``received_out_of_order`` (a hop whose
timestamp is earlier than the hop before it).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from phishlens.models import ParsedEmail, ReceivedHop

_WS_RE = re.compile(r"\s+")
_BRACKET_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]", re.IGNORECASE)
_TOKEN_SPLIT_RE = re.compile(r"[\s()\[\]<>,;=]+")
_KEYWORDS = frozenset({"from", "by", "via", "with", "id", "for"})

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Documentation ranges (RFC 5737 / RFC 3849) count as external so synthetic fixtures behave
# like real public addresses. Python reports them as private.
_DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
_SHARED_NET = ipaddress.ip_network("100.64.0.0/10")  # carrier-grade NAT (RFC 6598)


def _to_ip(text: str) -> IPAddress | None:
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def is_internal_ip(ip: str | IPAddress) -> bool:
    """True for private, loopback, link-local, multicast, reserved, unspecified and CGNAT IPs.

    Documentation ranges are treated as external (see module notes). Unparsable input is
    treated as internal so it is never reported as an originating IP.
    """
    addr = _to_ip(ip) if isinstance(ip, str) else ip
    if addr is None:
        return True
    if any(addr in net for net in _DOCUMENTATION_NETS if addr.version == net.version):
        return False
    if isinstance(addr, ipaddress.IPv4Address) and addr in _SHARED_NET:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _top_level_tokens(text: str) -> list[str]:
    """Split on whitespace outside parentheses, so comments stay one token."""
    tokens: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        if ch.isspace() and depth == 0:
            if buf:
                tokens.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    return tokens


def _clauses(text: str) -> dict[str, list[str]]:
    """Group top-level tokens by the clause keyword (``from``, ``by``, ...) that starts them.

    Only the first occurrence of each keyword starts a clause.
    """
    clauses: dict[str, list[str]] = {}
    current: list[str] | None = None
    for token in _top_level_tokens(text):
        key = token.lower()
        if key in _KEYWORDS and key not in clauses:
            current = clauses[key] = []
        elif current is not None:
            current.append(token)
    return clauses


def _host(tokens: list[str]) -> str | None:
    if not tokens or tokens[0].startswith(("(", "[")):
        return None
    host = tokens[0].strip("<>;,").rstrip(".").lower()
    return host or None


def _extract_ip(from_tokens: list[str]) -> str | None:
    """Find the connecting IP in the ``from`` clause: bracketed parts first, then any token."""
    text = " ".join(from_tokens)
    for match in _BRACKET_RE.finditer(text):
        ip = _to_ip(match.group(1))
        if ip is not None:
            return str(ip)
    for token in _TOKEN_SPLIT_RE.split(text):
        if token.lower().startswith("ipv6:"):
            token = token[5:]
        ip = _to_ip(token) if ("." in token or ":" in token) else None
        if ip is not None:
            return str(ip)
    return None


def _parse_timestamp(text: str) -> datetime | None:
    try:
        ts = parsedate_to_datetime(text.strip())
    except (TypeError, ValueError, IndexError):
        return None
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts


def parse_received(value: str) -> ReceivedHop:
    """Parse one ``Received`` header value. Never raises; unparsable fields are ``None``."""
    raw = value
    try:
        text = _WS_RE.sub(" ", value).strip()
        body, sep, date_part = text.rpartition(";")
        if not sep:
            body, date_part = text, ""
        clauses = _clauses(body)
        from_tokens = clauses.get("from", [])
        return ReceivedHop(
            from_host=_host(from_tokens),
            by_host=_host(clauses.get("by", [])),
            ip=_extract_ip(from_tokens),
            timestamp=_parse_timestamp(date_part) if date_part else None,
            raw=raw,
        )
    except Exception:
        return ReceivedHop(raw=raw)


def parse_received_chain(values: Iterable[str]) -> tuple[list[ReceivedHop], list[str]]:
    """Parse ``Received`` header values given in header order (newest first).

    Returns the hops ordered oldest to newest and a list of warnings. Hop numbers in the
    warnings are 1-based positions in the returned (oldest-first) chain.
    """
    chain = [parse_received(v) for v in reversed(list(values))]
    warnings: list[str] = []
    previous: datetime | None = None
    for number, hop in enumerate(chain, start=1):
        if hop.ip is None:
            warnings.append(f"received_no_ip: hop {number} has no parsable IP address")
        if hop.timestamp is not None:
            if previous is not None and hop.timestamp < previous:
                warnings.append(
                    f"received_out_of_order: hop {number} timestamp "
                    f"{hop.timestamp.isoformat()} is earlier than the previous hop "
                    f"({previous.isoformat()})"
                )
            previous = hop.timestamp
    return chain, warnings


def received_chain_from_headers(
    headers: Iterable[tuple[str, str]],
) -> tuple[list[ReceivedHop], list[str]]:
    """Parse the ``Received`` headers out of ``ParsedEmail.headers``."""
    return parse_received_chain(v for n, v in headers if n.lower() == "received")


def _is_trusted(hop: ReceivedHop, trusted_internal_hosts: Iterable[str]) -> bool:
    ip = _to_ip(hop.ip) if hop.ip else None
    host = (hop.from_host or "").lower()
    for entry in trusted_internal_hosts:
        entry = entry.strip().lower().rstrip(".")
        if not entry:
            continue
        if ip is not None:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                net = None
            if net is not None:
                if ip.version == net.version and ip in net:
                    return True
                continue
        if host and (host == entry or host.endswith("." + entry.lstrip("."))):
            return True
    return False


def originating_external_ip(
    chain: list[ReceivedHop], trusted_internal_hosts: Iterable[str] = ()
) -> str | None:
    """Return the IP of the first hop outside our own infrastructure, or ``None``.

    ``chain`` is ordered oldest to newest. It is walked from the newest hop (our own receiving
    server) back towards the sender. Hops whose IP is private/reserved, or whose IP or
    ``from`` host matches ``trusted_internal_hosts`` (IPs, CIDR ranges, host names or domains,
    where a domain also matches its subdomains) are skipped. The first remaining hop's IP is
    the one that handed the message to us.
    """
    trusted = list(trusted_internal_hosts)
    for hop in reversed(chain):
        if hop.ip is None or is_internal_ip(hop.ip) or _is_trusted(hop, trusted):
            continue
        return hop.ip
    return None


def delivery_time(email: ParsedEmail) -> datetime:
    """When the message was delivered: the newest Received timestamp, else Date, else now.

    The newest hop was written by our own receiving server, so it is the most trustworthy.
    """
    for hop in reversed(email.received_chain):
        if hop.timestamp is not None:
            return hop.timestamp
    return email.date or datetime.now(UTC)
