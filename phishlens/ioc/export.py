"""IOC exporters: CSV, JSON and a STIX 2.1 bundle.

CSV and JSON carry both the raw value (for tools that ingest IOCs) and the defanged form (for
people). The STIX bundle contains:

- an Identity for PhishLens (``created_by_ref`` of everything);
- one Indicator per malicious or suspicious IOC, with a STIX pattern for its type
  (``domain-name``, ``ipv4-addr``/``ipv6-addr``, ``url``, ``email-addr``, ``file`` hashes or
  name), ``indicator_types`` ``malicious-activity``/``anomalous-activity`` and the verdict as a
  label;
- the other IOCs as STIX Cyber Observables in one Observed Data object (``others="observed"``,
  the default) or left out (``others="exclude"``);
- a Report referencing all of the above.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
from datetime import UTC, datetime
from typing import Any, Literal

import stix2

from phishlens import __version__
from phishlens.models import IOC, IOCType

__all__ = ["CSV_COLUMNS", "indicator_pattern", "to_csv", "to_json", "to_stix_bundle"]

CSV_COLUMNS = ("type", "value", "defanged", "verdict", "source", "context")
INDICATOR_VERDICTS = ("malicious", "suspicious")
_HASH_KEYS = {IOCType.MD5: "MD5", IOCType.SHA1: "SHA-1", IOCType.SHA256: "SHA-256"}


def _row(ioc: IOC) -> dict[str, str]:
    return {
        "type": ioc.type.value,
        "value": ioc.value,
        "defanged": ioc.defanged,
        "verdict": ioc.verdict or "unknown",
        "source": ioc.source_module,
        "context": ioc.context,
    }


def to_csv(iocs: list[IOC]) -> str:
    """CSV with the columns in ``CSV_COLUMNS`` (quoted where needed)."""
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for ioc in iocs:
        writer.writerow(_row(ioc))
    return out.getvalue()


def to_json(iocs: list[IOC]) -> str:
    """A JSON list of IOC objects (same fields as the CSV)."""
    return json.dumps([_row(ioc) for ioc in iocs], indent=2, ensure_ascii=False)


# --- STIX ----------------------------------------------------------------------------------------


def _quote(value: str) -> str:
    """Escape a value for a STIX pattern string literal."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _ip_object(value: str) -> str:
    return "ipv6-addr" if isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address) else (
        "ipv4-addr"
    )


def indicator_pattern(ioc: IOC) -> str:
    """The STIX 2.1 pattern matching ``ioc``."""
    value = _quote(ioc.value)
    if ioc.type == IOCType.DOMAIN:
        return f"[domain-name:value = {value}]"
    if ioc.type == IOCType.IP:
        return f"[{_ip_object(ioc.value)}:value = {value}]"
    if ioc.type == IOCType.URL:
        return f"[url:value = {value}]"
    if ioc.type == IOCType.EMAIL:
        return f"[email-addr:value = {value}]"
    if ioc.type in _HASH_KEYS:
        return f"[file:hashes.'{_HASH_KEYS[ioc.type]}' = {value}]"
    return f"[file:name = {value}]"


def _observable(ioc: IOC) -> Any:
    if ioc.type == IOCType.DOMAIN:
        return stix2.DomainName(value=ioc.value)
    if ioc.type == IOCType.IP:
        if _ip_object(ioc.value) == "ipv6-addr":
            return stix2.IPv6Address(value=ioc.value)
        return stix2.IPv4Address(value=ioc.value)
    if ioc.type == IOCType.URL:
        return stix2.URL(value=ioc.value)
    if ioc.type == IOCType.EMAIL:
        return stix2.EmailAddress(value=ioc.value)
    if ioc.type in _HASH_KEYS:
        return stix2.File(hashes={_HASH_KEYS[ioc.type]: ioc.value})
    return stix2.File(name=ioc.value)


def to_stix_bundle(
    iocs: list[IOC],
    report_name: str = "PhishLens analysis",
    others: Literal["observed", "exclude"] = "observed",
    timestamp: datetime | None = None,
) -> stix2.Bundle:
    """A STIX 2.1 bundle for ``iocs`` (see the module docstring). Serialize with
    ``bundle.serialize(pretty=True)``."""
    when = timestamp or datetime.now(UTC)
    identity = stix2.Identity(
        name="PhishLens",
        identity_class="system",
        description=f"PhishLens {__version__} automated phishing analysis",
        created=when,
        modified=when,
    )
    objects: list[Any] = [identity]
    refs: list[str] = []

    observables: list[Any] = []
    for ioc in iocs:
        verdict = ioc.verdict or "unknown"
        if verdict in INDICATOR_VERDICTS:
            indicator = stix2.Indicator(
                name=f"{ioc.type.value}: {ioc.defanged}",
                description=ioc.context or None,
                pattern=indicator_pattern(ioc),
                pattern_type="stix",
                valid_from=when,
                created=when,
                modified=when,
                indicator_types=[
                    "malicious-activity" if verdict == "malicious" else "anomalous-activity"
                ],
                labels=[verdict],
                created_by_ref=identity.id,
            )
            objects.append(indicator)
            refs.append(indicator.id)
        elif others == "observed":
            observables.append(_observable(ioc))

    if observables:
        unique = list({o.id: o for o in observables}.values())
        observed = stix2.ObservedData(
            first_observed=when,
            last_observed=when,
            number_observed=1,
            object_refs=[o.id for o in unique],
            created=when,
            modified=when,
            created_by_ref=identity.id,
        )
        objects += unique + [observed]
        refs.append(observed.id)

    if refs:
        verdicts = sorted({(i.verdict or "unknown") for i in iocs})
        report = stix2.Report(
            name=report_name,
            description=f"{len(iocs)} IOCs extracted by PhishLens ({', '.join(verdicts)}).",
            published=when,
            created=when,
            modified=when,
            report_types=["threat-report"],
            object_refs=refs,
            created_by_ref=identity.id,
        )
        objects.append(report)
    return stix2.Bundle(objects=objects)
