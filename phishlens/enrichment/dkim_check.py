"""DKIM signature verification (RFC 6376) with dkimpy, fetching keys through our DNS helper.

Each ``DKIM-Signature`` header is verified on its own. dkimpy needs only one DNS lookup per
signature (the ``<selector>._domainkey.<domain>`` TXT key record), so the key is fetched first
with the cached async DNS helper and handed to dkimpy through its ``dnsfunc`` hook. No thread
or resolver of dkimpy's own is involved.

Every signature gets a ``status``:

- ``pass``: the body hash and signature verify.
- ``fail``: the body hash or the signature does not match (the message was changed).
- ``permerror``: the signature or key record is malformed, the key is missing or too small.
- ``temperror``: the key record could not be fetched (DNS timeout or server failure).
- ``expired``: the ``x=`` expiry is in the past, so dkimpy refuses to verify it.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

import dkim
from dkim.util import InvalidTagValueList, parse_tag_value

from phishlens.enrichment import dns as dns_helper

__all__ = ["DKIM_MIN_KEY_BITS", "DkimSignature", "verify_dkim"]

# Smallest RSA key accepted (RFC 8301 requires at least 1024 bits).
DKIM_MIN_KEY_BITS = 1024
MISSING_KEY_ERRORS = frozenset({"nxdomain", "no_answer"})


@dataclass
class DkimSignature:
    """One ``DKIM-Signature`` header and its verification outcome.

    ``signed_headers`` is the lowercased ``h=`` list. ``body_length`` is ``l=``, ``timestamp``
    ``t=`` and ``expiration`` ``x=`` (Unix seconds); each is ``None`` when the tag is absent.
    """

    domain: str = ""
    selector: str = ""
    algorithm: str = ""
    status: str = "permerror"
    error: str | None = None
    signed_headers: list[str] = field(default_factory=list)
    body_length: int | None = None
    timestamp: int | None = None
    expiration: int | None = None

    @property
    def valid(self) -> bool:
        return self.status == "pass"

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "valid": self.valid}


def _text(value: bytes | None) -> str:
    return value.decode("ascii", errors="replace").strip() if value else ""


def _int(value: bytes | None) -> int | None:
    text = re.sub(r"\s+", "", _text(value))
    return int(text) if text.isdigit() else None


def _describe(header_value: bytes) -> DkimSignature:
    """Read the tags of a signature without verifying it. Malformed tag lists give defaults."""
    try:
        tags = parse_tag_value(header_value)
    except (InvalidTagValueList, ValueError) as exc:
        return DkimSignature(error=f"malformed signature: {exc}")
    return DkimSignature(
        domain=_text(tags.get(b"d")).lower(),
        selector=_text(tags.get(b"s")).lower(),
        algorithm=_text(tags.get(b"a")).lower(),
        signed_headers=[
            h.strip().lower() for h in _text(tags.get(b"h")).split(":") if h.strip()
        ],
        body_length=_int(tags.get(b"l")),
        timestamp=_int(tags.get(b"t")),
        expiration=_int(tags.get(b"x")),
    )


def _pick_key(records: list[str]) -> str | None:
    """Return the DKIM key record among the TXT records (the first that has a ``p=`` tag)."""
    for record in records:
        if re.search(r"(^|;)\s*p\s*=", record):
            return record
    return records[0] if records else None


async def _verify_one(message: bytes, idx: int, sig_header: bytes) -> DkimSignature:
    info = _describe(sig_header)
    if info.error:
        return info
    verifier = dkim.DKIM(message, minkey=DKIM_MIN_KEY_BITS)
    try:
        prep = verifier.verify_headerprep(idx)
    except dkim.ValidationError as exc:
        info.status = "expired" if "x= value is past" in str(exc) else "permerror"
        info.error = str(exc)
        return info
    except dkim.DKIMException as exc:
        info.error = str(exc)
        return info
    if not prep:
        info.error = "signature header not found"
        return info
    sig, include_headers, sigheaders = prep

    key_name = f"{info.selector}._domainkey.{info.domain}"
    answer = await dns_helper.txt(key_name)
    if answer.error in MISSING_KEY_ERRORS:
        info.error = f"no key record at {key_name}"
        return info
    if answer.error:
        info.status, info.error = "temperror", f"DNS {answer.error} for {key_name}"
        return info
    key = (_pick_key(answer.records) or "").encode("utf-8", errors="replace")
    try:
        dkim.evaluate_pk(key_name, key)
    except Exception as exc:
        info.error = f"bad key record: {exc}"
        return info

    try:
        valid = verifier.verify_sig(sig, include_headers, sigheaders[idx], lambda *a, **k: key)
    except dkim.KeyFormatError as exc:
        info.error = str(exc)
        return info
    except dkim.ValidationError as exc:
        body_mismatch = "body hash mismatch" in str(exc)
        info.status, info.error = ("fail" if body_mismatch else "permerror"), str(exc)
        return info
    except dkim.DKIMException as exc:
        info.error = str(exc)
        return info
    info.status = "pass" if valid else "fail"
    info.error = None if valid else "signature does not verify"
    return info


async def verify_dkim(message: bytes) -> list[DkimSignature]:
    """Verify every ``DKIM-Signature`` on the raw ``message``, top to bottom.

    Problems with a single signature end up in its ``status``/``error``. A message dkimpy
    cannot parse at all raises ``dkim.MessageFormatError``, which the caller records.
    """
    signer = dkim.DKIM(message)
    sig_headers = [value for name, value in signer.headers if name.lower() == b"dkim-signature"]
    return [await _verify_one(message, idx, value) for idx, value in enumerate(sig_headers)]
