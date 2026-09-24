"""Shared pytest fixtures."""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import dkim
import dns.resolver
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from phishlens.config import get_settings
from phishlens.enrichment import dns as dns_helper


class FakeDns:
    """Stand-in for ``phishlens.enrichment.dns._query``: answers from a table, NXDOMAIN
    otherwise, and records every call. A table value may be an exception to raise."""

    def __init__(self, answers: dict[tuple[str, str], list[str] | Exception]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, name: str, rdtype: str, timeout: float) -> list[str]:
        self.calls.append((name, rdtype))
        answer = self.answers.get((name, rdtype), dns.resolver.NXDOMAIN())
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[dict], FakeDns]]:
    """Return a function that installs a ``FakeDns`` with the given answers.

    The DNS cache is emptied and the SQLite cache turned off, so answers never leak between tests.
    """
    monkeypatch.setenv("DNS_SQLITE_CACHE", "false")
    get_settings.cache_clear()
    dns_helper.clear_cache()

    def install(answers: dict) -> FakeDns:
        fake = FakeDns(answers)
        monkeypatch.setattr(dns_helper, "_query", fake)
        return fake

    yield install
    dns_helper.clear_cache()
    get_settings.cache_clear()


@dataclass(frozen=True)
class DkimKey:
    """A throwaway RSA key pair for signing test messages."""

    private_pem: bytes
    dns_record: str

    def sign(
        self, message: bytes, domain: str = "signer.test", selector: str = "sel", **kw
    ) -> bytes:
        """Return ``message`` with a DKIM-Signature header prepended."""
        kw.setdefault("include_headers", [b"from", b"to", b"subject", b"date"])
        header = dkim.sign(message, selector.encode(), domain.encode(), self.private_pem, **kw)
        return header + message

    def arc_sign(self, message: bytes, domain: str, srv_id: str, selector: str = "arc") -> bytes:
        """Return ``message`` with an ARC set prepended. ``message`` must already carry an
        Authentication-Results header from ``srv_id`` (it becomes the ARC-Authentication-Results).
        """
        headers = dkim.arc_sign(
            message, selector.encode(), domain.encode(), self.private_pem, srv_id.encode()
        )
        return b"".join(headers) + message


@pytest.fixture(scope="session")
def dkim_key() -> DkimKey:
    """A 2048-bit RSA key generated once per test run, with its DKIM DNS record."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    record = f"v=DKIM1; k=rsa; p={base64.b64encode(public_der).decode()}"
    return DkimKey(private_pem, record)
