"""Shared pytest fixtures."""

from __future__ import annotations

import base64
import socket
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import dkim
import dns.resolver
import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from phishlens.config import get_settings
from phishlens.enrichment import abusech, rdap
from phishlens.enrichment import base as enrichment_base
from phishlens.enrichment import dns as dns_helper
from phishlens.parser import parse_email
from phishlens.parser.received import originating_external_ip

pytest_plugins = ["pytester"]


class NetworkBlockedError(RuntimeError):
    """A test tried to open a real network connection."""


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> Iterator[None]:
    """CLAUDE.md: all network is mocked in tests. Any real connection attempt raises and, since
    analyzers catch exceptions, is also recorded and fails the test at teardown (unless the test
    is marked ``network_attempt_expected``). respx (HTTP) and ``fake_dns`` (DNS) intercept
    before a socket is ever opened."""
    attempts: list[str] = []

    def blocked(*args: object, **kwargs: object) -> None:
        attempts.append(repr(args[1:]))
        raise NetworkBlockedError(f"real network access in a test: {args[1:]!r}")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    yield
    if attempts and not request.node.get_closest_marker("network_attempt_expected"):
        pytest.fail(f"test tried real network access: {', '.join(attempts[:5])}")


@pytest.fixture(autouse=True)
def enrichment_env(monkeypatch: pytest.MonkeyPatch, tmp_path) -> Iterator[list[float]]:
    """Every test gets its own enrichment cache file and quarantine folder, empty caches and
    rate limiters, and no real waiting: sleeps in ``phishlens.enrichment.base`` return at once
    and are recorded in the returned list."""
    monkeypatch.setenv("ENRICHMENT_CACHE_PATH", str(tmp_path / "enrichment_cache.sqlite"))
    monkeypatch.setenv("QUARANTINE_DIR", str(tmp_path / "quarantine"))
    get_settings.cache_clear()
    enrichment_base.clear_cache()
    enrichment_base.reset_limiters()
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(enrichment_base, "_sleep", fake_sleep)
    yield sleeps
    enrichment_base.clear_cache()
    enrichment_base.reset_limiters()
    get_settings.cache_clear()


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


# --- A small fake internet for end-to-end tests -------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _world_dns() -> dict:
    answers: dict = {
        ("_dmarc.microsoft.com", "TXT"): ["v=DMARC1; p=reject"],
        ("_dmarc.paypal.com", "TXT"): ["v=DMARC1; p=reject"],
    }
    for path in FIXTURES.glob("*.eml"):
        emails = [parse_email(path.read_bytes())]
        emails += emails[0].nested_emails
        for email in emails:
            ip = originating_external_ip(email.received_chain)
            if email.return_path and ip:
                answers[(email.return_path.domain, "TXT")] = [f"v=spf1 ip4:{ip} -all"]
            for addr in email.from_addrs:
                answers[(addr.domain, "MX")] = [f"10 mx.{addr.domain}"]
    return answers


def _malwarebazaar(request: httpx.Request) -> httpx.Response:
    if EICAR_SHA256 in request.content.decode():
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [{"sha256_hash": EICAR_SHA256, "signature": "EICAR-Test-File"}],
            },
        )
    return httpx.Response(200, json={"query_status": "hash_not_found"})


@pytest.fixture
def world(fake_dns, respx_mock, monkeypatch: pytest.MonkeyPatch):
    """DNS: each fixture's envelope domain publishes SPF for its sending IP (as its
    Authentication-Results header says), microsoft.com and paypal.com DMARC reject, every From
    domain an MX. HTTP: MalwareBazaar knows EICAR, URLhaus nothing, RDAP answers 404."""
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-abusech")
    monkeypatch.setenv("TRUSTED_AUTHSERV_IDS", "mx.recipient.example")
    get_settings.cache_clear()
    fake_dns(_world_dns())
    respx_mock.post(abusech.MALWAREBAZAAR_API).mock(side_effect=_malwarebazaar)
    respx_mock.post(abusech.URLHAUS_API).respond(200, json={"query_status": "no_results"})
    respx_mock.get(url__startswith=rdap.RDAP_BOOTSTRAP_URL).respond(404)
    return respx_mock


