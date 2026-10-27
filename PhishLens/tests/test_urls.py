"""Tests for phishlens.analyzers.urls (static checks only; nothing is fetched)."""

from __future__ import annotations

from pathlib import Path

import pytest

from phishlens.analyzers import urls
from phishlens.models import EnrichmentResult, ParsedEmail, Severity, UrlRef, UrlSource
from phishlens.parser import parse_email

FIXTURES = Path(__file__).parent / "fixtures"
ALL_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.eml"))


def _ref(url: str, text: str | None = None, source: UrlSource = UrlSource.HTML_HREF) -> UrlRef:
    return UrlRef(url=url, visible_text=text, source=source)


async def _analyze(*refs: UrlRef):
    return await urls.analyze(ParsedEmail(urls=list(refs)))


def _ids(result) -> dict:
    return {f.id: f for f in result.findings}


def _flags(url: str, *texts: str) -> list[str]:
    return urls.static_checks(url, list(texts))["flags"]


async def test_fixture_5_link_mismatch_and_brand() -> None:
    result = await urls.analyze(parse_email((FIXTURES / "link_mismatch.eml").read_bytes()))
    findings = _ids(result)
    mismatch = findings["link_text_mismatch"]
    assert mismatch.severity == Severity.HIGH
    [entry] = mismatch.evidence["urls"]
    assert entry == {
        "url": "hxxp://paypal-secure-login[.]example/confirm",
        "visible_domain": "www[.]paypal[.]com",
        "actual_domain": "paypal-secure-login[.]example",
    }
    brand = findings["brand_in_unrelated_domain"]
    assert brand.severity == Severity.HIGH
    assert brand.evidence["urls"][0]["brands"] == ["PayPal"]
    assert "paypal-secure-login.example" not in str(brand.evidence)  # defanged everywhere
    rows = {r["url"]: r for r in result.raw["urls"]}
    assert rows["https://www.paypal.com/"]["flags"] == []
    bad = rows["http://paypal-secure-login.example/confirm"]
    assert bad["defanged"] == "hxxp://paypal-secure-login[.]example/confirm"
    assert bad["visible_texts"] == ["hxxps://www[.]paypal[.]com"]
    assert bad["sources"] == ["html_href"]


@pytest.mark.parametrize(
    ("url", "flag"),
    [
        ("http://203.0.113.9/login", "ip_address_url"),
        ("http://3405803785/", "ip_address_url"),  # decimal IP
        ("http://0xcb.0x0.0x71.0x9/", "ip_address_url"),  # hex IP
        ("http://[2001:db8::1]/", "ip_address_url"),
        ("https://bit.ly/abc123", "url_shortener"),
        ("http://paypal.com@evil.test/", "at_sign_in_url"),
        ("http://a.b.c.d.evil.test/", "excessive_subdomains"),
        ("http://micros0ft.com/", "brand_in_unrelated_domain"),
        ("http://evil.zip/", "risky_tld"),
        ("http://shop.test/account/verify?next=login", "credential_keywords"),
        ("data:text/html;base64,PGgxPkhpPC9oMT4=", "data_or_javascript_uri"),
        ("javascript:alert(1)", "data_or_javascript_uri"),
        ("http://xn--mnchen-3ya.test/", "punycode_url"),
    ],
)
def test_each_static_flag(url: str, flag: str) -> None:
    assert flag in _flags(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://www.paypal.com/",
        "https://docs.example.com/guide/intro",
        "https://mail.shop.example/unsubscribe",
        "https://a.b.shop.example/",  # 2 subdomain levels: fine
        "mailto:someone@example.com",
    ],
)
def test_clean_urls_have_no_flags(url: str) -> None:
    assert _flags(url) == []


def test_link_text_mismatch_rules() -> None:
    href = "http://evil.test/x"
    assert "link_text_mismatch" in _flags(href, "Go to https://paypal.com")
    assert "link_text_mismatch" in _flags(href, "www.paypal.com")
    assert "link_text_mismatch" not in _flags(href, "Click here")
    assert "link_text_mismatch" not in _flags("http://www.shop.test/a", "shop.test")
    assert "link_text_mismatch" not in _flags("http://mail.shop.test/a", "https://shop.test")


def test_credential_keywords_are_whole_words() -> None:
    checks = urls.static_checks("http://shop.test/sign-in/update.php", [])
    assert checks["details"]["credential_keywords"]["keywords"] == ["sign-in", "update"]
    assert "credential_keywords" not in _flags("http://shop.test/accountants/blog")
    assert "credential_keywords" not in _flags("http://login.shop.test/")  # host is not checked


def test_punycode_lookalike_is_high() -> None:
    checks = urls.static_checks("http://xn--pple-43d.com/", [])
    assert {"punycode_url", "brand_in_unrelated_domain"} <= set(checks["flags"])
    assert checks["details"]["punycode_url"] == {"decoded": "аpple[.]com", "lookalike": True}


async def test_punycode_finding_severity() -> None:
    lookalike = _ids(await _analyze(_ref("http://xn--pple-43d.com/")))["punycode_url"]
    plain = _ids(await _analyze(_ref("http://xn--mnchen-3ya.test/")))["punycode_url"]
    assert (lookalike.severity, plain.severity) == (Severity.HIGH, Severity.MEDIUM)


async def test_findings_are_grouped_per_id() -> None:
    result = await _analyze(_ref("http://203.0.113.9/"), _ref("http://198.51.100.3/a"))
    [finding] = [f for f in result.findings if f.id == "ip_address_url"]
    assert finding.evidence["count"] == 2
    assert [e["url"] for e in finding.evidence["urls"]] == [
        "hxxp://203[.]0[.]113[.]9/",
        "hxxp://198[.]51[.]100[.]3/a",
    ]


async def test_urls_are_deduplicated_with_sources_and_texts() -> None:
    result = await _analyze(
        _ref("http://evil.test/a", "Pay here", UrlSource.HTML_HREF),
        _ref("http://evil.test/a", None, UrlSource.TEXT_BODY),
        _ref("http://evil.test/a", "Pay here", UrlSource.HTML_HREF),
    )
    [row] = result.raw["urls"]
    assert row["sources"] == ["html_href", "text_body"]
    assert row["visible_texts"] == ["Pay here"]


async def test_extra_urls_from_pipeline() -> None:
    email = ParsedEmail(urls=[_ref("https://www.paypal.com/")])
    result = await urls.analyze(
        email, extra_urls=[_ref("http://203.0.113.9/", source=UrlSource.QR_CODE)]
    )
    rows = {r["url"]: r for r in result.raw["urls"]}
    assert rows["http://203.0.113.9/"]["sources"] == ["qr_code"]
    assert "ip_address_url" in _ids(result)


async def test_allowlisted_still_gets_static_checks() -> None:
    result = await _analyze(_ref("https://accounts.google.com/signin/v2", "https://evil.test"))
    [row] = result.raw["urls"]
    assert row["allowlisted"] is True
    assert "link_text_mismatch" in row["flags"]
    assert "credential_keywords" in row["flags"]


async def test_unparsable_url_is_kept() -> None:
    result = await _analyze(_ref("http://[not-an-ip/"))
    [row] = result.raw["urls"]
    assert row["parse_error"] and row["flags"] == []
    assert result.errors == []


async def test_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object) -> None:
        raise RuntimeError("checks exploded")

    monkeypatch.setattr(urls, "static_checks", boom)
    result = await _analyze(_ref("http://x.test/"))
    assert result.errors == ["static: RuntimeError: checks exploded"]


@pytest.mark.parametrize("name", ALL_FIXTURES)
async def test_every_fixture(name: str) -> None:
    result = await urls.analyze(parse_email((FIXTURES / name).read_bytes()))
    assert result.errors == []
    for row in result.raw["urls"]:
        assert "://" not in row["defanged"] or "hxxp" in row["defanged"] or "fxp" in row["defanged"]


# --- Reputation (lookup helpers mocked) ----------------------------------------------------------


def _res(service: str, status: str, **fields) -> EnrichmentResult:
    return EnrichmentResult(service=service, query="q", status=status, **fields)


class FakeReputation:
    """Stand-in for ``url_reputation`` and ``urlscan_scan``, answering per URL."""

    def __init__(self, reputation: dict | None = None, scans: dict | None = None) -> None:
        self.reputation = reputation or {}
        self.scans = scans or {}
        self.looked_up: list[str] = []
        self.scanned: list[str] = []

    async def lookup(self, url: str) -> list[EnrichmentResult]:
        self.looked_up.append(url)
        return self.reputation.get(url, [_res("google_safebrowsing", "unknown")])

    async def scan(self, url: str) -> EnrichmentResult:
        self.scanned.append(url)
        return self.scans.get(url, _res("urlscan", "not_configured"))


@pytest.fixture
def fake_rep(monkeypatch: pytest.MonkeyPatch):
    def install(**kwargs) -> FakeReputation:
        fake = FakeReputation(**kwargs)
        monkeypatch.setattr(urls, "url_reputation", fake.lookup)
        monkeypatch.setattr(urls, "urlscan_scan", fake.scan)
        return fake

    return install


BAD = "http://phish.test/login"


async def test_mocked_malicious_url_is_critical(fake_rep) -> None:
    fake = fake_rep(
        reputation={
            BAD: [
                _res("google_safebrowsing", "unknown"),
                _res("abusech", "malicious", link="https://urlhaus.abuse.ch/url/1/"),
            ]
        }
    )
    result = await _analyze(_ref(BAD))
    finding = _ids(result)["url_known_malicious"]
    assert finding.severity == Severity.CRITICAL
    assert finding.evidence["urls"] == [
        {"url": "hxxp://phish[.]test/login", "services": ["abusech"]}
    ]
    [row] = result.raw["urls"]
    assert row["reputation_verdict"] == "malicious"
    assert [r["service"] for r in row["reputation"]] == ["google_safebrowsing", "abusech"]
    assert row["reputation"][1]["link"] == "https://urlhaus.abuse.ch/url/1/"
    assert fake.scanned == []  # a verdict exists: no urlscan submission


async def test_suspicious_reputation_is_medium(fake_rep) -> None:
    fake_rep(reputation={BAD: [_res("virustotal", "suspicious", detections=1)]})
    finding = _ids(await _analyze(_ref(BAD)))["url_suspicious_reputation"]
    assert finding.severity == Severity.MEDIUM
    assert "url_known_malicious" not in _ids(await _analyze(_ref(BAD)))


async def test_all_services_not_configured_still_valid() -> None:
    """Real clients, no API keys: every service says not_configured and nothing is sent."""
    result = await _analyze(_ref(BAD), _ref("https://bit.ly/x"))
    assert result.errors == []
    for row in result.raw["urls"]:
        assert row["reputation_verdict"] == "not_configured"
        assert {r["status"] for r in row["reputation"]} == {"not_configured"}
        assert [r["service"] for r in row["reputation"]] == [
            "google_safebrowsing",
            "abusech",
            "virustotal",
            "urlscan",
        ]
    assert not {"url_known_malicious", "url_suspicious_reputation"} & set(_ids(result))


async def test_allowlisted_and_script_urls_skip_reputation(fake_rep) -> None:
    fake = fake_rep()
    result = await _analyze(
        _ref("https://accounts.google.com/"), _ref("javascript:alert(1)"), _ref(BAD)
    )
    assert fake.looked_up == [BAD]
    rows = {r["url"]: r for r in result.raw["urls"]}
    assert rows["https://accounts.google.com/"]["reputation"] == []
    assert rows["https://accounts.google.com/"]["reputation_verdict"] is None


def _scan(final_url: str, login_form: bool | None, status: str = "unknown") -> EnrichmentResult:
    return _res(
        "urlscan",
        status,
        details={
            "final_url": final_url,
            "screenshot_url": "https://urlscan.io/screenshots/u.png",
            "login_form": login_form,
        },
        link="https://urlscan.io/result/u/",
    )


async def test_urlscan_only_when_no_verdict(fake_rep) -> None:
    fake = fake_rep(
        reputation={"http://known.test/": [_res("abusech", "malicious")]},
        scans={BAD: _scan("https://creds.harvest.test/signin", login_form=True)},
    )
    result = await _analyze(_ref(BAD), _ref("http://known.test/"))
    assert fake.scanned == [BAD]
    findings = _ids(result)
    login = findings["urlscan_login_page_on_unrelated_domain"]
    assert login.severity == Severity.HIGH
    assert login.evidence["urls"] == [
        {
            "url": "hxxp://phish[.]test/login",
            "final_url": "hxxps://creds[.]harvest[.]test/signin",
            "screenshot_url": "https://urlscan.io/screenshots/u.png",
        }
    ]
    redirect = findings["redirect_to_different_domain"]
    assert redirect.severity == Severity.MEDIUM
    assert redirect.evidence["urls"][0]["final_domain"] == "harvest[.]test"
    row = {r["url"]: r for r in result.raw["urls"]}[BAD]
    assert row["final_url"] == "hxxps://creds[.]harvest[.]test/signin"
    assert row["screenshot_url"] == "https://urlscan.io/screenshots/u.png"
    assert row["urlscan_link"] == "https://urlscan.io/result/u/"
    assert row["reputation"][-1]["service"] == "urlscan"


async def test_login_page_on_sender_or_brand_domain_is_fine(fake_rep) -> None:
    fake_rep(
        scans={
            "http://go.shop.test/a": _scan("https://login.shop.test/", login_form=True),
            "http://x.test/b": _scan("https://www.paypal.com/signin", login_form=True),
        }
    )
    email = ParsedEmail(
        from_addrs=[
            {"address": "news@shop.test", "domain": "shop.test", "org_domain": "shop.test"}
        ],
        urls=[_ref("http://go.shop.test/a"), _ref("http://x.test/b")],
    )
    findings = _ids(await urls.analyze(email))
    assert "urlscan_login_page_on_unrelated_domain" not in findings
    assert findings["redirect_to_different_domain"].evidence["count"] == 1  # only x.test


async def test_urlscan_malicious_verdict_counts(fake_rep) -> None:
    fake_rep(scans={BAD: _scan(BAD, login_form=False, status="malicious")})
    result = await _analyze(_ref(BAD))
    assert _ids(result)["url_known_malicious"].evidence["urls"][0]["services"] == ["urlscan"]
    assert "redirect_to_different_domain" not in _ids(result)


async def test_urlscan_is_capped_per_email(fake_rep) -> None:
    fake = fake_rep()
    refs = [_ref(f"http://site{i}.test/") for i in range(8)]
    await _analyze(*refs)
    assert len(fake.looked_up) == 8
    assert len(fake.scanned) == urls.MAX_URLSCAN_PER_EMAIL


async def test_static_only_mode_makes_no_lookups(fake_rep) -> None:
    fake = fake_rep()
    result = await urls.analyze(ParsedEmail(urls=[_ref(BAD)]), reputation=False)
    assert fake.looked_up == [] and "reputation" not in result.raw["urls"][0]


async def test_reputation_failure_is_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(url: str) -> list:
        raise RuntimeError("lookup exploded")

    monkeypatch.setattr(urls, "url_reputation", boom)
    result = await _analyze(_ref(BAD))
    assert result.errors == ["reputation: RuntimeError: lookup exploded"]
    assert result.raw["urls"][0]["flags"] == ["credential_keywords"]
