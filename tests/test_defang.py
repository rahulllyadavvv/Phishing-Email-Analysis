"""Tests for phishlens.ioc.defang."""

from __future__ import annotations

import pytest

from phishlens.ioc.defang import defang_domain, defang_email, defang_ip, defang_url


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://evil.test/login", "hxxp://evil[.]test/login"),
        ("HTTPS://a.b.test:8443/x.y?q=1", "hxxps://a[.]b[.]test:8443/x.y?q=1"),
        ("ftp://files.test/a.b", "fxp://files[.]test/a.b"),
        ("http://paypal.com@evil.test/", "hxxp://paypal[.]com[@]evil[.]test/"),
        ("http://1.2.3.4/a", "hxxp://1[.]2[.]3[.]4/a"),
        ("http://[2001:db8::1]/", "hxxp://[2001:db8::1]/"),
        ("javascript:alert(1)", "javascript[:]alert(1)"),
        ("data:text/html;base64,PGh0bWw+", "data[:]text/html;base64,PGh0bWw+"),
        ("mailto:x@evil.test", "mailto:x[@]evil[.]test"),
        ("evil.test/path.php", "evil[.]test/path.php"),
    ],
)
def test_defang_url(url: str, expected: str) -> None:
    assert defang_url(url) == expected
    assert defang_url(expected) == expected  # idempotent


def test_defang_domain_ip_email() -> None:
    assert defang_domain("mail.evil.test") == "mail[.]evil[.]test"
    assert defang_domain("mail[.]evil.test") == "mail[.]evil[.]test"
    assert defang_ip("203.0.113.5") == "203[.]0[.]113[.]5"
    assert defang_email("a.b@mail.evil.test") == "a.b[@]mail[.]evil[.]test"
    assert defang_email(defang_email("a@b.test")) == "a[@]b[.]test"
    assert defang_email("no-at-sign.test") == "no-at-sign[.]test"
