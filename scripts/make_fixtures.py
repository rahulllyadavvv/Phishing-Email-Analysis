"""Generate harmless synthetic .eml fixtures into tests/fixtures/.

Every fixture uses reserved / `.example` domains and documentation IP ranges, except where a
fixture needs a brand name in a header or link text to model an impersonation. Nothing in the
fixtures is executable or functional malware. Output is deterministic (fixed dates, message IDs,
MIME boundaries, zip timestamps) so re-running the script gives byte-identical files.

Usage:
    python scripts/make_fixtures.py [OUT_DIR]
"""

from __future__ import annotations

import base64
import io
import struct
import sys
import zipfile
import zlib
from collections.abc import Callable
from email import policy
from email.headerregistry import Address
from email.message import EmailMessage, Message
from pathlib import Path

import segno
import yaml

DEFAULT_OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
DATE = "Mon, 07 Sep 2026 09:00:00 +0000"
ZIP_DATE_TIME = (2026, 9, 7, 9, 0, 0)
ZIP_PASSWORD = b"4455"
QR_URL = "http://phish-test.example/login"

# Built from pieces so this script file itself does not contain the literal test signature.
EICAR = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    + "$H+H*"
)


# --------------------------------------------------------------------------- helpers


def _base(
    from_: str | Address,
    to: str,
    subject: str,
    msg_id: str,
    return_path: str,
    auth_results: str,
    received_from: str = "mail.sender.example ([198.51.100.20])",
) -> EmailMessage:
    msg = EmailMessage()
    msg["Return-Path"] = f"<{return_path}>"
    msg["Received"] = (
        f"from {received_from} by mx.recipient.example with ESMTPS id {msg_id[:8]}; {DATE}"
    )
    msg["Authentication-Results"] = auth_results
    msg["From"] = from_
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = DATE
    msg["Message-ID"] = f"<{msg_id}@phishlens.test>"
    return msg


def _auth(domain: str, spf: str = "pass", dkim: str = "pass", dmarc: str = "pass") -> str:
    return (
        f"mx.recipient.example; spf={spf} smtp.mailfrom={domain}; "
        f"dkim={dkim} header.d={domain}; dmarc={dmarc} header.from={domain}"
    )


def _fix_boundaries(msg: Message, name: str) -> None:
    """Give every multipart a fixed boundary so output is reproducible."""
    n = 0
    for part in msg.walk():
        if part.is_multipart():
            part.set_boundary(f"==phishlens-{name}-{n}==")
            n += 1


def _dos_datetime(dt: tuple[int, int, int, int, int, int]) -> tuple[int, int]:
    y, mo, d, h, mi, s = dt
    return (h << 11) | (mi << 5) | (s // 2), ((y - 1980) << 9) | (mo << 5) | d


def make_zip(name: str, data: bytes) -> bytes:
    """Plain (unencrypted, deflated) zip with a fixed timestamp."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo(name, date_time=ZIP_DATE_TIME)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        zf.writestr(info, data)
    return buf.getvalue()


def _crc_table() -> list[int]:
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c)
    return table


def make_encrypted_zip(name: str, data: bytes, password: bytes) -> bytes:
    """Stored zip entry encrypted with traditional PKWARE (ZipCrypto) encryption.

    The standard library can read but not write encrypted zips, so this writes one by hand.
    """
    table = _crc_table()
    keys = [0x12345678, 0x23456789, 0x34567890]

    def crc(k: int, b: int) -> int:
        return (k >> 8) ^ table[(k ^ b) & 0xFF]

    def update(b: int) -> None:
        keys[0] = crc(keys[0], b)
        keys[1] = (keys[1] + (keys[0] & 0xFF)) & 0xFFFFFFFF
        keys[1] = (keys[1] * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = crc(keys[2], keys[1] >> 24)

    def stream_byte() -> int:
        t = (keys[2] | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    for b in password:
        update(b)

    crc32 = zlib.crc32(data) & 0xFFFFFFFF
    # 11 fixed "random" bytes + check byte (high byte of the CRC).
    header = bytes(range(1, 12)) + bytes([crc32 >> 24])
    encrypted = bytearray()
    for b in header + data:
        encrypted.append(b ^ stream_byte())
        update(b)

    fname = name.encode()
    mtime, mdate = _dos_datetime(ZIP_DATE_TIME)
    csize, usize = len(encrypted), len(data)
    local = struct.pack(
        "<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0x1, 0, mtime, mdate, crc32, csize, usize,
        len(fname), 0,
    ) + fname + bytes(encrypted)
    central = struct.pack(
        "<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0x1, 0, mtime, mdate, crc32, csize,
        usize, len(fname), 0, 0, 0, 0, 0o644 << 16, 0,
    ) + fname
    end = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def make_qr_png(url: str) -> bytes:
    buf = io.BytesIO()
    segno.make_qr(url, error="m").save(buf, kind="png", scale=6, border=4)
    return buf.getvalue()


# --------------------------------------------------------------------------- fixtures


def clean_newsletter() -> Message:
    msg = _base(
        Address("Example News", "news", "newsletter.example"),
        "reader@recipient.example",
        "Your September community newsletter",
        "clean-newsletter-0001",
        "bounce@newsletter.example",
        _auth("newsletter.example"),
        "mail.newsletter.example ([198.51.100.10])",
    )
    msg.set_content(
        "Hello reader,\n\n"
        "Here is what happened in the community this month: a new park opened, the library\n"
        "extended its hours and the local choir is looking for new members.\n\n"
        "Read more at https://www.newsletter.example/september\n\n"
        "You can unsubscribe at any time from your account settings.\n"
    )
    msg.add_alternative(
        "<html><body><p>Hello reader,</p>"
        "<p>Here is what happened in the community this month: a new park opened, the library "
        "extended its hours and the local choir is looking for new members.</p>"
        '<p><a href="https://www.newsletter.example/september">'
        "https://www.newsletter.example/september</a></p>"
        "<p>You can unsubscribe at any time from your account settings.</p></body></html>",
        subtype="html",
    )
    msg["List-Unsubscribe"] = "<https://www.newsletter.example/unsubscribe>"
    return msg


def spoof_unaligned() -> EmailMessage:
    msg = _base(
        Address("Microsoft Account Team", "account-security", "microsoft.com"),
        "victim@recipient.example",
        "Unusual sign-in activity on your account",
        "spoof-unaligned-0002",
        "mailer@zetatech.xyz",
        "mx.recipient.example; spf=pass smtp.mailfrom=zetatech.xyz; dkim=none; "
        "dmarc=fail header.from=microsoft.com",
        "mail.zetatech.xyz ([203.0.113.45])",
    )
    msg.set_content(
        "We detected an unusual sign-in to your account.\n\n"
        "If this was not you, review your recent activity at\n"
        "http://account-review.zetatech.example/verify\n\n"
        "Microsoft Account Team\n"
    )
    return msg


def display_name_trick() -> EmailMessage:
    msg = _base(
        Address("ceo@company.com", "attacker", "evil-example.net"),
        "finance@recipient.example",
        "Quick favour needed today",
        "display-name-0003",
        "attacker@evil-example.net",
        _auth("evil-example.net", dmarc="none"),
        "mail.evil-example.net ([203.0.113.60])",
    )
    msg.set_content(
        "Hi,\n\nAre you at your desk? I need you to process a payment for a supplier today.\n"
        "I am in meetings all day, so reply by email only.\n\nThanks\n"
    )
    return msg


def duplicate_from() -> Message:
    # EmailMessage refuses a second From header, so use a compat32 Message here.
    msg = Message(policy=policy.compat32)
    msg["Return-Path"] = "<billing@invoices.example>"
    msg["Received"] = (
        "from mail.invoices.example ([198.51.100.77]) by mx.recipient.example with ESMTPS "
        f"id dup00004; {DATE}"
    )
    msg["Authentication-Results"] = _auth("invoices.example", dmarc="fail")
    msg["From"] = "Billing <billing@invoices.example>"
    msg["From"] = "IT Helpdesk <helpdesk@recipient.example>"
    msg["To"] = "user@recipient.example"
    msg["Subject"] = "Outstanding invoice"
    msg["Date"] = DATE
    msg["Message-ID"] = "<duplicate-from-0004@phishlens.test>"
    msg["MIME-Version"] = "1.0"
    msg["Content-Type"] = 'text/plain; charset="utf-8"'
    msg["Content-Transfer-Encoding"] = "7bit"
    msg.set_payload("Please see the outstanding invoice and confirm payment details.\n")
    return msg


def link_mismatch() -> EmailMessage:
    msg = _base(
        Address("PayPal Service", "service", "paypal-notice.example"),
        "user@recipient.example",
        "Your account has been limited",
        "link-mismatch-0005",
        "service@paypal-notice.example",
        _auth("paypal-notice.example"),
        "mail.paypal-notice.example ([203.0.113.12])",
    )
    msg.set_content(
        "We noticed unusual activity. Please confirm your details at https://www.paypal.com\n"
    )
    msg.add_alternative(
        "<html><body><p>We noticed unusual activity on your account.</p>"
        '<p>Please confirm your details: <a href="http://paypal-secure-login.example/confirm">'
        "https://www.paypal.com</a></p></body></html>",
        subtype="html",
    )
    return msg


def lookalike_domain() -> EmailMessage:
    msg = _base(
        Address("Microsoft Support", "security", "micros0ft-support.example"),
        "user@recipient.example",
        "URGENT: Your password expires in 24 hours",
        "lookalike-0006",
        "security@micros0ft-support.example",
        _auth("micros0ft-support.example"),
        "mail.micros0ft-support.example ([203.0.113.33])",
    )
    msg.set_content(
        "URGENT ACTION REQUIRED\n\n"
        "Your password expires in 24 hours. Reset your password immediately or your account\n"
        "will be suspended and all data will be lost.\n\n"
        "Reset now: http://micros0ft-support.example/reset-password\n\n"
        "Microsoft Support\n"
    )
    return msg


def zip_attachment() -> EmailMessage:
    msg = _base(
        Address("Project Office", "office", "projects.example"),
        "team@recipient.example",
        "Meeting notes (zipped)",
        "zip-attachment-0007",
        "office@projects.example",
        _auth("projects.example"),
        "mail.projects.example ([198.51.100.30])",
    )
    msg.set_content("Hi team,\n\nThe meeting notes are attached as a zip file.\n")
    msg.add_attachment(
        make_zip("notes.txt", b"Meeting notes: nothing to see here. Harmless test file.\n"),
        maintype="application",
        subtype="zip",
        filename="notes.zip",
    )
    return msg


def password_zip() -> EmailMessage:
    msg = _base(
        Address("Accounts", "accounts", "billing-dept.example"),
        "user@recipient.example",
        "Invoice attached (protected)",
        "password-zip-0008",
        "accounts@billing-dept.example",
        _auth("billing-dept.example"),
        "mail.billing-dept.example ([203.0.113.81])",
    )
    msg.set_content(
        "Hello,\n\nThe invoice is attached as a protected archive.\n\n"
        "Password: 4455\n\nPlease open it today.\n"
    )
    msg.add_attachment(
        make_encrypted_zip("invoice.txt", b"Harmless test invoice text.\n", ZIP_PASSWORD),
        maintype="application",
        subtype="zip",
        filename="invoice.zip",
    )
    return msg


def double_extension() -> EmailMessage:
    msg = _base(
        Address("Accounts Payable", "ap", "vendor-invoices.example"),
        "user@recipient.example",
        "Invoice #20260907",
        "double-ext-0009",
        "ap@vendor-invoices.example",
        _auth("vendor-invoices.example"),
        "mail.vendor-invoices.example ([203.0.113.90])",
    )
    msg.set_content("Please find the invoice attached.\n")
    msg.add_attachment(
        b"This is a harmless placeholder, not an executable.\n",
        maintype="application",
        subtype="octet-stream",
        filename="invoice.pdf.exe",
    )
    return msg


_SMUGGLING_DATA = base64.b64encode(b"Harmless placeholder text for tests.").decode()
SMUGGLING_HTML = """<!DOCTYPE html>
<html>
<head><title>Secure Document</title></head>
<body>
<p>Loading your secure document...</p>
<script>
// Non-functional test pattern: this function is never called.
function neverCalled() {
  var data = "{data}";
  var bytes = atob(data);
  var blob = new Blob([bytes], {type: "application/octet-stream"});
  var a = document.createElement("a");
  a.href = window.URL.createObjectURL(blob);
  a.download = "document.zip";
  // a.click() intentionally omitted
}
</script>
</body>
</html>
""".replace("{data}", _SMUGGLING_DATA)


def html_smuggling() -> EmailMessage:
    msg = _base(
        Address("Document Share", "share", "docshare.example"),
        "user@recipient.example",
        "You have received a secure document",
        "html-smuggling-0010",
        "share@docshare.example",
        _auth("docshare.example"),
        "mail.docshare.example ([203.0.113.101])",
    )
    msg.set_content("A secure document has been shared with you. Open the attached file.\n")
    msg.add_attachment(
        SMUGGLING_HTML, subtype="html", filename="secure_document.html"
    )
    return msg


def tracking_pixel() -> EmailMessage:
    msg = _base(
        Address("Deals", "deals", "promo-offers.example"),
        "user@recipient.example",
        "Exclusive offer just for you",
        "tracking-pixel-0011",
        "deals@promo-offers.example",
        _auth("promo-offers.example"),
        "mail.promo-offers.example ([203.0.113.110])",
    )
    msg.set_content("Exclusive offer just for you. View this email in HTML.\n")
    msg.add_alternative(
        "<html><body>"
        "<p>Exclusive offer just for you! Save 50% this week.</p>"
        '<div style="display:none;font-size:0;color:#ffffff">'
        "invoice payment account verified safe legitimate newsletter</div>"
        '<span style="font-size:0px">hidden filler text to confuse filters</span>'
        '<img src="http://track.promo-offers.example/open.gif?id=abc123" '
        'width="1" height="1" alt="" style="border:0">'
        "</body></html>",
        subtype="html",
    )
    return msg


def qr_code() -> EmailMessage:
    msg = _base(
        Address("IT Security", "it-security", "mfa-update.example"),
        "user@recipient.example",
        "Action required: re-enrol multi-factor authentication",
        "qr-code-0012",
        "it-security@mfa-update.example",
        _auth("mfa-update.example"),
        "mail.mfa-update.example ([203.0.113.120])",
    )
    msg.set_content(
        "Your MFA enrolment expires today. Scan the QR code with your phone to re-enrol.\n"
    )
    msg.add_alternative(
        "<html><body><p>Your MFA enrolment expires today.</p>"
        "<p>Scan the QR code with your phone to re-enrol:</p>"
        '<img src="cid:qrcode@phishlens.test" alt="QR code"></body></html>',
        subtype="html",
    )
    html_part = msg.get_payload()[1]
    html_part.add_related(
        make_qr_png(QR_URL),
        maintype="image",
        subtype="png",
        cid="<qrcode@phishlens.test>",
        filename="qrcode.png",
        disposition="inline",
    )
    return msg


def forwarded_nested() -> EmailMessage:
    msg = _base(
        Address("Colleague", "colleague", "recipient.example"),
        "security-team@recipient.example",
        "Fwd: Unusual sign-in activity on your account",
        "forwarded-0013",
        "colleague@recipient.example",
        _auth("recipient.example"),
        "mail.recipient.example ([198.51.100.5])",
    )
    msg.set_content("Hi, I received the attached email. Is it legitimate?\n")
    msg.add_attachment(spoof_unaligned())
    return msg


def eicar_attachment() -> EmailMessage:
    msg = _base(
        Address("Test Sender", "test", "av-test.example"),
        "user@recipient.example",
        "Antivirus test file",
        "eicar-0014",
        "test@av-test.example",
        _auth("av-test.example"),
        "mail.av-test.example ([198.51.100.140])",
    )
    msg.set_content("Attached is the standard EICAR antivirus test file.\n")
    msg.add_attachment(
        EICAR.encode(),
        maintype="application",
        subtype="octet-stream",
        filename="eicar.com",
    )
    return msg


# name -> (builder, label entry)
FIXTURES: dict[str, tuple[Callable[[], Message], dict[str, object]]] = {
    "clean_newsletter": (
        clean_newsletter,
        {"verdict": "clean", "expected_signals": []},
    ),
    "spoof_unaligned": (
        spoof_unaligned,
        {
            "verdict": "malicious",
            "expected_signals": ["return_path_mismatch", "spf_domain_unaligned", "dmarc_fail",
                                 "brand_impersonation"],
        },
    ),
    "display_name_trick": (
        display_name_trick,
        {"verdict": "suspicious", "expected_signals": ["display_name_contains_email"]},
    ),
    "duplicate_from": (
        duplicate_from,
        {"verdict": "suspicious", "expected_signals": ["duplicate_from_header"]},
    ),
    "link_mismatch": (
        link_mismatch,
        {"verdict": "malicious", "expected_signals": ["link_text_href_mismatch",
                                                      "brand_impersonation"]},
    ),
    "lookalike_domain": (
        lookalike_domain,
        {"verdict": "malicious", "expected_signals": ["lookalike_domain", "urgent_language",
                                                      "credential_request"]},
    ),
    "zip_attachment": (
        zip_attachment,
        {"verdict": "clean", "expected_signals": ["archive_attachment"]},
    ),
    "password_zip": (
        password_zip,
        {"verdict": "suspicious", "expected_signals": ["encrypted_archive",
                                                       "password_in_body"]},
    ),
    "double_extension": (
        double_extension,
        {"verdict": "malicious", "expected_signals": ["double_extension",
                                                      "executable_attachment"]},
    ),
    "html_smuggling": (
        html_smuggling,
        {"verdict": "malicious", "expected_signals": ["html_smuggling"]},
    ),
    "tracking_pixel": (
        tracking_pixel,
        {"verdict": "suspicious", "expected_signals": ["tracking_pixel", "hidden_text"]},
    ),
    "qr_code": (
        qr_code,
        {"verdict": "suspicious", "expected_signals": ["qr_code_url"], "qr_url": QR_URL},
    ),
    "forwarded_nested": (
        forwarded_nested,
        {"verdict": "malicious", "expected_signals": ["nested_message", "return_path_mismatch",
                                                      "dmarc_fail"]},
    ),
    "eicar_attachment": (
        eicar_attachment,
        {"verdict": "malicious", "expected_signals": ["eicar_test_file"]},
    ),
}


def build_fixtures() -> dict[str, bytes]:
    """Return {filename: eml bytes} for every fixture."""
    out: dict[str, bytes] = {}
    for name, (builder, _) in FIXTURES.items():
        msg = builder()
        _fix_boundaries(msg, name)
        out[f"{name}.eml"] = msg.as_bytes()
    return out


def build_labels() -> str:
    labels = {f"{name}.eml": label for name, (_, label) in FIXTURES.items()}
    header = (
        "# Expected labels for synthetic fixtures. Generated by scripts/make_fixtures.py.\n"
        "# verdict: clean | suspicious | malicious\n"
        "# expected_signals: descriptive hints, not binding finding IDs.\n"
    )
    return header + yaml.safe_dump(labels, sort_keys=False)


def main(out_dir: Path = DEFAULT_OUT) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for filename, data in build_fixtures().items():
        (out_dir / filename).write_bytes(data)
    (out_dir / "labels.yaml").write_text(build_labels(), encoding="utf-8")
    print(f"Wrote {len(FIXTURES)} fixtures and labels.yaml to {out_dir}")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT)
