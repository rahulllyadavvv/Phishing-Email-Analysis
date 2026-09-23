import importlib.util
import io
import zipfile
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from types import ModuleType

import pytest
import yaml
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"


def _load_script() -> ModuleType:
    path = ROOT / "scripts" / "make_fixtures.py"
    spec = importlib.util.spec_from_file_location("make_fixtures", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mf = _load_script()

EXPECTED = [
    "clean_newsletter.eml",
    "spoof_unaligned.eml",
    "display_name_trick.eml",
    "duplicate_from.eml",
    "link_mismatch.eml",
    "lookalike_domain.eml",
    "zip_attachment.eml",
    "password_zip.eml",
    "double_extension.eml",
    "html_smuggling.eml",
    "tracking_pixel.eml",
    "qr_code.eml",
    "forwarded_nested.eml",
    "eicar_attachment.eml",
]


def _parse(name: str) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes((FIXTURES / name).read_bytes())


def _attachments(msg: EmailMessage) -> list[EmailMessage]:
    return list(msg.iter_attachments())


def test_all_fixtures_exist_and_parse() -> None:
    for name in EXPECTED:
        msg = _parse(name)
        assert msg["Subject"]
        assert not msg.defects, (name, msg.defects)


def test_committed_fixtures_match_generator() -> None:
    for filename, data in mf.build_fixtures().items():
        assert (FIXTURES / filename).read_bytes() == data, f"{filename} is stale; rerun script"


def test_labels_cover_every_fixture() -> None:
    labels = yaml.safe_load((FIXTURES / "labels.yaml").read_text(encoding="utf-8"))
    assert list(labels) == EXPECTED
    for entry in labels.values():
        assert entry["verdict"] in {"clean", "suspicious", "malicious"}
        assert isinstance(entry["expected_signals"], list)
    assert labels["clean_newsletter.eml"]["verdict"] == "clean"


def test_main_writes_to_directory(tmp_path: Path) -> None:
    mf.main(tmp_path)
    assert sorted(p.name for p in tmp_path.glob("*.eml")) == sorted(EXPECTED)
    assert (tmp_path / "labels.yaml").exists()


def test_spoof_unaligned_headers() -> None:
    msg = _parse("spoof_unaligned.eml")
    assert "microsoft.com" in msg["From"]
    assert "zetatech.xyz" in msg["Return-Path"]
    assert "spf=pass smtp.mailfrom=zetatech.xyz" in str(msg["Authentication-Results"])


def test_display_name_trick() -> None:
    raw = (FIXTURES / "display_name_trick.eml").read_text()
    assert 'From: "ceo@company.com" <attacker@evil-example.net>' in raw


def test_duplicate_from() -> None:
    msg = _parse("duplicate_from.eml")
    assert len(msg.get_all("From")) == 2


def test_link_mismatch() -> None:
    html = _parse("link_mismatch.eml").get_body(("html",)).get_content()
    assert 'href="http://paypal-secure-login.example/confirm">https://www.paypal.com</a>' in html


def test_lookalike_domain() -> None:
    msg = _parse("lookalike_domain.eml")
    assert "micros0ft-support.example" in msg["From"]
    assert "password" in msg.get_body(("plain",)).get_content().lower()


def test_zip_attachment() -> None:
    (att,) = _attachments(_parse("zip_attachment.eml"))
    zf = zipfile.ZipFile(io.BytesIO(att.get_content()))
    assert zf.namelist() == ["notes.txt"]
    assert b"Harmless" in zf.read("notes.txt")


def test_password_zip() -> None:
    msg = _parse("password_zip.eml")
    assert "Password: 4455" in msg.get_body(("plain",)).get_content()
    (att,) = _attachments(msg)
    zf = zipfile.ZipFile(io.BytesIO(att.get_content()))
    assert zf.infolist()[0].flag_bits & 0x1
    with pytest.raises(RuntimeError):
        zf.read("invoice.txt")
    assert zf.read("invoice.txt", pwd=b"4455") == b"Harmless test invoice text.\n"


def test_double_extension() -> None:
    (att,) = _attachments(_parse("double_extension.eml"))
    assert att.get_filename() == "invoice.pdf.exe"
    assert not att.get_content().startswith(b"MZ")


def test_html_smuggling() -> None:
    (att,) = _attachments(_parse("html_smuggling.eml"))
    html = att.get_content()
    for pattern in ("new Blob", "createObjectURL", ".download", "atob("):
        assert pattern in html
    assert "a.click()" not in html.replace("// a.click()", "")


def test_tracking_pixel() -> None:
    html = _parse("tracking_pixel.eml").get_body(("html",)).get_content()
    assert 'width="1" height="1"' in html
    assert "display:none" in html


def test_qr_code_png() -> None:
    msg = _parse("qr_code.eml")
    pngs = [p for p in msg.walk() if p.get_content_type() == "image/png"]
    assert len(pngs) == 1
    assert pngs[0]["Content-ID"] == "<qrcode@phishlens.test>"
    img = Image.open(io.BytesIO(pngs[0].get_content()))
    assert img.format == "PNG"


def _zbar_available() -> bool:
    try:
        import pyzbar.pyzbar  # noqa: F401
    except (ImportError, OSError):
        return False
    return True


@pytest.mark.skipif(not _zbar_available(), reason="zbar system library not installed")
def test_qr_code_decodes() -> None:
    from pyzbar.pyzbar import decode

    msg = _parse("qr_code.eml")
    png = next(p for p in msg.walk() if p.get_content_type() == "image/png").get_content()
    (result,) = decode(Image.open(io.BytesIO(png)))
    assert result.data.decode() == "http://phish-test.example/login"


def test_forwarded_nested() -> None:
    msg = _parse("forwarded_nested.eml")
    (att,) = _attachments(msg)
    assert att.get_content_type() == "message/rfc822"
    inner = att.get_content()
    assert inner["Message-ID"] == "<spoof-unaligned-0002@phishlens.test>"
    assert "zetatech.xyz" in inner["Return-Path"]


def test_eicar_attachment() -> None:
    (att,) = _attachments(_parse("eicar_attachment.eml"))
    data = att.get_content()
    assert data.startswith(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$")
    assert b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" in data
    assert len(data) == 68
