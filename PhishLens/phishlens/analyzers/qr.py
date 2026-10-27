"""QR code decoding from image bytes (pyzbar + Pillow), used for PDFs and image attachments.

zbar is a system library; without it ``qr_available()`` is False and ``decode_qr`` returns an
empty list, so callers record "QR decoding unavailable" instead of failing. Images are only
decoded into pixels, never displayed, and oversized images (decompression bombs) are refused.
"""

from __future__ import annotations

import io
from functools import cache
from typing import Any

from PIL import Image

__all__ = ["MAX_IMAGE_PIXELS", "decode_qr", "qr_available"]

MAX_IMAGE_PIXELS = 40_000_000  # about 6300 x 6300


@cache
def _pyzbar() -> Any:
    try:
        from pyzbar import pyzbar

        return pyzbar
    except (ImportError, OSError):  # pyzbar installed but the zbar library is missing
        return None


def qr_available() -> bool:
    return _pyzbar() is not None


def decode_qr(image_bytes: bytes) -> list[str]:
    """Texts of all QR codes in the image; empty when there are none, the image cannot be
    read, it is too large, or zbar is not installed."""
    decoder = _pyzbar()
    if decoder is None or not image_bytes:
        return []
    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            width, height = image.size
            if width * height > MAX_IMAGE_PIXELS:
                return []
            image.load()
            symbols = decoder.decode(image.convert("L"))
    except Exception:
        return []
    texts: list[str] = []
    for symbol in symbols:
        if getattr(symbol, "type", "QRCODE") != "QRCODE":
            continue
        text = symbol.data.decode("utf-8", errors="replace").strip()
        if text and text not in texts:
            texts.append(text)
    return texts
