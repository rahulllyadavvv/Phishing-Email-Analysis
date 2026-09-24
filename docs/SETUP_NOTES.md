# Setup Notes

System libraries that the Python packages need but that `pip` cannot install.
Tests that depend on them are skipped when they are missing.

## Missing on the dev machine (found in P0.1)

| Library | Needed by | macOS (Homebrew) | Debian/Ubuntu |
|---|---|---|---|
| libmagic | python-magic | `brew install libmagic` | `apt install libmagic1` |
| zbar | pyzbar | `brew install zbar` | `apt install libzbar0` |
| Pango / GObject (WeasyPrint libs) | weasyprint (PDF reports) | `brew install pango` | `apt install libpango-1.0-0 libpangoft2-1.0-0` |

On Apple Silicon you may also need `export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`
so the Python packages can find Homebrew libraries.

yara-python installed from a wheel and imports correctly.

## P0.4

- `tests/test_make_fixtures.py::test_qr_code_decodes` is skipped when zbar is missing.
- `tests/fixtures/eicar_attachment.eml` contains the EICAR antivirus test string (base64).
  Desktop antivirus may quarantine it. If it does, add an exclusion for `tests/fixtures/`.

## P4.4: urlscan.io privacy

Submitting a URL to urlscan.io makes urlscan visit it and store the result. `URLSCAN_VISIBILITY`
defaults to `unlisted`: the scan is not on the public feed, but urlscan and its security partners
can still see it. Phishing links often carry the victim's email address or a session token.
Use `private` (paid plans) for sensitive mail, or leave `URLSCAN_API_KEY` unset to turn urlscan off.
