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
