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

## P6.1: file type detection

`phishlens/analyzers/filetype.py` uses libmagic (python-magic) when the system library is
installed, and otherwise falls back to the signature table in `data/file_types.yaml`. Everything
works without libmagic. The `libmagic` variants of the tests in `tests/test_filetype.py` are
skipped when it is missing, and the fallback variants always run. libmagic recognizes many more
formats, so installing it is recommended (`brew install libmagic` / `apt install libmagic1`).

New Python dependencies: `py7zr` (7z), `pycdlib` (ISO images), `pyzipper` (AES-encrypted zips).

## P6.4: QR decoding

`phishlens/analyzers/qr.py` decodes QR codes with pyzbar, which needs the zbar system library
(`brew install zbar` / `apt install libzbar0`). Without it, QR decoding is skipped and recorded
(`qr_decoding: unavailable` in the report), and `test_pdf_qr_code_in_image` is skipped.

## P8.2: optional ML and LLM tone classifiers

Both are off unless configured, and the tests never need them:

- Local model: `pip install -e ".[ml]"` (transformers + torch), then set `TONE_MODEL_PATH` to a
  fine-tuned text-classification model folder (see P8.3 `scripts/train_tone_model.py`).
- LLM (Claude): `pip install -e ".[llm]"` (the `anthropic` SDK), set `LLM_API_KEY` and
  `LLM_TONE_ENABLED=true`. This sends the email subject and body (up to 50,000 characters) to
  Anthropic; each report records that in `raw["llm_warning"]`. `LLM_MODEL` defaults to
  `claude-opus-5`.

## P9.3: MITRE ATT&CK data

`python scripts/update_attack_data.py` downloads `enterprise-attack.json` (about 48 MB, 858
techniques at the time of writing) from the MITRE CTI GitHub repository into `data/mitre/`
(gitignored). Without it, technique names and tactics come from the fallback table in
`data/mitre_rules.yaml`, and `test_every_technique_exists_in_attack_data` is skipped. Loading
the file takes a few seconds; it is cached per process.

## P10.2: end-to-end tests

`tests/test_pipeline.py` runs every fixture through the whole pipeline against a fake internet
(fake DNS, respx for HTTP). `qr_code.eml` only reaches its expected "suspicious" verdict when
the QR code can be decoded, so that case is skipped without zbar.

## P11.3: PDF reports

PDF reports are rendered by WeasyPrint, which needs Pango (`brew install pango` on macOS; on
Apple Silicon also `export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`; `apt install
libpango-1.0-0 libpangoft2-1.0-0` on Debian/Ubuntu). Without it, `--format pdf` prints "PDF
skipped: ..." and every other format is still written; `test_pdf_is_a_pdf` is skipped.

## P14.1: evaluation

- `scripts/evaluate.py` needs matplotlib for its charts: `pip install -e ".[eval]"` (it is also
  in the `dev` extra).
- Quick run on the synthetic fixtures (no network):
  `python scripts/evaluate.py tests/fixtures --labels tests/fixtures/eval_labels.csv --no-network --tune`.
  Offline, SPF/DMARC and hash reputation are skipped, so `spoof_unaligned`, `eicar_attachment`,
  `tracking_pixel` and (without zbar) `qr_code` come out Clean; with network (or the fake
  internet in `tests/test_evaluate.py`) every fixture gets its expected verdict.
- For a real dataset, put the emails in `samples/eval/` (gitignored) with a labels CSV
  (`filename,label,manual_verdict,notes`). Run once with network to fill the enrichment cache,
  then re-run with `--cached-only` (for example after changing weights) without spending API
  quota. Reports go to `reports/evaluation/` (gitignored).
- The 14 fixtures are far too few to tune thresholds on: `--tune` on them only shows that the
  machinery works. Tune on a real, labelled dataset (see `scripts/prepare_datasets.md`).
