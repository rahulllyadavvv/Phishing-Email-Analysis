# CLAUDE.md

## Project purpose

PhishLens is an automated phishing email analysis tool (Python 3.11). A user submits an email
(`.eml` / `.msg`) or a single suspicious file. The tool runs header, sender/domain, body tone, URL,
attachment and hidden-artifact analysis, enriches indicators with threat-intel services, and
produces a verdict (Clean / Suspicious / Malicious), an IOC table, a MITRE ATT&CK mapping and an
HTML/PDF/JSON/CSV/STIX report. It is used through a Typer CLI, a FastAPI backend and a Streamlit UI
(the UI talks only to the API).

## Folder structure

```
phishlens/
  config.py        settings from env / .env (pydantic-settings), get_settings()
  models.py        shared pydantic models (ParsedEmail, Finding, AnalyzerResult, IOC, ...)
  pipeline.py      orchestrates parsing -> analyzers -> enrichment -> scoring -> report
  ingest/          input detection and routing (email vs single file)
  parser/          .eml / .msg parsing into ParsedEmail
  analyzers/       one module per analysis area (headers, sender, body, urls, attachments, ...)
  enrichment/      ALL external HTTP/DNS clients (cached, rate limited)
  ioc/             IOC extraction, normalization and defanging
  mapping/         MITRE ATT&CK mapping rules
  scoring/         weights, caps, thresholds and verdict logic
  reporting/       report generation; templates/ holds Jinja2 templates
api/               FastAPI backend
ui/                Streamlit frontend (calls the API only)
data/              YAML data files (brand registry, lexicons, weights, MITRE rules, yara/)
scripts/           helper scripts (e.g. synthetic fixture generation)
tests/             pytest tests; tests/fixtures/ holds synthetic harmless samples
docs/              prompts, decisions, setup notes, plans
samples/ quarantine/ reports/   local runtime folders (gitignored)
```

## Analyzer contract

Every analyzer module exposes:

```python
async def analyze(email: ParsedEmail) -> AnalyzerResult: ...
```

- It **never raises**. Any exception is caught and recorded as a string in
  `AnalyzerResult.errors`; the rest of the result stays usable.
- URLs it discovers (e.g. inside attachments, QR codes, HTML) are returned in
  `AnalyzerResult.extracted_urls` so the URL analyzer and IOC extraction can pick them up.
- Missing configuration (e.g. no API key) means the check is skipped, not an error.

## External calls

- All external HTTP and DNS calls go through `phishlens/enrichment/` (or the cached DNS helper
  `phishlens/enrichment/dns.py`), which provides caching and per-service rate limiting.
  Analyzers never create their own HTTP clients or resolvers.
- API keys are optional. `get_settings().is_enabled("<service>")` tells whether a service is
  configured; a missing key disables that service.

## SAFETY RULES

- **Never execute, open, render or fetch** attachments or URLs on the host. Analysis is static only
  (parsing bytes, hashing, reputation lookups by hash/URL string). Dynamic analysis happens only in
  an external sandbox.
- **Never upload files to third parties** unless `UPLOAD_FILES_TO_VT=true`. Hash lookups are fine.
- **Never log API keys.** Keys are `SecretStr` in `Settings`; never print or log
  `get_secret_value()`. `check-config` shows only enabled/disabled.
- **Defang malicious values in all outputs** (`hxxp://`, `example[.]com`, `1.2.3[.]4`) in reports,
  CLI output, API responses and UI. Only MITRE links and screenshot links may be clickable.
- Uploaded inputs are stored under `quarantine/` with generated names, never in a served folder.

## Finding IDs

Finding IDs are stable snake_case strings (e.g. `replyto_mismatch`, `domain_age_under_7_days`).
Scoring weights and MITRE rules reference them, so never rename an existing ID without updating
`data/` and tests in the same change.

## Data files

Brand registry, lexicons, scoring weights, MITRE rules and similar tables are YAML files in
`data/` (or next to the module that owns them), loaded through a cached loader. Never hard-code
these tables in Python.

## Conventions

- Type hints everywhere; `ruff check .` must be clean (line length 100).
- Every module has a pytest test file.
- All network is mocked in tests: `respx` for HTTP, `monkeypatch` for DNS. No real API keys.
- Fixtures are synthetic and harmless only (no real malware, no real phishing kits). Use
  reserved domains like `example.com` / `.test` in fixtures.
- Missing system libraries (libmagic, zbar, WeasyPrint libs) → mark only the affected tests with
  `pytest.mark.skipif` and document in `docs/SETUP_NOTES.md`.
- Record ambiguous design choices in `docs/DECISIONS.md` under the process heading.
- Never create or commit `.env`; document new settings in `.env.example` and `phishlens/config.py`.

## Commands

```bash
# install
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# test
pytest -q

# lint
ruff check .            # add --fix to auto-fix

# run CLI (entry point added in P10.4)
phishlens analyze path/to/email.eml --format json,html --out reports/
phishlens check-config

# run API
uvicorn api.main:app --reload

# run UI
streamlit run ui/app.py
```
