# Decisions

## P0.1: Project scaffold

- Build backend: setuptools. Packages found automatically: `phishlens*`, `api*`, `ui*`.
- `api/` and `ui/` get `__init__.py` files so they can be imported as packages.
- Empty directories (`data/`, `scripts/`, `tests/fixtures/`, `samples/`, `quarantine/`,
  `reports/`, `phishlens/reporting/templates/`) each have a `.gitkeep`. `samples/`, `quarantine/`
  and `reports/` are gitignored, so they are only created locally.
- Ruff: line length 100, target py311, rules E/F/W/I/B/UP. Excluded: `autopilot.py` and
  `progress.py` (autopilot tooling, not project code) plus the runtime data folders.
- pytest: `testpaths = ["tests"]`, `asyncio_mode = "auto"`. With zero tests pytest exits with
  code 5 ("no tests collected"). This is the expected result for P0.1.
- No version pins for dependencies yet. Pins can be added once the analysis code needs them.
- `.env.example` has sample local defaults for `REDIS_URL` and `DATABASE_URL`. All secrets are left blank.

## P0.2: Shared data models

- Fixed value sets are `StrEnum`s: `Severity`, `UrlSource`, `IOCType`, `CaseType`, and
  `VerdictLabel` (`clean` / `suspicious` / `malicious`, matching the report badges in PROMPTS.md).
  `IOC.verdict` stays a free `str | None` because reputation services use different words.
- Byte fields (`Attachment.data`, `ParsedEmail.raw_bytes`) use `Field(exclude=True, repr=False)`.
  They never appear in `model_dump()`, JSON output or repr. After a JSON round trip they are `b""`.
- `AnalysisReport.email` reuses `ParsedEmail` rather than a separate summary model. The byte
  exclusion already makes it a summary without raw bytes. `file_info` is an `Attachment`.
- `ParsedEmail.headers` is `list[tuple[str, str]]`, serialized as `[name, value]` pairs.
- `reply_to` is a list of `Address` (Reply-To can hold several addresses). `return_path` and
  `sender` are single optional addresses.
- `Finding.id` is checked against a snake_case regex. `Verdict.total_score` must be 0-100 and
  `confidence` must be 0.0-1.0. `Verdict` is optional on `AnalysisReport` so a partly built report
  can still be valid.
- All models use `extra="forbid"` so typos in field names fail fast. `created_at` defaults to
  the current UTC time.
