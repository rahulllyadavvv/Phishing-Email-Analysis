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
