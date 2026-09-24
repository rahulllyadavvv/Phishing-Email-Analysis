# YARA rules

PhishLens compiles every `*.yar` / `*.yara` file in this folder once (cached) and scans every
attachment and extracted file with it. A match becomes a `yara_match` finding. Its severity
comes from the rule's `meta: severity = "low|medium|high|critical"` (default: high).

Set `YARA_RULES_DIR` to use another folder.

## Adding community rules

Good free sources:

- **YARA-Forge** (curated, deduplicated, tested packages of public rules):
  https://yarahq.github.io/ . Download the `core` or `extended` package, unzip it, and copy
  `yara-rules-core.yar` into this folder.
- **Neo23x0/signature-base**: https://github.com/Neo23x0/signature-base (the `yara/` folder).
- **Elastic protections-artifacts**:
  https://github.com/elastic/protections-artifacts/tree/main/yara

Community rule sets are large. A file that fails to compile is skipped and reported in the
analyzer errors, so one bad file does not disable the others. Rules that use external variables
(e.g. `filename`, `filepath`) get empty values.

`phishlens_example.yar` is a harmless example that matches the marker string
`PHISHLENS-YARA-TEST-MARKER`. It is used by the tests; keep or delete it as you like.

Do not commit third-party rule packs unless their licenses allow it.
