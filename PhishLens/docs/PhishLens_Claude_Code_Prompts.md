# PhishLens: Process-by-Process Prompts for Claude Code

This is the complete build guide for PhishLens, the automated phishing email analysis tool. The project is split into 16 phases and 60 small processes. Each process is one prompt for Claude Code in VS Code, with a "Done when" check so you know when to move on.

## How to use this guide

1. Keep this file in your repo as `docs/PROMPTS.md` so you can open it next to Claude Code.
2. Run the processes in order. Later processes depend on the models and helpers created earlier.
3. Run **one process per session**. Use `/clear` between processes so old context doesn't pile up.
4. For processes marked **[PLAN FIRST]**, ask Claude Code to show its plan before writing code (or use plan mode), and review it.
5. After each process: run `pytest` and `ruff check .`, check the "Done when" list, then **commit**.
6. Claude Code reads `CLAUDE.md` automatically, so the prompts don't repeat the project rules. If Claude Code ever drifts from the rules, say "Re-read CLAUDE.md and follow it."
7. Keep real phishing samples in `samples/` (gitignored). Tests use only synthetic, harmless fixtures.

Claude Code documentation: https://docs.claude.com/en/docs/claude-code/overview

## Phase overview

| Phase | What it builds |
|---|---|
| 0 | Project setup, data models, rules, test fixtures |
| 1 | Email and file input, parsing |
| 2 | Header analysis (SPF, DKIM, DMARC, alignment, ARC) |
| 3 | Sender and domain analysis (lookalikes, identity binding) |
| 4 | External API clients (cache, rate limits) |
| 5 | URL analysis |
| 6 | Attachment analysis |
| 7 | Hidden artifacts |
| 8 | Body tone analysis |
| 9 | IOC extraction and MITRE ATT&CK mapping |
| 10 | Scoring engine, pipeline, CLI |
| 11 | Report generation |
| 12 | Backend API |
| 13 | User interface |
| 14 | Evaluation |
| 15 | Docker, CI, documentation |
| 16 | Optional: mailbox automation and response actions |

---

# Phase 0: Project setup

### P0.1 Project scaffold

```
We are building "PhishLens", an automated phishing email analysis tool in Python 3.11. A user uploads an email (.eml/.msg) or a single suspicious file, and the tool runs header, sender/domain, body tone, URL, attachment and hidden-artifact analysis, then produces a verdict (Clean / Suspicious / Malicious), an IOC table, MITRE ATT&CK mapping, and an HTML/PDF report, through a CLI, a FastAPI backend and a Streamlit UI.

Create only the scaffold, no analysis logic:

Folders:
  phishlens/ingest/  phishlens/parser/  phishlens/analyzers/  phishlens/enrichment/
  phishlens/ioc/  phishlens/mapping/  phishlens/scoring/  phishlens/reporting/templates/
  api/  ui/  data/  scripts/  tests/fixtures/  samples/  quarantine/  reports/
Add __init__.py files and an empty phishlens/pipeline.py.

pyproject.toml with dependencies: pydantic, pydantic-settings, dnspython, pyspf, dkimpy, checkdmarc, authres, tldextract, rapidfuzz, httpx, beautifulsoup4, python-magic, extract-msg, oletools, msoffcrypto-tool, pypdf, pefile, LnkParse3, yara-python, pyzbar, Pillow, iocextract, stix2, mitreattack-python, jinja2, weasyprint, fastapi, uvicorn, python-multipart, streamlit, redis, rq, sqlmodel, typer, rich.
Dev dependencies: pytest, pytest-asyncio, respx, ruff.

.gitignore: .env, samples/, quarantine/, reports/, cache files (*.sqlite), __pycache__, .venv.
.env.example with: VIRUSTOTAL_API_KEY, ABUSECH_API_KEY, GOOGLE_SAFEBROWSING_API_KEY, URLSCAN_API_KEY, ABUSEIPDB_API_KEY, HYBRID_ANALYSIS_API_KEY, CAPE_BASE_URL, LLM_API_KEY, UPLOAD_FILES_TO_VT=false, PHISHLENS_API_KEY, REDIS_URL, DATABASE_URL, TRUSTED_AUTHSERV_IDS, TRUSTED_INTERNAL_HOSTS, TRUSTED_ARC_SEALERS.
```

**Done when:** `pip install -e .[dev]` works, `pytest` runs with zero tests, `ruff check .` passes.

### P0.2 Shared data models

```
Create phishlens/models.py with pydantic v2 models. These are the contracts every module uses, so add clear docstrings.

- Address: display_name, address, domain, org_domain (registered domain)
- ReceivedHop: from_host, by_host, ip, timestamp, raw
- UrlRef: url, visible_text, source (text_body / html_href / html_src / form_action / attachment / qr_code / artifact)
- Attachment: filename, declared_type, detected_type, size, data (bytes, excluded from JSON), md5, sha1, sha256, parent (for files from archives), depth
- ParsedEmail: headers (ordered list of name/value pairs keeping duplicates), from_addrs (list), reply_to, return_path, sender, to, cc, subject, date, message_id, received_chain, auth_results_headers, text_body, html_body, urls, attachments, inline_images, nested_emails, parse_warnings, raw_bytes (excluded from JSON), sha256
- Finding: id (stable snake_case, e.g. "spf_pass_unaligned"), module, title, description, severity (info/low/medium/high/critical), score (int), evidence (dict), mitre (list of technique IDs)
- AnalyzerResult: module, findings, raw (dict for report tables), extracted_urls (list[UrlRef]), errors, skipped (bool), duration_ms
- IOC: type (domain/ip/url/email/md5/sha1/sha256/filename), value, defanged, source_module, verdict, context
- MitreTechnique: id, name, tactics, url, triggered_by (finding ids)
- Verdict: label, total_score, confidence, module_scores (dict), top_findings, overrides_applied
- AnalysisReport: case_id, case_type ("email" or "file"), created_at, email (ParsedEmail summary without raw bytes, optional), file_info (optional), results (dict module -> AnalyzerResult), iocs, mitre, verdict, services_used, services_not_configured, tool_version

Write tests that build each model and serialize an AnalysisReport to JSON without bytes fields.
```

**Done when:** tests pass and JSON output contains no raw bytes.

### P0.3 Config and CLAUDE.md

```
1. Create phishlens/config.py using pydantic-settings, loading all .env.example values with safe defaults. Provide a get_settings() cached function. API keys are optional; a missing key disables that service.

2. Create CLAUDE.md in the repo root with:
   - Project purpose (one paragraph) and the folder structure
   - Analyzer contract: every analyzer exposes `async def analyze(email: ParsedEmail) -> AnalyzerResult`, never raises, puts errors in AnalyzerResult.errors, and returns URLs it discovers in extracted_urls
   - All external HTTP/DNS calls go through phishlens/enrichment (or the cached DNS helper) with caching and rate limiting
   - SAFETY RULES: never execute, open, render or fetch attachments or URLs on the host; never upload files to third parties unless UPLOAD_FILES_TO_VT=true; never log API keys; defang malicious values in all outputs
   - Finding IDs are stable snake_case strings because scoring weights and MITRE rules reference them
   - Data files (brand registry, lexicons, weights, MITRE rules) are YAML in data/ or the module folder, never hard-coded
   - Conventions: type hints everywhere, ruff clean, pytest test for every module, all network mocked in tests (respx for HTTP, monkeypatch for DNS), synthetic harmless fixtures only
   - Commands: install, test, lint, run CLI, run API, run UI
```

**Done when:** `CLAUDE.md` exists and `get_settings()` loads without a `.env` file.

### P0.4 Synthetic test fixtures

```
Create scripts/make_fixtures.py that generates harmless synthetic .eml files into tests/fixtures/ using Python's email library, and run it. Each fixture gets a matching expected-label entry in tests/fixtures/labels.yaml.

Fixtures:
1. clean_newsletter.eml: aligned headers, normal content
2. spoof_unaligned.eml: From microsoft.com, Return-Path zetatech.xyz, Authentication-Results showing spf=pass for zetatech.xyz
3. display_name_trick.eml: From: "ceo@company.com" <attacker@evil-example.net>
4. duplicate_from.eml: two From headers
5. link_mismatch.eml: HTML link text shows paypal.com, href goes to paypal-secure-login.example
6. lookalike_domain.eml: from micros0ft-support.example with urgent password reset text
7. zip_attachment.eml: zip containing a harmless text file
8. password_zip.eml: encrypted zip with "Password: 4455" in the body
9. double_extension.eml: attachment named invoice.pdf.exe (harmless bytes)
10. html_smuggling.eml: HTML attachment containing a Blob + download JavaScript pattern (non-functional)
11. tracking_pixel.eml: 1x1 remote image and hidden text
12. qr_code.eml: inline PNG with a QR code of http://phish-test.example/login
13. forwarded_nested.eml: message/rfc822 attachment containing spoof_unaligned.eml
14. eicar_attachment.eml: attachment containing the standard EICAR test string

Use .example and reserved domains so nothing points to real sites.
```

**Done when:** all 14 fixtures exist and open correctly in a mail client or text editor.

---

# Phase 1: Input and parsing

### P1.1 Email loader

```
Implement phishlens/ingest/loader.py:
- load_input(path_or_bytes, filename=None) -> ("email", raw_bytes) or ("file", raw_bytes)
- Detect .eml by content (RFC 822 headers at the start), .msg by OLE signature. Anything else is treated as a standalone file.
- Convert .msg to raw RFC 822 bytes using extract-msg (keep headers, bodies and attachments). If the .msg has no transport headers, add a parse warning.
- Enforce a max size from config (default 25 MB).
Tests with fixtures and a generated .msg if possible (otherwise mock extract-msg).
```

**Done when:** every fixture loads as "email" and a random binary loads as "file".

### P1.2 Header and address parsing

```
Implement phishlens/parser/headers.py:
- Parse with email.message_from_bytes(policy=policy.default).
- Keep ALL headers in original order including duplicates.
- Decode encoded-word headers safely; never crash on bad encoding (record a parse warning).
- Parse From, Reply-To, Sender, Return-Path, To, Cc into Address objects with org_domain via tldextract.
- Warnings for: multiple From headers, multiple addresses in one From, a display name that contains an email address, empty or missing From.
Tests on fixtures 2, 3 and 4.
```

**Done when:** the display-name trick and duplicate From produce warnings.

### P1.3 Received chain

```
Implement phishlens/parser/received.py:
- Parse Received headers into ReceivedHop objects ordered oldest to newest.
- Extract IPv4/IPv6 addresses from bracketed parts, host names, and timestamps.
- Helper originating_external_ip(chain, trusted_internal_hosts) returning the first hop outside our own infrastructure, ignoring private/reserved IPs.
- Warnings for timestamps out of order and hops with no parsable IP.
Tests with synthetic Received chains including private IPs and IPv6.
```

**Done when:** the originating IP is correct for all test chains.

### P1.4 Bodies and URL extraction

```
Implement phishlens/parser/body.py:
- Extract text/plain and text/html bodies across multipart/alternative and multipart/mixed, handling charsets, quoted-printable and base64.
- If only HTML exists, derive text with BeautifulSoup (never render it).
- Extract UrlRefs from the text body (regex) and HTML (a href with visible text, img/script src, form action, meta refresh). Normalize and deduplicate but keep all sources for each URL.
Tests on fixtures 1 and 5 (the link mismatch must keep visible text and href).
```

**Done when:** fixture 5 yields one UrlRef with visible text "paypal.com" and the fake href.

### P1.5 Attachment and nested email extraction

```
Implement phishlens/parser/attachments.py:
- Extract all attachments and inline parts into Attachment objects with hashes (md5, sha1, sha256) and declared type.
- message/rfc822 parts are parsed recursively into nested_emails (max depth 3).
- Inline images go into inline_images (still hashed).
- Assemble everything in phishlens/parser/__init__.py as parse_email(raw_bytes) -> ParsedEmail, including the email's own sha256.
Archive unpacking is NOT done here (that is Phase 6).
Tests on fixtures 7, 12, 13 and 14.
```

**Done when:** `parse_email` returns a complete `ParsedEmail` for every fixture without errors.

---

# Phase 2: Header analysis

### P2.1 DNS helper and trusted Authentication-Results

```
1. phishlens/enrichment/dns.py: async cached DNS helper (dnspython) for TXT, MX, A records with timeout, in-memory + SQLite cache, and errors returned as values (not raised).
2. phishlens/analyzers/header.py (start it): parse Authentication-Results headers with authres. Trust only those whose authserv-id is in TRUSTED_AUTHSERV_IDS. Any other Authentication-Results header creates a "forged_auth_results_header" finding (medium) with the header in evidence.
Tests with monkeypatched DNS and fixture 2.
```

**Done when:** an Authentication-Results header from an untrusted authserv-id is flagged.

### P2.2 SPF verification

```
Add SPF to the header analyzer:
- Take the originating external IP (P1.3) and the Return-Path domain (fallback: HELO domain).
- Evaluate with pyspf using the DNS helper where possible.
- Record result (pass/fail/softfail/neutral/none/temperror/permerror), the SPF-authenticated domain, and the IP in raw["spf"].
- Findings: spf_fail, spf_softfail, spf_none, spf_error.
Tests with mocked SPF records for pass, fail and softfail.
```

**Done when:** raw["spf"] shows the authenticated domain for each test.

### P2.3 DKIM verification and signature quality

```
Add DKIM to the header analyzer:
- Verify every DKIM-Signature with dkimpy (DNS lookups through our helper/mocks).
- For each signature record: d= domain, selector, valid, h= header list, l= present, t= timestamp, x= expiry.
- Findings: dkim_invalid, dkim_none, dkim_body_length_tag (l= present), dkim_unsigned_critical_headers (From/Subject/To missing from h=), dkim_expired_or_old (possible replay; age threshold in config).
Tests: generate a test key pair in the test, sign a message, verify pass; tamper the body, verify fail; sign with l= and check the finding.
```

**Done when:** pass, fail and quality findings are all covered by tests.

### P2.4 DMARC policy and alignment (core mechanism)

```
Add DMARC to the header analyzer:
- Fetch the DMARC record for the From org domain (fall back to organizational domain rules). Record p, sp, adkim, aspf, pct in raw["dmarc"].
- Compute alignment ourselves: relaxed = org domains match, strict (adkim/aspf=s) = exact match.
  spf_aligned, dkim_aligned (any VALID signature aligned), dmarc_pass = spf_aligned or dkim_aligned.
  auth_but_unaligned = (spf passed or any valid DKIM) and not dmarc_pass.
- Findings: spf_pass_unaligned / dkim_pass_unaligned (HIGH), auth_but_unaligned (CRITICAL, regardless of DMARC policy), dmarc_fail, dmarc_none_record, dmarc_policy_none (low).
- raw["auth_summary"]: a table with each mechanism, result, authenticated domain, aligned yes/no.
Tests: fully aligned pass, the zetatech.xyz vs microsoft.com case, p=none spoof, strict alignment with a subdomain.
```

**Done when:** fixture 2 produces `auth_but_unaligned` as critical.

### P2.5 ARC, ESPs and header anomalies

```
Finish the header analyzer:
- data/esp_domains.yaml: common ESP DKIM/Return-Path domains (sendgrid.net, mailchimpapp.net, mcsv.net, amazonses.com, mailgun.org, sparkpostmail.com, etc.). If the only passing domain is an ESP unaligned with From, add finding esp_unaligned naming the ESP.
- ARC: verify with dkimpy. If SPF/DKIM fail but a valid ARC chain is sealed by a TRUSTED_ARC_SEALERS domain, downgrade those findings to low and add arc_trusted_forward (info).
- Findings from parser warnings: multiple_from_headers, display_name_contains_address, received_chain_anomaly.
- Final raw["header_verdict"] using this matrix: aligned pass = ok; pass but unaligned = spoofing; fail = high risk (higher if dmarc p=none let it through); fail + trusted ARC = likely forward.
Tests for each branch.
```

**Done when:** all header tests pass and the analyzer never raises on any fixture.

---

# Phase 3: Sender and domain analysis

### P3.1 Reference data

```
Create YAML data files with a loader in phishlens/data_loader.py (cached):
- data/brand_registry.yaml: ~30 commonly impersonated brands (Microsoft, Google, Apple, Amazon, PayPal, Netflix, DHL, FedEx, LinkedIn, Facebook/Meta, Instagram, WhatsApp, Adobe, DocuSign, Dropbox, SBI, HDFC Bank, ICICI Bank, Axis Bank, Paytm, PhonePe, India Post, Income Tax Department, etc.). Each: name, keywords/variants, legitimate_domains, esp_domains. Plus an "organization" section for the user's own domains.
- data/free_webmail.yaml: gmail.com, outlook.com, hotmail.com, yahoo.com, proton.me, etc.
- data/risky_tlds.yaml, data/shorteners.yaml.
Add a comment at the top of each file explaining how to extend it.
```

**Done when:** the loader returns validated objects and tests check the files parse.

### P3.2 Domain consistency and display-name spoofing

```
Start phishlens/analyzers/domain.py:
- Compare org domains of From, Return-Path, Reply-To, Sender. Findings: returnpath_mismatch, replyto_mismatch, replyto_free_webmail (high when From is a corporate domain).
- Display-name spoofing: brand keyword in display name while the From domain is free webmail or not a legitimate brand domain → display_name_brand_spoof (high).
raw["domain_table"] for the report.
Tests with fixtures and synthetic addresses.
```

**Done when:** `"PayPal Security" <x@gmail.com>` is flagged.

### P3.3 Lookalike domain detection

```
Add lookalike detection to the domain analyzer, as a reusable function check_lookalike(domain) -> list of matches (also used by the URL analyzer):
- Damerau-Levenshtein distance (rapidfuzz) against all brand legitimate domains, comparing registered-domain labels
- Homoglyph/confusable normalization and IDN/punycode (xn--) decoding
- Combosquatting: brand keyword inside another domain (microsoft-support-login.example)
- TLD swap: same label, different TLD
- Exclude exact legitimate domains
Findings: lookalike_domain (high), punycode_domain (medium, high if it decodes to a brand lookalike).
Tests: micros0ft.com, paypa1.com, an xn-- Cyrillic "apple", paypal-secure-login.net, microsoft.com (no finding).
```

**Done when:** every lookalike test case is detected with the matched brand.

### P3.4 Identity binding

```
Add identity binding to the domain analyzer, exposed as bind_identity(claimed_brands, authenticated_domains) -> list[Finding]:
- Claimed brands come from: display name, lookalike matches, subject. (The tone analyzer will call this later with brands found in the body.)
- Authenticated domains come from the header analyzer's raw["auth_summary"] (the aligned authenticated domain, else the From domain marked as unauthenticated).
- If a claimed brand's legitimate_domains do not include the authenticated org domain → brand_impersonation (high; critical if the domain is also a lookalike or newly registered). Evidence: claimed brand, where it was claimed, authenticated domain, brand's legitimate domains.
Note: the domain analyzer needs header results, so accept an optional context dict with previous results; the pipeline (Phase 10) will pass it.
Tests: lookalike domain with fully passing auth is still flagged; genuine microsoft.com mail is not.
```

**Done when:** fixture 6 produces `brand_impersonation`.

### P3.5 Domain age and MX

```
Finish the domain analyzer:
- Domain age via the RDAP client (phishlens/enrichment/rdap.py, create a minimal version now with caching; Phase 4 will align it with the base client). Use rdap.org bootstrap. Findings: domain_age_under_7_days (critical), under_30_days (high), under_180_days (low). RDAP unavailable → error, not a finding.
- No MX record for the From domain → from_domain_no_mx (medium).
- Apply to From, Return-Path and Reply-To domains (deduplicated).
Tests with respx-mocked RDAP responses.
```

**Done when:** the domain analyzer passes all tests and never raises.

---

# Phase 4: External API clients

### P4.1 Base client, cache and rate limiting [PLAN FIRST]

```
Implement phishlens/enrichment/base.py:
- Async httpx client wrapper with per-service token-bucket rate limiting (limits in config), retries with exponential backoff for 429 and 5xx, and timeouts.
- SQLite cache: key = service + normalized query, TTL per service (default 24h), stores normalized results.
- Missing API key → returns status "not_configured" without any network call.
- Normalized EnrichmentResult: service, query, status (malicious/suspicious/clean/unknown/error/not_configured), detections (int), total_engines, details (dict), cached (bool), link (report URL if any).
- Never log API keys.
Refactor the RDAP client from P3.5 to use it.
Tests: cache hit, 429 retry, missing key, timeout.
```

**Done when:** base tests pass and RDAP uses the base client.

### P4.2 VirusTotal client

```
Implement phishlens/enrichment/virustotal.py (API v3): url lookup (base64url URL id), file hash lookup, domain lookup, IP lookup, and file upload only if UPLOAD_FILES_TO_VT=true. Map last_analysis_stats to the normalized status (malicious if ≥ threshold engines, configurable). Include the GUI link.
Tests with respx: malicious, clean, not found (unknown), 429.
```

**Done when:** all four lookup types are tested.

### P4.3 abuse.ch and Google Safe Browsing

```
Implement:
- phishlens/enrichment/abusech.py: URLhaus URL lookup, MalwareBazaar hash lookup, ThreatFox IOC search, all using one Auth-Key.
- phishlens/enrichment/safebrowsing.py: v4 threatMatches:find with batching (up to 500 URLs per request).
Tests with respx for hits and misses.
```

**Done when:** batch lookups and single lookups are tested.

### P4.4 urlscan.io and AbuseIPDB

```
Implement:
- phishlens/enrichment/urlscan.py: submit with visibility from config (default "unlisted"), poll result with backoff (max wait configurable), return verdict, final URL, redirect chain, page title, screenshot URL, and whether a login form was detected if available. Search existing scans first to avoid duplicate submissions.
- phishlens/enrichment/abuseipdb.py: IP check returning abuse confidence score, ISP, country, usage type.
Tests with respx including polling.
```

**Done when:** submission, polling and existing-scan reuse are tested.

### P4.5 Sandbox clients and lookup order

```
Implement:
- phishlens/enrichment/sandbox.py: abstract SandboxClient with submit(file) and get_report(id) returning SandboxReport (verdict, score, processes, network domains/IPs/URLs, dropped file hashes, signatures). Implementations: HybridAnalysisClient and CapeClient (base URL from config). Neither is used unless configured.
- phishlens/enrichment/lookup.py: helpers url_reputation(url) and hash_reputation(sha256) that query services in order (free/generous first: Safe Browsing → URLhaus → VirusTotal for URLs; MalwareBazaar → VirusTotal for hashes), stop early on a confident malicious result, and return all results.
Tests for lookup order and early stopping.
```

**Done when:** VirusTotal is only called when the earlier services return unknown.

---

# Phase 5: URL analysis

### P5.1 Static URL checks

```
Implement phishlens/analyzers/urls.py (static part, no network):
- Input: email.urls plus any extra UrlRefs passed in by the pipeline.
- Findings per URL: link_text_mismatch (visible domain ≠ href domain), ip_address_url, url_shortener, at_sign_in_url, excessive_subdomains, brand_in_unrelated_domain (use check_lookalike from P3.3), risky_tld, credential_keywords (login/verify/secure/update/account), data_or_javascript_uri, punycode_url.
- Skip well-known safe domains from a small allowlist (data/url_allowlist.yaml) for reputation lookups, but still apply static checks.
raw["urls"]: one row per URL with defanged URL, visible text, source, static flags.
Tests with fixture 5 and synthetic URLs.
```

**Done when:** fixture 5 produces `link_text_mismatch` and `brand_in_unrelated_domain`.

### P5.2 URL reputation

```
Add reputation to the URL analyzer:
- Use lookup.url_reputation for each unique URL (concurrently, respecting rate limits).
- Submit to urlscan.io only when still unknown and not allowlisted. NEVER fetch URLs from the host.
- Findings: url_known_malicious (critical), url_suspicious_reputation (medium), urlscan_login_page_on_unrelated_domain (high), redirect_to_different_domain (medium).
- Add reputation results, final URL and screenshot link to raw["urls"].
Tests with mocked lookup helpers.
```

**Done when:** a mocked malicious URL produces a critical finding and all services "not_configured" still returns a valid result.

---

# Phase 6: Attachment analysis

### P6.1 Archive unpacking, identification and filename tricks [PLAN FIRST]

```
Start phishlens/analyzers/attachments.py:
- Unpack archives (zip, 7z via py7zr, tar, gz, iso via pycdlib; add dependencies) recursively with limits from config: depth 3, 100 files, 200 MB total, per-file timeout. Limit breaches → archive_limit_exceeded (medium, possible zip bomb).
- Password-protected archives: extract candidate passwords from the email body (regex for "password", "pass", "pwd", "code" followed by a token) and try them. Findings: encrypted_archive_password_in_body (high), encrypted_archive_unopened (high).
- Real type with python-magic. Findings: type_mismatch (declared/extension vs real), double_extension, rtlo_filename (U+202E), whitespace_padded_extension, high_risk_file_type (list in config: exe, scr, js, jse, vbs, hta, lnk, iso, img, vhd, one, html, htm, svg, docm, xlsm, pptm, bat, cmd, ps1, msi, jar).
- Hash every file including unpacked ones (parent recorded).
Tests with fixtures 7, 8 and 9.
```

**Done when:** the password zip is opened with "4455" and the double extension is flagged.

### P6.2 Hash reputation

```
Add hash reputation to the attachment analyzer:
- For each file, lookup.hash_reputation(sha256).
- Known malicious → attachment_known_malicious (critical) with detection counts and malware family names; skip static and sandbox stages for that file.
raw["attachments"]: one row per file (filename, parent, real type, size, hashes, reputation per service).
Tests with fixture 14 (EICAR) and a mocked malicious MalwareBazaar result.
```

**Done when:** EICAR with mocked reputation is critical and other stages are skipped for it.

### P6.3 Office and RTF static analysis

```
Add static analysis for Office and RTF files:
- olevba: macros present, auto-exec triggers, suspicious keywords (Shell, CreateObject, URLDownloadToFile, WScript, PowerShell), IOCs found in macros. mraptor verdict. XLM macro detection.
- oleobj: embedded objects and external links.
- OOXML: check .rels files for external targets, especially attachedTemplate (remote template injection).
- Encrypted Office docs: try msoffcrypto-tool with body passwords; note if still encrypted.
- rtfobj for RTF embedded objects.
Findings: office_macro_autoexec (high), office_macro_suspicious_calls (high), xlm_macro (high), remote_template_injection (high), office_external_link (medium), rtf_embedded_object (medium), encrypted_office_document (medium).
URLs found go to extracted_urls with source "attachment".
Tests: build a docx/docm with python-docx or raw zip manipulation containing a harmless macro-like vbaProject stub if feasible; otherwise mock olevba output. Build a docx with an external attachedTemplate relationship.
```

**Done when:** remote template injection and macro findings are tested.

### P6.4 PDF, HTML and SVG static analysis

```
Add static analysis for PDF, HTML and SVG:
- PDF (pypdf, no rendering): JavaScript, /OpenAction, /AA, /Launch, /EmbeddedFile, /URI links; extract embedded images and decode QR codes with pyzbar.
- HTML/SVG: HTML smuggling patterns (new Blob, msSaveOrOpenBlob, URL.createObjectURL + download attribute, large atob strings), forms posting to external domains, password input fields, script in SVG, obfuscated JS (long base64/hex strings, eval, unescape).
Findings: pdf_javascript (high), pdf_auto_action (high), pdf_launch_action (critical), pdf_embedded_file (medium), html_smuggling (critical), credential_form_attachment (high), svg_script (high), obfuscated_script (medium).
All links/QR URLs → extracted_urls.
Tests with fixture 10 and generated PDFs.
```

**Done when:** fixture 10 produces `html_smuggling`.

### P6.5 Executables, shortcuts, images and YARA

```
Add static analysis for remaining types:
- PE (pefile): suspicious imports, high section entropy (packer), missing or invalid signature presence, unusual compile time.
- LNK (LnkParse3): target path and arguments; flag powershell, mshta, cmd /c, rundll32, regsvr32, wscript, remote paths.
- Images: QR decoding (pyzbar + Pillow) → extracted_urls.
- YARA: compile all rules in data/yara/ once (cached) and scan every file; add data/yara/README.md explaining how to download community rules (e.g. YARA-Forge) and a tiny example rule for tests.
Findings: pe_executable_attachment (high), pe_packed (medium), lnk_suspicious_command (critical), qr_code_url (medium), yara_match (severity from rule meta, default high).
Tests with the example YARA rule and a synthetic LNK if possible (else mock).
```

**Done when:** YARA matching and QR extraction from fixture 12's image work.

### P6.6 Sandbox gating and quarantine

```
Finish the attachment analyzer:
- Sandbox only when: a sandbox is configured AND hash reputation is unknown AND (high_risk_file_type OR any medium+ static finding). Otherwise record why it was skipped.
- Map SandboxReport to findings: sandbox_malicious (critical), sandbox_suspicious (medium). Network IOCs and dropped hashes go into raw for IOC extraction. A clean sandbox result adds info only and never removes static findings.
- Quarantine: store each analyzed file in quarantine/<case_or_email_sha256>/ inside a zip with password "infected".
- Expose analyze_files(files) for standalone file cases (Phase 10).
Tests with a mocked sandbox client.
```

**Done when:** the attachment analyzer passes all tests and quarantine zips are created.

---

# Phase 7: Hidden artifacts

### P7.1 Hidden artifacts analyzer

```
Implement phishlens/analyzers/artifacts.py:
- Tracking pixels: img with width/height ≤ 1, display:none or visibility:hidden images, remote images with long unique ID parameters. Record tracking domains in raw.
- Hidden text and filter evasion: display:none / visibility:hidden / font-size:0 / color matching background text blocks, zero-width Unicode characters, large random filler text, big differences between text/plain and HTML content.
- Obfuscation: base64 or HTML-entity-encoded links, script tags in the email body, meta refresh.
- Malformed headers: missing Message-ID or Date, Date in the future or > 30 days old, Message-ID domain unrelated to From domain, suspicious X-Mailer (data/suspicious_mailers.yaml).
- QR codes in inline_images → extracted_urls.
Findings with stable IDs for each check.
Tests with fixtures 11 and 12 plus small synthetic HTML snippets.
```

**Done when:** fixture 11 produces tracking pixel and hidden text findings.

---

# Phase 8: Body tone analysis

### P8.1 Rule-based tone analysis

```
Implement phishlens/analyzers/tone.py (rule layer):
- data/lexicons/: urgency.yaml, fear.yaml, greed.yaml, authority.yaml, credential_request.yaml, payment_request.yaml, secrecy.yaml, generic_greeting.yaml. Each has phrases and regex patterns. Include common English phishing phrases and a few Hindi/Hinglish examples.
- Normalize text (lowercase, collapse whitespace, remove zero-width characters) from subject + text body.
- Per-category matches with snippet context; per-category score caps.
- Brand mentions: find brand keywords from the registry in subject and body and call bind_identity from P3.4 (using header context when provided).
Findings: tone_urgency, tone_fear, tone_greed, tone_authority, credential_request, payment_request, secrecy_request, generic_greeting.
raw["highlights"]: list of (category, phrase, start, end) for UI highlighting.
Tests with sample texts.
```

**Done when:** fixture 6 produces urgency and credential_request findings.

### P8.2 ML and LLM classifiers

```
Add an optional ML layer to the tone analyzer:
- ToneClassifier interface returning probability and an optional rationale.
- LocalTransformerClassifier: load a Hugging Face model from TONE_MODEL_PATH if present (transformers + torch as an optional dependency group "ml"); disabled gracefully when missing.
- LLMClassifier (off by default): call an LLM API with a strict JSON output schema {urgency, greed, fear (0-10 each), impersonated_brand, requested_action, rationale}; validate with pydantic; retry once on invalid JSON; log a warning in raw that content was sent to a third party.
- Findings: ml_phishing_probability_high (score scaled by probability) and llm_impersonation (if a brand is named).
Tests with mocked classifiers only.
```

**Done when:** the tone analyzer works with no model configured and with each mocked classifier.

### P8.3 Training script

```
Create scripts/train_tone_model.py:
- Input CSV with columns text,label (1 = phishing, 0 = legitimate).
- Clean text (strip HTML, normalize), stratified train/validation/test split.
- Fine-tune distilbert-base-uncased with the Hugging Face Trainer; configurable epochs, batch size, max length.
- Report precision, recall, F1 and a confusion matrix on the test split; save the model and a metrics.json to models/tone/.
- scripts/prepare_datasets.md: instructions for building the CSV from public corpora (e.g. Nazario phishing corpus, SpamAssassin, Enron ham), including de-duplication and balancing.
```

**Done when:** the script runs on a tiny synthetic CSV end to end.

---

# Phase 9: IOCs and MITRE ATT&CK

### P9.1 IOC extraction

```
Implement phishlens/ioc/extract.py:
- Collect IOCs from ParsedEmail and all AnalyzerResults: From/Reply-To/Return-Path addresses and domains, originating and external Received IPs (skip private and trusted internal), all URLs and their domains, tracking domains, attachment filenames and hashes (md5/sha1/sha256), sandbox network IOCs and dropped hashes, URLs from attachments and QR codes.
- Use iocextract on free text fields in raw results as a safety net.
- Deduplicate by (type, value); merge sources and contexts; set verdict from related findings/reputation (malicious/suspicious/unknown/clean).
- Defang: hxxp/hxxps, [.] in domains and IPs, [@] in emails.
Tests on fixtures 2, 5 and 14.
```

**Done when:** IOCs are deduplicated and every value has a defanged form.

### P9.2 IOC exporters

```
Implement phishlens/ioc/export.py:
- to_csv (type, value, defanged, verdict, source, context)
- to_json
- to_stix_bundle: STIX 2.1 with the stix2 library: Indicator objects with proper patterns for each IOC type (domain-name, ipv4-addr/ipv6-addr, url, email-addr, file hashes), a Report object referencing them, and labels from verdicts. Only malicious/suspicious IOCs become Indicators; others become Observed Data (or are excluded, configurable).
Tests: the STIX bundle parses back with stix2 and patterns are valid.
```

**Done when:** the STIX test passes.

### P9.3 MITRE ATT&CK mapping

```
Implement phishlens/mapping/:
- scripts/update_attack_data.py: download enterprise-attack.json from the official MITRE CTI GitHub repo into data/mitre/.
- mitre_rules.yaml mapping finding IDs to technique IDs, including at least:
  attachment_known_malicious, sandbox_malicious, office_macro_autoexec → T1566.001, T1204.002
  url_known_malicious, link_text_mismatch → T1566.002, T1204.001
  urlscan_login_page_on_unrelated_domain, credential_form_attachment → T1598.003
  brand_impersonation, display_name_brand_spoof → T1656
  lookalike_domain + domain_age_under_30_days → T1583.001
  double_extension → T1036.007; rtlo_filename → T1036.002
  office_macro_suspicious_calls → T1059.005
  remote_template_injection → T1221
  html_smuggling → T1027.006
  high_risk_file_type with iso/img/vhd → T1553.005
  obfuscated_script → T1027
- map_findings(findings) -> list[MitreTechnique] with names, tactics and URLs from the local ATT&CK data (mitreattack-python), grouped with the triggering findings. Support combination rules (all listed findings required).
- A test ensures every technique ID in the YAML exists in the ATT&CK data (skip if data not downloaded).
```

**Done when:** mapping tests pass on sample finding sets.

---

# Phase 10: Scoring, pipeline and CLI

### P10.1 Scoring engine [PLAN FIRST]

```
Implement phishlens/scoring/:
- weights.yaml: score per finding ID (fallback by severity: info 0, low 5, medium 15, high 30, critical 50), per-module caps, verdict thresholds for email cases (Clean < 30, Suspicious 30–59, Malicious ≥ 60) and separate thresholds for file cases, and override rules (e.g. attachment_known_malicious, url_known_malicious, sandbox_malicious, html_smuggling → Malicious; arc_trusted_forward reduces header penalties).
- RuleScorer.score(results, case_type) -> Verdict with total, module_scores, top 5 contributing findings, overrides applied, and confidence (share of modules completed without errors, reduced when key services were not configured).
- Scorer interface so a trained model can replace it via config (MLScorer placeholder that loads a scikit-learn model if present).
- scripts/export_features.py: turn saved AnalysisReports into a feature CSV (one column per finding ID, module scores, label if known).
Tests: thresholds, caps, overrides, confidence.
```

**Done when:** scoring tests pass for all override rules.

### P10.2 Email pipeline orchestrator

```
Implement analyze_email(raw_bytes, progress_cb=None) in phishlens/pipeline.py:
1. parse_email
2. header analyzer first (the domain analyzer needs its results), then run domain, tone, artifacts and attachments concurrently with asyncio.gather, passing a context dict containing header results
3. collect extracted_urls from attachments and artifacts, then run the URL analyzer on email.urls + extracted URLs
4. nested emails (message/rfc822): analyze recursively (depth ≤ 2) and include their findings with a "nested:" prefix in evidence
5. IOC extraction → MITRE mapping → scoring
6. build AnalysisReport with services_used / services_not_configured
Per-analyzer timeouts from config; a failing analyzer records an error and the pipeline continues. progress_cb(module, status) is called with pending/running/done/error.
End-to-end tests on all fixtures with all network mocked, asserting labels from tests/fixtures/labels.yaml.
```

**Done when:** every fixture gets its expected verdict.

### P10.3 Standalone file pipeline

```
Implement analyze_file(raw_bytes, filename, progress_cb=None):
- Build a minimal context with the file as the only Attachment (hashes computed).
- Run the attachment analyzer (analyze_files), then the URL analyzer on extracted URLs, then IOC extraction, MITRE mapping and scoring with case_type "file" and file thresholds.
- Header, domain, tone and artifacts are marked skipped with the reason "not an email".
- If the uploaded file is actually an email (detected by the loader), route it to analyze_email instead.
- Add analyze_input(raw_bytes, filename) that routes automatically.
Tests: harmless text file (Clean), EICAR with mocked reputation (Malicious), zip containing the double-extension file.
```

**Done when:** file cases work end to end and email files uploaded as "files" are routed correctly.

### P10.4 CLI

```
Implement a Typer CLI (entry point "phishlens") with rich output:
- phishlens analyze <path> [--format json,html,pdf,csv,stix] [--out reports/] [--no-network]
  Auto-routes email vs file. Shows a live per-module progress display, then a summary panel: verdict (colored), score, confidence, top findings, IOC count, MITRE techniques.
- phishlens analyze-file <path> (forces file mode)
- phishlens check-config: which services are configured (never print key values)
--no-network disables all enrichment clients (useful for offline demos and tests).
Report output uses Phase 11; until then, write JSON only.
```

**Done when:** `phishlens analyze tests/fixtures/spoof_unaligned.eml` prints a Suspicious or Malicious verdict with reasons.

---

# Phase 11: Report generation

### P11.1 HTML report template

```
Implement phishlens/reporting/templates/report.html (Jinja2), self-contained with inline CSS, no external assets or scripts, print-friendly, clean professional design. Sections in order:
a. Header: PhishLens logo text, case ID, case type, timestamp, large verdict badge (green Clean / amber Suspicious / red Malicious), score out of 100, confidence
b. Executive summary (from P11.2)
c. Email overview: From (display + address), To, Subject, Date, Message-ID, Return-Path, Reply-To, originating IP (or file overview for file cases)
d. Header authentication: SPF/DKIM/DMARC table with result, authenticated domain, aligned yes/no, DMARC policy, ARC status, and the header verdict
e. Received chain table
f. Sender and domain: consistency table, lookalike matches, domain ages, identity binding (claimed vs authenticated)
g. Body analysis: tactics by category with quoted snippets
h. URLs table: defanged URL, visible text, source, per-service verdicts, final URL, screenshot link
i. Attachments table: filename, parent, real type, size, hashes, reputation, static findings, sandbox result
j. Hidden artifacts
k. IOC table (type, defanged value, verdict, source)
l. MITRE ATT&CK table (ID linked to attack.mitre.org, name, tactic, triggered by)
m. Score breakdown per module and full findings list (severity, title, evidence)
n. Recommended actions
o. Footer: tool version, services used / not configured, disclaimer that verdicts are automated
Sections with no data show "No findings". For file cases, email-only sections are replaced by one note explaining they were not run.
All malicious values are defanged plain text. Only MITRE links and screenshot links are clickable.
```

**Done when:** the template renders for a clean email, a malicious email and a file case.

### P11.2 Executive summary and recommendations

```
Implement phishlens/reporting/summary.py:
- build_summary(report) -> 3 to 5 plain-English sentences generated from the verdict and top findings using templates per finding ID (no LLM needed). Example: "The email claims to be from Microsoft, but it was authenticated by zetatech.xyz, a domain registered 4 days ago."
- build_recommendations(report) -> action list by verdict and findings (e.g. block sender domain and IOCs, search and remove from other mailboxes, reset credentials if the link was clicked, isolate host if the attachment was opened, report to the impersonated brand, no action for Clean).
Tests: summaries for fixtures 2, 6 and 14 mention the key evidence.
```

**Done when:** summaries read naturally and reference real evidence.

### P11.3 PDF and export bundle

```
Implement phishlens/reporting/generate.py:
- generate_report(report, formats, out_dir) -> dict of format -> path for: html, pdf (WeasyPrint from the same HTML, with page numbers and repeated table headers), json (full AnalysisReport), csv (IOCs), stix (bundle), and "zip" (all of the above in one archive).
- File names: <case_id>_<verdict>.<ext>.
Wire it into the CLI --format option.
Tests: every format is created; a check that the HTML contains no live http links other than attack.mitre.org and screenshot hosts.
```

**Done when:** `phishlens analyze <fixture> --format html,pdf,csv,stix` creates all files.

---

# Phase 12: Backend API

### P12.1 Database models

```
Implement api/db.py with SQLModel (SQLite by default, Postgres via DATABASE_URL):
- Case: id (short readable ID), created_at, case_type, original_filename, input_sha256, subject, sender, verdict, score, confidence, status (queued/running/done/error), error_message, report_json_path, report_files (JSON dict of format → path).
- Session helper and table creation on startup.
Tests with an in-memory SQLite database.
```

**Done when:** create, read, list and delete work in tests.

### P12.2 Job queue and progress

```
Implement api/worker.py with RQ + Redis:
- Job function run_analysis(case_id, stored_input_path, filename, mode) that calls analyze_input / analyze_file, writes per-module progress to Redis (hash progress:<case_id>), saves the AnalysisReport JSON, generates all report formats, and updates the Case row.
- Uploaded inputs are stored under quarantine/uploads/ (never in a web-served folder).
- Failures set status "error" with a message; partial reports are still saved when possible.
- A fake synchronous queue for tests.
Tests with the fake queue.
```

**Done when:** a job completes and progress shows every module as done.

### P12.3 API endpoints

```
Implement api/main.py with FastAPI:
- POST /api/analyze: upload .eml or .msg (max 25 MB) → {case_id}
- POST /api/analyze-file: upload one or more files of any type → [{case_id, filename}]
- POST /api/analyze-raw: JSON {raw_source} for pasted email source → {case_id}
- GET /api/cases/{id}/status: overall status + per-module progress
- GET /api/cases/{id}: full AnalysisReport JSON
- GET /api/cases/{id}/report?format=html|pdf|json|csv|stix|zip: file download
- GET /api/cases: paginated list, filters: verdict, case_type, date_from, date_to, q (subject/sender search)
- GET /api/stats: counts per verdict, cases per day (last 30 days)
- DELETE /api/cases/{id}: deletes the case, its reports and quarantined input
- GET /api/health: Redis and worker status, configured services (true/false only), tool version
Validate file types and sizes, return clear error messages.
Tests with TestClient for every endpoint.
```

**Done when:** all endpoint tests pass.

### P12.4 Security and deduplication

```
Harden the API:
- API key auth via X-API-Key header (PHISHLENS_API_KEY) on all endpoints except /api/health.
- CORS restricted to the UI origin from config.
- Deduplication: if input_sha256 already has a completed case, return it unless ?force=true.
- Upload filenames are sanitized; stored files use generated names.
- Rate limit uploads per client IP (simple in-memory limiter, configurable).
- Never return quarantined file contents through the API.
Tests for auth failure, dedup and force re-analysis.
```

**Done when:** unauthenticated requests are rejected and duplicate uploads return the existing case.

---

# Phase 13: User interface

### P13.1 UI foundation

```
Set up the Streamlit app in ui/ that talks ONLY to the FastAPI backend:
- ui/api_client.py: typed functions for every endpoint using httpx, API base URL and key from environment, friendly error handling (backend down, auth failed, file too large).
- .streamlit/config.toml: professional theme; consistent verdict colors (green Clean, amber Suspicious, red Malicious) defined once in ui/theme.py with helper components: verdict_badge, score_gauge, severity_pill, defanged_code (monospace with copy button).
- Multipage layout: Analyze, Case view, History, Settings. Sidebar with the PhishLens name, backend status indicator, and navigation.
- Never render any email HTML or attachment content in the UI; show sanitized text only.
```

**Done when:** the app starts and shows backend status from `/api/health`.

### P13.2 Analyze page

```
Build the Analyze page with three tabs:
1. "Analyze email": drag-and-drop uploader for .eml/.msg. Under it, an expandable "How do I get the email file?" section explaining: Gmail (three-dot menu → Download message → .eml), Outlook desktop (File → Save As, or drag the email to the desktop → .msg), Outlook on the web (download from the message options menu), Thunderbird (right-click → Save As). Add a note that screenshots, PDFs or copied text will not work because headers are needed, and that forwarding normally loses the original headers.
2. "Analyze file": uploader for any file type (multiple files allowed), with the note: "Only the file is analyzed. Upload the full email for header, sender and content checks."
3. "Paste email source": text area for raw source (e.g. Gmail "Show original").
After submission: a live progress list of modules (Parsing, Header, Sender & domain, Body tone, URLs, Attachments, Hidden artifacts, IOCs, MITRE mapping, Scoring, Report) with pending/running/done/error icons, polling /status every second. When done, switch to the Case view for that case. Multiple files show one progress card per file.
```

**Done when:** uploading each fixture leads to its case view with live progress along the way.

### P13.3 Case view page

```
Build the Case view page (case ID from query parameter or session state):
- Top section: large verdict badge, score gauge (0–100), confidence, case type, executive summary, and download buttons for HTML, PDF, JSON, IOC CSV, STIX and ZIP.
- Tabs: Overview | Headers | Sender & domain | Body | URLs | Attachments | Artifacts | IOCs | MITRE ATT&CK | All findings.
  - Overview: top 5 findings with severity pills and module score bar chart.
  - Headers: SPF, DKIM, DMARC cards showing result, authenticated domain and aligned/unaligned; ARC status; header verdict; Received chain table.
  - Sender & domain: consistency table, lookalike matches, domain ages, identity binding card (claimed brand vs authenticated domain).
  - Body: sanitized text with suspicious phrases highlighted by category color and a legend.
  - URLs: table with per-service verdicts; urlscan screenshots shown as thumbnails when available.
  - Attachments: table with type, hashes (copyable), reputation, static findings, sandbox result; archive contents shown as a tree.
  - IOCs: filterable table (by type and verdict) with copy buttons for defanged values.
  - MITRE ATT&CK: technique cards grouped by tactic, linking to attack.mitre.org.
  - All findings: sortable table with expandable evidence.
- For file cases, hide email-only tabs and show a note explaining why.
```

**Done when:** the case view shows every tab correctly for an email case and a file case.

### P13.4 History and Settings pages

```
Build:
- History page: summary metrics (total cases, % Malicious / Suspicious / Clean), a chart of verdicts over the last 30 days (from /api/stats), and a table of cases (date, case type, subject or filename, sender, verdict badge, score) with filters (verdict, case type, date range), search, pagination, click-to-open, and delete with confirmation.
- Settings page: configured services (from /api/health) with sign-up links for missing ones, worker and Redis status, current thresholds (read-only), tool version, and a short "How PhishLens works" explanation of the 7 analysis steps.
```

**Done when:** history filtering works and settings reflect the real configuration.

---

# Phase 14: Evaluation

### P14.1 Evaluation harness

```
Create scripts/evaluate.py:
- Input: a folder of emails and a labels CSV (filename, label phishing/legit, optional manual_verdict, notes).
- Options: --cached-only (no new API calls), --no-network, --limit N.
- Run analyze_input on each; treat Suspicious as phishing by default (configurable).
- Output: confusion matrix, precision, recall, F1, false positive rate, average processing time, per-module contribution (how often each module's findings appear in correct vs wrong verdicts), agreement rate with manual_verdict, and a list of misclassified emails with their top findings.
- Threshold tuning mode: try threshold pairs and show the precision/recall trade-off.
- Save an HTML evaluation report (charts as embedded PNGs with matplotlib) in reports/evaluation/.
```

**Done when:** the script runs on the fixtures and produces the HTML evaluation report.

---

# Phase 15: Deployment and documentation

### P15.1 Docker

```
Create Docker setup:
- Dockerfile (Python 3.11 slim) with system packages: libmagic, zbar, WeasyPrint dependencies (pango, cairo), yara.
- docker-compose.yml services: redis, api, worker, ui. Shared volumes: data (DB, reports), quarantine (worker and API only). The UI container has no access to quarantine.
- .env loaded by all services. Health checks for api and redis.
- `docker compose up` starts everything; the UI is on port 8501, API on 8000.
- Makefile shortcuts: make up, make down, make test, make lint, make fixtures.
```

**Done when:** `docker compose up` works and a fixture can be analyzed through the UI.

### P15.2 Continuous integration

```
Create .github/workflows/ci.yml:
- On push and pull request: set up Python 3.11, install system deps, install the project, run ruff and pytest (network fully mocked), and build the Docker image.
- Cache pip dependencies.
- Fail if any test tries real network access (use a pytest fixture that blocks sockets).
```

**Done when:** CI passes on GitHub.

### P15.3 README and architecture docs

```
Write documentation:
- README.md: one-line pitch ("Upload one email file and get a complete, explainable phishing investigation in a single report"), feature list mapped to the 7 analysis steps, what makes it different (identity binding, alignment recomputation, explainable scoring, analyst-ready IOC/MITRE/STIX output, free and self-hosted, privacy by default), architecture diagram in mermaid, quick start with Docker, API key sign-up list with links for each service and free-tier notes, how to export .eml/.msg from common mail clients, usage for UI/CLI/API, evaluation results section (placeholder table), safety notes, limitations (compromised legitimate accounts, no inline blocking, free-tier limits), roadmap, license.
- docs/ARCHITECTURE.md: each analyzer, the finding contract, scoring and overrides, the identity-binding mechanism with the verdict matrix, and the data files and how to extend them.
- docs/PROMPTS.md: this prompt guide.
```

**Done when:** a new user can install and run PhishLens from the README alone.

---

# Phase 16 (optional): Mailbox automation and response

### P16.1 Reporting mailbox ingestion

```
Implement phishlens/ingest/imap_poller.py and a worker entry point:
- Poll a dedicated reporting mailbox over IMAP (credentials from .env) on an interval.
- For each new report, extract the ORIGINAL email from a message/rfc822 attachment and analyze that (not the forward). If the user forwarded inline, analyze it but add a finding "forwarded_inline_headers_lost" and lower confidence.
- Record the reporter address on the Case; mark processed messages with a flag or move them to a folder.
- Same interface stubs for Gmail API and Microsoft Graph ingestion (implement later).
Tests with a mocked IMAP client.
```

**Done when:** a mocked mailbox with a forwarded fixture creates a case.

### P16.2 Response actions and audit log

```
Implement phishlens/response/ with each action behind a config flag (all off by default):
- Reply to the reporter with the verdict, a short plain-English explanation and next steps.
- Slack/Teams webhook alert for Suspicious and Malicious cases, with a link to the case in the UI.
- Microsoft Graph quarantine: move matching messages (by Message-ID) to a quarantine folder; requires explicit config and logs every action.
- Audit log table (timestamp, case, action, target, result) with an API endpoint and a UI section in the case view.
Tests with mocked SMTP, webhook and Graph calls.
```

**Done when:** every action is logged and nothing runs unless enabled in config.

---

## Final checklist

- [ ] All 14 fixtures give the expected verdicts
- [ ] Email upload, file upload and pasted source all work in the UI
- [ ] Reports download in HTML, PDF, JSON, CSV, STIX and ZIP
- [ ] Missing API keys never crash anything
- [ ] No attachment or URL is ever opened or fetched on the host
- [ ] Evaluation report generated on your manually labeled cases
- [ ] `docker compose up` works on a fresh machine
- [ ] README explains setup, usage, differences and limitations
