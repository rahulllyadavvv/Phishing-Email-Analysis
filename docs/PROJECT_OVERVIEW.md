# PhishLens: project overview

## 1. What it is

PhishLens is a self-hosted tool that investigates phishing emails, written in Python 3.11. You give
it a suspicious email (`.eml` or Outlook `.msg`) or any single file. It runs a **static**
investigation and returns:

- a **verdict**: Clean, Suspicious or Malicious, with a **0–100 score** and a **confidence** value;
- the **top reasons** behind the verdict, so every point on the score can be explained;
- a **defanged IOC table** (URLs, domains, IPs, emails, hashes, file names);
- a **MITRE ATT&CK mapping**;
- reports in **HTML, PDF, JSON, CSV, STIX 2.1 and ZIP**.

You can use it in three ways: a **Typer CLI**, a **FastAPI REST API** and a **Streamlit web UI**.
The UI talks only to the API. The codebase is about 14k lines of Python plus about 60 test files.

## 2. Tech stack

| Area | Libraries / tools |
|---|---|
| Core / config | `pydantic`, `pydantic-settings` (settings from `.env`), `pyyaml` (all tables live in YAML) |
| Email parsing | stdlib `email`, `extract-msg` (Outlook .msg), `beautifulsoup4` (HTML bodies) |
| Email authentication | `pyspf` (SPF), `dkimpy` (DKIM + ARC), `checkdmarc` (DMARC records), `authres` (Authentication-Results headers), `dnspython` |
| Domain checks | `tldextract`, `rapidfuzz` (Damerau-Levenshtein for lookalikes), a Unicode confusables map |
| Attachments | `python-magic` (libmagic), `oletools` + `msoffcrypto-tool` (Office macros), `pypdf`, `pefile` (Windows EXEs), `LnkParse3` (shortcut files), `py7zr`, `pyzipper`, `pycdlib` (ISO), `yara-python`, `pyzbar` + `Pillow` (QR codes) |
| IOCs / threat intel formats | `iocextract`, `stix2`, `mitreattack-python` |
| HTTP | `httpx` (async), with SQLite caching and token-bucket rate limits |
| Reports | `jinja2` templates, `weasyprint` (HTML → PDF) |
| Backend | `fastapi`, `uvicorn`, `python-multipart`, `sqlmodel` (SQLite case store), `redis` + `rq` (job queue) |
| Frontend / CLI | `streamlit`, `typer`, `rich` |
| Optional ML / LLM | `transformers` + `torch` (local tone model), `anthropic` (Claude second opinion) |
| Dev | `pytest`, `pytest-asyncio`, `respx` (HTTP mocks), `ruff`, `fakeredis`, Docker + Makefile, CI |

## 3. External APIs used

All of these are **optional and have free tiers**. A missing key only disables that service. Every
call goes through `phishlens/enrichment/`, which caches answers in SQLite (default 24 h),
rate-limits each service and retries with backoff.

| Service | Used for | Key |
|---|---|---|
| **VirusTotal** | file hash, URL, domain and IP reputation | `VIRUSTOTAL_API_KEY` |
| **abuse.ch** (MalwareBazaar + URLhaus) | known-malware hashes, known-malicious URLs | `ABUSECH_API_KEY` |
| **Google Safe Browsing** | phishing/malware URL lists | `GOOGLE_SAFEBROWSING_API_KEY` |
| **urlscan.io** | remote page scan (unlisted by default): final URL, screenshot, login-form detection | `URLSCAN_API_KEY` |
| **AbuseIPDB** | reputation of the sending IP | `ABUSEIPDB_API_KEY` |
| **Hybrid Analysis** | sandbox reports; uploads only if `UPLOAD_FILES_TO_HYBRID_ANALYSIS=true` | `HYBRID_ANALYSIS_API_KEY` |
| **CAPE** | your own self-hosted sandbox | `CAPE_BASE_URL` |
| **Claude (Anthropic)** | optional second opinion on tone/impersonation | `LLM_API_KEY` + `LLM_TONE_ENABLED=true` |
| **RDAP** (no key) | domain registration date (domain age) | — |
| **DNS** (no key) | SPF/DKIM/DMARC records, MX lookups (cached helper `enrichment/dns.py`) | — |

`phishlens check-config` shows which services are enabled. It never prints the keys.

## 4. How a check flows

```
Upload (.eml/.msg/file)
   │
   ▼
ingest/      → is it an email or a single file? size limits, .msg → RFC 822
   ▼
parser/      → ParsedEmail (headers, addresses, Received chain, text/HTML body, links, attachments)
   ▼
1. header analyzer        (runs first: the others need its auth results)
   ▼
2. domain analyzer  ─┐
3. tone analyzer    ─┤   domain → tone run in order;
4. artifacts        ─┤   artifacts and attachments run in parallel with them
5. attachments      ─┘
   ▼
6. urls analyzer          (runs last: collects every URL the others found,
   ▼                       including ones from HTML, attachments and QR codes)
7. nested emails          (attached/forwarded messages are analyzed recursively)
   ▼
IOC extraction + defang → MITRE mapping → scoring → reports
```

Every analyzer follows the same contract: `async def analyze(email) -> AnalyzerResult`.

- It **never raises**. Errors go into `result.errors`, and those errors lower the confidence value.
- Each analyzer has a timeout.
- Progress is reported per module, and the UI shows it live.

**How a request runs through the API:**

1. The upload is saved under `quarantine/uploads/<case id>/`.
2. A job is queued in Redis/RQ (or runs in-process with `JOB_QUEUE=sync`).
3. The worker runs the pipeline and stores the case in SQLite.
4. The UI polls `/api/cases/{id}/status`.

If the same input was already analyzed, the existing case is returned. Add `?force=true` to analyze
it again.

### What each step checks

**1. Header** (`analyzers/header.py`)

- It re-verifies **SPF** against the originating IP taken from the Received chain.
- It verifies **DKIM** signatures and their quality: the `l=` body-length tag, unsigned critical
  headers, old signatures.
- It verifies **ARC** chains.
- It **recomputes DMARC alignment** itself instead of trusting the `Authentication-Results`
  header, which an attacker can forge. Findings include `spf_fail`, `dmarc_fail`,
  `forged_auth_results_header`, and `auth_but_unaligned` (SPF or DKIM passed, but only for some
  other domain).
- It also detects bulk-mail providers (ESPs), multiple From headers and Received-chain anomalies.

**2. Domain / sender** (`analyzers/domain.py`)

- **Address consistency:** compares From, Reply-To, Return-Path and Sender (`replyto_mismatch`,
  free-webmail reply-to).
- **Lookalike domains:** checked by edit distance, a homoglyph/punycode skeleton, TLD swaps and
  brand-plus-word combinations.
- **Display-name brand spoofing:** a brand name in the display name with an address that doesn't
  belong to the brand.
- **Domain age** via RDAP: under 7, 30 or 180 days.
- **No MX record** on the From domain.
- **Identity binding** (see below).

**3. Tone** (`analyzers/tone.py`)

- YAML lexicons (`data/lexicons/`) cover urgency, fear, greed, authority, secrecy, generic
  greetings, credential requests and payment requests.
- Points grow with the number of distinct phrases matched.
- Two optional extra layers: a local ML model and Claude.

**4. Artifacts** (`analyzers/artifacts.py`)

- **Hidden HTML tricks:** hidden or filler text, zero-width characters, tracking pixels, text/HTML
  mismatch, scripts, meta refresh, encoded links.
- **Header oddities:** missing Message-ID or Date, dates in the future, suspicious X-Mailer values.

**5. Attachments**

- **File type:** identified from magic bytes, not the extension. Flags type mismatch, double
  extensions, RTLO (right-to-left override) file names and high-risk types.
- **Archives:** zip/7z/tar/gz/ISO are unpacked in memory with zip-bomb limits. Passwords found in
  the email body are tried.
- **Office files:** auto-exec macros, XLM macros, remote template injection.
- **PDF / HTML / SVG:** PDF JavaScript and launch actions, HTML smuggling, credential forms, SVG
  scripts.
- **Binaries:** PE executables (packed or not) and LNK files with suspicious commands.
- **Also:** QR code decoding, YARA rules, hash reputation (MalwareBazaar/VT) and optional sandbox
  submission.
- Every attachment is stored in an AES-encrypted zip in `quarantine/`.

**6. URLs** (`analyzers/urls.py`)

- **Static checks:** IP hosts, shorteners, risky TLDs, punycode, `@` in the URL,
  `javascript:`/`data:` URIs, brand names on unrelated domains, and link text that shows a
  different domain than the link goes to.
- **Reputation:** Google Safe Browsing → URLhaus → VirusTotal, stopping at the first malicious
  answer.
- **urlscan.io:** reports redirects and login pages on unrelated domains.
- PhishLens never fetches a page itself.

### Identity binding (what makes it different)

This check asks: does the brand the email *claims* to be match the domain that *actually
authenticated* it?

- **Claimed brand:** found in the display name, a lookalike sender domain, the subject or the body.
- **Real identity:** the From domain, plus whether DMARC alignment succeeded.
- When they don't match, it raises `brand_impersonation`. Severity depends on where the claim was
  made:

| Situation | Severity |
|---|---|
| Brand claimed only in the subject or body | medium |
| Brand claimed in the display name, or the sender is free webmail | high |
| The brand's own domain is used but didn't authenticate | high |
| Lookalike or newly registered domain | critical |

## 5. How scoring works

The rule scorer is in `phishlens/scoring/rule_scorer.py`, and all numbers are in
`data/weights.yaml`.

**Step 1: points per finding.** Each finding ID has a weight. Some examples:

| Finding | Pts | Finding | Pts |
|---|---|---|---|
| `auth_but_unaligned` | 45 | `attachment_known_malicious` | 70 |
| `spf_fail` / `dmarc_fail` | 25 | `sandbox_malicious` | 70 |
| `lookalike_domain` | 35 | `html_smuggling` | 60 |
| `domain_age_under_7_days` | 40 | `url_known_malicious` | 60 |
| `brand_impersonation` | 50 / 35 / 15 (crit/high/med) | `double_extension` / `rtlo_filename` | 40 |
| `link_text_mismatch` | 30 | `credential_request` | 20 |
| `tone_urgency` | 12 | `tracking_pixel` | 2 |

- A finding with no listed weight uses the **severity fallback**: info 0, low 5, medium 15,
  high 30, critical 50.
- Tone points scale with how many phrases matched: `weight × (0.5 + 0.5 × matched/cap)`.
- ML findings are multiplied by their probability.

**Step 2: module caps.** Each module can add only so much, so a pushy newsletter can't become
Malicious on tone alone.

| Module | header | domain | urls | attachments | artifacts | tone | nested |
|---|---|---|---|---|---|---|---|
| Cap | 60 | 50 | 60 | 70 | 25 | 30 | 60 |

**Step 3: total.** The total is the sum of the capped module scores, clamped to 0–100.

**Step 4: thresholds.**

| Case type | Suspicious from | Malicious from |
|---|---|---|
| Email | 30 | 60 |
| Single file | 20 | 50 |

**Step 5: overrides.** These force a minimum label and raise the score to that label's threshold:

- `attachment_known_malicious`, `url_known_malicious`, `sandbox_malicious` or `html_smuggling` →
  **Malicious**
- `auth_but_unaligned` **and** `brand_impersonation` together → **Malicious** (`spoofed_brand`)
- any critical finding → at least **Suspicious**

**Step 6: confidence.**

- It starts as the share of modules that ran without errors.
- It drops by 0.1 for each key service that isn't configured (VirusTotal, Safe Browsing,
  abuse.ch), up to 0.3.
- It never goes below 0.1.

**Step 7: top reasons.** The 5 highest-scoring findings become the "why" shown in every report.

**Worked example:** a fake "PayPal" email sent from `paypa1-secure.example`.

| Module | Findings | Raw points | After cap |
|---|---|---|---|
| Header | `auth_but_unaligned` 45 + `dmarc_fail` 25 | 70 | **60** |
| Domain | `lookalike_domain` 35 + critical `brand_impersonation` 50 | 85 | **50** |
| Tone | urgency + credential request | ~29 | **~29** |

- The total is about 139, clamped to **100**, so the verdict is **Malicious**.
- The `spoofed_brand` override also fires, so the verdict would be Malicious even if the score
  were lower.

**Other scorer and tuning scripts:**

- `SCORER=ml` switches to an optional trained scorer. The rule scorer is the default.
- `scripts/evaluate.py --tune` reports precision, recall, F1 and false positive rate, and shows
  how other thresholds would change them.

## 6. After scoring

- **IOCs** (`phishlens/ioc/`): extracted, normalized and defanged (`hxxp://evil[.]com`). Private
  IPs and trusted internal hosts are skipped. Exported as CSV, JSON and a STIX 2.1 bundle.
- **MITRE ATT&CK** (`data/mitre_rules.yaml`): rules map finding IDs to techniques such as:
  - T1566.001/.002 (spearphishing attachment/link);
  - T1204.001/.002 (user execution);
  - T1221 (template injection);
  - T1027.006 (HTML smuggling);
  - T1036.002/.007 (RTLO, double extension);
  - T1059.005 (VBA);
  - T1583.001 (domains);
  - T1598.003 (spearphishing for information).
- **Reports:** Jinja2 HTML with an executive summary and recommended actions. Every string is
  auto-defanged; only MITRE and urlscan links are clickable. The PDF is the same HTML rendered by
  WeasyPrint.

## 7. Safety rules built in

- **Static only:** attachments and URLs are never opened, executed, rendered or fetched on the
  host.
- **No file uploads** to third parties unless you turn on the upload switch. Hash lookups are
  always allowed.
- **API keys** are `SecretStr` and are never logged.
- **Quarantine:** uploads are stored under `quarantine/` with generated names and are never
  served.
- **Upload limits:** the API is rate-limited per IP and can optionally require an `X-API-Key`.

## 8. Interfaces

- **CLI:**
  - `phishlens analyze mail.eml --format json,html --out reports/`
  - `phishlens analyze-file x.zip`
  - `phishlens check-config`
  - `--no-network` for offline runs
- **API:**
  - submit: `POST /api/analyze`, `/api/analyze-file`, `/api/analyze-raw`
  - results: `GET /api/cases/{id}` (+ `/status`, `/report?format=pdf`)
  - list and manage: `GET /api/cases`, `/api/stats`, `/api/health`, `DELETE /api/cases/{id}`
- **UI pages:**
  - **Analyze:** upload or paste, with live progress.
  - **Case view:** one tab per module, highlighted phrases, urlscan screenshots, archive tree,
    IOCs, MITRE.
  - **History:** stats and a 30-day chart.
  - **Settings.**
- **Run it:** `make up` starts everything in Docker. The UI is on :8501 and the API on :8000.

## 9. Known limitations

- **Hijacked real accounts:** mail from a compromised mailbox passes SPF, DKIM and DMARC, so
  PhishLens relies on content, links and attachments, and may rate it lower than it deserves.
- **Not a gateway:** it investigates emails you submit. It doesn't block mail.
- **Free-tier quotas:** reputation coverage depends on the keys you add and their limits.
- **English only:** the lexicons and brand lists are English-centric and need tuning for other
  organizations.
- **No evaluation results yet:** the table in the README is still empty because it needs a real
  labelled dataset.
