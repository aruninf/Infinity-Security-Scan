# Infinity-Security-Scan

Enterprise Web Application & API Security Scanner Platform.

Infinity-Security-Scan is an advanced, high-performance security assessment platform equipped with a modern web console, automated schema guardrails, active DAST fuzzing, API-logic testing, and genuine evidence-based reporting — everything visible in-browser, no downloads needed.

---

## Key Features

- **🌐 Web Application Security Scanning**: Comprehensive inspection for OWASP Top 10 (SQLi, XSS, SSRF, RCE, IDOR), known CVEs, sensitive exposures (`.env`, `.git`, backups), administrative dashboards, and security misconfigurations.
- **⚡ API Security Assessment**: Native support for OpenAPI 3.x, Swagger 2.0, and Postman Collections (automatically converted). Automatically bypasses schema parameter aborts (`-sfv`) and accepts variable definitions.
- **🔐 Auto-login**: give a test account email + password once — the scanner logs in through your API's own sign-in endpoint, **verifies** the token against a who-am-i endpoint, and scans as that account. Rejected tokens abort instead of producing fake-clean unauthenticated scans. Tokens never touch logs.
- **🎯 Path scope**: scan one module at a time (e.g. `/api/v1/auth` for auth-layer only) with the full template set — or the whole API.
- **🧾 Required-input detection**: the scanner reads your spec and asks for REAL values (real object IDs for BOLA coverage, login creds for auth) instead of silently testing synthetic 404s.
- **🧠 API-logic phase (schemathesis)**: automatic schema-aware testing — 500s, response-vs-schema violations, validation bypasses, stateful workflows — fed with your real IDs plus curated SecLists payload dictionaries.
- **🛡️ Full-Spectrum Enterprise Audit**: deep test combining signatures + DAST fuzzing + API-logic + SSL/TLS checks. Signatures and DAST run as **separate phases** so `-dast` can never silently filter out 99% of templates.
- **📊 Genuine in-browser reports**: Executive + Engineering report with business **impact**, fix guidance, evidence and CVE/CWE refs for every finding — shown inline, nothing to download. Controls read TESTED / SKIPPED / INCONCLUSIVE (never assumed Passed); thin-coverage scans grade **Inconclusive**, never A+.

---

## Quick Start

### 1. Build Engine Binary

```bash
make build
```

This compiles `./bin/nuclei` (Infinity Core Engine).

### 2. Start the Local Web Console

```bash
pip install -r gui/requirements.txt
python gui/app.py
```

Open your browser at:
👉 **[http://127.0.0.1:9057](http://127.0.0.1:9057)**

### 3. Run an Authenticated API Audit (recommended first run)

1. Target: your spec URL (e.g. `http://host:8080/api/docs-json`) or upload `openapi.json`.
2. Click **🔍 Detect Required Inputs From Spec** — fill the REAL IDs it lists (e.g. `id`, `parentId`) with values from your test account.
3. Fill **Auto-login** email + password (test account must already exist — OTP-gated sign-up can't be automated).
4. Optional: **Limit To Paths** `/api/v1/auth` for an auth-layer-only pass.
5. Launch. Expect a `verified ✓` toast, then watch the Executive Report — every finding carries impact + fix + evidence.

---

## CLI Usage (no GUI)

```bash
# Web Application (two-phase: signatures + DAST, merged genuine report)
./tools/fused-scan.sh -target https://example.com -out out/

# API via OpenAPI (schemathesis + signatures + DAST)
./tools/fused-scan.sh -spec api-spec.json -out out/ \
  -auth 'you@mail.com:Password123!' -auth-base http://10.20.20.9:8080 \
  -scope /api/v1/auth -V id=real-uuid -V parentId=real-id

# Raw engine (single commands)
./bin/nuclei -target https://example.com -tags owasp,cve,misconfig
./bin/nuclei -l api-spec.json -im openapi -sfv -dast -pe report.pdf -se report.sarif
```

Artifacts land in `out/`: `genuine-report.{json,sarif,md}` (evidence-gated verdict), plus per-phase logs.

---

## Security Checks — What Is Tested

| # | Check | How | Needs |
|---|---|---|---|
| 1 | Dynamic Injection Fuzzing (DAST) | Fault-injection over query / body / header / path / cookie | `-dast` phase (automatic in GUI) |
| 2 | SQL & NoSQL Injection | DB escape, blind boolean/time payloads | DAST + tags |
| 3 | Cross-Site Scripting (XSS) | Reflected/stored context + analyzer verification | DAST + tags |
| 4 | RCE / Command Injection | OS command & code-exec sinks | signature templates |
| 5 | SSRF / OAST | Interactsh out-of-band probing | signature templates |
| 6 | SSTI | Template interpolation & sandbox escapes | DAST |
| 7 | BOLA / IDOR (API) | Cross-object access with **real IDs** + stateful API-logic flows | OpenAPI + IDs + schemathesis phase |
| 8 | API Schema Conformance | 500s, response-vs-schema, validation bypass | schemathesis phase (auto) |
| 9 | Auth / Session Flaws | Missing auth, defaults, leaks; verified-token scanning | login creds |
| 10 | Exposure / Panels / Headers / CORS / SSL | Discovery, hardening, certificate checks | signature templates |

Every report marks each control TESTED / SKIPPED / INCONCLUSIVE with the reason — a control that never ran is never shown as passed.

### Companion tools (external, never vendored)

- **schemathesis** (`uv tool install schemathesis`): auto-runs for OpenAPI scans when present; prefilled (`max-examples 50`, `fuzzing+stateful`, `rate-limit auto`). Skips with a log note when absent.
- **SecLists** (`SECLISTS_DIR` → sparse checkout): curated SQLi/XSS payloads auto-baked into the API-logic dictionaries; discovery profiles documented in `tools/seclists-profiles.yaml`.

---

## How a Scan Flows (GUI)

```
spec / URLs in → sanitize → path-scope slice → auto-login (+verify token)
  → Phase 0 schemathesis (real IDs + SecLists dicts, JUnit → findings)
  → Phase 1 signatures — full CVE/exposure/panel set (NO -dast filter)
  → Phase 2 DAST fuzz (WITH -dast)
  → merge + dedupe → genuine verdict (I/F/D/C/B/A+) → in-browser report
```

- `GET /api/jobs/{id}/view-report` — full standalone report (printable).
- `GET /api/jobs/{id}/report-data` — report JSON incl. per-finding impact/remediation/evidence.
- `GET /api/jobs/{id}/finding/{idx}` — single enriched finding.
- `POST /api/spec-inputs` — required-input ask-list for any spec.
- `GET /api/tooling-status` — schemathesis/SecLists availability.

---

## License

MIT / Apache 2.0.
