# Infinity Security Platform

Enterprise Web Application & API Security Scanner Console.

## Prerequisites

```bash
make build            # produces ./bin/nuclei (Infinity Engine)
pip install -r gui/requirements.txt
```

## Run

```bash
python gui/app.py
# Open http://127.0.0.1:9057
```

## Security Assessment Profiles

1. **Web Application Security Audit**:
   - Targeted checks for OWASP Top 10 (SQLi, XSS, SSRF, RCE, IDOR, Broken Auth).
   - Sensitive file exposures (`.env`, `.git`, backups, secrets).
   - Administrative panels & dashboards detection.
   - Active DAST payload fuzzing on URL parameters and headers.

2. **API Security Assessment**:
   - Native support for OpenAPI 3.x, Swagger 2.0, and Postman Collections (auto-converted to OpenAPI 3).
   - Dynamic parameter variable support (`id=1`, `categoryId=1`, `parentId=1`).
   - Automated schema validation bypass (`-sfv`) to avoid scans halting on missing sample fields.

3. **Full-Spectrum Enterprise Audit**:
   - Deep-spectrum assessment combining Web App, API, DAST, and infrastructure checks.

4. **Surface Threat Exposure & Recon**:
   - Fast non-intrusive discovery of exposed panels, technologies, and SSL/TLS posture.

## Executive & Technical Reports

Downloadable artifacts generated per assessment in `gui/jobs/<id>/`:
- `report.pdf` — Executive Security Assessment Report
- `report.sarif` — SARIF 2.1.0 Standard for CI/CD & IDEs
- `results.json` — Structured JSON findings
- `findings.txt` — Plaintext matching summary
- `run.log` — Full execution terminal audit trail
- `md/` — Markdown documentation format
