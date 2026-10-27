# How It Works: Technical Architecture & Execution Pipeline

Infinity Security Scan is an enterprise-grade Web Application and API Security Assessment platform. It combines high-speed signature inspection, active Dynamic Application Security Testing (DAST) parameter fuzzing, and schema-aware API logic testing into a cohesive, evidence-gated security engine.

This document details the architectural components, multi-phase execution pipeline, credential handling, and reporting mechanisms.

---

## 1. System Architecture Overview

The platform is structured into four decoupled layers:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Web Console Frontend UI                         │
│   Landing Portal (landing.html)  │  Unified Security Console (index.html)│
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ HTTP REST & JSON Telemetry
┌────────────────────────────────────▼───────────────────────────────────┐
│                     FastAPI Orchestration Backend                      │
│                  (gui/app.py — bound to 127.0.0.1:9057)                │
│                                                                        │
│  ┌──────────────────────┐ ┌──────────────────────┐ ┌────────────────┐ │
│  │  Spec Parser &       │ │   Auto-Auth Module   │ │  Route Spider  │ │
│  │  Sanitizer           │ │   (autoauth.py)      │ │  (crawler.py)  │ │
│  │  (specfields.py)     │ └──────────────────────┘ └────────────────┘ │
│  └──────────────────────┘                                              │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ Subprocess Execution Sandbox
┌────────────────────────────────────▼───────────────────────────────────┐
│                     Multi-Phase Execution Pipeline                     │
│                                                                        │
│   ┌───────────────────┐  ┌────────────────────┐  ┌──────────────────┐  │
│   │ Phase 0:          │  │ Phase 1:           │  │ Phase 2:         │  │
│   │ schemathesis      │  │ Nuclei Signatures  │  │ Nuclei DAST      │  │
│   │ (API Logic &      │  │ (Broad CVEs,       │  │ (Active Fault    │  │
│   │  Validation)      │  │  Secrets, Panels)  │  │  Injection)      │  │
│   └─────────┬─────────┘  └─────────┬──────────┘  └─────────┬────────┘  │
└─────────────┼──────────────────────┼───────────────────────┼───────────┘
              │                      │                       │
┌─────────────▼──────────────────────▼───────────────────────▼───────────┐
│                   Fusion & Evidence Engine (fusion.py)                 │
│    - Deduplication & Severity Normalization                            │
│    - OWASP Top 10 & CWE Mapping                                        │
│    - Evidence Verification & Inconclusive vs Clean Verdict Grading     │
│    - Multi-Format Reports: In-Browser HTML, PDF, SARIF, JSON, Markdown │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Subsystems

### 2.1. Ingestion & Discovery

Infinity Security Scan ingests multiple target formats and automatically adapts the scanning pipeline:

- **OpenAPI 3.x & Swagger 2.0 Specs**: Ingested via local file upload or remote URL (`http://host/docs-json`). The engine validates schemas, extracts path items, methods, parameters, and security schemes.
- **Postman Collections (v2.1)**: Automatically converted to standard OpenAPI 3.0 via `gui/postman_to_openapi.py`.
- **Target URLs & IP Addresses**: Crawled using `gui/crawler.py` to identify hidden endpoints, login portals, administrative interfaces, and single-page application (SPA) client routes before executing scans.
- **Path-Scope Slicing**: When evaluating specific modules (e.g. `/api/v1/auth`), `specfields.slice_paths()` isolates only relevant endpoints, eliminating noise from unneeded routes.

### 2.2. Spec Input Detection (`specfields.py`)

A common flaw in automated API scanners is submitting synthetic dummy values (e.g., `id=string`), which cause target APIs to immediately respond with `400 Bad Request` or `404 Not Found`. This prevents actual business logic from being reached.

- The **Detect Required Inputs** feature inspects schema ASTs to identify path parameters and required fields (such as user IDs, account UUIDs, or tenant keys).
- Operators supply real values via `-V key=value`, which are dynamically bound to requests during scanning. This enables genuine Broken Object Level Authorization (BOLA/IDOR) verification.

### 2.3. Automated Authentication (`autoauth.py`)

API and Web App scans frequently require authenticated sessions. Infinity Security Scan handles authentication securely:

1. **Endpoint Probing**: Queries standard authentication paths (`/api/v1/auth/sign-in`, `/api/v1/login`, `/auth/login`) with supplied test credentials.
2. **Token Extraction**: Recursively inspects response payloads for access tokens (`accessToken`, `token`, `idToken`, `jwt`).
3. **WhoAmI Verification Probe**: Before firing any scan requests, the token is verified against an identity endpoint (`/api/v1/auth/me`, `/me`).
   - If the endpoint accepts the token (`200 OK`), the scan proceeds.
   - If rejected (`401` or `403`), the scan aborts immediately. This prevents running an unauthenticated scan that produces a false "Clean" report.
4. **MFA Detection**: If multi-factor authentication (`nextStep`, `mfaRequired`) is required, the engine halts with clear instructions to provide a pre-authenticated session token.

---

## 3. The Multi-Phase Scanning Engine

Traditional scanners often combine broad vulnerability templates with active injection flags (e.g., running `nuclei -tags cve,owasp -dast`). In Nuclei, applying `-dast` at template load time filters out all templates that do not contain explicit fuzzing rules, silently discarding over 99% of signature templates (reducing 9,000 checks to ~50).

Infinity Security Scan resolves this by orchestrating a **sequential multi-phase execution pipeline**:

```
                       ┌───────────────────────────────┐
                       │ Target Ingested & Auto-Auth   │
                       └──────────────┬────────────────┘
                                      │
                                      ▼
                       ┌───────────────────────────────┐
                       │ Phase 0: schemathesis         │
                       │ - Schema-aware fuzzing        │
                       │ - Real UUID/ID binding        │
                       │ - SecLists dictionary feeds   │
                       │ - Catches 500s & violations   │
                       └──────────────┬────────────────┘
                                      │
                                      ▼
                       ┌───────────────────────────────┐
                       │ Phase 1: Nuclei Signatures    │
                       │ (Without -dast flag)          │
                       │ - Full CVE inspection         │
                       │ - Exposed secrets & .env      │
                       │ - Admin panels & CORS flaws   │
                       │ - SSL/TLS cipher hygiene      │
                       └──────────────┬────────────────┘
                                      │
                                      ▼
                       ┌───────────────────────────────┐
                       │ Phase 2: Nuclei DAST Fuzzing  │
                       │ (With -dast flag)             │
                       │ - Active AST fault injection  │
                       │ - SQLi & Blind Boolean payloads│
                       │ - Reflected/Stored XSS        │
                       │ - Out-of-band SSRF / SSTI     │
                       └──────────────┬────────────────┘
                                      │
                                      ▼
                       ┌───────────────────────────────┐
                       │ Phase 3: Artifact Fusion      │
                       │ - Deduplication & Correlation │
                       │ - Genuine Evidence Verdict    │
                       └───────────────────────────────┘
```

### Phase 0: API Logic Fuzzing (`schemathesis`)
- Triggered automatically for OpenAPI/Swagger targets.
- Uses stateful, property-based schema testing with user-provided IDs and SecLists wordlists.
- Detects unhandled server exceptions (HTTP 500), schema discrepancies, status code mismatches, and boundary violations.
- Produces `schemathesis.json` and standard JUnit XML.

### Phase 1: High-Fidelity Signature & Exposure Inspection
- Executes the Nuclei engine without the `-dast` filter.
- Loads complete vulnerability rulesets: OWASP Top 10 misconfigurations, known CVEs, exposed Git/.env directories, and misconfigured CORS/HTTP headers.
- Produces `results.p1.json`, `findings.p1.txt`, and `report.p1.sarif`.

### Phase 2: Active Dynamic Application Security Testing (DAST)
- Executes the Nuclei engine with the `-dast` flag enabled.
- Interrogates application parameters (query parameters, request bodies, headers, path variables, cookies).
- Injects fault payloads for SQL Injection, Cross-Site Scripting (XSS), Server-Side Request Forgery (SSRF), Server-Side Template Injection (SSTI), and Remote Code Execution (RCE).
- Produces `results.p2.json`, `findings.p2.txt`, and `report.p2.sarif`.

---

## 4. Correlation & Evidence Fusion (`fusion.py`)

Once scan phases finish, the Fusion engine synthesizes findings into a unified, evidence-gated security report:

1. **Artifact Normalization**: Ingests outputs from all phases (`results.p1.json`, `results.p2.json`, `schemathesis.json`).
2. **Deduplication**: Correlates identical issues found across phases by endpoint, vulnerability type, and parameter signature.
3. **OWASP Top 10 Mapping**: Maps every finding to its corresponding OWASP category (A01:2021 through A10:2021) and CWE identifier.
4. **Evidence-Gated Verdicts**:
   - Every evaluated security control is explicitly marked as **TESTED**, **SKIPPED**, or **INCONCLUSIVE**.
   - If a scan suffered high error rates, rate-limiting (HTTP 429), or insufficient coverage, the overall rating is graded **INCONCLUSIVE** rather than an unwarranted "A+ Clean" pass.
   - Genuine vulnerabilities require recorded HTTP request/response proofs or matcher signatures before being counted.

---

## 5. Reporting Subsystem

All scan results are compiled into multiple output formats:

- **In-Browser Interactive Viewer**: Rendered directly in the web console (`/api/jobs/{id}/view-report`). No external reader or software download is required.
- **Executive Summary**: Business impact statements, compliance posture, and risk scores designed for leadership.
- **Engineering Remediation**: Exact reproduction steps, vulnerable parameters, affected endpoints, and code-level remediation guidelines.
- **Downloadable Artifacts**:
  - `report.pdf`: Standalone executive assessment report.
  - `genuine-report.json`: Machine-readable consolidated findings.
  - `report.sarif`: OASIS Standard Static/Dynamic Analysis Results Format for GitHub Advanced Security and CI/CD pipelines.
  - `run.log`: Sanitized execution logs.

---

## 6. Execution Interfaces

Infinity Security Scan can be operated through three interfaces:

### Web Console (GUI)
```bash
pip install -r gui/requirements.txt
python gui/app.py
# Access console at http://127.0.0.1:9057
```

### Integrated CLI Script
```bash
./tools/fused-scan.sh -spec api-spec.json -out out/ \
  -auth 'user@example.com:Password123!' -auth-base http://127.0.0.1:8080 \
  -scope /api/v1/auth -V id=user-uuid
```

### Direct Core Engine CLI
```bash
./bin/nuclei -target https://example.com -tags owasp,cve,misconfig -sfv
```
