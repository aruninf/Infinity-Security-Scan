# Infinity-Security-Scan

Enterprise Web Application & API Security Scanner Platform.

Infinity-Security-Scan is an advanced, high-performance security assessment platform equipped with a modern web console, automated schema guardrails, active DAST fuzzing, and executive report generation.

---

## Key Features

- **🌐 Web Application Security Scanning**: Comprehensive inspection for OWASP Top 10 (SQLi, XSS, SSRF, RCE, IDOR), known CVEs, sensitive exposures (`.env`, `.git`, backups), administrative dashboards, and security misconfigurations.
- **⚡ API Security Assessment**: Native support for OpenAPI 3.x, Swagger 2.0, and Postman Collections (automatically converted). Automatically bypasses schema parameter aborts (`-sfv`) and accepts variable definitions.
- **🛡️ Full-Spectrum Enterprise Audit**: Deep-penetration test combining Web App, API, DAST fuzzing, and SSL/TLS infrastructure checks.
- **🔍 Surface Threat Exposure & Recon**: Rapid non-intrusive discovery of exposed panels, technology fingerprinting, and certificate posture.
- **📊 Executive & Technical Reports**: Automated generation of Executive PDF (`report.pdf`), SARIF 2.1.0 standard (`report.sarif`), Markdown documentation, and structured JSON results—even for clean scans.
- **🖥️ Modern Web Console**: Real-time streaming terminal logs, interactive vulnerability inspection drawer, and local job history.

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

---

## CLI Usage

```bash
# Scan a Web Application
./bin/nuclei -target https://example.com -tags owasp,cve,misconfig -dast

# Scan an API via OpenAPI specification
./bin/nuclei -l api-spec.json -im openapi -sfv -dast -pe report.pdf -se report.sarif
```

---

## License

MIT / Apache 2.0.
