# Data Leakage & Security Assessment

This document provides a comprehensive security and data privacy assessment of the **Infinity Security Scan** platform (including the Nuclei core engine, FastAPI web console, automation scripts, and background workers). It addresses potential data leakage vectors, implemented safeguards, and enterprise hardening recommendations.

---

## 1. Executive Summary

| Risk Vector | Default Behavior | Potential Leakage | Implemented Safeguard / Mitigation | Residual Risk |
|---|---|---|---|---|
| **OAST / Interactsh** | Enabled for blind vulnerabilities | Payload IDs and internal target IPs sent to public OAST servers | Configurable private OAST server (`-iserver`) or completely disabled via `-no-interactsh` (`-ni`) | Low (Mitigated) |
| **Telemetry & Update Checks** | Engine checks for updates | Scanner IP and version checked against GitHub / ProjectDiscovery APIs | Disable with `-disable-update-check` (`-duc`) and `-no-meta` | Zero when flagged |
| **Process Table Secrets (`ps aux`)** | Headers previously passed via CLI args | Process listing could expose `Authorization: Bearer <token>` to local users | Headers stored in mode `0600` file and passed as `-H <filepath>` | Zero |
| **Execution Logs (`run.log`)** | Child process outputs streamed to disk | Token or credential reflection in debug outputs | Stream-level regex redaction (`_redact`) masking tokens, basic auth, and secrets | Zero |
| **Job Scratch Storage (`gui/jobs/`)** | Local files store scan findings & configs | Unprivileged local access to scan reports or targets | `.gitignore` exclusion, `0600`/`0700` POSIX permissions, credential exclusion from downloadable API lists | Low |
| **Web Console Network Exposure** | Bound to `127.0.0.1:9057` | If bound to `0.0.0.0`, unauthenticated network users could access scan reports | Localhost-only binding; reverse proxy + authentication required for shared deployment | Zero in default configuration |
| **Target Data in Findings** | Vulnerabilities return target dumps (`.env`, PII) | Scanned targets' sensitive data stored in `results.json` and reports | Confined to job directory; API job purge endpoint (`/api/jobs/clear`) | Managed by operator |

---

## 2. In-Depth Analysis of Potential Leakage Vectors

### 2.1. Out-of-Band Testing (OAST / Interactsh)

#### The Mechanism
Nuclei incorporates an Out-of-Band Application Security Testing (OAST) client using **Interactsh**. For vulnerabilities that produce no immediate HTTP response (e.g., Blind SSRF, Blind RCE, Out-of-Band SQL Injection, Blind XXE), Nuclei injects an interactsh callback URL (such as `xyz.oast.fun` or `xyz.interact.sh`). If the target is vulnerable, it performs a DNS lookup, HTTP request, or LDAP connection back to the Interactsh server.

#### Potential Data Leakage Issue
When scanning internal, private, or classified enterprise networks:
- The callback request contains a unique identifier correlating the probe with the target.
- The public Interactsh cluster receives:
  1. The public egress IP address of the vulnerable target.
  2. DNS query logs revealing hostnames or internal IP addresses if embedded in payloads.
  3. Out-of-band HTTP request headers.

#### Safeguards & Remediation
- **Completely Disable Interactsh**: If external network calls are prohibited, pass `-no-interactsh` (`-ni`):
  ```bash
  ./bin/nuclei -target https://internal.corp -ni
  ```
- **Self-Hosted Private Interactsh Server**: For enterprise environments requiring out-of-band vulnerability detection without public infrastructure, deploy an internal Interactsh server:
  ```bash
  ./bin/nuclei -target https://internal.corp \
    -iserver https://interactsh.internal.corp \
    -itoken YOUR_SECURE_TOKEN
  ```

---

### 2.2. Engine Telemetry & Version Updates

#### The Mechanism
By default, the core engine checks for software updates and template repository releases on startup.

#### Potential Data Leakage Issue
- Periodic queries to ProjectDiscovery / GitHub release endpoints disclose the scanner's external IP address, engine version, and scan frequency to external infrastructure.

#### Safeguards & Remediation
- In air-gapped, isolated, or strict data-privacy environments, disable all remote checks:
  ```bash
  ./bin/nuclei -disable-update-check -no-meta
  ```
- In `gui/app.py` and `tools/fused-scan.sh`, update checks are bypassed during automated scanning jobs.

---

### 2.3. Credential & Bearer Token Exposure in Process Tables

#### The Mechanism
When scanning authenticated APIs, the scanner uses a Bearer token or session header.

#### Potential Data Leakage Issue
If passed directly on the command line:
```bash
# VULNERABLE: Process list reveals secrets to any user on the machine
./bin/nuclei -H "Authorization: Bearer eyJhbGciOi..." -target https://target.com
```
Any unprivileged user or process monitor executing `ps aux`, `ps -ef`, or inspecting `/proc/<PID>/cmdline` can view the raw token.

#### Safeguards Implemented
Infinity Security Scan utilizes file-based header injection:
1. `gui/app.py` writes headers to a dedicated file: `job_dir / "headers.txt"`.
2. The file is created with restricted POSIX permissions (`0o600` — readable and writable exclusively by the process owner).
3. The engine is invoked with the file reference:
   ```bash
   ./bin/nuclei -H /path/to/job/headers.txt ...
   ```
4. As a result, the OS process table displays only the file path, and the token is never exposed in process listings.

---

### 2.4. Execution Logs & Artifact Sanitization

#### The Mechanism
The web console captures subprocess standard output and standard error, writing execution traces to `run.log`.

#### Potential Data Leakage Issue
If target web servers, proxies, or scanning tools reflect authorization headers or credentials in error messages or debug outputs, these could be written to `run.log`. Because `run.log` can be downloaded via the web interface (`/api/jobs/{id}/log`), unsanitized logs could expose credentials.

#### Safeguards Implemented
In `gui/app.py`:
1. Every line of output from child processes is passed through `_redact()` before being written to disk:
   ```python
   def _redact(line: str) -> str:
       if not line:
           return line
       line = re.sub(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1***", line, flags=re.IGNORECASE)
       line = re.sub(r"(Basic\s+)[A-Za-z0-9+/=]+", r"\1***", line, flags=re.IGNORECASE)
       line = re.sub(r"((?:token|password|passwd|api[_-]?key|secret|authorization)\s*[:=]\s*)[^\s,;&\"']+", r"\1***", line, flags=re.IGNORECASE)
       return line
   ```
2. The initial command banner written to `run.log` is also sanitized via `_redact()`.
3. The temporary `auth.json` file writes only masked tokens (e.g. `eyJhbG...4xZa`) and is restricted to permissions `0600`.

---

### 2.5. Storage Hygiene in `gui/jobs/`

#### The Mechanism
Each scan generates a unique directory under `gui/jobs/<job-id>/` containing:
- `input.used` (the target list or OpenAPI schema)
- `results.json` / `findings.txt` (vulnerability outputs)
- `report.pdf` / `report.sarif` (compiled reports)
- `headers.txt` / `auth.json` (authentication metadata)

#### Safeguards Implemented
1. **Repository Containment**: The entire `/gui/jobs/` directory is registered in `.gitignore`, preventing accidental commits to source control.
2. **Download Allowlist**: The FastAPI file-download endpoint (`/api/jobs/{id}/download/{filename}`) enforces a strict allowlist:
   ```python
   DOWNLOADABLE = {
       "findings.txt", "results.json", "report.sarif", "report.pdf",
       "run.log", "input.used", "genuine-report.json",
       "genuine-report.sarif", "genuine-report.md",
       "schemathesis.json", "schemathesis-junit.xml"
   }
   ```
   Internal credential files (`headers.txt`, `auth.json`, `st-vars.json`) cannot be downloaded via the web API.
3. **Automated Purge Support**: Operators can wipe all prior job data and reports at any time by calling `POST /api/jobs/clear`.

---

### 2.6. Local Web Console Network Exposure

#### The Mechanism
The web console is hosted using FastAPI and Uvicorn.

#### Potential Data Leakage Issue
If bound to all interfaces (`0.0.0.0`) on an untrusted local area network or shared server without an authentication layer:
- Other network devices could query `/api/jobs` and access vulnerability reports.
- Attackers could submit scan requests against internal network devices (SSRF).

#### Safeguards & Deployment Doctrine
1. **Localhost Binding by Default**: Uvicorn binds strictly to `127.0.0.1:9057`, ensuring the console is accessible only from the local machine.
2. **Multi-User / Remote Access Best Practices**:
   If hosting the web console on a shared server:
   - Bind Uvicorn to `127.0.0.1` and place it behind a reverse proxy (e.g. NGINX, Caddy, or Cloudflare Tunnel).
   - Enforce TLS encryption (HTTPS).
   - Enforce HTTP Basic Authentication or Single Sign-On (SSO / OAuth2).

---

### 2.7. Target Data in Vulnerability Findings

#### The Mechanism
When tests discover vulnerabilities such as exposed `.env` files, database dumps, directory listings, or server error traces, the matching evidence snippet (HTTP response body) is captured in `results.json` and presented in the in-browser report.

#### Operator Considerations
- Scan reports may contain genuine secrets leaked *from the scanned target* (such as leaked database passwords or API keys).
- Treat generated assessment reports (`report.pdf`, `genuine-report.json`, `gui/jobs/`) as confidential material.
- Secure report storage and purge jobs once assessment reviews are complete.

---

## 3. Enterprise Hardening Checklist

For organizations deploying Infinity Security Scan in high-assurance environments:

- [x] **Header isolation**: Pass all credentials and tokens using files with `0600` permissions rather than CLI arguments.
- [x] **Log scrubbing**: Ensure Bearer tokens, Basic auth hashes, and API keys are redacted before writing to log streams.
- [x] **Source control containment**: Verify `.gitignore` excludes `/gui/jobs/`, `*.log`, and temporary scan outputs.
- [ ] **Disable public OAST**: For air-gapped networks, run scans with `-no-interactsh` (`-ni`) or configure a private `-iserver`.
- [ ] **Disable update checks**: In offline environments, add `-disable-update-check` (`-duc`) to prevent external lookups.
- [ ] **Reverse proxy protection**: When exposing the web interface, protect it with TLS and strong authentication.
- [ ] **Data retention**: Regularly invoke the cleanup API (`POST /api/jobs/clear`) or establish a cron job to purge `gui/jobs/` records according to your data retention policy.
