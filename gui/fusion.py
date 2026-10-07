"""Infinity fusion layer — genuine, evidence-based App/API report.

Do NOT vendor schemathesis/ or SecLists/ into this repo (they are ~200MB / ~5GB
untracked dirs). Treat both as external, optional tools:

- nuclei (Go, ./bin/nuclei): exploit / misconfig / CVE signature + active DAST.
- schemathesis (Python, `uvx schemathesis`): schema-aware API logic —
  500s, schema violations, validation bypass, stateful sequences.
- SecLists (wordlists): discovery + fuzz dictionaries, referenced by path only.

This module merges the outputs into one deduplicated, evidence-gated report.
A finding is "verified" only if it carries rule + location + evidence snippet.
Controls are reported as TESTED / SKIPPED / INCONCLUSIVE — never blanket "Passed".
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}

# ---- Business-impact library: category -> (impact, fix) ----
# Shown for EVERY finding in the in-browser Executive & Engineering report.
# Template's own description/remediation win when present; this is the fallback.
IMPACTS: list[tuple[tuple[str, ...], str, str]] = [
    (("sqli", "sql-injection", "nosql"), "Attackers can read, modify or delete database contents and may escalate to server access.",
     "Use parameterized queries / ORM bindings; least-privilege DB user; WAF as defense-in-depth."),
    (("xss", "cross-site"), "Attackers can hijack user sessions, steal tokens and deface pages in victims' browsers.",
     "Context-aware output encoding; Content-Security-Policy; HttpOnly + Secure cookies."),
    (("rce", "command-injection", "code-execution", "command injection"), "Full server compromise: arbitrary OS command or code execution.",
     "Never pass input to shells/eval; strict allowlists; sandbox execution; patch the component."),
    (("ssrf", "server-side-request"), "Server can be abused to reach internal services and cloud metadata; credential theft risk.",
     "Egress allowlist; block metadata IPs; validate and resolve URLs server-side."),
    (("ssti", "template-injection"), "Server-side template evaluation can escalate to remote code execution.",
     "Sandbox templates; never render user input as template; logic-less templates only."),
    (("idor", "bola", "broken-object", "broken object"), "Attackers can access or modify other users' objects by changing IDs.",
     "Enforce per-object authorization on every endpoint; unpredictable IDs alone are not a fix."),
    (("auth", "login", "session", "jwt", "token", "default-cred", "default credential"), "Authentication weakness can lead to account takeover.",
     "Enforce strong auth; rotate secrets; lockout + MFA; short-lived tokens."),
    (("exposure", "disclosure", ".env", ".git", "backup", "panel", "dashboard", "directory-listing", "debug"),
     "Sensitive files, source or admin panels exposed to the internet aid full compromise.",
     "Remove from web root; require auth + IP allowlist; disable debug in production."),
    (("cors", "cross-origin"), "Misconfigured cross-origin trust lets malicious sites read authenticated responses.",
     "Explicit origin allowlist; never reflect Origin with credentials; Vary: Origin."),
    (("ssl", "tls", "cipher", "certificate", "hsts"), "Weak transport lets attackers intercept or downgrade traffic; compliance failure.",
     "Valid certificates; strong ciphers only; HSTS; TLS 1.2+ minimum."),
    (("schema", "conformance", "validation-bypass", "not_a_server_error", "server-error", "500"),
     "API crashes or contract violations: availability risk and broken clients/integrations.",
     "Validate all inputs; fix handlers returning 500; keep responses schema-conformant."),
    (("cve",), "Known published vulnerability with public exploits likely in circulation.",
     "Patch to the fixed version immediately; apply vendor mitigations meanwhile."),
    (("misconfig", "header", "cors", "cookie", "csrf"), "Security hardening gap widens the blast radius of any other bug.",
     "Apply baseline headers/flags per the finding detail; verify in the retest."),
]


def _cat_blob_text(f: dict) -> str:
    info = f.get("info", {}) if isinstance(f.get("info"), dict) else {}
    tags = info.get("tags") or f.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return " ".join([
        str(f.get("rule_id") or f.get("rule") or f.get("template-id") or ""),
        str(f.get("name") or info.get("name") or ""),
        str(f.get("matcher") or f.get("matcher-name") or ""),
        str(f.get("type") or ""),
        " ".join(str(t) for t in tags),
    ]).lower()


def impact_for(f: dict) -> tuple[str, str, str]:
    """Return (category, impact, fix) for a nuclei-raw or genuine-normalized finding."""
    blob = _cat_blob_text(f)
    for keys, impact, fix in IMPACTS:
        if any(k in blob for k in keys):
            return keys[0].upper().replace("-", " "), impact, fix
    sev = str((f.get("info", {}) or {}).get("severity") or f.get("severity") or "info").lower()
    if sev in ("critical", "high"):
        return "GENERAL", "High-severity weakness — treat as exploitable until triaged.", "Triage promptly; isolate exposure; patch or mitigate."
    return "GENERAL", "Observed security-relevant behavior worth tracking.", "Review the evidence; harden or accept the risk explicitly."


def _cut(s, n: int = 1500) -> str:
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n] + f"\n…[truncated {len(s) - n} chars]"


def enrich_finding(f: dict) -> dict:
    """Full engineering detail for ONE finding (nuclei-raw or genuine shape).

    Always includes impact + remediation + evidence + refs so the in-browser
    report shows everything with zero downloads.
    """
    info = f.get("info", {}) if isinstance(f.get("info"), dict) else {}
    cls = info.get("classification") or {}
    if not isinstance(cls, dict):
        cls = {}
    refs: list[str] = []
    for key in ("cve-id", "cwe-id"):
        v = cls.get(key)
        if isinstance(v, list):
            refs += [str(x) for x in v if x]
        elif v:
            refs.append(str(v))
    r = info.get("reference") or f.get("reference") or []
    if isinstance(r, str):
        refs.append(r)
    else:
        try:
            refs += [str(x) for x in list(r)[:8] if x]
        except Exception:
            pass
    cvss = cls.get("cvss-score") or cls.get("cvss_metrics") or ""
    evidence: list[str] = []
    for key in ("matched", "evidence"):
        v = f.get(key)
        if isinstance(v, str) and v.strip():
            evidence.append(_cut(v.strip(), 600))
    for v in (f.get("extracted-results") or f.get("extracted_results") or []):
        if str(v).strip():
            evidence.append(_cut(str(v).strip(), 600))
    fuzz = " ".join(str(f.get(k) or "") for k in
                    ("fuzzing_method", "fuzzing_parameter", "fuzzing_position", "analyzer_details")).strip()
    if fuzz:
        evidence.append(_cut("fuzz: " + fuzz, 400))
    category, impact, fix = impact_for(f)
    remediation = (info.get("remediation") or "").strip() or fix
    return {
        "source": f.get("source") or ("schemathesis" if str(f.get("rule_id") or "").startswith("schemathesis/") else "nuclei"),
        "rule": f.get("rule_id") or f.get("rule") or f.get("template-id") or "finding",
        "name": f.get("name") or info.get("name") or "Finding",
        "severity": str(info.get("severity") or f.get("severity") or "info").lower(),
        "location": f.get("matched_at") or f.get("location") or f.get("host") or "",
        "category": category,
        "impact": impact,
        "description": (info.get("description") or "")[:1200],
        "remediation": remediation[:1200],
        "evidence": evidence[:6],
        "refs": refs[:8],
        "cvss": str(cvss)[:40],
        "request": _cut(f.get("request") or ""),
        "response": _cut(f.get("response") or ""),
        "curl": _cut(f.get("curl-command") or f.get("curl") or "", 800),
    }


def parse_nuclei_results(path: Path) -> list[dict]:
    """Parse nuclei -je/-jle output (JSON array or JSONL)."""
    if not path.exists() or path.stat().st_size == 0:
        return []
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return []
    items: list[dict] = []
    if text.startswith("["):
        try:
            data = json.loads(text)
            items = data if isinstance(data, list) else [data]
        except Exception:
            items = []
    else:
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in "[]":
                continue
            try:
                items.append(json.loads(line))
            except Exception:
                continue
    out = []
    for f in items:
        if not isinstance(f, dict):
            continue
        info = f.get("info", {}) if isinstance(f.get("info"), dict) else {}
        out.append({
            "source": "nuclei",
            "rule_id": f.get("template-id") or info.get("name") or "nuclei-finding",
            "name": info.get("name") or f.get("template-id") or "Nuclei finding",
            "severity": str(info.get("severity") or f.get("severity") or "info").lower(),
            "matched_at": f.get("matched-at") or f.get("host") or f.get("url") or "",
            "matcher": f.get("matcher-name") or "",
            "evidence": _nuclei_evidence(f),
            "raw": f,
        })
    return out


def _nuclei_evidence(f: dict) -> str:
    for key in ("matched", "extracted-results", "extracted_results"):
        v = f.get(key)
        if isinstance(v, list) and v:
            return str(v[0])[:400]
        if isinstance(v, str) and v.strip():
            return v.strip()[:400]
    req = f.get("request") or ""
    resp = f.get("response") or ""
    blob = f"{req}\n{resp}".strip()
    return blob[:400]


def parse_schemathesis_report(path: Path) -> list[dict]:
    """Parse schemathesis JSON/HAR-ish report into unified findings.

    Supports the generic shape: {"failures"|"results"|"checks": [...]} where each
    entry carries operation/method/path/status/check/message. Unknown shapes
    yield [] (never fabricate findings).
    """
    if not path.exists() or path.stat().st_size == 0:
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return []
    entries: list[dict] = []
    if isinstance(doc, dict):
        for key in ("failures", "results", "checks", "events"):
            v = doc.get(key)
            if isinstance(v, list):
                entries = v
                break
    elif isinstance(doc, list):
        entries = doc
    out = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        # Only keep explicit failures/errors, never "passed" checks.
        status = str(e.get("status") or e.get("outcome") or "").lower()
        if status and status not in ("fail", "failed", "failure", "error"):
            # If schema has explicit verbose check objects, skip passes.
            if "check" in e or "outcome" in e:
                continue
        method = e.get("method") or (e.get("operation") or {}).get("method") if isinstance(e.get("operation"), dict) else e.get("method")
        route = e.get("path") or e.get("route") or (e.get("operation") or {}).get("path") if isinstance(e.get("operation"), dict) else e.get("path")
        check = e.get("check") or e.get("check_name") or e.get("name") or "api-logic-failure"
        msg = e.get("message") or e.get("detail") or e.get("error") or ""
        loc = f"{(method or 'HTTP').upper()} {route or e.get('url') or ''}".strip()
        sev = _schemathesis_severity(str(check), str(msg), e.get("status_code"))
        out.append({
            "source": "schemathesis",
            "rule_id": f"schemathesis/{check}",
            "name": f"API logic: {check}",
            "severity": sev,
            "matched_at": e.get("url") or loc,
            "matcher": str(check),
            "evidence": str(msg)[:400] or loc[:400],
            "raw": e,
        })
    return out


def _schemathesis_severity(check: str, msg: str, status_code) -> str:
    blob = f"{check} {msg} {status_code}".lower()
    if "500" in blob or "internal server error" in blob or "crash" in blob:
        return "high"
    if "schema" in blob or "conformance" in blob or "validation" in blob:
        return "medium"
    if "unauthorized" in blob or "auth" in blob or "bola" in blob or "idor" in blob:
        return "high"
    return "medium"


def dedupe_key(f: dict) -> str:
    loc = re.sub(r"\s+", " ", (f.get("matched_at") or "").strip().lower())
    rule = (f.get("rule_id") or f.get("name") or "").strip().lower()
    ev = (f.get("evidence") or "")[:120].strip().lower()
    h = hashlib.sha1(f"{rule}|{loc}|{ev}".encode("utf-8", "ignore")).hexdigest()[:16]
    return f"{f.get('source')}:{rule}:{h}"


def merge_findings(*lists: list[dict]) -> tuple[list[dict], int]:
    """Merge + dedupe; split verified vs quarantined (no evidence)."""
    seen: dict[str, dict] = {}
    for lst in lists:
        for f in lst:
            k = dedupe_key(f)
            if k not in seen:
                seen[k] = f
    verified, quarantined = [], []
    for f in seen.values():
        has_rule = bool(f.get("rule_id"))
        has_loc = bool((f.get("matched_at") or "").strip())
        has_ev = bool((f.get("evidence") or "").strip())
        f["confidence"] = "verified" if (has_rule and has_loc and has_ev) else "low"
        (verified if f["confidence"] == "verified" else quarantined).append(f)
    verified.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 0), reverse=True)
    return verified, len(quarantined)


def parse_run_coverage(log_text: str, cmdline: str = "") -> dict:
    """Extract real coverage signals from nuclei run.log + command line.

    Two-phase logs contain the counters twice (signatures + DAST): templates
    and requests are summed, targets take the max. Never invent numbers.
    Also counts DAST phases and exposes per-phase template counts so a
    DAST-only 51-template run can never masquerade as a full 9k audit.
    """
    def total(pat: str) -> int:
        return sum(int(x) for x in re.findall(pat, log_text or "", re.IGNORECASE))

    def maxt(pat: str) -> int:
        vals = [int(x) for x in re.findall(pat, log_text or "", re.IGNORECASE)]
        return max(vals) if vals else 0

    blob = f"{log_text or ''}\n{cmdline or ''}".lower()
    phases = len(re.findall(r"phase \d+/", log_text or "", re.IGNORECASE)) or 1
    cov = {
        "targets_loaded": maxt(r"targets loaded for current scan:\s*(\d+)"),
        "templates_loaded": total(r"templates loaded for current scan:\s*(\d+)"),
        "requests_sent": total(r"http connections:\s*(\d+)\s*total"),
        "phases": phases,
        "dast_enabled": ("-dast" in blob or "dast" in blob),
        "dast_only": ("-dast" in blob and "phase 1" not in (log_text or "").lower())
        or (phases == 1 and "-dast" in (cmdline or "").lower()),
        "input_mode": (re.search(r"-im\s+([a-z]+)", blob).group(1) if re.search(r"-im\s+([a-z]+)", blob) else ""),
        "tags": (re.search(r"-tags\s+([a-z0-9_,\-]+)", blob).group(1) if re.search(r"-tags\s+([a-z0-9_,\-]+)", blob) else ""),
        "scan_time": "",
    }
    m = re.search(r"scan completed in\s*([0-9a-zA-Z\.\s]+)", log_text or "", re.IGNORECASE)
    if m:
        cov["scan_time"] = m.group(1).split(".")[0]
    stm = re.search(r"schemathesis:\s*ran=(\d)", log_text or "", re.IGNORECASE)
    cov["st_ran"] = stm.group(1) == "1" if stm else False
    return cov


def build_controls(coverage: dict, nuclei_count: int, schema_count: int) -> list[dict]:
    """Derive control status from what actually ran — no blanket Passed.

    Status: TESTED (evidence/coverage present) / SKIPPED (flag/tag absent) /
    INCONCLUSIVE (ran but zero requests/endpoints).
    """
    tags = (coverage.get("tags") or "").lower()
    dast = bool(coverage.get("dast_enabled"))
    dast_only = bool(coverage.get("dast_only"))
    mode = (coverage.get("input_mode") or "").lower()
    reqs = coverage.get("requests_sent", 0)
    ran_anything = reqs > 0 or nuclei_count > 0 or coverage.get("templates_loaded", 0) > 0

    def status(wanted_tags: tuple[str, ...], needs_dast: bool = False, needs_api: bool = False,
               needs_signatures: bool = False) -> str:
        if needs_dast and not dast:
            return "SKIPPED"
        if needs_api and mode not in ("openapi", "swagger"):
            return "SKIPPED"
        if needs_signatures and dast_only:
            # DAST-only run loads ~50 fuzz templates; the ~9k signature
            # templates (CVE/exposure/panel) never executed.
            return "SKIPPED"
        if wanted_tags and tags and not any(t in tags for t in wanted_tags):
            return "SKIPPED"
        if not ran_anything:
            return "INCONCLUSIVE"
        return "TESTED"

    has_schema = schema_count > 0 or mode in ("openapi", "swagger")
    return [
        {"name": "Dynamic Injection Fuzzing (DAST)", "status": status((), needs_dast=True),
         "desc": "Fault-injection over query/body/header/path (requires -dast)"},
        {"name": "SQL & NoSQL Injection", "status": status(("sqli", "owasp", "dast")),
         "desc": "DB escape / blind injection payloads"},
        {"name": "Cross-Site Scripting (XSS)", "status": status(("xss", "owasp", "dast")),
         "desc": "Reflected/stored context checks"},
        {"name": "RCE / Command Injection", "status": status(("rce", "owasp"), needs_signatures=True),
         "desc": "OS command / code-exec sinks (signature templates; skipped in DAST-only runs)"},
        {"name": "SSRF / OAST", "status": status(("ssrf", "owasp"), needs_signatures=True),
         "desc": "Interactsh out-of-band probing (signature templates; skipped in DAST-only runs)"},
        {"name": "SSTI", "status": status(("ssti",), needs_dast=True),
         "desc": "Template interpolation payloads"},
        {"name": "BOLA / IDOR (API)", "status": status(("api", "owasp"), needs_api=True) if has_schema else "SKIPPED",
         "desc": "Cross-object access; needs OpenAPI + schemathesis/stateful run"},
        {"name": "API Schema Conformance", "status": "TESTED" if coverage.get("st_ran") else "SKIPPED",
         "desc": "500s, response-vs-schema, validation bypass (auto schemathesis phase; skipped when binary absent)"},
        {"name": "Auth / Session Flaws", "status": status(("misconfig", "exposure"), needs_signatures=True),
         "desc": "Missing auth, defaults, leaks (signature templates; skipped in DAST-only runs)"},
        {"name": "Exposure / Panels / Headers / CORS / SSL", "status": status(("exposure", "panel", "misconfig", "ssl", "cors", "tech"), needs_signatures=True),
         "desc": "Discovery + hardening checks (signature templates; skipped in DAST-only runs)"},
    ]


def verdict(findings: list[dict], coverage: dict) -> tuple[str, str, str]:
    """Return (grade, label, explain). Zero findings with thin coverage != clean.

    Guardrails (empirical from this incident):
    - 0 requests/targets -> Inconclusive.
    - DAST-only single phase with ~50 templates / <20 requests per target ->
      Inconclusive LOW-COVERAGE (the old fake-A+ shape: 1 target, 51 tmpl, 4 req).
    - Broad web/API scans should show hundreds of templates and requests;
      anything under the floor is flagged, never graded A+.
    """
    reqs = coverage.get("requests_sent", 0)
    targets = coverage.get("targets_loaded", 0) or 1
    tmpls = coverage.get("templates_loaded", 0)
    if not findings:
        if reqs == 0 and coverage.get("targets_loaded", 0) == 0:
            return "I", "#94a3b8", "Inconclusive — no targets/requests observed in run.log"
        per_target = reqs / max(targets, 1)
        if coverage.get("dast_only") and (tmpls <= 100 or per_target < 20):
            return "I", "#facc15", (
                f"Inconclusive LOW-COVERAGE — DAST-only phase ({tmpls} templates, "
                f"{reqs} requests / {targets} target). Signature templates were skipped; re-run two-phase scan."
            )
        if tmpls < 100 or per_target < 5:
            return "I", "#facc15", (
                f"Inconclusive LOW-COVERAGE — {tmpls} templates, {reqs} requests / "
                f"{targets} target(s). Below minimum audit floor; do not call clean."
            )
        return "A+", "#10b981", "Clean Assessment — zero verified findings with observed coverage"
    crit = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    med = sum(1 for f in findings if f.get("severity") == "medium")
    if crit:
        return "F", "#f43f5e", f"Critical Risk — {crit} critical verified"
    if high:
        return "D", "#f59e0b", f"High Risk — {high} high verified"
    if med:
        return "C", "#facc15", "Moderate Risk — medium verified"
    return "B", "#3b82f6", "Low Risk — low/info verified"


def build_genuine_report(job_dir: Path) -> dict:
    """Read job_dir artifacts, write genuine-report.{json,sarif,md}, return summary."""
    job_dir = Path(job_dir)
    log_path = job_dir / "run.log"
    log_text = log_path.read_text(encoding="utf-8", errors="ignore") if log_path.exists() else ""
    cmdline = ""
    for line in log_text.splitlines()[:5]:
        if line.startswith("$"):
            cmdline = line
            break
    nuclei = parse_nuclei_results(job_dir / "results.json")
    schema = parse_schemathesis_report(job_dir / "schemathesis.json")
    verified, quarantined = merge_findings(nuclei, schema)
    coverage = parse_run_coverage(log_text, cmdline)
    controls = build_controls(coverage, len(nuclei), len(schema))
    grade, color, label = verdict(verified, coverage)
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in verified:
        sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1

    report = {
        "tool": "Infinity fusion (nuclei + schemathesis + SecLists dictionaries)",
        "grade": grade, "grade_color": color, "label": label,
        "coverage": coverage,
        "severity_counts": sev_counts,
        "verified_findings": len(verified),
        "quarantined_low_confidence": quarantined,
        "schemathesis_findings": len(schema),
        "nuclei_findings": len(nuclei),
        "controls": controls,
        "findings": [
            {"source": f["source"], "rule": f["rule_id"], "name": f["name"],
             "severity": f["severity"], "location": f["matched_at"],
             "evidence": f["evidence"][:300], "confidence": f["confidence"]}
            for f in verified
        ],
    }
    (job_dir / "genuine-report.json").write_text(json.dumps(report, indent=2))
    (job_dir / "genuine-report.sarif").write_text(json.dumps(_to_sarif(report), indent=2))
    (job_dir / "genuine-report.md").write_text(_to_markdown(report))
    return report


def _to_sarif(report: dict) -> dict:
    rules, results = [], []
    seen_rules: dict[str, int] = {}
    for f in report["findings"]:
        rid = f["rule"]
        if rid not in seen_rules:
            seen_rules[rid] = len(rules)
            rules.append({"id": rid, "name": f["name"],
                          "properties": {"severity": f["severity"], "source": f["source"]}})
        results.append({
            "ruleId": rid, "ruleIndex": seen_rules[rid], "level": _sarif_level(f["severity"]),
            "message": {"text": f"{f['name']} @ {f['location']} | evidence: {f['evidence'][:200]}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f['location']}}}],
        })
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "Infinity fusion genuine report",
                                           "version": "1.0", "rules": rules}},
                      "results": results,
                      "properties": {"coverage": report["coverage"], "verdict": report["label"]}}]}


def _sarif_level(sev: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning"}.get(sev, "note")


def _to_markdown(report: dict) -> str:
    lines = [f"# Genuine Security Report — {report['label']}", "",
             f"Grade: **{report['grade']}** | Verified: **{report['verified_findings']}** "
             f"| Quarantined (low confidence): **{report['quarantined_low_confidence']}**",
             f"Nuclei: {report['nuclei_findings']} | Schemathesis: {report['schemathesis_findings']}", "",
             "## Coverage (observed, not claimed)",
             f"- targets_loaded: {report['coverage']['targets_loaded']}",
             f"- templates_loaded: {report['coverage']['templates_loaded']}",
             f"- requests_sent: {report['coverage']['requests_sent']}",
             f"- dast: {report['coverage']['dast_enabled']} | input_mode: {report['coverage']['input_mode'] or '-'} | tags: {report['coverage']['tags'] or '-'}",
             f"- schemathesis API-logic phase: {'ran' if report['coverage'].get('st_ran') else 'skipped (binary absent or non-API target)'}", "",
             "## Controls (TESTED / SKIPPED / INCONCLUSIVE only)",
             "| Control | Status | Scope |",
             "|---|---|---|"]
    for c in report["controls"]:
        lines.append(f"| {c['name']} | {c['status']} | {c['desc']} |")
    lines += ["", "## Verified findings (evidence required)", "| Source | Severity | Rule | Location | Evidence |",
              "|---|---|---|---|---|"]
    for f in report["findings"][:100]:
        lines.append(f"| {f['source']} | {f['severity']} | {f['rule']} | {f['location'][:80]} | {(f['evidence'] or '')[:80]} |")
    if not report["findings"]:
        lines.append("| - | - | no verified findings | check coverage above before calling this clean | - |")
    return "\n".join(lines) + "\n"
