#!/usr/bin/env bash
# Infinity fused scan — CLI without GUI.
# Phase 0 (optional): schemathesis API-logic  (needs: uvx schemathesis, OpenAPI file/URL)
# Phase 1 (always):   nuclei signatures WITHOUT -dast (full CVE/exposure/panel set)
# Phase 2 (optional): nuclei DAST/fuzz WITH -dast (fuzzable requests only)
# Phase 3 (always):   genuine-report merge      (needs: python3 gui/fusion.py)
#
# Why two nuclei phases? With -dast the loader keeps ONLY fuzzable templates
# (~50); without it you get the full set (~9k for broad tags). Running
# tags+-dast in one command silently drops 99% of checks and yields 4-request
# fake-A+ scans. Never combine them in a single run.
#
# SecLists is referenced via $SECLISTS_DIR only — never vendored.
# Usage:
#   ./tools/fused-scan.sh -spec api-spec.json -out out/ [-tags owasp,cve,misconfig] [-no-dast] [-max-examples 50]
#   ./tools/fused-scan.sh -target https://example.com -out out/
#   ./tools/fused-scan.sh -spec api-spec.json -out out/ -auth 'user@example.com:Password123!' -auth-base http://10.20.20.9:8080
#   ./tools/fused-scan.sh -spec api-spec.json -out out/ -scope /api/v1/auth -V id=real-uuid -V parentId=real-id
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT=""; SPEC=""; TARGET=""; TAGS="owasp,cve,misconfig"; DAST=1; MAX_EXAMPLES="50"; AUTH=""; AUTH_BASE=""; SCOPE=""; VARS=()

while [[ $# -gt 0 ]]; do case "$1" in
  -spec) SPEC="$2"; shift 2;;
  -target) TARGET="$2"; shift 2;;
  -out) OUT="$2"; shift 2;;
  -tags) TAGS="$2"; shift 2;;
  -no-dast) DAST=0; shift;;
  -max-examples) MAX_EXAMPLES="$2"; shift 2;;
  -auth) AUTH="$2"; shift 2;;
  -auth-base) AUTH_BASE="$2"; shift 2;;
  -scope) SCOPE="$2"; shift 2;;
  -V) VARS+=("$2"); shift 2;;
  *) echo "unknown arg $1" >&2; exit 2;;
esac; done
[[ -z "$OUT" ]] && { echo "-out required" >&2; exit 2; }
mkdir -p "$OUT" "$OUT/md"
chmod 700 "$OUT"
# vars for nuclei -V and schemathesis real-id bindings (REAL object ids -> BOLA coverage)
VAR_FLAGS=(); VARS_JSON_CONTENT="{"
for kv in "${VARS[@]:-}"; do
  [[ -z "$kv" ]] && continue
  VAR_FLAGS+=(-V "$kv"); VARS_JSON_CONTENT="$VARS_JSON_CONTENT$(python3 -c "import json,sys; k,v=sys.argv[1].split('=',1); print(json.dumps(k)+':'+json.dumps(v)+',')" "$kv")"
done
VARS_JSON_CONTENT="${VARS_JSON_CONTENT%,}}"
printf '%s' "$VARS_JSON_CONTENT" > "$OUT/st-vars.json"
chmod 600 "$OUT/st-vars.json"

# --- Path scope: module-only scans (e.g. auth layer) ---
if [[ -n "$SCOPE" && -n "$SPEC" && -f "$SPEC" ]]; then
  python3 - "$SPEC" "$SCOPE" "$OUT/spec.scoped.json" <<'PY'
import json,sys
sys.path.insert(0, "gui")
from specfields import slice_paths
doc=json.load(open(sys.argv[1]))
sliced,kept,dropped=slice_paths(doc,sys.argv[2])
assert kept>0, f"scope matched 0 paths"
json.dump(sliced,open(sys.argv[3],"w"))
print(f"[fusion] scope '{sys.argv[2]}': {kept} kept, {dropped} dropped")
PY
  SPEC="$OUT/spec.scoped.json"
fi

# --- Phase -1: auto-login (fresh Bearer token, never logged) ---
AUTH_HDR=()
if [[ -n "$AUTH" ]]; then
  AID="${AUTH%%:*}"; APW="${AUTH#*:}"
  [[ -z "$AUTH_BASE" ]] && { echo "-auth-base required with -auth" >&2; exit 2; }
  TOKEN="$(python3 "$ROOT/gui/autoauth.py" --base "$AUTH_BASE" --id "$AID" --pw "$APW" --print-token)" || { echo "[fusion] auto-login failed (see above); aborting instead of running an unauthenticated fake-clean scan" >&2; exit 1; }
  if ! python3 "$ROOT/gui/autoauth.py" --base "$AUTH_BASE" --token "$TOKEN" --verify; then
    echo "[fusion] token REJECTED by the API (see above); aborting instead of running an unauthenticated fake-clean scan" >&2; exit 1
  fi
  printf 'Authorization: Bearer %s\n' "$TOKEN" > "$OUT/auth-headers.txt"
  chmod 600 "$OUT/auth-headers.txt"
  unset TOKEN
  AUTH_HDR=(-H "$OUT/auth-headers.txt")
  echo "[fusion] auto-login OK (token stored 0600, excluded from logs)"
fi

# --- Phase -2: required-input ask-list (never silently skip) ---
if [[ -n "$SPEC" && -f "$SPEC" ]]; then
  echo "[fusion] required inputs in spec (fill with REAL values via -V key=value / vars file; IDs back BOLA coverage):"
  python3 "$ROOT/gui/specfields.py" "$SPEC" 2>/dev/null | head -n 20 || true
fi

# --- Phase 0: schemathesis API-logic (prefilled toml: auth + real-ids + SecLists) ---
SCHEMA_JSON="$OUT/schemathesis.json"
: > "$SCHEMA_JSON" || true
if [[ -n "$SPEC" ]]; then
  if command -v schemathesis >/dev/null 2>&1 || command -v uvx >/dev/null 2>&1; then
    ST_BIN=(schemathesis); command -v schemathesis >/dev/null 2>&1 || ST_BIN=(uvx schemathesis)
    echo "[fusion] phase0 schemathesis (prefilled: max-examples=50, phases=fuzzing+stateful, junit report)"
    SPEC_ABS="$(cd "$(dirname "$SPEC")" && pwd)/$(basename "$SPEC")"
    OUT_ABS="$(cd "$OUT" && pwd)"
    HDR_FILE="$OUT_ABS/auth-headers.txt"
    VARS_JSON="$OUT_ABS/st-vars.json"
    python3 - "$SPEC_ABS" "$VARS_JSON" "$HDR_FILE" "$OUT_ABS" "$MAX_EXAMPLES" <<'PY'
import json,sys,os
sys.path.insert(0, "gui")
from pathlib import Path
import stconfig, specfields
spec_path, vars_path, hdr_path, out = sys.argv[1], sys.argv[2], sys.argv[3], Path(sys.argv[4])
max_ex = int(sys.argv[5]) if len(sys.argv) > 5 else 50
doc = json.loads(Path(spec_path).read_text())
user_vars = json.loads(Path(vars_path).read_text()) if Path(vars_path).exists() else {}
hdrs = Path(hdr_path).read_text().splitlines() if Path(hdr_path).exists() else []
info = stconfig.build_job_config(out, doc, user_vars, hdrs, max_examples=max_ex)
print(f"[fusion] st toml: real_ids_bound={info['real_ids_bound']} seclists={bool(info['seclists_dir'])}")
PY
    (cd "$OUT_ABS" && "${ST_BIN[@]}" run "$SPEC_ABS" --phases fuzzing,stateful \
      --report junit --report-dir "$OUT_ABS/st" --max-examples "$MAX_EXAMPLES" 2>&1 | tee "$OUT_ABS/schemathesis.log") || true
    python3 - "$OUT_ABS" <<'PY' || true
import json,sys,glob
sys.path.insert(0, "gui")
from pathlib import Path
from stconfig import junit_to_failures
out = Path(sys.argv[1])
xmls = sorted(glob.glob(str(out / "st" / "*.xml")))
fails = junit_to_failures(Path(xmls[0])) if xmls else []
norm = [{"status": "failed", **f} for f in fails]
(out / "schemathesis.json").write_text(json.dumps({"failures": norm, "meta": {"junit": Path(xmls[0]).name if xmls else ""}}, indent=2))
print(f"[fusion] schemathesis: ran=1 findings={len(norm)}")
PY
  else
    echo "[fusion] schemathesis not installed — skipping phase0 (uv tool install schemathesis to enable)" | tee "$OUT/schemathesis.log"
    echo '{"failures":[]}' > "$SCHEMA_JSON"
  fi
else
  echo '{"failures":[]}' > "$SCHEMA_JSON"
fi

# --- Phase 1+2: nuclei (two-phase, merged) ---
ENGINE="${NUCLEI_BIN:-$ROOT/bin/nuclei}"
[[ -x "$ENGINE" ]] || { echo "build engine first: make build" >&2; exit 1; }
if [[ -n "$SPEC" ]]; then INPUT=(-l "$SPEC" -im openapi -sfv); else INPUT=(-target "$TARGET"); fi
echo "[fusion] phase1 signatures (no -dast)"
# shellcheck disable=SC2086
"$ENGINE" "${INPUT[@]}" -tags "$TAGS" "${AUTH_HDR[@]}" "${VAR_FLAGS[@]}" \
  -o "$OUT/findings.p1.txt" -je "$OUT/results.p1.json" -se "$OUT/report.p1.sarif" -me "$OUT/md" 2>&1 | tee "$OUT/run.log"
if [[ "$DAST" == 1 ]]; then
  echo "[fusion] phase2 DAST fuzz (with -dast)"
  # shellcheck disable=SC2086
  "$ENGINE" "${INPUT[@]}" -tags "$TAGS" -dast "${AUTH_HDR[@]}" "${VAR_FLAGS[@]}" \
    -o "$OUT/findings.p2.txt" -je "$OUT/results.p2.json" -se "$OUT/report.p2.sarif" -me "$OUT/md" 2>&1 | tee -a "$OUT/run.log"
else
  echo "[fusion] DAST skipped (-no-dast)"
fi
python3 - "$OUT" <<'PY'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
merged = []
for name in ("results.p1.json", "results.p2.json"):
    p = out / name
    if p.exists() and p.stat().st_size:
        try:
            doc = json.loads(p.read_text())
            merged += doc if isinstance(doc, list) else [doc]
        except Exception:
            for line in p.read_text().splitlines():
                try: merged.append(json.loads(line))
                except Exception: pass
(out / "results.json").write_text(json.dumps(merged, indent=2) if merged else "[]")
with open(out / "findings.txt", "w") as fh:
    for name in ("findings.p1.txt", "findings.p2.txt"):
        p = out / name
        if p.exists() and p.stat().st_size: fh.write(p.read_text() + "\n")
PY

# --- SecLists hint (reference only) ---
if [[ -n "${SECLISTS_DIR:-}" && -d "${SECLISTS_DIR}" ]]; then
  echo "[fusion] SECLISTS_DIR=$SECLISTS_DIR (see tools/seclists-profiles.yaml for curated files)"
else
  echo "[fusion] SECLISTS_DIR not set — discovery/fuzz dictionaries skipped (optional)"
fi

# --- Phase 3: genuine merge ---
cp "$SCHEMA_JSON" "$OUT/schemathesis.json" 2>/dev/null || true
python3 - "$OUT" <<'PY'
import sys; sys.path.insert(0, "gui")
from pathlib import Path
from fusion import build_genuine_report
rep = build_genuine_report(Path(sys.argv[1]))
print(f"[fusion] grade={rep['grade']} verified={rep['verified_findings']} "
      f"quarantined={rep['quarantined_low_confidence']} nuclei={rep['nuclei_findings']} schema={rep['schemathesis_findings']}")
print(f"[fusion] verdict: {rep['label']}")
PY
echo "[fusion] artifacts: $OUT/genuine-report.json $OUT/genuine-report.sarif $OUT/genuine-report.md"
