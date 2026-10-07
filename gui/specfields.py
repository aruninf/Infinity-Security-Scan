"""Required-input detection for Infinity scans — ask the user, don't silently skip.

The nuclei engine resolves an OpenAPI parameter value as:
  -V vars override -> schema default -> schema example -> enum[0]
  -> synthetic generated example (with -sfv) / SKIP request (without -sfv).

Synthetic values keep requests flowing but are weak for identity params:
`/documents/{id}` with a generated id returns 404, so BOLA/IDOR is never truly
tested. This module mirrors the engine's "missing" definition and returns the
ask-list so the UI/CLI can prompt for REAL values (real object ids from the
test account, tenant ids, etc.) which are then passed as -V vars.

Also reports auth schemes (login creds needed) and OTP-gated registration
(sign-up requires out-of-band verification -> must be completed manually once;
the scanner then logs in with the verified account via autoauth).
"""

from __future__ import annotations

import json

HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD")


def _resolve_ref(node: dict, spec: dict, depth: int = 0):
    while isinstance(node, dict) and "$ref" in node and depth < 5:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            break
        cur = spec
        try:
            for part in ref[2:].split("/"):
                cur = cur[part.replace("~1", "/").replace("~0", "~")]
            node = cur
            depth += 1
        except (KeyError, TypeError):
            break
    return node


def _schema_has_value(schema: dict, spec: dict) -> bool:
    schema = _resolve_ref(schema or {}, spec)
    if not isinstance(schema, dict):
        return False
    if schema.get("default") is not None or schema.get("example") is not None:
        return True
    if schema.get("enum"):
        return True
    return False


def extract_required_inputs(spec: dict, user_vars: dict | None = None) -> dict:
    """Return {required_vars, auth, otp, counts} for an OpenAPI/Swagger dict."""
    user_vars = user_vars or {}
    spec = spec or {}
    params: dict[str, dict] = {}

    def note(name: str, where: str, path: str, has_default: bool):
        e = params.setdefault(name, {"key": name, "locations": [], "paths": [], "has_default": True})
        if where not in e["locations"]:
            e["locations"].append(where)
        if len(e["paths"]) < 8:
            e["paths"].append(path)
        elif len(e["paths"]) == 8:
            e["paths"].append("...")
        e["has_default"] = e["has_default"] and has_default

    paths = spec.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters") or []
        for method, op in item.items():
            if method.upper() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            seen = set()
            for p in list(shared) + list(op.get("parameters") or []):
                p = _resolve_ref(p, spec)
                if not isinstance(p, dict) or "name" not in p:
                    continue
                name = p["name"]
                where = str(p.get("in", "")).lower()
                if (name, where) in seen:
                    continue
                seen.add((name, where))
                required = bool(p.get("required")) or where == "path"
                if not required:
                    continue
                if name in user_vars:
                    continue  # user already supplied a real value
                has_default = _schema_has_value(p.get("schema"), spec) or p.get("example") is not None or bool(p.get("examples"))
                note(name, where, f"{method.upper()} {path}", has_default)

    required_vars = sorted(params.values(), key=lambda e: (e["has_default"], e["key"]))

    schemes = ((spec.get("components") or {}).get("securitySchemes") or {})
    auth = {"bearer": False, "api_key": False, "basic": False, "oauth": False, "schemes": sorted(schemes.keys())}
    for s in schemes.values():
        s = _resolve_ref(s, spec)
        t = str((s or {}).get("type", "")).lower()
        if t == "http" and str((s or {}).get("scheme", "")).lower() == "bearer":
            auth["bearer"] = True
        elif t == "apikey":
            auth["api_key"] = True
        elif t == "http":
            auth["basic"] = True
        elif t == "oauth2":
            auth["oauth"] = True

    # OTP-gated registration: signup/register endpoint whose body needs a
    # verification/OTP token the scanner cannot obtain out-of-band.
    otp: list[dict] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        pl = path.lower()
        if "sign-up" not in pl and "signup" not in pl and "register" not in pl:
            continue
        for method, op in item.items():
            if method.upper() not in ("POST", "PUT") or not isinstance(op, dict):
                continue
            content = (((op.get("requestBody") or {}).get("content") or {}).get("application/json") or {})
            schema = _resolve_ref(content.get("schema") or {}, spec)
            props = schema.get("properties") or {}
            gated = [k for k in props
                     if "verif" in k.lower() or "otp" in k.lower() or k.lower().endswith("token")]
            if gated:
                otp.append({"endpoint": f"{method.upper()} {path}", "needs": sorted(gated),
                            "note": "requires out-of-band email/SMS verification; complete once manually, then scan with that account"})

    return {
        "required_vars": required_vars,
        "missing_no_default": [e["key"] for e in required_vars if not e["has_default"]],
        "auth": auth,
        "otp_gated_signup": otp,
        "counts": {"paths": len(paths), "required_params": len(required_vars)},
    }


def match_scope(text: str, pattern: str) -> bool:
    """Substring match, or /regex/ match. Empty pattern matches all.

    Only `/.../ ` with a TRAILING slash is treated as regex delimiters;
    a plain absolute path like `/api/v1/auth` is used as-is (regex-tried
    first, substring fallback) so leading slashes are never stripped.
    """
    if not pattern:
        return True
    p = pattern
    if len(p) > 2 and p.startswith("/") and p.endswith("/"):
        p = p[1:-1]
    try:
        import re
        if re.search(p, text):
            return True
    except Exception:
        pass
    return p in text


def slice_paths(spec: dict, pattern: str) -> tuple[dict, int, int]:
    """Return (sliced_spec, kept, dropped) keeping only matching paths."""
    paths = (spec or {}).get("paths") or {}
    kept = {p: v for p, v in paths.items() if match_scope(p, pattern or "")}
    out = dict(spec)
    out["paths"] = kept
    return out, len(kept), len(paths) - len(kept)


def parse_vars_text(text: str) -> dict:
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip():
            out[k.strip()] = v.strip()
    return out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="List required OpenAPI inputs to ask the user for")
    ap.add_argument("spec", help="path to openapi.json/yaml (json only for yaml-less envs)")
    ap.add_argument("--vars", default="", help="already-provided vars text (key=value lines)")
    a = ap.parse_args()
    raw = open(a.spec, encoding="utf-8").read()
    try:
        doc = json.loads(raw)
    except Exception as e:
        print(f"could not parse spec as JSON: {e}")
        raise SystemExit(2)
    rep = extract_required_inputs(doc, parse_vars_text(a.vars))
    print(f"paths={rep['counts']['paths']} required_params={rep['counts']['required_params']}")
    for e in rep["required_vars"]:
        flag = "synthetic-ok" if e["has_default"] else "ASK-USER (no default; synthetic id -> likely 404, BOLA untested)"
        print(f"  {e['key']} [{','.join(e['locations'])}] {flag} e.g. {e['paths'][0] if e['paths'] else ''}")
    if rep["auth"]["schemes"]:
        print("auth schemes:", ", ".join(rep["auth"]["schemes"]), "-> provide login creds (auto-login), not a pasted token")
    for o in rep["otp_gated_signup"]:
        print(f"otp-gated: {o['endpoint']} needs {o['needs']} -> {o['note']}")
