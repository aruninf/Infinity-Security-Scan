"""Auto-auth for Infinity scans — log in with an account, scan with its token.

Instead of pasting `Authorization: Bearer <token>` manually, provide the
account credentials once; this module calls the API's own login endpoints,
extracts the JWT, and returns it for scan-time header injection.

Supports the common shape seen in OpenAPI specs (e.g. /api/v1/auth/sign-in,
/api/v1/auth/login with {identifier, password} -> JSON containing
accessToken/access_token/token). Registration (sign-up) is intentionally NOT
automated: most APIs gate it behind email/SMS OTP verification tokens, so a
"create account" button would silently produce unverified sessions. Create the
test account once in the app, then let every scan log in fresh (tokens expire).

Secrets hygiene: tokens are never printed by this module except via
--print-token (for local scripting). Callers must redact them from logs and
store them with 0600 permissions. Job dirs are gitignored (/gui/jobs/).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
import urllib.error

LOGIN_PATHS = ("/api/v1/auth/sign-in", "/api/v1/auth/login", "/api/v1/login", "/api/login", "/auth/login", "/api/auth/login")
ME_PATHS = ("/api/v1/auth/me", "/api/v1/users/me", "/api/v1/profile/me", "/api/me", "/me")
TOKEN_KEYS = ("accessToken", "access_token", "token", "idToken", "id_token", "authToken", "jwt", "jwtToken")
NEXT_STEP_KEYS = ("nextStep", "next_step", "challenge", "mfaRequired", "requiresMfa")


def origin(url: str) -> str:
    """Reduce any URL/endpoint pasted by the user to its origin.

    Users paste things like http://host:8080/api/auth/login or bare
    host:8080 — login probing needs scheme://host:port, never the path.
    """
    from urllib.parse import urlsplit
    u = (url or "").strip().split()[0] if (url or "").strip() else ""
    if u and "://" not in u:
        u = "http://" + u
    try:
        p = urlsplit(u)
        if p.hostname:
            host = p.hostname
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            netloc = host + (f":{p.port}" if p.port else "")
            return f"{p.scheme or 'http'}://{netloc}"
    except Exception:
        pass
    return (u or "").rstrip("/")


def mask(token: str) -> str:
    if not token:
        return ""
    if len(token) <= 10:
        return "***"
    return f"{token[:6]}...{token[-4:]}"


def _find_first(obj, keys: tuple[str, ...]):
    """Recursively find first string value under any of keys (case-insensitive)."""
    want = {k.lower() for k in keys}
    best = None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and k.lower() in want and len(v) >= 8:
                if best is None or len(v) > len(best):
                    best = v
            found = _find_first(v, keys)
            if found and (best is None or len(found) > len(best)):
                best = found
    elif isinstance(obj, list):
        for v in obj:
            found = _find_first(v, keys)
            if found and (best is None or len(found) > len(best)):
                best = found
    return best


def _post_json(url: str, payload: dict, timeout: int) -> tuple[int, dict | str]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "User-Agent": "Infinity-AutoAuth/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(1 * 1024 * 1024).decode("utf-8", "ignore")
            try:
                return resp.status, json.loads(body) if body else {}
            except Exception:
                return resp.status, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(1 * 1024 * 1024).decode("utf-8", "ignore")
            try:
                return e.code, json.loads(body) if body else {}
            except Exception:
                return e.code, body
        except Exception:
            return e.code, str(e)
    except Exception as e:
        return -1, str(e)


def auto_login(base_url: str, identifier: str, password: str, timeout: int = 20) -> dict:
    """Log in, verify the token, return {ok, token, refresh, verified, ...}.

    Never raises; ok=False carries a human-readable detail for the UI.
    verified: True (me-endpoint accepted it) / False (rejected: 401/403) /
    None (no me-endpoint to check against — token untested).
    """
    base = origin(base_url)
    if not base or not identifier or not password:
        return {"ok": False, "verified": None, "detail": "base URL, identifier and password are all required"}
    payload_variants = [
        {"identifier": identifier, "password": password},
        {"email": identifier, "password": password},
        {"username": identifier, "password": password},
    ]
    tried = []
    for path in LOGIN_PATHS:
        url = base + path
        for payload in payload_variants:
            status, doc = _post_json(url, payload, timeout)
            tried.append(f"{path}:{status}")
            if status in (429,):
                return {"ok": False, "verified": None, "detail": f"rate-limited by {path} (429). Wait and retry; do not brute-force."}
            if status == 404:
                break  # path doesn't exist, next path
            if status == -1:
                return {"ok": False, "verified": None, "detail": f"connection failed for {url}: {doc}"}
            if status in (200, 201) and isinstance(doc, dict):
                nxt = _find_first(doc, NEXT_STEP_KEYS)
                if nxt:
                    return {"ok": False, "verified": None, "detail": f"login needs extra step ({nxt}). Complete MFA/OTP in the app, then use a fresh account or paste a token."}
                token = _find_first(doc, TOKEN_KEYS)
                if token:
                    v = verify_token(base, token, timeout)
                    return {"ok": True, "token": token,
                            "refresh": _find_first(doc, ("refreshToken", "refresh_token")) or "",
                            "login_path": path, "detail": f"logged in via {path}",
                            "verified": v["verified"], "verify_detail": v["detail"]}
                return {"ok": False, "verified": None, "detail": f"{path} returned 200 but no token field found (keys tried: {', '.join(TOKEN_KEYS)}). Response keys: {sorted(doc.keys())[:10]}"}
            if status in (200, 201):
                return {"ok": False, "verified": None, "detail": f"{path} returned {status} non-JSON ({str(doc)[:120]}). Login response unreadable."}
            if status in (400, 401, 403, 422):
                msg = doc.get("message") if isinstance(doc, dict) else doc
                last_err = f"{path} -> {status}: {str(msg)[:150]}"
        # fall through to next path
    return {"ok": False, "verified": None, "detail": f"no login endpoint accepted the credentials (tried: {', '.join(tried)}). {locals().get('last_err', '')}"}


def verify_token(base_url: str, token: str, timeout: int = 20) -> dict:
    """Prove the token works: GET a me/profile endpoint with it.

    Returns {verified: True/False/None, detail}. None = no me-endpoint found
    to check against (token untested, not rejected).
    """
    base = origin(base_url)
    tried = []
    for path in ME_PATHS:
        url = base + path
        req = urllib.request.Request(
            url, method="GET",
            headers={"Accept": "application/json", "Authorization": f"Bearer {token}",
                     "User-Agent": "Infinity-AutoAuth/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return {"verified": True, "detail": f"token accepted by {path} ({resp.status})"}
        except urllib.error.HTTPError as e:
            tried.append(f"{path}:{e.code}")
            if e.code == 404:
                continue
            if e.code in (401, 403):
                return {"verified": False, "detail": f"token REJECTED by {path} ({e.code}). Wrong account, expired token, or token belongs to another environment."}
            return {"verified": None, "detail": f"{path} -> {e.code}; cannot confirm token."}
        except Exception as e:
            return {"verified": None, "detail": f"verify request failed: {e}"}
    return {"verified": None, "detail": f"no who-am-i endpoint found (tried: {', '.join(tried)}). Token untested — scan proceeds, watch for 401s in findings."}


def main() -> int:
    ap = argparse.ArgumentParser(description="Log in to API and obtain bearer token")
    ap.add_argument("--base", required=True, help="API base URL or any endpoint URL (reduced to origin)")
    ap.add_argument("--id", required=False, default="", help="login identifier (email/phone)")
    ap.add_argument("--pw", required=False, default="", help="account password")
    ap.add_argument("--token", required=False, default="", help="verify this token instead of logging in")
    ap.add_argument("--verify", action="store_true", help="only verify (with --token) or login+verify")
    ap.add_argument("--print-token", action="store_true", help="print raw token to stdout (local scripting only)")
    a = ap.parse_args()
    if a.verify and a.token and not a.id:
        v = verify_token(a.base, a.token)
        print(json.dumps({"verified": v["verified"], "detail": v["detail"]}))
        return 0 if v["verified"] else 1
    res = auto_login(a.base, a.id, a.pw)
    if res.get("ok"):
        if a.print_token:
            print(res["token"])
        else:
            print(json.dumps({"ok": True, "login_path": res["login_path"],
                              "verified": res.get("verified"), "verify_detail": res.get("verify_detail"),
                              "token": mask(res["token"])}))
        return 0
    print(json.dumps({"ok": False, "detail": res.get("detail")}), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
