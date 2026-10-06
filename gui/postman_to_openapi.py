"""Convert a Postman Collection (v2.0/v2.1 JSON) to a minimal OpenAPI 3.0 spec.

Only what nuclei's `-im openapi` needs is generated: servers, paths,
method, query/header/path params, and a best-effort requestBody.
Postman variables ({{var}}) are replaced with a placeholder value since
OpenAPI has no equivalent.
"""

from __future__ import annotations

import json
import re
import sys
from urllib.parse import urlparse

VAR_RE = re.compile(r"\{\{([^}]+)\}\}")


def _clean(value: str, placeholder: str = "test") -> str:
    return VAR_RE.sub(placeholder, value or "")


def _parse_url(url):
    """Return (server_base, path, query_list). query_list = [(key, value)]."""
    if isinstance(url, str):
        raw = _clean(url)
    elif isinstance(url, dict):
        raw = _clean(url.get("raw", ""))
        if not raw:
            host = url.get("host", "")
            host_s = ".".join(host) if isinstance(host, list) else str(host or "")
            path = url.get("path", "")
            path_s = ("/" + "/".join(path)) if isinstance(path, list) else str(path or "")
            raw = f"https://{host_s}{path_s}" if host_s else path_s
    else:
        return None, "/", []
    if raw.startswith("{{") or not raw:
        return None, "/", []
    if "://" not in raw:
        raw = "https://" + raw.lstrip("/")
    try:
        p = urlparse(raw)
    except Exception:
        return None, "/", []
    if not p.hostname:
        return None, "/", []
    base = f"{p.scheme or 'https'}://{p.hostname}"
    if p.port:
        base += f":{p.port}"
    path = p.path or "/"
    queries = []
    if isinstance(url, dict) and isinstance(url.get("query"), list):
        for q in url["query"]:
            if isinstance(q, dict) and not q.get("disabled"):
                queries.append((q.get("key", ""), q.get("value", "test")))
    return base, path, queries


def _walk_items(items):
    for it in items or []:
        if "item" in it:  # folder
            yield from _walk_items(it["item"])
        elif "request" in it:
            yield it.get("name", "request"), it["request"]


def _request_parts(req):
    """Normalize postman request -> (method, url, headers, body, auth)."""
    if isinstance(req, str):
        return "GET", req, [], None, {}
    method = (req.get("method") or "GET").lower()
    url = req.get("url", "")
    headers = [
        h for h in (req.get("header") or [])
        if isinstance(h, dict) and h.get("key") and not h.get("disabled")
    ]
    return method, url, headers, req.get("body"), req.get("auth") or {}


def convert(collection: dict) -> dict:
    servers: dict[str, None] = {}
    paths: dict = {}
    security_schemes: dict = {}
    top_security: list = []

    for name, req in _walk_items(collection.get("item")):
        method, url, headers, body, auth = _request_parts(req)
        base, path, queries = _parse_url(url)
        if base is None:
            continue
        servers[base] = None
        path = _clean(path) or "/"

        params: list = []
        seen_path_params = set(re.findall(r"\{([^}]+)\}", path))
        for key, val in queries:
            if not key:
                continue
            params.append({
                "name": key, "in": "query", "required": False,
                "schema": {"type": "string"},
                "example": _clean(str(val)) or "test",
            })
        for h in headers:
            params.append({
                "name": h["key"], "in": "header", "required": False,
                "schema": {"type": "string"},
                "example": _clean(str(h.get("value", ""))) or "test",
            })
        for pp in seen_path_params:
            params.append({
                "name": pp, "in": "path", "required": True,
                "schema": {"type": "string"}, "example": "test",
            })

        # --- auth -> header/query param + reusable securityScheme ---
        op_security: list = []
        atype = (auth.get("type") or "").lower()
        if atype == "apikey":
            kv = {d.get("key"): d.get("value") for d in (auth.get("apikey") or []) if isinstance(d, dict)}
            key = _clean(str(kv.get("key", "X-API-Key")))
            val = _clean(str(kv.get("value", "test")))
            where = str(kv.get("in", "header")).lower()
            params.append({
                "name": key, "in": "query" if where == "query" else "header",
                "required": False, "schema": {"type": "string"}, "example": val or "test",
            })
            security_schemes["apiKeyAuth"] = {
                "type": "apiKey", "in": where if where in ("query", "header") else "header",
                "name": key,
            }
            op_security.append({"apiKeyAuth": []})
        elif atype == "basic":
            security_schemes["basicAuth"] = {"type": "http", "scheme": "basic"}
            op_security.append({"basicAuth": []})
        elif atype == "bearer":
            security_schemes["bearerAuth"] = {"type": "http", "scheme": "bearer"}
            op_security.append({"bearerAuth": []})

        # --- body -> best-effort JSON body ---
        request_body = None
        if isinstance(body, dict) and body.get("mode") == "raw":
            raw = _clean(str(body.get("raw", "")))
            if raw and method in ("post", "put", "patch", "delete"):
                try:
                    example = json.loads(raw)
                except Exception:
                    example = raw
                request_body = {"content": {"application/json": {"schema": {}, "example": example}}}

        op = {
            "summary": _clean(str(name))[:120],
            "parameters": params,
            "responses": {"200": {"description": "OK"}},
        }
        if request_body:
            op["requestBody"] = request_body
        if op_security:
            op["security"] = op_security
        paths.setdefault(path, {})[method] = op

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Converted from Postman", "version": "1.0.0"},
        "servers": [{"url": s} for s in servers] or [{"url": "https://example.com"}],
        "paths": paths,
    }
    if security_schemes:
        spec["components"] = {"securitySchemes": security_schemes}
    if top_security:
        spec["security"] = top_security
    return spec


def main() -> None:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} collection.json openapi.json")
        sys.exit(2)
    with open(sys.argv[1]) as f:
        collection = json.load(f)
    spec = convert(collection)
    with open(sys.argv[2], "w") as f:
        json.dump(spec, f, indent=2)
    print(f"wrote {sys.argv[2]}: {len(spec['paths'])} paths, {len(spec['servers'])} servers")


if __name__ == "__main__":
    main()
