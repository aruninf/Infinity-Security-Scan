"""Infinity Security Platform — Automated Web Application Crawler & Route Discovery Engine.

Discovers client-side routes (SPA / Next.js / React), HTML links, form actions,
and active API endpoints across any target web application.
"""

from __future__ import annotations

import concurrent.futures
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Set

COMMON_APP_ROUTES = [
    "/",
    "/login",
    "/signin",
    "/dashboard",
    "/admin",
    "/register",
    "/signup",
    "/forgot-password",
    "/reset-password",
    "/auth",
    "/auth/login",
    "/api",
    "/api/auth",
    "/api/auth/login",
    "/api/v1",
    "/api/v2",
    "/api/users",
    "/api/profile",
    "/profile",
    "/account",
    "/settings",
    "/projects",
    "/tasks",
    "/reports",
    "/timesheet",
    "/attendance",
    "/tracker",
    "/app",
    "/home",
    "/overview",
    "/portal",
    "/docs",
    "/swagger",
    "/openapi.json",
    "/swagger.json",
    "/robots.txt",
    "/sitemap.xml",
]

STATIC_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".map", ".mp4", ".mp3", ".webm", ".pdf", ".zip"
)


def _clean_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") or "/", "", "", ""))


def _is_same_origin(base_origin: str, target_url: str) -> bool:
    try:
        b = urllib.parse.urlparse(base_origin)
        t = urllib.parse.urlparse(target_url)
        return b.scheme == t.scheme and b.netloc == t.netloc
    except Exception:
        return False


def _fetch_page(url: str, headers: dict[str, str] | None = None, timeout: float = 6.0) -> tuple[int, str, str]:
    hdrs = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*",
    }
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read(2 * 1024 * 1024).decode("utf-8", errors="ignore")
            return resp.status, resp.url, content
    except urllib.error.HTTPError as e:
        return e.code, url, ""
    except Exception:
        return 0, url, ""


def _probe_route(url: str, headers: dict[str, str] | None = None, timeout: float = 5.0) -> tuple[str, int]:
    hdrs = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Infinity-Crawler/1.0",
        "Accept": "*/*",
    }
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return url, resp.status
    except urllib.error.HTTPError as e:
        return url, e.code
    except Exception:
        return url, 0


def discover_web_routes(
    target_url: str,
    custom_headers: dict[str, str] | None = None,
    max_workers: int = 15,
    timeout: float = 6.0
) -> list[str]:
    """Crawl and discover active routes and endpoints on a target web application."""
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    parsed = urllib.parse.urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    base_clean = _clean_url(target_url)

    discovered_paths: Set[str] = set()
    script_urls: Set[str] = set()

    # 1. Fetch homepage & extract links / scripts / form actions
    status, final_url, html = _fetch_page(target_url, custom_headers, timeout=timeout)
    if status > 0 and html:
        # Extract href links
        for m in re.finditer(r'href=[\"\x27]([^\x27\"#\s>]+)[\"\x27]', html, re.IGNORECASE):
            link = m.group(1).strip()
            full_url = urllib.parse.urljoin(target_url, link)
            if _is_same_origin(origin, full_url):
                p = urllib.parse.urlparse(full_url).path
                if p and not p.lower().endswith(STATIC_EXTENSIONS + (".js",)):
                    discovered_paths.add(p)

        # Extract form action URLs
        for m in re.finditer(r'action=[\"\x27]([^\x27\"#\s>]+)[\"\x27]', html, re.IGNORECASE):
            act = m.group(1).strip()
            full_url = urllib.parse.urljoin(target_url, act)
            if _is_same_origin(origin, full_url):
                p = urllib.parse.urlparse(full_url).path
                if p:
                    discovered_paths.add(p)

        # Extract JS scripts for SPA route extraction
        for m in re.finditer(r'src=[\"\x27]([^\x27\"#\s>]+\.js[^\x27\"#\s>]*)[\"\x27]', html, re.IGNORECASE):
            s_link = m.group(1).strip()
            s_full = urllib.parse.urljoin(target_url, s_link)
            if _is_same_origin(origin, s_full):
                script_urls.add(s_full)

    # 2. Extract SPA routes from JavaScript bundles (Next.js / React Router / Vue)
    for s_url in list(script_urls)[:12]:  # inspect up to 12 main chunk files
        s_status, _, js_content = _fetch_page(s_url, custom_headers, timeout=4.0)
        if s_status == 200 and js_content:
            # Find routes like '/login', '/dashboard', '/api/users'
            for m in re.finditer(r'[\"\x27](/(?:[a-zA-Z0-9_\-]+/)*(?:[a-zA-Z0-9_\-]+))[\"\x27]', js_content):
                p = m.group(1)
                if (
                    not p.startswith(("/_next", "/_static", "/node_modules", "/webpack"))
                    and not p.lower().endswith(STATIC_EXTENSIONS + (".js",))
                    and 1 < len(p) < 65
                    and not re.search(r"[<>{}\\\^`~]", p)
                ):
                    discovered_paths.add(p)

    # 3. Merge with common application routes
    all_candidate_paths = set(COMMON_APP_ROUTES) | discovered_paths
    candidate_urls = [urllib.parse.urljoin(origin, p) for p in all_candidate_paths]

    # 4. Concurrently probe candidate URLs to filter out 404s and keep live routes
    live_targets: Set[str] = {base_clean}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(_probe_route, u, custom_headers, timeout=timeout): u
            for u in candidate_urls
        }
        for future in concurrent.futures.as_completed(future_to_url):
            try:
                url, code = future.result()
                # 200-399 = valid pages/redirects
                # 401/403 = protected live routes / auth portals
                # 400/405/500 = active API endpoints with parameter requirements
                if 200 <= code <= 399 or code in (400, 401, 403, 405):
                    clean = _clean_url(url)
                    live_targets.add(clean)
            except Exception:
                continue

    # Return list sorted with base URL first, followed by live discovered routes
    result = [base_clean]
    for u in sorted(live_targets):
        if u != base_clean and u not in result:
            result.append(u)

    return result
