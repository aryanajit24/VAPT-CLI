#!/usr/bin/env python3
"""Airbnb Phase 1 — Surface Reconnaissance

Targets the HIGH-VALUE in-scope assets:
  1. www.airbnb.com — main site (359 resolved, 23%)
  2. api.airbnb.com — API (18 resolved)
  3. The new AI Customer Service Assistant (promo target)
  4. support-api.airbnb.com (1 resolved — fresh!)
  5. *.airbnb.com wildcard
  6. New wildcards: *.musta.ch, *.airbnbpayments.com, *.airbnb.org (0 resolved — virgin!)

Strategy: Homepage → JS bundles → API endpoints → GraphQL → AI Assistant surface → fresh domains
"""

import re
import json
import time
import hashlib
import requests
from urllib.parse import urljoin, urlparse
from collections import defaultdict

requests.packages.urllib3.disable_warnings()

S = requests.Session()
S.headers.update({
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
})
S.verify = False

DELAY = 1.5  # Polite

results = {
    "js_bundles": [],
    "api_endpoints": [],
    "graphql_ops": [],
    "secrets": [],
    "headers_analysis": {},
    "ai_assistant_surface": {},
    "fresh_domains": {},
    "interesting_findings": [],
}

def p(msg):
    print(f"[*] {msg}")

def ok(msg):
    print(f"[+] {msg}")

def warn(msg):
    print(f"[!] {msg}")

def fetch(url, **kw):
    time.sleep(DELAY)
    try:
        r = S.get(url, timeout=20, allow_redirects=True, **kw)
        return r
    except Exception as e:
        warn(f"  Failed {url}: {e}")
        return None

# ─── 1. Main site analysis ──────────────────────────────────────

p("=" * 60)
p("PHASE 1A: www.airbnb.com — Homepage & JS Bundle Analysis")
p("=" * 60)

r = fetch("https://www.airbnb.com/")
if r:
    ok(f"Homepage: {r.status_code} ({len(r.text)} bytes)")
    
    # Security headers
    sec_headers = {}
    for h in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
              "Strict-Transport-Security", "X-XSS-Protection", "Referrer-Policy",
              "Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy"]:
        v = r.headers.get(h)
        if v:
            sec_headers[h] = v[:200]
        else:
            sec_headers[h] = "MISSING"
            
    results["headers_analysis"]["www.airbnb.com"] = sec_headers
    
    missing = [h for h, v in sec_headers.items() if v == "MISSING"]
    if missing:
        warn(f"  Missing security headers: {', '.join(missing)}")
    
    # CSP analysis
    csp = r.headers.get("Content-Security-Policy", "")
    if csp:
        ok(f"  CSP present ({len(csp)} chars)")
        if "unsafe-inline" in csp:
            warn("  CSP allows unsafe-inline!")
            results["interesting_findings"].append({
                "type": "csp_weakness",
                "detail": "CSP allows unsafe-inline",
                "target": "www.airbnb.com",
            })
        if "unsafe-eval" in csp:
            warn("  CSP allows unsafe-eval!")
            results["interesting_findings"].append({
                "type": "csp_weakness",
                "detail": "CSP allows unsafe-eval",
                "target": "www.airbnb.com",
            })
        # Check for wildcard sources
        wildcards = re.findall(r'\*\.[\w.-]+', csp)
        if wildcards:
            warn(f"  CSP wildcard sources: {wildcards[:10]}")
    else:
        warn("  NO CSP header!")
        results["interesting_findings"].append({
            "type": "missing_csp",
            "target": "www.airbnb.com",
        })
    
    # Extract JS bundles
    js_urls = set()
    for m in re.finditer(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', r.text):
        url = m.group(1)
        if url.startswith("//"):
            url = "https:" + url
        elif url.startswith("/"):
            url = f"https://www.airbnb.com{url}"
        js_urls.add(url)
    
    # Also check for dynamic chunk loading patterns
    for m in re.finditer(r'["\'](/(?:static|_next|bundles|assets)/[^"\']*\.js)["\']', r.text):
        js_urls.add(f"https://www.airbnb.com{m.group(1)}")
    
    # Check for webpack/chunk patterns
    for m in re.finditer(r'["\'](https?://[^"\']*\.js(?:\?[^"\']*)?)["\']', r.text):
        js_urls.add(m.group(1))
    
    results["js_bundles"] = sorted(js_urls)
    ok(f"  Found {len(js_urls)} JS bundles")
    
    # Extract inline config/data
    for m in re.finditer(r'<script[^>]*>\s*window\.__(\w+)\s*=\s*({.*?})\s*;?\s*</script>', r.text, re.DOTALL):
        var_name = m.group(1)
        ok(f"  Found window.__{var_name} config data")
        try:
            data = json.loads(m.group(2))
            if isinstance(data, dict):
                for k in list(data.keys())[:20]:
                    p(f"    Key: {k}")
        except:
            pass

    # Check for Next.js data
    for m in re.finditer(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', r.text, re.DOTALL):
        ok("  Found __NEXT_DATA__ (Next.js app)")
        try:
            nd = json.loads(m.group(1))
            if "props" in nd:
                ok(f"    Has props with {len(str(nd['props']))} chars of data")
            if "buildId" in nd:
                ok(f"    Build ID: {nd['buildId']}")
        except:
            pass

    # Look for API base URLs
    for m in re.finditer(r'(?:api[_-]?(?:url|base|host|endpoint)|API_(?:URL|BASE))["\']?\s*[:=]\s*["\']([^"\']+)["\']', r.text, re.I):
        url = m.group(1)
        ok(f"  API endpoint reference: {url}")
        results["api_endpoints"].append(url)

# ─── 2. JS Bundle Deep Analysis (sample top 20) ─────────────────

p("")
p("=" * 60)
p("PHASE 1B: JS Bundle Analysis — Mining APIs & Secrets")
p("=" * 60)

SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API Key"),
    (r'(?:secret|token|password|passwd|pwd)\s*[:=]\s*["\']([A-Za-z0-9_\-]{10,})["\']', "Secret/Token"),
    (r'(?:aws_access_key_id|AKIA)[A-Z0-9]{12,}', "AWS Key"),
    (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "GitHub Token"),
    (r'sk-[A-Za-z0-9]{48,}', "OpenAI Key"),
    (r'xox[bpors]-[A-Za-z0-9-]+', "Slack Token"),
    (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
    (r'(?:maps|places|geocode)\.googleapis\.com', "Google Maps API"),
    (r'firebase[a-z]*\.googleapis\.com', "Firebase Endpoint"),
    (r'[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com', "AWS API Gateway"),
    (r'https?://[a-z0-9-]+\.s3\.amazonaws\.com', "S3 Bucket"),
    (r'(?:OPENAI|ANTHROPIC|CLAUDE)_API_KEY', "LLM API Key Reference"),
]

API_PATTERNS = [
    r'["\'](/api/v[0-9]+/[^"\']+)["\']',
    r'["\'](/graphql[^"\']*)["\']',
    r'["\'](/internal/[^"\']+)["\']',
    r'["\'](/soa/[^"\']+)["\']',
    r'["\'](/v[0-9]+/[^"\']+)["\']',
    r'["\'](/help/[^"\']+)["\']',
    r'["\'](/contact[^"\']*)["\']',
    r'["\'](/ai[/_-][^"\']*)["\']',
    r'["\'](/chat[/_-]?[^"\']*)["\']',
    r'["\'](/assistant[/_-]?[^"\']*)["\']',
    r'["\'](?:https?://[^"\']*airbnb[^"\']*(/[^"\']+))["\']',
]

GRAPHQL_PATTERNS = [
    r'(?:query|mutation|subscription)\s+(\w+)\s*(?:\(|{)',
    r'operationName["\']?\s*[:=]\s*["\'](\w+)["\']',
]

all_apis = set()
all_secrets = []
all_gql_ops = set()

for i, js_url in enumerate(results["js_bundles"][:25]):
    if not js_url.startswith("http"):
        continue
    p(f"  [{i+1}/{min(25, len(results['js_bundles']))}] Fetching {js_url[:80]}...")
    r = fetch(js_url)
    if not r or r.status_code != 200:
        continue
    
    body = r.text
    
    # API endpoints
    for pattern in API_PATTERNS:
        for m in re.finditer(pattern, body):
            api = m.group(1)
            if len(api) > 5 and not api.endswith(".js") and not api.endswith(".css"):
                all_apis.add(api)
    
    # Secrets
    for pattern, name in SECRET_PATTERNS:
        for m in re.finditer(pattern, body, re.I):
            val = m.group(0)[:100]
            h = hashlib.md5(val.encode()).hexdigest()[:8]
            all_secrets.append({"type": name, "hash": h, "source": js_url.split("/")[-1][:30], "preview": val[:50]})
    
    # GraphQL operations
    for pattern in GRAPHQL_PATTERNS:
        for m in re.finditer(pattern, body):
            all_gql_ops.add(m.group(1))

results["api_endpoints"] = sorted(set(results["api_endpoints"]) | all_apis)
results["secrets"] = all_secrets
results["graphql_ops"] = sorted(all_gql_ops)

ok(f"Total API endpoints found: {len(results['api_endpoints'])}")
for ep in sorted(results["api_endpoints"])[:40]:
    p(f"  {ep}")

if all_secrets:
    warn(f"Potential secrets found: {len(all_secrets)}")
    for s in all_secrets[:15]:
        warn(f"  [{s['type']}] in {s['source']}: {s['preview']}")

ok(f"GraphQL operations: {len(results['graphql_ops'])}")
for op in sorted(results["graphql_ops"])[:30]:
    p(f"  {op}")

# ─── 3. AI Customer Service Assistant ───────────────────────────

p("")
p("=" * 60)
p("PHASE 1C: AI Customer Service Assistant — Surface Mapping")
p("=" * 60)

# The AI assistant is at /help/contact-us
ai_urls = [
    "https://www.airbnb.com/help",
    "https://www.airbnb.com/help/contact-us",
    "https://www.airbnb.com/help/contact-us?entry=HELP_CENTER&role=guest",
]

for url in ai_urls:
    p(f"Fetching {url}...")
    r = fetch(url)
    if not r:
        continue
    ok(f"  {r.status_code} — {len(r.text)} bytes — Final URL: {r.url}")
    
    # Check for redirects (auth required?)
    if r.url != url and "login" in r.url.lower():
        warn("  Redirected to login — auth required")
    
    # Look for AI/chat specific JS/APIs
    ai_patterns = [
        r'["\']([^"\']*(?:ai|chat|assistant|bot|llm|gpt|model|prompt)[^"\']*)["\']',
        r'(?:websocket|wss?)://[^"\']+',
        r'["\']([^"\']*(?:conversation|message|thread|session)[^"\']*\.?(?:json|api)?)["\']',
    ]
    
    ai_refs = set()
    for pattern in ai_patterns:
        for m in re.finditer(pattern, r.text, re.I):
            val = m.group(1) if m.lastindex else m.group(0)
            if len(val) > 3 and len(val) < 200:
                ai_refs.add(val)
    
    if ai_refs:
        ok(f"  AI-related references ({len(ai_refs)}):")
        for ref in sorted(ai_refs)[:25]:
            p(f"    {ref}")
        results["ai_assistant_surface"][url] = sorted(ai_refs)
    
    # Extract any hidden form fields or CSRF tokens
    forms = re.findall(r'<form[^>]*>.*?</form>', r.text, re.DOTALL | re.I)
    if forms:
        ok(f"  Found {len(forms)} form(s)")
        for form in forms[:3]:
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', form, re.I)
            if inputs:
                p(f"    Form fields: {inputs}")

# ─── 4. API Endpoint Discovery ──────────────────────────────────

p("")
p("=" * 60)
p("PHASE 1D: api.airbnb.com — API Surface Analysis")
p("=" * 60)

# Common API paths to probe
api_paths = [
    "/v2/",
    "/v3/",
    "/v1/",
    "/api/v2/",
    "/graphql",
    "/health",
    "/status",
    "/robots.txt",
    "/.well-known/openapi.json",
    "/.well-known/security.txt",
    "/swagger.json",
    "/openapi.json",
    "/docs",
    "/debug",
]

for path in api_paths:
    url = f"https://api.airbnb.com{path}"
    p(f"Probing {url}...")
    r = fetch(url)
    if not r:
        continue
    
    status = r.status_code
    size = len(r.text)
    ct = r.headers.get("content-type", "")
    
    if status == 200:
        ok(f"  {status} — {size} bytes — {ct}")
        if "json" in ct:
            try:
                data = r.json()
                if isinstance(data, dict):
                    ok(f"    Keys: {list(data.keys())[:15]}")
            except:
                pass
        elif size < 2000:
            p(f"    Body preview: {r.text[:300]}")
    elif status in (301, 302, 307, 308):
        loc = r.headers.get("Location", "N/A")
        p(f"  {status} → {loc}")
    elif status == 403:
        p(f"  {status} Forbidden — {size} bytes")
    elif status == 404:
        pass  # expected
    else:
        p(f"  {status} — {size} bytes")

# ─── 5. support-api.airbnb.com (Fresh — only 1 resolved!) ──────

p("")
p("=" * 60)
p("PHASE 1E: support-api.airbnb.com — Fresh Target (1 resolved)")
p("=" * 60)

support_paths = [
    "/",
    "/health",
    "/status",
    "/graphql",
    "/api/v1/",
    "/v1/tickets",
    "/v1/conversations",
    "/robots.txt",
    "/.well-known/security.txt",
]

for path in support_paths:
    url = f"https://support-api.airbnb.com{path}"
    p(f"Probing {url}...")
    r = fetch(url)
    if not r:
        continue
    
    status = r.status_code
    size = len(r.text)
    ct = r.headers.get("content-type", "")
    
    if status == 200:
        ok(f"  {status} — {size} bytes — {ct}")
        if size < 3000:
            p(f"    {r.text[:500]}")
    elif status in (301, 302, 307, 308):
        loc = r.headers.get("Location", "N/A")
        p(f"  {status} → {loc}")
    else:
        p(f"  {status} — {size} bytes")

# ─── 6. Fresh Wildcard Domains (0 resolved) ────────────────────

p("")
p("=" * 60)
p("PHASE 1F: Fresh Domains — Zero Resolved Reports")
p("=" * 60)

fresh_domains = [
    "musta.ch",
    "airbnbpayments.com",
    "airbnb.org",
]

for domain in fresh_domains:
    p(f"\n--- {domain} ---")
    for proto in ["https", "http"]:
        url = f"{proto}://{domain}/"
        p(f"  Trying {url}...")
        r = fetch(url)
        if not r:
            continue
        ok(f"  {r.status_code} — {len(r.text)} bytes — Final: {r.url}")
        
        # Security headers
        missing_h = []
        for h in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"]:
            if not r.headers.get(h):
                missing_h.append(h)
        if missing_h:
            warn(f"  Missing: {', '.join(missing_h)}")
        
        # Check for clickjacking (X-Frame-Options)
        xfo = r.headers.get("X-Frame-Options", "")
        if not xfo:
            warn(f"  No X-Frame-Options — possible clickjacking!")
            results["interesting_findings"].append({
                "type": "clickjacking",
                "target": domain,
                "detail": "Missing X-Frame-Options header",
            })
        
        results["fresh_domains"][domain] = {
            "status": r.status_code,
            "final_url": r.url,
            "size": len(r.text),
            "missing_headers": missing_h,
        }
        break  # Don't try HTTP if HTTPS worked

# ─── 7. CORS Checks ────────────────────────────────────────────

p("")
p("=" * 60)
p("PHASE 1G: CORS Misconfiguration Checks")
p("=" * 60)

cors_targets = [
    "https://www.airbnb.com/",
    "https://api.airbnb.com/v2/",
    "https://support-api.airbnb.com/",
    "https://www.airbnb.com/help",
    "https://www.airbnb.com/api/v3/",
]

evil_origins = [
    "https://evil.com",
    "https://www.airbnb.com.evil.com",
    "https://airbnbevil.com",
    "null",
    "https://www.airbnb.com%0d%0a",
]

for target in cors_targets:
    for origin in evil_origins:
        p(f"  CORS: {target} ← Origin: {origin}")
        time.sleep(DELAY)
        try:
            r = S.get(target, headers={"Origin": origin}, timeout=15)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao and acao != "*":
                if origin in acao or acao == "null":
                    warn(f"    CORS REFLECTS ORIGIN! ACAO={acao} ACAC={acac}")
                    results["interesting_findings"].append({
                        "type": "cors_misconfiguration",
                        "target": target,
                        "origin": origin,
                        "acao": acao,
                        "acac": acac,
                        "severity": "high" if acac.lower() == "true" else "medium",
                    })
                else:
                    p(f"    ACAO={acao[:60]} (does not reflect)")
            elif acao == "*":
                p(f"    ACAO=* (wildcard, no credentials)")
        except Exception as e:
            pass

# ─── 8. Cookie Security Audit ──────────────────────────────────

p("")
p("=" * 60)
p("PHASE 1H: Cookie Security Audit")  
p("=" * 60)

r = fetch("https://www.airbnb.com/")
if r:
    for cookie in S.cookies:
        flags = []
        if cookie.secure:
            flags.append("Secure")
        else:
            flags.append("NO-Secure")
            results["interesting_findings"].append({
                "type": "insecure_cookie",
                "target": "www.airbnb.com",
                "cookie": cookie.name,
                "detail": "Missing Secure flag",
            })
        
        if "httponly" in str(cookie._rest).lower() or cookie.has_nonstandard_attr("httponly") or cookie.has_nonstandard_attr("HttpOnly"):
            flags.append("HttpOnly")
        else:
            flags.append("NO-HttpOnly")
        
        samesite = "unknown"
        for attr in ["samesite", "SameSite"]:
            if cookie.has_nonstandard_attr(attr):
                samesite = cookie.get_nonstandard_attr(attr) or "unset"
        flags.append(f"SameSite={samesite}")
        
        ok(f"  {cookie.name}: domain={cookie.domain} path={cookie.path} flags=[{', '.join(flags)}]")

# ─── SUMMARY ────────────────────────────────────────────────────

p("")
p("=" * 60)
p("PHASE 1 SUMMARY")
p("=" * 60)

ok(f"JS Bundles found:       {len(results['js_bundles'])}")
ok(f"API Endpoints found:    {len(results['api_endpoints'])}")
ok(f"GraphQL Operations:     {len(results['graphql_ops'])}")
ok(f"Potential Secrets:       {len(results['secrets'])}")
ok(f"Interesting Findings:   {len(results['interesting_findings'])}")
ok(f"Fresh Domains checked:  {len(results['fresh_domains'])}")

for finding in results["interesting_findings"]:
    warn(f"  → [{finding['type']}] {finding.get('target', '')} — {finding.get('detail', finding.get('severity', ''))}")

# Save results
with open("/tmp/airbnb_phase1_results.json", "w") as f:
    json.dump(results, f, indent=2, default=str)

ok("Results saved to /tmp/airbnb_phase1_results.json")
ok("Phase 1 complete — proceeding to Phase 2 for deep analysis")
