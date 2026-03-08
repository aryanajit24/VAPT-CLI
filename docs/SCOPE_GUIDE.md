# Scope YAML Guide — VAPT CLI Autonomous Hunt

This guide explains how to write a **program scope YAML file** for
`vapt hunt-auto`, the autonomous bug bounty hunting command.

The scope file tells VAPT CLI everything about the bug bounty program:
what to test, what to avoid, how fast to go, and what payout to expect.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [File Structure](#file-structure)
3. [Section Reference](#section-reference)
   - [program](#program)
   - [scope](#scope)
   - [excluded_vulnerabilities](#excluded_vulnerabilities)
   - [bounty](#bounty)
   - [testing](#testing)
   - [modules](#modules)
4. [Asset Types](#asset-types)
5. [Category Names](#category-names)
6. [Rate Profiles](#rate-profiles)
7. [Examples](#examples)
8. [Running a Hunt](#running-a-hunt)
9. [Output Structure](#output-structure)
10. [Tips & Best Practices](#tips--best-practices)

---

## Quick Start

```bash
# 1. Copy the example scope
cp scopes/example-program.yaml scopes/my-target.yaml

# 2. Edit it with your program's details
vim scopes/my-target.yaml

# 3. Run the hunt
vapt hunt-auto scopes/my-target.yaml
```

That's it. VAPT CLI reads the YAML, builds a strategy, and runs the
full 5-phase pipeline.

---

## File Structure

Every scope file is a standard YAML document with these top-level keys:

```yaml
program:                    # metadata about the bug bounty program
scope:                      # in-scope and out-of-scope targets
excluded_vulnerabilities:   # vulnerability types to skip
bounty:                     # payout tiers (for prioritization)
testing:                    # rate limits and testing constraints
modules:                    # (optional) which scanner modules to run
```

All sections except `scope.in_scope` are optional.

---

## Section Reference

### `program`

Program metadata. Used in reports and logs.

```yaml
program:
  name: Meesho                              # program name
  platform: hackerone                       # hackerone | bugcrowd | intigriti | other
  url: https://hackerone.com/meesho         # link to program page
```

| Field      | Required | Description                        |
|------------|----------|------------------------------------|
| `name`     | No       | Program name (used in reports)     |
| `platform` | No       | Bug bounty platform                |
| `url`      | No       | Direct link to the program page    |

---

### `scope`

Defines what's in scope and what's not. This is the most important section.

```yaml
scope:
  in_scope:
    - target: "*.meesho.com"
      type: web
      eligible_for_bounty: true
      max_severity: critical
      notes: Main web properties

    - target: "api.meesho.com"
      type: api
      eligible_for_bounty: true
      max_severity: critical

  out_of_scope:
    - target: "blog.meesho.com"
      type: web
      notes: WordPress — not managed by Meesho
```

#### In-scope asset fields

| Field                | Required | Default    | Description                                |
|----------------------|----------|------------|--------------------------------------------|
| `target`             | **Yes**  | —          | Domain, wildcard, IP, or CIDR              |
| `type`               | No       | `web`      | Asset type (see [Asset Types](#asset-types))|
| `eligible_for_bounty`| No       | `true`     | Whether findings pay bounty                |
| `max_severity`       | No       | `critical` | Maximum accepted severity                  |
| `notes`              | No       | —          | Free-text notes for your reference         |

#### Out-of-scope asset fields

| Field    | Required | Description                          |
|----------|----------|--------------------------------------|
| `target` | **Yes**  | Domain or pattern to exclude         |
| `type`   | No       | Asset type                           |
| `notes`  | No       | Why it's excluded                    |

#### Target patterns

```yaml
# Exact domain
- target: "api.example.com"

# Wildcard subdomain
- target: "*.example.com"

# IP address
- target: "203.0.113.10"

# CIDR range
- target: "10.0.0.0/24"

# URL prefix (for API-specific scopes)
- target: "https://api.example.com/v2/*"
```

---

### `excluded_vulnerabilities`

Vulnerability categories the program explicitly excludes. Findings in
these categories are filtered out before reporting.

```yaml
excluded_vulnerabilities:
  - category: missing_security_headers
    reason: Not eligible per policy
    detail: X-Frame-Options, CSP, etc. are informational only

  - category: rate_limiting
    reason: Out of scope

  - category: self_xss
    reason: Requires social engineering

  - category: clickjacking
    reason: Only on sensitive actions
    detail: Must demonstrate real impact (payment, settings)
```

| Field      | Required | Description                               |
|------------|----------|-------------------------------------------|
| `category` | **Yes**  | Category name (see [Category Names](#category-names)) |
| `reason`   | No       | Short reason for exclusion                |
| `detail`   | No       | Longer explanation                        |

---

### `bounty`

Payout tiers. Used by the duplicate detector and report prioritizer
to estimate ROI.

```yaml
bounty:
  - severity: critical
    min: 5000
    max: 20000
  - severity: high
    min: 2000
    max: 5000
  - severity: medium
    min: 500
    max: 2000
  - severity: low
    min: 100
    max: 500
```

| Field      | Required | Description                  |
|------------|----------|------------------------------|
| `severity` | **Yes**  | critical / high / medium / low |
| `min`      | **Yes**  | Minimum payout in USD        |
| `max`      | **Yes**  | Maximum payout in USD        |

---

### `testing`

Constraints that control scanner behavior. These ensure you stay within
the program's rules.

```yaml
testing:
  max_requests_per_second: 10
  no_automated_scanners: false
  no_destructive_testing: true
  required_headers:
    X-Bug-Bounty: researcher-testing
    X-Researcher: your-username
  proxy_required: false
  allowed_hours_utc: "09:00-17:00"   # optional
```

| Field                      | Required | Default | Description                               |
|----------------------------|----------|---------|-------------------------------------------|
| `max_requests_per_second`  | No       | 10      | Per-domain rate limit                     |
| `no_automated_scanners`    | No       | `false` | If `true`, uses manual-only polite mode   |
| `no_destructive_testing`   | No       | `false` | Skip write/delete operations              |
| `required_headers`         | No       | `{}`    | Extra headers on every request            |
| `proxy_required`           | No       | `false` | Require all traffic through a proxy       |
| `allowed_hours_utc`        | No       | —       | Testing window (not enforced, advisory)   |
| `user_agent`               | No       | —       | Custom User-Agent string                  |

> **Tip:** If `no_automated_scanners` is `true`, VAPT CLI automatically
> switches to "polite" rate profile regardless of `--rate`.

---

### `modules`

Optional list of scanner modules to run. Omit this section to run all
available modules.

```yaml
modules:
  - web
  - api
  - ssl
  - dom
  - auth
  - fuzz
  - cve
  - advanced
  - race
  - smuggle
  - cloud
  - jsscan
```

Available modules:

| Module     | What it does                                    |
|------------|-------------------------------------------------|
| `web`      | CORS, headers, redirects, cookie security       |
| `api`      | REST/GraphQL endpoint testing                   |
| `ssl`      | TLS version, cipher suite, certificate issues   |
| `dom`      | DOM XSS, JavaScript sink analysis               |
| `auth`     | Authentication bypass, session management       |
| `fuzz`     | Parameter fuzzing, injection testing            |
| `cve`      | Known CVE detection via version fingerprinting  |
| `advanced` | SSTI, deserialization, prototype pollution      |
| `race`     | Race condition / TOCTOU testing                 |
| `smuggle`  | HTTP request smuggling                          |
| `cloud`    | S3 buckets, Azure blobs, GCP storage            |
| `jsscan`   | API keys, tokens, secrets in JavaScript         |

---

## Asset Types

Use these values in the `type` field:

| Type       | Description                         |
|------------|-------------------------------------|
| `web`      | Web application (default)           |
| `api`      | REST / GraphQL API                  |
| `mobile`   | Mobile application (Android/iOS)    |
| `network`  | IP range or infrastructure          |
| `other`    | Anything else                       |

---

## Category Names

Standard category names for `excluded_vulnerabilities`. Use these
consistently:

| Category                       | Description                                |
|--------------------------------|--------------------------------------------|
| `xss`                          | Cross-site scripting                       |
| `self_xss`                     | Self-XSS (requires social engineering)     |
| `cors`                         | CORS misconfiguration                      |
| `csrf`                         | Cross-site request forgery                 |
| `ssrf`                         | Server-side request forgery                |
| `idor`                         | Insecure direct object reference           |
| `sqli`                         | SQL injection                              |
| `ssti`                         | Server-side template injection             |
| `redirect` / `open_redirect`   | Open redirect                              |
| `clickjacking`                 | Clickjacking / UI redressing               |
| `missing_security_headers`     | Missing HTTP security headers              |
| `information_disclosure`       | Sensitive information exposure              |
| `rate_limiting`                | Missing or weak rate limiting              |
| `spf_dmarc`                    | Email SPF/DKIM/DMARC issues                |
| `subdomain_takeover`           | Dangling CNAME / subdomain takeover        |
| `ssl_tls`                      | TLS/SSL configuration issues               |
| `jwt`                          | JWT vulnerabilities                        |
| `race_condition`               | Race conditions / TOCTOU                   |
| `smuggling`                    | HTTP request smuggling                     |
| `graphql`                      | GraphQL-specific issues                    |
| `cloud`                        | Cloud storage misconfigurations            |
| `host_header`                  | Host header injection                      |

---

## Rate Profiles

Control scanning speed with the `--rate` flag:

| Profile      | Delay     | Best for                                    |
|--------------|-----------|---------------------------------------------|
| `aggressive` | 0.1s      | Your own assets / lab environments          |
| `normal`     | 0.5s      | Most bug bounty programs (default)          |
| `polite`     | 1.5s      | Programs that say "be gentle"               |
| `stealth`    | 3.0s      | Programs with strict rate limits / WAFs     |

All profiles include adaptive backoff: if the tool detects a WAF block
or 429 response, it automatically slows down and retries.

---

## Examples

### Minimal scope (just targets)

```yaml
scope:
  in_scope:
    - target: "example.com"
```

### HackerOne program

```yaml
program:
  name: Shopify
  platform: hackerone
  url: https://hackerone.com/shopify

scope:
  in_scope:
    - target: "*.shopify.com"
      type: web
      eligible_for_bounty: true
    - target: "*.myshopify.com"
      type: web
      eligible_for_bounty: true
  out_of_scope:
    - target: "*.shopifycloud.com"
    - target: "help.shopify.com"
    - target: "community.shopify.com"

excluded_vulnerabilities:
  - category: missing_security_headers
    reason: Not eligible
  - category: rate_limiting
    reason: Out of scope
  - category: clickjacking
    reason: Non-sensitive pages only

bounty:
  - severity: critical
    min: 10000
    max: 50000
  - severity: high
    min: 5000
    max: 10000
  - severity: medium
    min: 500
    max: 5000
  - severity: low
    min: 100
    max: 500

testing:
  max_requests_per_second: 5
  no_destructive_testing: true
  required_headers:
    X-Bug-Bounty: researcher-name
```

### Bugcrowd program

```yaml
program:
  name: Optus
  platform: bugcrowd
  url: https://bugcrowd.com/optus

scope:
  in_scope:
    - target: "*.optus.com.au"
      type: web
    - target: "api.optus.com.au"
      type: api
  out_of_scope:
    - target: "careers.optus.com.au"

testing:
  max_requests_per_second: 3
  no_automated_scanners: true
  no_destructive_testing: true
```

### API-only program

```yaml
program:
  name: Internal API Testing
  platform: other

scope:
  in_scope:
    - target: "api.internal.com"
      type: api

modules:
  - api
  - fuzz
  - auth

testing:
  max_requests_per_second: 20
  required_headers:
    Authorization: "Bearer YOUR_TOKEN_HERE"
```

---

## Running a Hunt

### Basic usage

```bash
vapt hunt-auto scopes/my-target.yaml
```

### With authentication (required for IDOR, auth bypass testing)

```bash
vapt hunt-auto scopes/my-target.yaml \
  --cookies-a "session=user1_session_cookie" \
  --cookies-b "session=user2_session_cookie"
```

Or with bearer tokens:

```bash
vapt hunt-auto scopes/my-target.yaml \
  --bearer-a "eyJhbGciOiJIUzI1NiJ9..." \
  --bearer-b "eyJhbGciOiJIUzI1NiJ9..."
```

### With proxy (Burp Suite)

```bash
vapt hunt-auto scopes/my-target.yaml \
  --proxy http://127.0.0.1:8080
```

### Stealth mode

```bash
vapt hunt-auto scopes/my-target.yaml --rate stealth
```

### With duplicate estimation

```bash
# Program is 2 years old with 150 resolved reports
vapt hunt-auto scopes/my-target.yaml \
  --program-age 24 \
  --resolved 150
```

### Custom output directory

```bash
vapt hunt-auto scopes/my-target.yaml --output ./shopify-hunt
```

---

## Output Structure

After a hunt completes, the output directory contains:

```
vapt-reports/
├── hunt_findings.json          # All confirmed findings (JSON)
├── hunt_summary.json           # Pipeline stats and timings
├── proofs/                     # PoC artifacts
│   ├── cors_1_poc.html         # Clickable HTML exploit
│   ├── xss_2_poc.html          # XSS PoC page
│   ├── cors_1_curl.sh          # Reproduction cURL command
│   ├── xss_2_curl.sh
│   ├── cors_1_evidence.txt     # Evidence summary
│   └── xss_2_evidence.txt
├── bounty_report.md            # Full bounty report (Markdown)
├── bounty_report_fields.json   # Platform submission fields
└── per_finding/                # Individual finding reports
    ├── finding_1.md
    └── finding_2.md
```

### hunt_findings.json

```json
[
  {
    "title": "CORS Misconfiguration allows credential theft",
    "category": "cors",
    "severity": "high",
    "url": "https://api.example.com/user/profile",
    "_validated": true,
    "_confidence": 0.95,
    "_decision": "escalate",
    "_duplicate_risk": "low"
  }
]
```

### proofs/ directory

Each finding gets:
- **HTML PoC** — a self-contained page that demonstrates the vulnerability
- **cURL script** — a shell command to reproduce the finding
- **Evidence file** — text summary for copy/paste into reports

---

## Tips & Best Practices

1. **Always provide two auth sessions** (`--cookies-a` and `--cookies-b`)
   for IDOR testing. Without them, authorization bugs can't be detected.

2. **Set `--program-age` and `--resolved`** accurately. This helps the
   duplicate detector estimate whether your finding is likely a dupe.

3. **Start with `--rate polite`** on new programs until you know their
   WAF tolerance, then increase to `normal`.

4. **Read the program policy carefully** before writing your scope YAML.
   Copy exclusions word-for-word into `excluded_vulnerabilities`.

5. **Use `required_headers`** to identify yourself. Many programs ask
   researchers to include a custom header.

6. **Review `hunt_findings.json`** after each run. The tool flags
   duplicate risk — focus on "low" risk findings first.

7. **Keep scope files in version control** — one YAML per program,
   stored in the `scopes/` directory.

8. **Proxy through Burp** (`--proxy http://127.0.0.1:8080`) during
   initial runs to inspect what's being sent.

9. **Don't test on programs where `no_automated_scanners: true`** unless
   you're comfortable with the polite mode behavior (1.5s+ between
   requests, UA rotation, no aggressive fuzzing).

10. **Update your scope YAML** when the program changes its policy.
    Programs frequently add/remove targets and exclusions.
