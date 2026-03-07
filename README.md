# VAPT CLI

![Version](https://img.shields.io/badge/version-1.0.0-blue?style=flat-square)
![Python](https://img.shields.io/badge/python-3.10+-green?style=flat-square)
![Tests](https://img.shields.io/badge/tests-242%20passing-brightgreen?style=flat-square)
![License](https://img.shields.io/github/license/aryanajit24/VAPT-CLI?style=flat-square)

A command-line tool that finds security vulnerabilities in websites, APIs, networks, mobile apps, and source code.

---

## What Does This Tool Do?

Think of a website like a house. This tool checks if any doors are unlocked, if the windows are open, or if someone left the keys under the doormat. Except instead of a house, it checks websites and apps for security problems that hackers could exploit.

It can:
- **Intercept traffic** — MITM proxy with SSL interception, request replay, and flow storage
- **Interactive TUI** — terminal-based UI with proxy log, repeater, intruder, and codec tabs
- **Find open doors** — scan ports and services running on a server
- **Check the locks** — test SSL/TLS certificates and encryption
- **Try the windows** — look for web vulnerabilities like XSS, SQL injection, CSRF
- **Read the blueprints** — analyze JavaScript files for hidden endpoints and secrets
- **Test the alarm system** — check authentication, sessions, and access controls
- **Inspect the cloud** — find misconfigured S3 buckets, Azure blobs, Firebase databases
- **Analyze mobile apps** — decompile Android APKs and iOS IPAs for security issues
- **Review source code** — detect hardcoded secrets, unsafe patterns, vulnerable dependencies
- **Fuzz endpoints** — Burp Intruder-style 4-mode fuzzing engine with built-in payload sets
- **Analyze tokens** — Sequencer-style token randomness analysis with statistical tests
- **Encode/decode anything** — Base64, URL, Hex, HTML, JWT, hash identification
- **Crawl websites** — Playwright-based headless crawler with form/JS/endpoint discovery
- **Write the report** — generate professional PDF, HTML, or JSON reports

---

## Installation

### Quick Install (Recommended)

```sh
git clone https://github.com/aryanajit24/VAPT-CLI.git
cd VAPT-CLI
bash install.sh
```

The installer creates a virtual environment, installs all dependencies, and sets up the `vapt` command.

### Manual Install

```sh
git clone https://github.com/aryanajit24/VAPT-CLI.git
cd VAPT-CLI
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Verify Installation

```sh
vapt --version
```

You should see the VAPT CLI version.

---

## First-Time Setup

Before scanning, configure your API keys. These are optional but unlock extra features like Shodan reconnaissance, VirusTotal checks, and NVD CVE lookups.

```sh
vapt config setup
```

This walks you through setting up:
- **Shodan** — for internet-wide device and service search
- **VirusTotal** — for checking domains against malware databases
- **SecurityTrails** — for DNS and subdomain history
- **Hunter.io** — for finding email addresses tied to a domain
- **NVD** — for looking up known CVEs (Common Vulnerabilities and Exposures)
- **SendGrid** — for email notifications when scans finish

All API keys are encrypted with AES-256-GCM and stored locally in `~/.vapt/`.

---

## Usage

Every command follows the same pattern:

```
vapt <command> --target <url-or-domain> [options]
```

### The Basics

**Run a full scan** (does everything at once):
```sh
vapt scan --target example.com
```

**Run recon only** (just gather info, no active testing):
```sh
vapt recon --target example.com
```

**Scan specific ports**:
```sh
vapt portscan --target example.com --ports 80,443,8080
```

**Check SSL/TLS**:
```sh
vapt sslscan --target example.com
```

### Web Scanning

**Web vulnerability scan** (XSS, SQLi, open redirects, header issues):
```sh
vapt webscan --target https://example.com
```

**DOM-based testing** (client-side XSS, prototype pollution, exposed secrets):
```sh
vapt domscan --target https://example.com
```

**API security scan**:
```sh
vapt apiscan --target https://api.example.com --token YOUR_BEARER_TOKEN
```

**Directory and file fuzzing** (find hidden paths, admin panels, IDOR):
```sh
vapt fuzz --target https://example.com
```

### Authentication Testing

**Auth scanner** (CSRF, CORS, IDOR, JWT, OAuth, session, default credentials):
```sh
vapt authscan --target https://example.com
```

**Auth flow testing** (privilege escalation, session fixation):
```sh
vapt authflow --target https://example.com
```

### Advanced Testing

**Advanced injections** (NoSQL, LDAP, deserialization, CRLF, cache poisoning):
```sh
vapt advanced --target https://example.com
```

**Race condition testing** (double-spend, rate limit bypass):
```sh
vapt racescan --target https://example.com
```

**HTTP request smuggling** (CL.TE, TE.CL, H2 downgrade):
```sh
vapt smuggle --target https://example.com
```

**Business logic scanner**:
```sh
vapt bizscan --target https://example.com
```

### Proxy & Interactive Tools

**Start the intercepting proxy** (like Burp's proxy — intercepts HTTP/HTTPS with SSL MITM):
```sh
vapt proxy --port 8080
```
Configure your browser to use `127.0.0.1:8080` as a proxy. Install the CA cert from `~/.vapt/ca/ca.pem` to intercept HTTPS.

**Launch the interactive TUI** (terminal UI with proxy log, repeater, intruder, and codec):
```sh
vapt tui
```
Use keyboard shortcuts: `1`=Proxy, `2`=Repeater, `3`=Intruder, `4`=Codec, `q`=Quit.

**Crawl a website** (Playwright-based headless browser crawler):
```sh
vapt crawl --target https://example.com --depth 3 --max-pages 100
```
Discovers pages, forms, API endpoints, JS files, and technologies. Use `--light` for a faster requests-based crawl.

**Run the Intruder** (Burp Intruder replacement with 4 attack modes):
```sh
vapt intruder --target "https://example.com/search?q=§test§" --attack sniper --payloads sqli
```
Mark positions with `§markers§`. Attack modes: `sniper`, `battering_ram`, `pitchfork`, `cluster_bomb`. Built-in payloads: `sqli`, `xss`, `traversal`, `ssti`, `nosql`, `commands`, `common_passwords`, `idor`.

**Analyze token randomness** (Burp Sequencer replacement):
```sh
vapt sequencer --url https://example.com/login --from cookie --name session --samples 200
```
Collects tokens and runs Shannon entropy, chi-squared, monobit, runs, and block frequency tests.

**Encode/decode data** (Burp Decoder replacement):
```sh
vapt codec "hello world" --op b64e     # Base64 encode
vapt codec "aGVsbG8=" --op b64d        # Base64 decode
vapt codec "password" --op sha256       # SHA-256 hash
vapt codec "5d41402abc4b2a76b9719d911017c592" --op hashid  # Identify hash type
vapt codec "eyJhbGciOi..." --op jwtd    # Decode JWT
vapt codec "test data" --op smart       # Try all decodings
```

### Infrastructure

**Cloud misconfiguration scanner** (S3, Azure, GCP, Firebase):
```sh
vapt cloudscan --target example.com
```

**Infrastructure scanner** (admin panels, config files, debug endpoints, backups):
```sh
vapt infrascan --target example.com
```

**Database scanner** (exposed databases, no-auth access, default credentials):
```sh
vapt dbscan --target example.com
```

### JavaScript & Mobile

**Deep JavaScript recon** (mine endpoints, secrets, and API routes from JS files):
```sh
vapt deepjs --target https://example.com
```

**Mobile app analysis** (static analysis of Android APK or iOS IPA):
```sh
vapt mobilescan --app ./target-app.apk
```

### Bug Bounty Modes

**Interactive hunt mode** (guided bug bounty hunting):
```sh
vapt hunt
```
This asks you questions about the target program, then builds and runs a complete scanning strategy. Great for beginners.

**Elite mode** (8-phase strategic pipeline for experienced hunters):
```sh
vapt elite
```
Runs: Deep JS Recon → Endpoint Intelligence → Authenticated Testing → Business Logic → OOB Testing → Targeted Scanning → Elite Intelligence with novelty scoring → Report Generation.

### Reports & Monitoring

**Re-generate a report from a previous scan**:
```sh
vapt report --scan-file ./vapt-reports/scan_abc123.json --format pdf
```

**Continuous monitoring** (re-scan every 24 hours):
```sh
vapt monitor --target example.com --interval 86400
```

---

## Scan Options

These options work with `vapt scan` and most other commands:

| Option | Short | What It Does |
|--------|-------|-------------|
| `--target` | `-t` | The URL, domain, or IP to scan |
| `--output` | `-o` | Where to save reports (default: `./vapt-reports`) |
| `--format` | `-f` | Report format: `html`, `pdf`, `json`, or comma-separated |
| `--deep` | `-d` | Also scan discovered subdomains |
| `--max-subs` | | Max subdomains to deep-scan (default: 5) |
| `--validate` | | Re-test findings to filter false positives |
| `--waf-bypass` | | Detect WAF and try bypass techniques |
| `--fast` | | Skip slow modules if WAF is detected |
| `--stealth` | `-s` | Speed profile: `aggressive`, `normal`, `polite`, `stealth` |
| `--safety` | | Safety profile: `aggressive`, `standard`, `hackerone`, `bugcrowd` |
| `--modules` | | Only run specific modules (comma-separated) |
| `--executive` | | Also generate an executive summary |
| `--notify` | | Send email/Slack alerts when done |
| `--show-all` | | Show all findings including out-of-scope |

### Authentication Options

For scanning targets that require login:

| Option | What It Does |
|--------|-------------|
| `--auth` | Auth method: `bearer`, `basic`, `cookie`, `form`, `digest`, `oauth2`, `header` |
| `--token` | Bearer token value |
| `--username` / `-u` | Username |
| `--password` / `-P` | Password |
| `--cookies` | Cookie string (`name=val; name2=val2`) |
| `--login-url` | Login page URL (for form-based auth) |
| `--headers` | Custom headers (`Key:Value,Key2:Value2`) |

### Scope Control

| Option | What It Does |
|--------|-------------|
| `--scope-in` | Only test these targets (comma-separated) |
| `--scope-out` | Never test these targets (comma-separated) |
| `--scope-file` | Path to a YAML scope definition file |
| `--min-severity` | Minimum severity to report: `critical`, `high`, `medium`, `low`, `info` |
| `--exclude-categories` | Skip certain vuln categories (comma-separated) |

---

## Examples

### Example 1: Quick website check

```sh
vapt scan --target mysite.com --fast --format html
```

Runs a full scan in fast mode and saves an HTML report.

### Example 2: Authenticated API scan

```sh
vapt apiscan --target https://api.mysite.com --token eyJhbGciOi...
```

Tests API endpoints using your bearer token.

### Example 3: Deep scan with validation

```sh
vapt scan --target mysite.com --deep --validate --waf-bypass --format html,pdf,json
```

Scans the main target plus subdomains, validates findings to remove false positives, bypasses WAF, and generates reports in all three formats.

### Example 4: Bug bounty on HackerOne

```sh
vapt scan --target target.com --safety hackerone --stealth polite --validate --scope-file scopes/program.yaml
```

Uses HackerOne-safe settings, polite request rates, validates findings, and respects the program's scope file.

### Example 5: Mobile app audit

```sh
vapt mobilescan --app ./downloads/app-release.apk --format pdf
```

Decompiles the APK and checks for hardcoded secrets, insecure storage, weak crypto, and more.

---

## Configuration Management

```sh
# Show current config (API keys are masked)
vapt config show

# Run the full setup wizard
vapt config setup

# Set a single config value
vapt config set max_threads 10

# Update one API key
vapt config set-key shodan YOUR_API_KEY
```

---

## Database & Updates

```sh
# Check knowledge base status
vapt db status

# Seed the knowledge base with vulnerability data
vapt db seed

# Reset the database
vapt db reset

# Update tools and vulnerability signatures
vapt update
```

---

## Project Structure

```
vapt/
├── main.py              # All 32 CLI commands
├── banner.py            # The cool banner you see when it starts
├── config.py            # Config wizard and API key management
├── database/            # SQLite knowledge base
│   ├── db.py            # Database connection and init
│   ├── models.py        # SQLAlchemy models
│   └── seed_kb.py       # Seeds the KB with vulnerability data
├── engine/              # Core logic engines
│   ├── ai_triage.py     # AI-powered finding prioritization
│   ├── browser.py       # Headless browser for JS-heavy sites
│   ├── compliance.py    # NIS2/ISO 27001 compliance mapping
│   ├── correlator.py    # Links related findings together
│   ├── evidence.py      # Enriches findings with proof
│   ├── exploit_validator.py  # Active exploit confirmation
│   ├── intelligence.py  # Threat intelligence lookups
│   ├── intruder.py      # Burp Intruder replacement (4 attack modes)
│   ├── knowledge_base.py    # Vulnerability knowledge base
│   ├── oob_server.py    # Out-of-band callback server
│   ├── oob.py           # OOB payload manager
│   ├── parallel.py      # Parallel scan execution
│   ├── payloads.py      # Payload generation
│   ├── risk_scorer.py   # CVSS-based risk scoring
│   ├── safe_mode.py     # Safety profiles for bug bounty
│   ├── scope.py         # Scope enforcement
│   ├── sequencer.py     # Token randomness analyzer
│   ├── session_manager.py   # Authenticated session handling
│   ├── smart_hunt.py    # Smart hunting orchestrator
│   ├── validator.py     # False positive filtering
│   └── waf.py           # WAF detection and bypass
├── scanner/             # All scanning modules
│   ├── advanced.py      # NoSQL, LDAP, deserialization, CRLF
│   ├── apiscan.py       # API security testing
│   ├── authflow.py      # Auth flow and privilege testing
│   ├── authscan.py      # CSRF, CORS, IDOR, JWT, OAuth
│   ├── bizscan.py       # Business logic vulnerabilities
│   ├── cloudscan.py     # Cloud misconfigurations
│   ├── codescan.py      # Source code analysis (SAST)
│   ├── crawler.py       # Playwright headless browser crawler
│   ├── cve.py           # CVE lookup and matching
│   ├── dbscan.py        # Database exposure scanning
│   ├── deepjs.py        # Deep JavaScript reconnaissance
│   ├── domscan.py       # DOM XSS and client-side security
│   ├── fuzzer.py        # Directory/file/IDOR fuzzing
│   ├── infrascan.py     # Infrastructure scanning
│   ├── jsscan.py        # JS secret scanning
│   ├── mobilescan.py    # Android APK / iOS IPA analysis
│   ├── monitor.py       # Continuous monitoring
│   ├── portscan.py      # Port and service scanning
│   ├── racescan.py      # Race condition testing
│   ├── recon.py         # Reconnaissance and asset discovery
│   ├── smuggler.py      # HTTP request smuggling
│   ├── sslscan.py       # SSL/TLS analysis
│   ├── takeover.py      # Subdomain takeover detection
│   └── webscan.py       # Web vulnerability scanning
├── plugins/             # Custom plugin system
│   ├── loader.py        # YAML plugin loader
│   └── example_checks.yaml
├── reporting/           # Report generation
│   ├── bounty_report.py # Bug bounty report formatter
│   ├── elite_report.py  # Elite mode reports
│   ├── generator.py     # Core report engine
│   ├── html.py          # HTML report renderer
│   ├── json_report.py   # JSON report output
│   ├── pdf.py           # PDF report renderer
│   └── templates/       # Jinja2 HTML/CSS templates
├── proxy/               # Intercepting proxy
│   ├── server.py        # MITM proxy with SSL interception
│   └── storage.py       # SQLite flow storage
├── tui/                 # Interactive terminal UI
│   └── app.py           # Textual TUI with 4 tabs
└── utils/               # Shared utilities
    ├── auth.py          # Authentication helpers│   ├── codec.py         # Encoder/decoder/hash tools    ├── helpers.py       # Common helper functions
    ├── notifications.py # Email/Slack alerts
    ├── ratelimit.py     # Rate limiting and stealth
    ├── validators.py    # Input validation
    └── wordlists.py     # Fuzzing wordlists
```

---

## How It Works (Simple Version)

Here's what happens when you run `vapt scan --target example.com`:

1. **Recon** — Finds subdomains, DNS records, WHOIS info, technologies used
2. **Port Scan** — Checks which ports are open and what services are running
3. **SSL Check** — Tests the HTTPS certificate and encryption strength
4. **Web Scan** — Tests for XSS, SQL injection, open redirects, missing headers
5. **DOM Scan** — Checks client-side JavaScript for vulnerabilities
6. **Auth Scan** — Tests CSRF, CORS, session management, default credentials
7. **API Scan** — Tests REST/GraphQL endpoints for security issues
8. **Fuzzing** — Tries thousands of paths to find hidden files and directories
9. **Race Testing** — Sends parallel requests to find race conditions
10. **Smuggling** — Tests for HTTP request smuggling vulnerabilities
11. **Cloud Check** — Looks for exposed S3 buckets, Azure blobs, Firebase
12. **CVE Lookup** — Matches detected software versions against known vulnerabilities
13. **Infrastructure** — Checks for exposed admin panels, config files, backups
14. **Database** — Tests for exposed databases with no authentication
15. **Plugins** — Runs any custom checks you've defined in YAML
16. **Validation** — Re-tests findings to confirm they're real (if `--validate` is on)
17. **Correlation** — Links related findings together for a complete picture
18. **Compliance** — Maps findings to NIS2/ISO 27001 requirements
19. **Reporting** — Generates a professional report in your chosen format

---

## Safety Profiles

When doing bug bounty, you don't want to accidentally break something or go out of scope. Safety profiles control what the tool is allowed to do:

| Profile | What It Does |
|---------|-------------|
| `aggressive` | No limits — full testing, full speed |
| `standard` | Default — safe for most targets |
| `hackerone` | Follows HackerOne program rules |
| `bugcrowd` | Follows Bugcrowd program rules |
| `meesho` | Custom profile for Meesho's program |
| `optus` | Custom profile for Optus's program |

Use them like this:
```sh
vapt scan --target example.com --safety hackerone
```

---

## Stealth Profiles

Control how fast and noisy the scanner is:

| Profile | Requests/sec | Use When |
|---------|-------------|----------|
| `aggressive` | No limit | Testing your own stuff |
| `normal` | 10/sec | General scanning |
| `polite` | 3/sec | Bug bounty programs |
| `stealth` | 1/sec | Avoiding detection |

```sh
vapt scan --target example.com --stealth polite
```

---

## Scope Files

You can define what's in-scope and out-of-scope using a YAML file:

```yaml
program: "Example Program"
platform: "hackerone"
in_scope:
  - "*.example.com"
  - "api.example.com"
out_of_scope:
  - "blog.example.com"
  - "status.example.com"
severity_exclusions:
  - "info"
```

Then use it:
```sh
vapt scan --target example.com --scope-file scopes/example.yaml
```

---

## Custom Plugins

Create your own checks in YAML:

```yaml
- id: custom-admin-check
  name: "Admin Panel Exposed"
  description: "Checks if common admin panels are publicly accessible"
  severity: high
  paths:
    - /admin
    - /administrator
    - /wp-admin
  match:
    status: 200
    body_contains: "login"
```

Save it as a `.yaml` file and pass it:
```sh
vapt scan --target example.com --plugins ./my-plugins/
```

---

## Requirements

- Python 3.10 or newer
- macOS, Linux, or Windows (WSL recommended)
- Optional: Go tools (Subfinder, Nuclei) for enhanced scanning — installed automatically by `install.sh`

### Python Dependencies

The main libraries used:

| Library | Purpose |
|---------|---------|
| typer + rich | CLI interface and pretty output |
| textual | Interactive terminal UI (TUI) |
| requests + httpx | HTTP requests |
| beautifulsoup4 + lxml | HTML parsing |
| dnspython | DNS lookups |
| python-nmap | Port scanning |
| cryptography | AES-256-GCM key encryption |
| sqlalchemy | Knowledge base database |
| jinja2 + weasyprint | HTML/PDF report generation |
| playwright | Headless browser for JS-heavy sites |
| shodan | Shodan API integration |
| paramiko | SSH testing |
| pyyaml | Config and scope file parsing |

---

## Running Tests

```sh
# Activate the virtual environment
source venv/bin/activate

# Run all 242 tests
python3 -m pytest tests/ -v

# Run only the v8 module tests
python3 -m pytest tests/test_v8_modules.py -v

# Run the Burp replacement module tests
python3 -m pytest tests/test_burp_modules.py -v

# Run with coverage
python3 -m pytest tests/ --cov=vapt --cov-report=html
```

---

## Common Questions

**Q: Is this legal to use?**
Only scan targets you have permission to test. Using this on websites you don't own or don't have authorization to test is illegal. Bug bounty programs give you explicit permission for specific targets.

**Q: Do I need all the API keys?**
No. The tool works without any API keys. Keys just unlock extra features like Shodan device search and VirusTotal malware checks.

**Q: Will this break the target website?**
With default settings (`--safety standard`), the tool is non-destructive. It only sends GET requests and lightweight tests. Use `--safety aggressive` only on targets you own.

**Q: How is this different from Burp Suite or OWASP ZAP?**
VAPT CLI is fully command-line based with an integrated intercepting proxy, Intruder-style fuzzer, token Sequencer, and codec — similar to Burp Suite Pro but terminal-native. It runs automated scans without a GUI, generates reports automatically, and is designed for CI/CD pipelines, bug bounty automation, and people who prefer terminals over GUIs.

**Q: Can I use this in a CI/CD pipeline?**
Yes. Use `--format json` to get machine-readable output, and `--min-severity high` to fail only on serious findings.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

Built by [@aryanajit24](https://github.com/aryanajit24)

