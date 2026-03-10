
from __future__ import annotations

import math
import re
from collections import deque
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

from vapt.utils.helpers import sanitize_target


_SECRET_PATTERNS: list[tuple[re.Pattern, str, str, str, float, str]] = []


def _p(pattern: str, cat: str, title: str, sev: str, cvss: float, desc: str) -> None:
    _SECRET_PATTERNS.append((
        re.compile(pattern, re.IGNORECASE),
        cat, title, sev, cvss, desc,
    ))


_p(r"""(?:['"`])?(AKIA[0-9A-Z]{16})(?:['"`])?""",
   "exposed_secret", "AWS Access Key ID", "critical", 9.8,
   "Hardcoded AWS access key found in JavaScript. Can access AWS resources.")
_p(r"""(?:aws_secret_access_key|aws_secret|secretAccessKey)\s*[:=]\s*['"`]([A-Za-z0-9/+=]{40})['"`]""",
   "exposed_secret", "AWS Secret Access Key", "critical", 9.8,
   "AWS secret key found in JavaScript. Full access to AWS account possible.")

_p(r"""(?:AIza[0-9A-Za-z_-]{35})""",
   "exposed_secret", "Google API Key", "high", 7.5,
   "Google API key in JavaScript. May allow access to Google Cloud services.")
_p(r"""(?:['"`])?(\d+-[a-z0-9]+\.apps\.googleusercontent\.com)(?:['"`])?""",
   "exposed_secret", "Google OAuth Client ID", "medium", 5.3,
   "Google OAuth Client ID exposed. May enable phishing or token theft.")

_p(r"""(?:apiKey|firebase[_-]?api[_-]?key)\s*[:=]\s*['"`]([A-Za-z0-9_-]{20,50})['"`]""",
   "exposed_secret", "Firebase API Key", "high", 7.5,
   "Firebase API key found. May allow DB access or user enumeration.")
_p(r"""(?:['"`])(https://[a-z0-9-]+\.firebaseio\.com)['"`]""",
   "exposed_secret", "Firebase Database URL", "high", 8.1,
   "Firebase database URL exposed. Check for open database rules.")
_p(r"""(?:['"`])(https://[a-z0-9-]+\.firebaseapp\.com)['"`]""",
   "info_disclosure", "Firebase App URL", "low", 3.7,
   "Firebase app URL found in JS.")
_p(r"""(?:messagingSenderId|storageBucket|authDomain|projectId|appId|measurementId)\s*[:=]\s*['"`]([^'"`]+)['"`]""",
   "info_disclosure", "Firebase Configuration", "medium", 5.3,
   "Firebase configuration keys found. Combined with other keys may allow full access.")

_p(r"""(?:sk_live_[0-9a-zA-Z]{24,99})""",
   "exposed_secret", "Stripe Live Secret Key", "critical", 9.8,
   "Stripe live secret key! Can charge cards and access payment data.")
_p(r"""(?:pk_live_[0-9a-zA-Z]{24,99})""",
   "info_disclosure", "Stripe Live Publishable Key", "low", 2.0,
   "Stripe publishable key (public by design, but confirms Stripe usage).")
_p(r"""(?:sk_test_[0-9a-zA-Z]{24,99})""",
   "exposed_secret", "Stripe Test Secret Key", "high", 7.5,
   "Stripe test secret key. Can access test payment data and configs.")

_p(r"""(?:ghp_[0-9a-zA-Z]{36})""",
   "exposed_secret", "GitHub Personal Access Token", "critical", 9.8,
   "GitHub PAT found. Can access private repos and modify code.")
_p(r"""(?:gho_[0-9a-zA-Z]{36})""",
   "exposed_secret", "GitHub OAuth Token", "critical", 9.8,
   "GitHub OAuth token found.")
_p(r"""(?:glpat-[0-9a-zA-Z_-]{20,})""",
   "exposed_secret", "GitLab Personal Access Token", "critical", 9.8,
   "GitLab personal access token found.")

_p(r"""(xox[bpors]-[0-9a-zA-Z-]{10,})""",
   "exposed_secret", "Slack Token", "high", 8.1,
   "Slack API token found. Can read messages, channels, files.")
_p(r"""(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)""",
   "exposed_secret", "Slack Webhook URL", "high", 7.5,
   "Slack incoming webhook found. Can send messages to Slack channel.")

_p(r"""(?:AC[a-f0-9]{32})""",
   "exposed_secret", "Twilio Account SID", "high", 7.5,
   "Twilio Account SID found in JavaScript.")
_p(r"""(?:SK[a-f0-9]{32})""",
   "exposed_secret", "Twilio API Key", "high", 8.1,
   "Twilio API key found. Can send SMS, make calls, access account.")

_p(r"""(?:SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43})""",
   "exposed_secret", "SendGrid API Key", "high", 8.1,
   "SendGrid API key. Can send emails, access mail logs.")
_p(r"""(?:key-[0-9a-zA-Z]{32})""",
   "exposed_secret", "Mailgun API Key", "high", 8.1,
   "Possible Mailgun API key found.")

_p(r"""(?:api[_-]?key|apikey|api_secret|app[_-]?key|app[_-]?secret|secret[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*['"`]([A-Za-z0-9_/+=.!@#$%^&*-]{16,100})['"`]""",
   "exposed_secret", "Generic API Key / Secret", "high", 7.5,
   "API key or secret found in JavaScript source code.")
_p(r"""(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`\s]{6,100})['"`]""",
   "exposed_secret", "Hardcoded Password", "high", 8.1,
   "Password found in JavaScript source. May allow direct authentication.")
_p(r"""(?:['"`])(Bearer\s+eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]*)['"`]""",
   "exposed_secret", "Bearer Token / JWT in Source", "high", 8.1,
   "JWT bearer token found in JS. May still be valid.")

_p(r"""(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})""",
   "exposed_secret", "JSON Web Token (JWT)", "high", 7.5,
   "JWT token found in JavaScript. Decode at jwt.io to inspect claims.")

_p(r"""(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)""",
   "exposed_secret", "Private Key Material", "critical", 9.8,
   "Private key found in JavaScript! Full cryptographic compromise.")

_p(r"""(?:['"`])(https?://(?:(?:staging|stg|dev|internal|test|uat|qa|preprod|sandbox|local|admin|backend|api-internal|api-dev|api-staging)[.-])[^\s'"`]{5,})['"`]""",
   "info_disclosure", "Internal / Staging URL", "medium", 5.3,
   "Internal or staging URL found in JS. May expose unauthenticated dev services.")
_p(r"""(?:['"`])(https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost)(?::\d+)?[^\s'"`]*)['"`]""",
   "info_disclosure", "Private/Local IP URL in JS", "medium", 5.3,
   "Private network URL found in JavaScript. May indicate internal service endpoints.")

_p(r"""(?:['"`])(https?://[a-z0-9.-]+\.s3[.-](?:amazonaws\.com|[a-z0-9-]+\.amazonaws\.com)[^\s'"`]*)['"`]""",
   "info_disclosure", "AWS S3 Bucket URL", "medium", 5.3,
   "S3 bucket URL found. Check for public access and sensitive data.")
_p(r"""(?:['"`])(https?://[a-z0-9.-]+\.blob\.core\.windows\.net[^\s'"`]*)['"`]""",
   "info_disclosure", "Azure Blob Storage URL", "medium", 5.3,
   "Azure blob storage URL found. Check for public read access.")
_p(r"""(?:['"`])(https?://storage\.googleapis\.com/[^\s'"`]+)['"`]""",
   "info_disclosure", "Google Cloud Storage URL", "medium", 5.3,
   "GCS URL found. Check for public access.")

_p(r"""(?:['"`])(\/(?:api\/)?(?:v[0-9]+\/)?(?:admin|internal|debug|graphql|swagger|docs|health|metrics|status|config|settings|env|users|user|accounts?|payments?|billing|orders?|auth|login|signup|register|reset|password|token|secret|private|backend)[^\s'"`]*)['"`]""",
   "endpoint_disclosure", "Sensitive API Endpoint", "low", 3.7,
   "Hidden API endpoint found in JavaScript. May accept direct requests.")


SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")


FP_VALUES: set[str] = {
    "undefined", "null", "true", "false", "none",
    "your_api_key", "YOUR_API_KEY", "YOUR-API-KEY",
    "xxx", "XXXX", "xxxxxxxx", "test", "example",
    "placeholder", "your-key", "your_key", "change_me",
    "TODO", "FIXME", "INSERT_KEY_HERE", "apiKey",
    "replace_me", "changethis", "sample", "demo",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _is_false_positive(value: str) -> bool:
    if not value or len(value) < 8:
        return True
    v = value.strip("'\"` \t\n")
    if v.lower() in {fp.lower() for fp in FP_VALUES}:
        return True
    if len(set(v)) <= 2:
        return True
    if len(v) > 15 and _shannon_entropy(v) < 2.5:
        return True
    if re.match(r"^[a-z][a-zA-Z]+\(", v):
        return True
    return False


class JSSecretScanner:

    def __init__(
        self,
        timeout: int = 10,
        max_js_files: int = 100,
        session: Any = None,
    ) -> None:
        self.timeout = timeout
        self.max_js_files = max_js_files
        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.verify = False
            self.session.headers.update({
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                              "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
            })

    def run(self, target: str) -> dict[str, Any]:
        target = sanitize_target(target)
        base_url = (
            target
            if target.startswith(("http://", "https://"))
            else f"https://{target}"
        )

        result: dict[str, Any] = {
            "target": base_url,
            "category": "jsscan",
            "js_files_scanned": 0,
            "findings": [],
        }

        js_urls = self._discover_js_files(base_url)
        result["js_files_discovered"] = len(js_urls)

        seen_secrets: set[str] = set()
        for js_url in js_urls[: self.max_js_files]:
            try:
                resp = self.session.get(js_url, timeout=self.timeout)
                if resp.status_code != 200:
                    continue
                if len(resp.content) < 50:
                    continue
                result["js_files_scanned"] += 1
                findings = self._scan_js_content(js_url, resp.text, seen_secrets)
                result["findings"].extend(findings)

                sm_findings = self._check_source_map(js_url, resp.text)
                result["findings"].extend(sm_findings)

            except RequestException:
                continue

        return result

    def _discover_js_files(self, base_url: str) -> list[str]:
        js_urls: set[str] = set()
        visited: set[str] = set()
        queue: deque[str] = deque([base_url])
        origin = urlparse(base_url).netloc
        max_pages = 30

        while queue and len(visited) < max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)

            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            except RequestException:
                continue
            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            for script in soup.find_all("script", src=True):
                src = script["src"]
                abs_url = urljoin(resp.url, src)
                parsed = urlparse(abs_url)
                if parsed.netloc == origin or abs_url.endswith(".js"):
                    js_urls.add(abs_url)

            for link in soup.find_all("link", {"as": "script"}):
                href = link.get("href", "")
                if href:
                    js_urls.add(urljoin(resp.url, href))

            for tag in soup.find_all("a", href=True):
                href = urljoin(resp.url, tag["href"])
                parsed = urlparse(href)
                if parsed.netloc == origin and href not in visited:
                    queue.append(href)

        common_js_paths = [
            "/static/js/main.js", "/static/js/app.js", "/static/js/bundle.js",
            "/assets/js/app.js", "/js/app.js", "/js/main.js",
            "/dist/js/app.js", "/build/static/js/main.js",
            "/webpack-runtime.js", "/vendor.js", "/chunk-vendors.js",
            "/_next/static/chunks/main.js", "/_next/static/chunks/pages/_app.js",
        ]
        for path in common_js_paths:
            url = base_url.rstrip("/") + path
            try:
                resp = self.session.head(url, timeout=5)
                if resp.status_code == 200 and "javascript" in resp.headers.get("Content-Type", ""):
                    js_urls.add(url)
            except RequestException:
                pass

        return sorted(js_urls)

    def _scan_js_content(
        self, js_url: str, content: str, seen: set[str],
    ) -> list[dict]:
        findings: list[dict] = []

        for regex, cat, title, sev, cvss, desc in _SECRET_PATTERNS:
            for m in regex.finditer(content):
                matched = m.group(1) if m.lastindex else m.group(0)
                dedup_key = (title, matched[:50])
                if dedup_key in seen:
                    continue

                if cat == "exposed_secret" and _is_false_positive(matched):
                    continue
                if cat == "endpoint_disclosure" and _is_false_positive(matched):
                    continue

                seen.add(dedup_key)

                start = max(0, m.start() - 80)
                end = min(len(content), m.end() + 80)
                context = content[start:end].replace("\n", " ").strip()

                findings.append({
                    "vuln_id": self._vuln_id(cat),
                    "category": cat,
                    "title": f"{title} in {urlparse(js_url).path}",
                    "description": desc,
                    "severity": sev,
                    "cvss_score": cvss,
                    "scanner": "JSSecretScanner",
                    "url": js_url,
                    "evidence": f"File: {js_url}\nMatch: {matched[:200]}\nContext: ...{context}...",
                    "matched_value": matched[:200],
                    "js_file": js_url,
                })

        return findings

    def _check_source_map(self, js_url: str, content: str) -> list[dict]:
        findings: list[dict] = []
        m = SOURCE_MAP_RE.search(content)
        if not m:
            return findings

        map_ref = m.group(1)
        if map_ref.startswith("data:"):
            return findings

        map_url = urljoin(js_url, map_ref)
        try:
            resp = self.session.get(map_url, timeout=self.timeout)
            if resp.status_code == 200 and len(resp.content) > 100:
                ct = resp.headers.get("Content-Type", "")
                text = resp.text[:500]
                if "mappings" in text or "sources" in text or "json" in ct:
                    source_count = text.count('"sources"')
                    findings.append({
                        "vuln_id": "JS-005",
                        "category": "info_disclosure",
                        "title": f"Source map exposed: {urlparse(map_url).path}",
                        "description": (
                            "JavaScript source map file is publicly accessible. "
                            "Source maps contain the ORIGINAL unminified source code, "
                            "including comments, variable names, and internal logic. "
                            "This effectively gives attackers the full application source code."
                        ),
                        "severity": "high",
                        "cvss_score": 7.5,
                        "scanner": "JSSecretScanner",
                        "url": map_url,
                        "evidence": (
                            f"Source map URL: {map_url}\n"
                            f"Size: {len(resp.content)} bytes\n"
                            f"Content-Type: {ct}\n"
                            f"Preview: {text[:300]}"
                        ),
                    })
        except RequestException:
            pass

        return findings

    @staticmethod
    def _vuln_id(category: str) -> str:
        return {
            "exposed_secret": "JS-001",
            "info_disclosure": "JS-002",
            "endpoint_disclosure": "JS-006",
        }.get(category, "JS-001")
