
from __future__ import annotations

import copy
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests


CWE_MAP: dict[str, str] = {
    "sql_injection": "CWE-89",
    "sqli": "CWE-89",
    "blind_sqli": "CWE-89",
    "xss": "CWE-79",
    "reflected_xss": "CWE-79",
    "stored_xss": "CWE-79",
    "dom_xss": "CWE-79",
    "ssti": "CWE-1336",
    "template_injection": "CWE-1336",
    "command_injection": "CWE-78",
    "cmdi": "CWE-78",
    "path_traversal": "CWE-22",
    "traversal": "CWE-22",
    "lfi": "CWE-98",
    "ssrf": "CWE-918",
    "xxe": "CWE-611",
    "open_redirect": "CWE-601",
    "redirect": "CWE-601",
    "csrf": "CWE-352",
    "cors": "CWE-942",
    "idor": "CWE-639",
    "bola": "CWE-639",
    "jwt": "CWE-345",
    "broken_auth": "CWE-287",
    "default_credentials": "CWE-1392",
    "exposed_admin_panel": "CWE-425",
    "exposed_debug_endpoint": "CWE-489",
    "session_fixation": "CWE-384",
    "missing_auth": "CWE-306",
    "privilege_escalation": "CWE-269",
    "mass_assignment": "CWE-915",
    "oauth": "CWE-346",
    "mfa_bypass": "CWE-308",
    "race_condition": "CWE-362",
    "toctou": "CWE-367",
    "request_smuggling": "CWE-444",
    "http_smuggling": "CWE-444",
    "crlf_injection": "CWE-93",
    "header_injection": "CWE-113",
    "security_header": "CWE-693",
    "missing_header": "CWE-693",
    "info_disclosure": "CWE-200",
    "sensitive_data": "CWE-200",
    "directory_listing": "CWE-548",
    "exposed_file": "CWE-538",
    "subdomain_takeover": "CWE-923",
    "ssl_tls": "CWE-326",
    "weak_cipher": "CWE-327",
    "expired_cert": "CWE-298",
    "insecure_cookie": "CWE-614",
    "nosql_injection": "CWE-943",
    "ldap_injection": "CWE-90",
    "deserialization": "CWE-502",
    "prototype_pollution": "CWE-1321",
    "postmessage": "CWE-345",
    "websocket": "CWE-1385",
    "exposed_secret": "CWE-798",
    "api_key_exposure": "CWE-798",
    "graphql": "CWE-200",
    "cache_poisoning": "CWE-349",
    "s3_bucket": "CWE-284",
    "cloud_misconfiguration": "CWE-16",
    "open_port": "CWE-284",
    "default_creds": "CWE-1392",
    "cve": "CWE-1035",
    "technology_disclosure": "CWE-200",
    "cors_misconfiguration": "CWE-942",
    "robots_exposure": "CWE-200",
    "access_control": "CWE-284",
    "endpoint_disclosure": "CWE-200",
    "jsscan": "CWE-798",
}

CVSS_VECTORS: dict[str, str] = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "high":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "medium":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "low":      "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    "info":     "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
}

CATEGORY_CVSS: dict[str, tuple[float, str]] = {
    "sql_injection":       (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "sqli":                (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "command_injection":   (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "cmdi":                (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "ssti":                (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "xxe":                 (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "ssrf":                (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "deserialization":     (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "request_smuggling":   (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    "xss":                 (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "reflected_xss":       (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "dom_xss":             (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "csrf":                (8.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    "idor":                (7.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    "bola":                (7.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    "jwt":                 (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "cors":                (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    "open_redirect":       (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "path_traversal":      (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "race_condition":      (8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "subdomain_takeover":  (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    "default_credentials": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "exposed_admin_panel": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "exposed_debug_endpoint": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "exposed_secret":      (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
}


def format_raw_request(prepared: requests.PreparedRequest) -> str:
    method = prepared.method or "GET"
    url = prepared.url or ""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    lines = [f"{method} {path} HTTP/1.1"]
    lines.append(f"Host: {parsed.hostname or 'unknown'}")

    if prepared.headers:
        for key, val in prepared.headers.items():
            if key.lower() == "host":
                continue
            lines.append(f"{key}: {val}")

    body = ""
    if prepared.body:
        if isinstance(prepared.body, bytes):
            try:
                body = prepared.body.decode("utf-8", errors="replace")
            except Exception:
                body = "<binary data>"
        else:
            body = str(prepared.body)

    raw = "\r\n".join(lines) + "\r\n\r\n"
    if body:
        raw += body
    return raw


def format_raw_response(resp: requests.Response, max_body: int = 2000) -> str:
    lines = [f"HTTP/1.1 {resp.status_code} {resp.reason or ''}"]

    for key, val in resp.headers.items():
        lines.append(f"{key}: {val}")

    raw = "\r\n".join(lines) + "\r\n\r\n"

    body = resp.text[:max_body] if resp.text else ""
    if len(resp.text or "") > max_body:
        body += f"\n\n[... truncated, {len(resp.text)} bytes total ...]"
    raw += body
    return raw


@dataclass
class CapturedExchange:
    method: str
    url: str
    request_raw: str
    response_raw: str
    status_code: int
    response_time: float
    response_body: str = ""
    response_headers: dict = field(default_factory=dict)


class EvidenceCollector:

    def __init__(self, session: requests.Session | None = None, timeout: int = 10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self._exchanges: list[CapturedExchange] = []
        self.last_request: str = ""
        self.last_response: str = ""
        self.last_status: int = 0
        self.last_body: str = ""
        self.last_headers: dict = {}

    def __getattr__(self, name: str):
        return getattr(self.session, name)

    def _capture(self, resp: requests.Response, elapsed: float) -> CapturedExchange:
        req_raw = format_raw_request(resp.request)
        resp_raw = format_raw_response(resp)
        exchange = CapturedExchange(
            method=resp.request.method or "GET",
            url=resp.request.url or "",
            request_raw=req_raw,
            response_raw=resp_raw,
            status_code=resp.status_code,
            response_time=elapsed,
            response_body=resp.text[:5000] if resp.text else "",
            response_headers=dict(resp.headers),
        )
        self._exchanges.append(exchange)
        self.last_request = req_raw
        self.last_response = resp_raw
        self.last_status = resp.status_code
        self.last_body = resp.text[:5000] if resp.text else ""
        self.last_headers = dict(resp.headers)
        return exchange

    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", False)
        t0 = time.time()
        resp = self.session.get(url, **kwargs)
        self._capture(resp, time.time() - t0)
        return resp

    def post(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", False)
        t0 = time.time()
        resp = self.session.post(url, **kwargs)
        self._capture(resp, time.time() - t0)
        return resp

    def put(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        t0 = time.time()
        resp = self.session.put(url, **kwargs)
        self._capture(resp, time.time() - t0)
        return resp

    def delete(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        t0 = time.time()
        resp = self.session.delete(url, **kwargs)
        self._capture(resp, time.time() - t0)
        return resp

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        t0 = time.time()
        resp = self.session.request(method, url, **kwargs)
        self._capture(resp, time.time() - t0)
        return resp

    @property
    def exchanges(self) -> list[CapturedExchange]:
        return list(self._exchanges)

    def clear(self) -> None:
        self._exchanges.clear()
        self.last_request = ""
        self.last_response = ""


STEPS_TEMPLATES: dict[str, list[str]] = {
    "sql_injection": [
        "Navigate to {url}",
        "Locate the input field for parameter '{parameter}'",
        "Enter the following SQL injection payload: `{payload}`",
        "Submit the form / send the request",
        "Observe the response — the application returns SQL error messages or altered query results, confirming injection",
    ],
    "sqli": [
        "Navigate to {url}",
        "Locate the input field for parameter '{parameter}'",
        "Enter the following SQL injection payload: `{payload}`",
        "Submit the form / send the request",
        "Observe the response — the application returns SQL error messages or altered query results, confirming injection",
    ],
    "blind_sqli": [
        "Send a normal request to {url} and note the baseline response time",
        "Inject the time-based payload in parameter '{parameter}': `{payload}`",
        "Observe that the response is delayed by several seconds compared to the baseline",
        "Repeat 3 times to confirm the delay is consistent and not caused by network latency",
        "The consistent time difference proves blind SQL injection — the database is executing the injected SLEEP/WAITFOR",
    ],
    "xss": [
        "Navigate to {url}",
        "Enter the XSS payload in parameter '{parameter}': `{payload}`",
        "Submit the request",
        "Observe that the payload is reflected in the page without sanitization (view source to confirm)",
        "The injected script executes in the browser context — check browser Developer Tools > Console for proof",
    ],
    "reflected_xss": [
        "Open a browser and navigate to {url}",
        "In parameter '{parameter}', enter the XSS payload: `{payload}`",
        "Submit the request and observe the page source (Ctrl+U)",
        "Confirm the payload appears unescaped/unencoded in the HTML response body",
        "Open Developer Tools (F12) > Console tab to observe JavaScript execution confirming XSS",
    ],
    "dom_xss": [
        "Navigate to {url} in a browser",
        "Open Developer Tools (F12) > Sources tab",
        "Identify the dangerous DOM sink: {evidence}",
        "Modify the URL fragment/parameter to include the payload: `{payload}`",
        "Observe the payload flows from the source to the sink and executes in the browser console",
    ],
    "ssti": [
        "Navigate to {url}",
        "In parameter '{parameter}', enter the template expression: `{payload}`",
        "Submit the request",
        "Observe the server evaluates the mathematical expression and returns the computed result in the response",
        "This confirms server-side template injection — the template engine is processing attacker-controlled input",
    ],
    "command_injection": [
        "Navigate to {url}",
        "In parameter '{parameter}', enter the OS command payload: `{payload}`",
        "Submit the request",
        "Examine the response body — it contains output of the injected system command (e.g., user list, hostname)",
        "This confirms arbitrary command execution on the server with the web application's privileges",
    ],
    "cmdi": [
        "Navigate to {url}",
        "In parameter '{parameter}', enter the OS command payload: `{payload}`",
        "Submit the request",
        "Examine the response body — it contains output of the injected system command (e.g., user list, hostname)",
        "This confirms arbitrary command execution on the server with the web application's privileges",
    ],
    "path_traversal": [
        "Navigate to {url}",
        "Modify the file path parameter '{parameter}' to: `{payload}`",
        "Submit the request",
        "Observe the response body contains contents of a system file (e.g., root:x:0:0 from /etc/passwd)",
        "This confirms arbitrary file read — an attacker can access any file readable by the web server process",
    ],
    "ssrf": [
        "Navigate to {url}",
        "In parameter '{parameter}', enter an internal URL: `{payload}`",
        "Submit the request",
        "Observe the response contains data from the internal resource (cloud metadata, internal API response, etc.)",
        "This confirms SSRF — the server made a request to an internal/restricted resource on the attacker's behalf",
    ],
    "xxe": [
        "Send a POST request to {url} with Content-Type: application/xml",
        "Include the following XXE payload in the XML body: `{payload}`",
        "Submit the request",
        "Observe the response includes the contents of the external entity (e.g., /etc/passwd or SYSTEM file)",
        "This confirms XXE — the XML parser resolves external entities allowing file read and SSRF",
    ],
    "open_redirect": [
        "Navigate to {url}",
        "Modify the redirect parameter '{parameter}' to: `{payload}`",
        "Submit the request / click the link",
        "Observe the browser redirects to the attacker-controlled domain (evil.com) instead of a trusted location",
        "An attacker can craft a link using the trusted domain that silently redirects victims to a phishing site",
    ],
    "csrf": [
        "Log in to the application at {url} in Browser A",
        "Inspect the POST form — note the absence of any CSRF/anti-forgery token",
        "Create an HTML file with an auto-submitting hidden form targeting the same endpoint (see PoC below)",
        "Open the HTML file in Browser A (still logged in)",
        "Observe the action completes successfully without user interaction — the server accepted the forged request",
    ],
    "cors": [
        "Send a request to {url} with the header `Origin: https://attacker.com`",
        "Inspect the response headers — observe `Access-Control-Allow-Origin: https://attacker.com` is reflected",
        "Also note `Access-Control-Allow-Credentials: true` is present",
        "This means any website can make authenticated cross-origin requests to this API endpoint",
        "An attacker can host a page that silently reads the victim's data via XMLHttpRequest/fetch",
    ],
    "idor": [
        "Log in as User A and navigate to {url}",
        "Note the resource identifier in the URL or request body (e.g., /api/user/123)",
        "Change the ID to a different user's ID (e.g., /api/user/124) and resend the request",
        "Observe that the server returns User B's data without any authorization check",
        "This confirms IDOR — any authenticated user can access any other user's resources by modifying the ID",
    ],
    "jwt": [
        "Capture the JWT token from the authentication response at {url}",
        "Decode the JWT at jwt.io — note the header (algorithm) and payload (claims)",
        "Modify the token as follows: {evidence}",
        "Send a request to {url} with the modified/forged JWT in the Authorization header",
        "Observe the server accepts the tampered token — confirming the JWT validation is broken",
    ],
    "default_credentials": [
        "Navigate to the login page at {url}",
        "Enter the default credentials found: {evidence}",
        "Click Login / submit the authentication form",
        "Observe that the application grants access — the default credentials are still active",
        "Full administrative access is now available to anyone who knows these well-known defaults",
    ],
    "exposed_admin_panel": [
        "Open a browser and navigate to {url}",
        "Observe the server returns an admin login page (HTTP 200) with authentication form fields",
        "Note the technology stack and framework visible in the admin panel (e.g., WordPress, phpMyAdmin, Django)",
        "Attempt login with common default credentials (admin/admin, admin/password, root/root)",
        "This admin panel is publicly accessible — it should be restricted by IP allowlist or VPN",
    ],
    "exposed_debug_endpoint": [
        "Open a browser or use cURL to send a GET request to {url}",
        "Observe the server returns debug/monitoring information (HTTP 200)",
        "Review the response for sensitive data: environment variables, database URIs, API keys, heap dumps",
        "Note: {evidence}",
        "This debug endpoint must not be accessible in production — it exposes internal application state",
    ],
    "race_condition": [
        "Prepare {payload} identical requests to {url}",
        "Use a concurrent HTTP tool (Burp Turbo Intruder, Python asyncio) to send all requests simultaneously",
        "Execute the batch — all requests should arrive within the same millisecond window",
        "Observe that multiple requests succeed when only one should be allowed (e.g., double withdrawal)",
        "The server fails to properly serialize access — the race window allows duplicate operations",
    ],
    "request_smuggling": [
        "Identify the front-end/back-end infrastructure at {url} (different HTTP parsers)",
        "Send the smuggling probe with conflicting Content-Length and Transfer-Encoding headers",
        "Compare the response timing: normal request vs. smuggled request (smuggled one is delayed)",
        "Use the PoC payload to confirm request splitting — the second request is interpreted differently",
        "This confirms HTTP request smuggling — the front-end and back-end disagree on request boundaries",
    ],
    "subdomain_takeover": [
        "Resolve DNS for the subdomain at {url} — observe the CNAME record",
        "Note the CNAME points to an external service (e.g., {evidence}) that is unclaimed",
        "Visit the subdomain in a browser — observe it returns a default/error page from the hosting provider",
        "Register the unclaimed resource on the external service (e.g., create the GitHub Pages site, Heroku app)",
        "The subdomain now serves attacker-controlled content under the organization's trusted domain",
    ],
    "exposed_secret": [
        "Navigate to {url} in a browser or fetch the page source via cURL",
        "Search the response body/JavaScript source for secret patterns",
        "Locate the exposed credential: {evidence}",
        "Test the credential against its associated service to confirm it is valid and active",
        "The exposed secret grants unauthorized access to the connected service/API",
    ],
    "security_header": [
        "Send an HTTP request to {url} using cURL or a browser",
        "Inspect the response headers (cURL: look at headers; browser: Developer Tools > Network tab)",
        "Confirm that the following security header is missing: {evidence}",
        "Without this header, the application is vulnerable to client-side attacks (clickjacking, XSS, MIME sniffing)",
        "See the Remediation section below for the exact header value to add",
    ],
    "insecure_cookie": [
        "Log in to the application at {url}",
        "Open Developer Tools (F12) > Application tab > Cookies",
        "Inspect the session cookie — note the missing flag: {evidence}",
        "Without this flag, the session cookie can be stolen via XSS (missing HttpOnly) or intercepted over HTTP (missing Secure)",
        "See the Remediation section for the exact cookie attributes to set",
    ],
    "directory_listing": [
        "Open a browser and navigate to {url}",
        "Observe that the server displays a full listing of files and subdirectories",
        "Click through the listed files — note any sensitive files (config, backup, logs, etc.)",
        "This exposes the internal file structure and may reveal credentials, source code, or backup files",
        "An attacker can enumerate all files without authentication",
    ],
    "exposed_file": [
        "Open a browser or use cURL to send a GET request to {url}",
        "Observe the server returns the file contents (HTTP 200) or confirms its existence (HTTP 403)",
        "Examine the response: {evidence}",
        "This file should not be publicly accessible — it may contain credentials, source code, or internal configuration",
        "Verify the file path ({payload}) is accessible without any authentication",
    ],
    "prototype_pollution": [
        "Navigate to {url} in a browser",
        "Open Developer Tools (F12) > Console tab",
        "Identify the vulnerable JavaScript merge/extend code: {evidence}",
        "In the console, execute: `Object.prototype.polluted = true;` after the vulnerable merge runs",
        "Observe that the `.polluted` property now appears on ALL objects — confirming prototype pollution",
    ],
    "s3_bucket": [
        "Use cURL or a browser to send a GET request to the S3 bucket URL: {url}",
        "Observe the response — it returns XML listing the bucket contents (ListBucketResult)",
        "Attempt to download a file from the bucket to confirm read access",
        "Attempt to upload a test file (PUT) to check for write access",
        "The bucket is publicly accessible without authentication — sensitive data may be exposed",
    ],
    "cloud_misconfiguration": [
        "Send an unauthenticated HTTP request to the cloud resource: {url}",
        "Observe the response: {evidence}",
        "Confirm that no authentication or authorization was required to access this resource",
        "Enumerate what data or functionality is exposed via this misconfigured endpoint",
        "The cloud resource is publicly accessible due to misconfigured IAM/security groups",
    ],
    "technology_disclosure": [
        "Run: `curl -sI {url}` to fetch the HTTP response headers",
        "Examine the Server, X-Powered-By, X-AspNet-Version, X-Generator headers",
        "Observe: {evidence}",
        "These headers reveal the exact technology stack and version, allowing targeted CVE exploitation",
        "Recommendation: Remove or generalize version information from response headers",
    ],
    "cors_misconfiguration": [
        "Run: `curl -sI -H 'Origin: https://evil.com' {url}`",
        "Inspect the response headers for Access-Control-Allow-Origin and Access-Control-Allow-Credentials",
        "Observe: the server reflects the attacker's Origin (`https://evil.com`) in Access-Control-Allow-Origin",
        "With `Access-Control-Allow-Credentials: true`, any website can steal authenticated user data via cross-origin requests",
        "Proof: {evidence}",
    ],
    "robots_exposure": [
        "Run: `curl -s {url}` to fetch the robots.txt file",
        "Identify sensitive Disallow paths (admin, backup, config, internal API endpoints)",
        "For each sensitive path, run: `curl -sI <base_url><path>` and check the HTTP status code",
        "If the path returns HTTP 200 — the sensitive resource is actually accessible to anyone",
        "Evidence: {evidence}",
    ],
    "info_disclosure": [
        "Run: `curl -s {url}` and examine the full response body",
        "Search for leaked data in HTML comments (<!-- -->), JavaScript, or response headers",
        "Observe: {evidence}",
        "This information helps attackers map internal infrastructure, find credentials, or identify further attack vectors",
        "Any credentials, API keys, or internal URLs found should be rotated immediately",
    ],
    "endpoint_disclosure": [
        "Fetch the JavaScript file: `curl -s {url}` and save the content",
        "Search the JS source for API endpoint paths using: `grep -oE '\"/(api|admin|internal|graphql)[^\"]+\"' <file>`",
        "Observe the hidden endpoint(s): {evidence}",
        "Test each endpoint directly: `curl -s https://<target><endpoint>` — check if they accept unauthenticated requests",
        "Hidden endpoints may expose admin panels, internal APIs, or debug interfaces not linked from the UI",
    ],
}

DEFAULT_STEPS = [
    "Send an HTTP request to {url}",
    "Include the payload `{payload}` in the identified parameter '{parameter}'",
    "Observe the response — the server behaviour changes, confirming the vulnerability: {evidence}",
    "Repeat the request to verify the issue is consistently reproducible",
    "See the PoC section below for the exact cURL command and Python script",
]


def generate_steps(finding: dict) -> list[str]:
    category = finding.get("category", "").lower()
    template = STEPS_TEMPLATES.get(category, DEFAULT_STEPS)

    url = finding.get("url", "the target endpoint")
    parameter = finding.get("parameter") or finding.get("param") or "the vulnerable parameter"
    payload = finding.get("payload") or "the test payload (see PoC below)"
    evidence_raw = finding.get("evidence") or "anomalous server response"
    evidence = str(evidence_raw)[:200]
    impact = finding.get("impact") or "exploitation of this vulnerability class"

    subs = {
        "url": url,
        "parameter": parameter,
        "payload": payload,
        "evidence": evidence,
        "impact": impact,
    }

    steps = []
    for i, step in enumerate(template, 1):
        try:
            rendered = step.format(**subs)
        except (KeyError, IndexError):
            rendered = step
        steps.append(f"{i}. {rendered}")
    return steps


IMPACT_MAP: dict[str, str] = {
    "sql_injection": "An attacker can read, modify, or delete the entire database. This may lead to full data breach, authentication bypass, and potentially remote code execution via database functions.",
    "sqli": "An attacker can read, modify, or delete the entire database. This may lead to full data breach, authentication bypass, and potentially remote code execution via database functions.",
    "blind_sqli": "An attacker can extract database contents one character at a time. While slower than error-based SQLi, this still leads to full database compromise.",
    "xss": "An attacker can execute arbitrary JavaScript in victim browsers, leading to session hijacking, credential theft, defacement, or malware distribution.",
    "reflected_xss": "An attacker can craft malicious URLs that execute JavaScript in victim browsers when clicked, leading to session hijacking and credential theft.",
    "dom_xss": "An attacker can manipulate client-side JavaScript execution to steal cookies, redirect users, or perform actions as the victim.",
    "ssti": "An attacker can execute arbitrary code on the server through template injection, leading to complete server compromise and data breach.",
    "command_injection": "An attacker can execute arbitrary operating system commands on the server, leading to complete system compromise.",
    "cmdi": "An attacker can execute arbitrary operating system commands on the server, leading to complete system compromise.",
    "path_traversal": "An attacker can read arbitrary files from the server, including configuration files, source code, and credentials.",
    "ssrf": "An attacker can make the server send requests to internal services, potentially accessing cloud metadata, internal APIs, and other protected resources.",
    "xxe": "An attacker can read local files, perform SSRF, or cause denial of service through XML External Entity injection.",
    "open_redirect": "An attacker can redirect users to malicious websites using the application's trusted domain, enabling phishing attacks.",
    "csrf": "An attacker can perform actions on behalf of authenticated users without their consent, such as changing passwords, transferring funds, or modifying data.",
    "cors": "An attacker can make cross-origin requests to the API from any website, stealing user data and performing unauthorized actions.",
    "idor": "An attacker can access or modify other users' data by manipulating object references, leading to unauthorized data access.",
    "bola": "An attacker can access other users' objects by manipulating the API endpoint IDs, bypassing authorization checks.",
    "jwt": "An attacker can forge or manipulate JWT tokens to impersonate other users or escalate privileges.",
    "default_credentials": "An attacker can gain full administrative access using well-known default credentials.",
    "exposed_admin_panel": "An exposed admin panel reveals the application's management interface, allowing brute-force attacks and providing reconnaissance for further exploitation.",
    "exposed_debug_endpoint": "An exposed debug/monitoring endpoint can leak environment variables, internal application state, heap dumps, or even provide remote code execution.",
    "race_condition": "An attacker can exploit timing vulnerabilities to perform double-spending, bypass rate limits, or create duplicate resources.",
    "request_smuggling": "An attacker can poison web caches, bypass security controls, hijack other users' requests, and steal credentials.",
    "subdomain_takeover": "An attacker can serve malicious content on the organization's subdomain, enabling credential theft and phishing.",
    "exposed_secret": "An attacker can use the exposed API key or credential to access the associated service, potentially leading to data breach or financial loss.",
    "security_header": "Missing security headers leave the application vulnerable to clickjacking, XSS, MIME sniffing, and other client-side attacks.",
    "insecure_cookie": "Session cookies without proper flags can be stolen via XSS, MITM attacks, or CSRF, leading to session hijacking.",
    "directory_listing": "Exposed directory listings reveal internal file structure, potentially leading to discovery of sensitive files and configuration data.",
    "exposed_file": "Exposed sensitive files may contain credentials, API keys, database connection strings, or other confidential information.",
    "prototype_pollution": "An attacker can modify JavaScript object prototypes, leading to denial of service, property injection, or remote code execution.",
    "s3_bucket": "Publicly accessible cloud storage may expose sensitive data, backups, or credentials to unauthorized users.",
    "cloud_misconfiguration": "Misconfigured cloud resources may expose internal services, data, or administrative interfaces to the internet.",
    "ssl_tls": "Weak SSL/TLS configuration allows man-in-the-middle attacks, credential interception, or downgrade attacks.",
    "nosql_injection": "An attacker can manipulate NoSQL queries to bypass authentication, exfiltrate data, or perform denial of service.",
    "deserialization": "An attacker can execute arbitrary code on the server by injecting malicious serialized objects.",
    "cache_poisoning": "An attacker can poison web caches to serve malicious content to other users.",
    "technology_disclosure": "Exposed technology/version headers enable attackers to identify exact software versions, look up known CVEs, and launch targeted exploits. This significantly reduces the effort required for a successful attack.",
    "cors_misconfiguration": "An attacker can host a malicious page that makes authenticated cross-origin requests to the API, stealing user data (PII, session tokens, financial info) from any victim who visits the attacker's page.",
    "robots_exposure": "Sensitive paths discovered via robots.txt are publicly accessible, exposing admin panels, backup files, internal APIs, or configuration data that should not be reachable from the internet.",
    "info_disclosure": "Leaked information (API keys, internal URLs, credentials in HTML comments, debug data) provides attackers with credentials or reconnaissance data for further exploitation.",
    "endpoint_disclosure": "Hidden API endpoints discovered in JavaScript source may accept unauthenticated requests, exposing admin functionality, internal APIs, or debug interfaces.",
}

REMEDIATION_MAP: dict[str, str] = {
    "sql_injection": "- Use parameterized queries (prepared statements) for ALL database interactions\n- Implement input validation with strict allowlists\n- Apply least-privilege database accounts\n- Deploy a Web Application Firewall (WAF) as defense-in-depth\n- Reference: [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)",
    "sqli": "- Use parameterized queries (prepared statements) for ALL database interactions\n- Implement input validation with strict allowlists\n- Apply least-privilege database accounts\n- Deploy a Web Application Firewall (WAF) as defense-in-depth\n- Reference: [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)",
    "blind_sqli": "- Use parameterized queries (prepared statements) for ALL database interactions\n- Implement input validation with strict allowlists\n- Apply least-privilege database accounts\n- Ensure error messages do not reveal database information\n- Reference: [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)",
    "xss": "- Encode all user input before rendering in HTML (context-aware output encoding)\n- Implement Content-Security-Policy header with strict-dynamic or nonce-based policy\n- Use HttpOnly and Secure flags on session cookies\n- Sanitize HTML input with a proven library (DOMPurify, bleach)\n- Reference: [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)",
    "reflected_xss": "- Encode all user input before rendering in HTML (context-aware output encoding)\n- Implement Content-Security-Policy header with strict-dynamic or nonce-based policy\n- Use HttpOnly and Secure flags on session cookies\n- Sanitize HTML input with a proven library (DOMPurify, bleach)\n- Reference: [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)",
    "dom_xss": "- Avoid using dangerous JavaScript sinks (innerHTML, document.write, eval)\n- Use textContent or createElement instead of innerHTML\n- Sanitize all URL fragment/query data before use in DOM manipulation\n- Implement a strong CSP with script-src nonce\n- Reference: [OWASP DOM-based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)",
    "ssti": "- Never pass user input directly into template engines\n- Use a logic-less template engine (Mustache) or sandbox the template engine\n- Validate and sanitize all user input before template rendering\n- Apply principle of least privilege to the template engine process\n- Reference: [PortSwigger SSTI Prevention](https://portswigger.net/web-security/server-side-template-injection)",
    "command_injection": "- Never pass user input to shell commands; use language-level APIs instead\n- If shell execution is unavoidable, use strict allowlist validation\n- Avoid shell=True in Python subprocess calls\n- Run the application with minimal OS privileges\n- Reference: [OWASP OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)",
    "cmdi": "- Never pass user input to shell commands; use language-level APIs instead\n- If shell execution is unavoidable, use strict allowlist validation\n- Avoid shell=True in Python subprocess calls\n- Run the application with minimal OS privileges\n- Reference: [OWASP OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)",
    "path_traversal": "- Validate file paths against an allowlist of permitted directories\n- Use chroot jails or containerized file access\n- Reject input containing ../ or URL-encoded variants\n- Normalize file paths before validation using realpath()\n- Reference: [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)",
    "ssrf": "- Validate and allowlist all user-supplied URLs\n- Block requests to internal IP ranges (10.x, 172.16.x, 192.168.x, 127.x, 169.254.x)\n- Use a dedicated egress proxy with strict URL filtering\n- Disable unnecessary URL handlers (file://, gopher://, dict://)\n- Reference: [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)",
    "xxe": "- Disable external entity processing in all XML parsers\n- Use defusedxml (Python) or JAXP features (Java) to disable DTDs\n- Validate XML input against a strict schema\n- Use JSON instead of XML where possible\n- Reference: [OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)",
    "open_redirect": "- Validate redirect URLs against an allowlist of permitted domains\n- Use relative paths instead of full URLs for redirects\n- Warn users before redirecting to external domains\n- Avoid using user-controlled parameters for redirect targets\n- Reference: [OWASP Unvalidated Redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)",
    "csrf": "- Implement anti-CSRF tokens (synchronizer token pattern) on all state-changing forms\n- Use SameSite=Strict or SameSite=Lax cookie attribute\n- Verify Origin and Referer headers on state-changing requests\n- Use framework-provided CSRF protection (Django CSRF, Express csurf)\n- Reference: [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)",
    "cors": "- Restrict Access-Control-Allow-Origin to specific trusted domains (never use *)\n- Do NOT reflect the Origin header value as the ACAO value\n- Set Access-Control-Allow-Credentials: false unless absolutely required\n- Validate the Origin header against a strict allowlist server-side\n- Reference: [OWASP CORS Misconfiguration](https://portswigger.net/web-security/cors)",
    "idor": "- Implement server-side authorization checks for every object access\n- Use indirect object references (UUIDs instead of sequential IDs)\n- Verify the authenticated user owns the requested resource\n- Log and alert on unauthorized access attempts\n- Reference: [OWASP IDOR Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)",
    "jwt": "- Use strong signing algorithms (RS256, ES256) — never HS256 with weak secrets\n- Validate all JWT claims (exp, iss, aud) server-side\n- Reject unsigned tokens (alg: none)\n- Store JWTs securely (HttpOnly cookies, not localStorage)\n- Reference: [OWASP JWT Security](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)",
    "default_credentials": "- Change ALL default credentials immediately after deployment\n- Enforce strong password policies (16+ chars, complexity)\n- Implement account lockout and monitoring for brute-force attempts\n- Remove or disable default/demo accounts in production\n- Reference: [OWASP Default Credentials](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials)",
    "exposed_admin_panel": "- Move admin panels to a non-standard URL path (avoid /admin, /dashboard)\n- Restrict admin panel access by IP allowlist or VPN\n- Implement multi-factor authentication for all admin accounts\n- Add rate limiting and account lockout on admin login\n- Reference: [OWASP Admin Interface Security](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security)",
    "exposed_debug_endpoint": "- Remove or disable all debug/profiler/monitoring endpoints in production\n- If monitoring is required, restrict access by IP allowlist or authentication\n- For Spring Boot: management.endpoints.web.exposure.exclude=* in production\n- For Django: set DEBUG=False in production settings\n- Reference: [OWASP Debug Endpoint Exposure](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods)",
    "race_condition": "- Use database-level transactions with proper isolation (SERIALIZABLE)\n- Implement idempotency keys for financial and state-changing operations\n- Use distributed locks (Redis, database advisory locks) for critical sections\n- Add server-side rate limiting per user per operation\n- Reference: [OWASP Race Condition](https://owasp.org/www-community/vulnerabilities/Race_condition)",
    "request_smuggling": "- Ensure front-end and back-end servers use the same HTTP parsing rules\n- Normalize Transfer-Encoding and Content-Length handling\n- Upgrade to HTTP/2 end-to-end (immune to CL/TE smuggling)\n- Reject ambiguous requests with both CL and TE headers\n- Reference: [PortSwigger HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)",
    "subdomain_takeover": "- Remove DNS records (CNAME, A) pointing to decommissioned services\n- Monitor all subdomains and their DNS targets regularly\n- Claim resources on external services before creating DNS records\n- Implement automated subdomain monitoring and alerting\n- Reference: [OWASP Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)",
    "exposed_secret": "- Rotate ALL exposed credentials and API keys immediately\n- Use environment variables or secret management (Vault, AWS Secrets Manager)\n- Never commit secrets to source code or client-side JavaScript\n- Implement pre-commit hooks to prevent secret leakage (git-secrets, gitleaks)\n- Reference: [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)",
    "security_header": "- Add Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-xxx'\n- Add X-Content-Type-Options: nosniff\n- Add X-Frame-Options: DENY (or use CSP frame-ancestors)\n- Add Strict-Transport-Security: max-age=31536000; includeSubDomains\n- Add Referrer-Policy: strict-origin-when-cross-origin\n- Add Permissions-Policy to restrict browser features\n- Reference: [OWASP Security Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)",
    "insecure_cookie": "- Set the Secure flag on ALL cookies (prevents transmission over HTTP)\n- Set the HttpOnly flag on session cookies (prevents JavaScript access)\n- Set SameSite=Lax or SameSite=Strict to prevent CSRF\n- Set appropriate Expires/Max-Age for session cookies\n- Reference: [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)",
    "directory_listing": "- Disable directory listing in the web server configuration\n- For Apache: Options -Indexes in .htaccess or httpd.conf\n- For Nginx: autoindex off; in the server block\n- Add index files (index.html) to all directories\n- Reference: [OWASP Directory Listing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information)",
    "exposed_file": "- Block access to sensitive files (.env, .git, .svn, backup files) in web server config\n- For Nginx: location ~ /\\. { deny all; }\n- For Apache: <FilesMatch \"\\.(env|git|svn|bak|sql|log)\">\n    Require all denied\n  </FilesMatch>\n- Move sensitive files outside the web root\n- Audit deployed files and remove unnecessary ones\n- Reference: [OWASP Sensitive File Exposure](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information)",
    "prototype_pollution": "- Avoid using recursive merge/extend functions on user-controlled objects\n- Use Object.create(null) for lookup maps instead of {}\n- Freeze Object.prototype in critical code paths\n- Validate that __proto__, constructor, prototype are not in user input\n- Reference: [Snyk Prototype Pollution](https://learn.snyk.io/lessons/prototype-pollution/javascript/)",
    "s3_bucket": "- Enable S3 Block Public Access at the account and bucket level\n- Review and restrict bucket policies and ACLs\n- Enable CloudTrail logging for S3 API calls\n- Use VPC endpoints for internal access to S3\n- Reference: [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)",
    "cloud_misconfiguration": "- Apply principle of least privilege to all cloud IAM policies\n- Enable logging and monitoring (CloudTrail, Azure Monitor, GCP Audit Logs)\n- Use cloud security posture management (CSPM) tools\n- Restrict public access to cloud resources using security groups and network ACLs\n- Reference: [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)",
    "ssl_tls": "- Disable SSLv3, TLS 1.0, and TLS 1.1 — require TLS 1.2+ minimum\n- Use strong cipher suites (ECDHE+AESGCM) and disable weak ones (RC4, 3DES)\n- Enable HSTS with a long max-age and includeSubDomains\n- Renew certificates before expiry and automate renewal (Let's Encrypt)\n- Reference: [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)",
    "nosql_injection": "- Use parameterized queries for NoSQL databases (MongoDB $where, $regex)\n- Validate and sanitize all user input before database operations\n- Disable server-side JavaScript execution in MongoDB\n- Apply least-privilege database accounts\n- Reference: [OWASP NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)",
    "bola": "- Implement server-side authorization checks for every API object access\n- Use UUIDs instead of sequential integer IDs for object references\n- Verify the authenticated user owns the requested resource in every handler\n- Log and alert on unauthorized access attempts\n- Reference: [OWASP API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)",
    "security_misconfiguration": "- Review and harden all server configurations\n- Disable unnecessary HTTP methods (PUT, DELETE, TRACE)\n- Remove default pages, error messages, and debug endpoints\n- Implement proper error handling that doesn't leak technical details\n- Reference: [OWASP Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)",
    "technology_disclosure": "- Remove or generalize the `Server` header (e.g., `Server: webserver` instead of `Server: Apache/2.4.49`)\n- Remove `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version` headers entirely\n- In Nginx: `server_tokens off;`\n- In Apache: `ServerTokens Prod` and `ServerSignature Off`\n- In Express.js: `app.disable('x-powered-by')`\n- Reference: [OWASP HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)",
    "cors_misconfiguration": "- Never reflect the Origin header verbatim in Access-Control-Allow-Origin\n- Maintain a strict allowlist of trusted origins and validate against it\n- Set `Access-Control-Allow-Credentials: true` ONLY with specific whitelisted origins\n- Never use `Access-Control-Allow-Origin: *` with credentials\n- Reference: [OWASP CORS](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html)",
    "robots_exposure": "- Do not rely on robots.txt to hide sensitive paths — use proper access controls\n- Require authentication for all admin, backup, config, and internal API paths\n- Restrict access by IP allowlist or VPN where feasible\n- Audit all Disallow entries and ensure referenced paths return 403/404 to unauthenticated users\n- Reference: [OWASP Robots.txt](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage)",
    "info_disclosure": "- Remove HTML comments containing sensitive information before deployment\n- Strip debug/development comments in the build pipeline (minification)\n- Never hardcode API keys, passwords, or tokens in client-side code\n- Use environment variables for secrets and server-side key management\n- Audit response bodies and headers for information leaks\n- Reference: [OWASP Information Leakage](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage)",
    "endpoint_disclosure": "- Do not expose internal API paths in client-side JavaScript\n- Use environment-specific API base URLs (inject at build time, not hardcode)\n- Implement authentication and authorization on ALL API endpoints\n- Regularly audit JavaScript bundles for leaked internal paths\n- Use tools like webpack-obfuscator to minimize endpoint exposure\n- Reference: [OWASP API Security](https://owasp.org/www-project-api-security/)",
}

DESCRIPTION_MAP: dict[str, str] = {
    "sql_injection": "The application is vulnerable to SQL injection. User-supplied input is inserted directly into SQL queries without parameterization or proper sanitization, allowing an attacker to manipulate the database query logic.",
    "sqli": "The application is vulnerable to SQL injection. User-supplied input is inserted directly into SQL queries without parameterization or proper sanitization, allowing an attacker to manipulate the database query logic.",
    "xss": "The application is vulnerable to Cross-Site Scripting (XSS). User input is reflected in the page without proper encoding or sanitization, allowing injection of arbitrary JavaScript that executes in other users' browsers.",
    "reflected_xss": "User input is reflected in the HTTP response without proper HTML encoding. This allows an attacker to inject JavaScript that executes when a victim clicks a crafted URL.",
    "dom_xss": "The application's client-side JavaScript contains an unsafe data flow from a user-controllable source (e.g., location.hash) to a dangerous sink (e.g., innerHTML), allowing DOM-based XSS.",
    "ssti": "The application is vulnerable to Server-Side Template Injection. User input is embedded directly into server-side templates without sanitization, allowing execution of arbitrary expressions and potentially full code execution.",
    "command_injection": "The application passes user-controlled input to system shell commands without proper sanitization, allowing an attacker to inject and execute arbitrary OS commands.",
    "path_traversal": "The application allows directory traversal through manipulated file path parameters. By using sequences like ../, an attacker can access files outside the intended directory.",
    "ssrf": "The application makes server-side HTTP requests using user-supplied URLs without proper validation, allowing an attacker to send requests to internal services.",
    "xxe": "The application processes XML input with external entity processing enabled, allowing an attacker to read local files, perform SSRF, or cause denial of service.",
    "open_redirect": "The application redirects users based on a user-controlled parameter without validating the destination URL, allowing redirection to attacker-controlled domains.",
    "csrf": "The application does not implement CSRF tokens or other anti-CSRF mechanisms, allowing an attacker to forge cross-site requests that perform actions as the authenticated user.",
    "cors": "The application's CORS policy is misconfigured, allowing arbitrary or attacker-controlled origins to make authenticated cross-origin requests.",
    "idor": "The application does not verify that the authenticated user is authorized to access the requested object, allowing horizontal privilege escalation via direct object reference manipulation.",
    "jwt": "The application's JWT implementation is vulnerable — tokens can be forged or manipulated due to weak signing, missing validation, or algorithm confusion.",
    "default_credentials": "The application or service uses factory-default login credentials that have not been changed, providing trivial unauthorized access.",
    "exposed_admin_panel": "An administrative panel login page is publicly accessible. While access may require credentials, exposure of the admin interface enables targeted brute-force attacks and reveals the application technology stack.",
    "exposed_debug_endpoint": "A debug, monitoring, or profiling endpoint is publicly accessible in production. This can expose internal application state, environment variables, database connections, and may allow remote code execution.",
    "race_condition": "The application does not properly synchronize access to shared resources, allowing concurrent requests to exploit timing windows for unauthorized operations.",
    "request_smuggling": "The front-end and back-end servers interpret HTTP request boundaries differently, allowing an attacker to smuggle requests that bypass security controls.",
    "subdomain_takeover": "A subdomain's DNS record points to an external service that is no longer claimed, allowing an attacker to register the resource and serve content on the subdomain.",
    "exposed_secret": "API keys, credentials, or other secrets are exposed in client-side code, public repositories, or configuration files accessible to unauthorized users.",
    "security_header": "The HTTP response is missing one or more security headers that protect against common client-side attacks.",
    "prototype_pollution": "The application uses unsafe JavaScript object merging that allows an attacker to inject properties into the Object prototype, affecting all objects.",
    "technology_disclosure": "The server exposes technology and version information in HTTP response headers (Server, X-Powered-By, etc.), enabling attackers to fingerprint the stack and find targeted CVE exploits.",
    "cors_misconfiguration": "The application's CORS policy reflects attacker-controlled origins with credentials allowed, enabling any website to make authenticated requests and steal user data.",
    "robots_exposure": "The robots.txt file discloses sensitive paths (admin, backup, config, internal APIs) that are also publicly accessible (HTTP 200), providing attackers a roadmap to hidden resources.",
    "info_disclosure": "The application leaks sensitive information (API keys, credentials, internal URLs, debug data) in HTML comments, response headers, or JavaScript source code.",
    "endpoint_disclosure": "Hidden API endpoints are exposed in JavaScript source files, revealing internal paths that may accept unauthenticated requests or expose admin/debug functionality.",
}


def generate_poc(finding: dict) -> str:
    url = finding.get("url", "<target>")
    method = "GET"
    payload = finding.get("payload", "")
    parameter = finding.get("parameter", "")
    category = finding.get("category", "").lower()

    parts = []

    post_categories = {"csrf", "mass_assignment", "race_condition", "xxe", "request_smuggling"}
    get_categories = {"exposed_file", "directory_listing", "security_header",
                      "insecure_cookie", "s3_bucket", "subdomain_takeover",
                      "exposed_secret", "open_redirect"}

    if category in post_categories:
        method = "POST"
    elif category in get_categories:
        method = "GET"
    elif category in ("sqli", "sql_injection", "xss", "reflected_xss",
                       "ssti", "command_injection", "cmdi", "path_traversal",
                       "ssrf", "blind_sqli"):
        method = "GET"

    parts.append("# PoC — cURL")
    parts.append("# Copy-paste this command into your terminal to reproduce:\n")
    if method == "GET" and parameter and payload:
        parts.append(f'curl -v "{url}?{parameter}={payload}"')
    elif method == "POST" and parameter and payload:
        parts.append(f'curl -v -X POST "{url}" -d "{parameter}={payload}"')
    elif method == "POST" and payload:
        parts.append(f'curl -v -X POST "{url}" -d \'{payload}\'')
    else:
        parts.append(f'curl -v "{url}"')

    parts.append("\n\n# PoC — Python")
    parts.append("import requests\n")
    if method == "GET" and parameter and payload:
        parts.append(f'resp = requests.get("{url}", params={{"{parameter}": "{payload}"}}, verify=False)')
    elif method == "POST" and parameter and payload:
        parts.append(f'resp = requests.post("{url}", data={{"{parameter}": "{payload}"}}, verify=False)')
    elif method == "POST" and payload:
        parts.append(f'resp = requests.post("{url}", data=\'{payload}\', verify=False)')
    else:
        parts.append(f'resp = requests.get("{url}", verify=False)')
    parts.append('print(f"Status: {resp.status_code}")')
    parts.append('print(resp.text[:2000])')

    if category in ("xss", "reflected_xss", "dom_xss", "open_redirect"):
        parts.append("\n\n# PoC — Browser")
        if parameter and payload:
            full_url = f"{url}?{parameter}={payload}"
        else:
            full_url = url
        parts.append("# Open this URL in your browser:")
        parts.append(f"# {full_url}")

    return "\n".join(parts)


def enrich_finding(finding: dict) -> dict:
    f = copy.deepcopy(finding)
    cat = f.get("category", "").lower()
    sev = f.get("severity", "info").lower()

    if not f.get("cwe"):
        f["cwe"] = CWE_MAP.get(cat, "CWE-200")

    if not f.get("cvss_vector"):
        if cat in CATEGORY_CVSS:
            _, vector = CATEGORY_CVSS[cat]
            f["cvss_vector"] = vector
        else:
            f["cvss_vector"] = CVSS_VECTORS.get(sev, CVSS_VECTORS["info"])

    if not f.get("cvss_score"):
        if cat in CATEGORY_CVSS:
            f["cvss_score"] = CATEGORY_CVSS[cat][0]
        else:
            f["cvss_score"] = {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 3.0, "info": 0.0}.get(sev, 0)

    if not f.get("description"):
        f["description"] = DESCRIPTION_MAP.get(cat, f.get("title", "Vulnerability detected"))

    if not f.get("impact"):
        f["impact"] = IMPACT_MAP.get(cat, "This vulnerability may allow unauthorized access or data exposure.")

    if not f.get("steps_to_reproduce"):
        f["steps_to_reproduce"] = generate_steps(f)

    if not f.get("poc"):
        f["poc"] = generate_poc(f)

    f.setdefault("evidence", "")
    f.setdefault("payload", "")
    f.setdefault("request", "")
    f.setdefault("response", "")
    if not f.get("remediation") or f["remediation"] == "Refer to OWASP guidelines for this vulnerability class.":
        f["remediation"] = REMEDIATION_MAP.get(cat, "- Review and fix the vulnerability according to OWASP guidelines\n- Perform a code review of the affected component\n- Re-test after remediation to confirm the fix\n- Reference: [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)")
    f.setdefault("confidence", 0.85)
    f.setdefault("scanner", "VAPT CLI")
    f.setdefault("validated", False)
    f.setdefault("url", "")
    f.setdefault("parameter", "")

    return f


def enrich_all_findings(findings: list[dict]) -> list[dict]:
    return [enrich_finding(f) for f in findings]
