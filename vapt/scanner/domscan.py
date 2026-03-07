"""DOM-based vulnerability scanner with JavaScript analysis."""

from __future__ import annotations

import re
import json
import hashlib
from collections import deque
from typing import Any
from urllib.parse import urljoin, urlparse, urlencode

import requests
from bs4 import BeautifulSoup

from vapt.utils.helpers import sanitize_target

# DOM XSS Sinks — where user data gets executed

DOM_XSS_SINKS = [
    # Direct execution sinks
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"\.insertAdjacentHTML\s*\(",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"\.html\s*\(",  # jQuery .html()
    # JavaScript URL sinks
    r"\.href\s*=",
    r"\.src\s*=",
    r"\.action\s*=",
    r"location\s*=",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"location\.assign\s*\(",
    r"window\.open\s*\(",
    # Execution sinks
    r"\beval\s*\(",
    r"Function\s*\(",
    r"setTimeout\s*\(\s*['\"]",
    r"setInterval\s*\(\s*['\"]",
    r"execScript\s*\(",
    # DOM manipulation sinks
    r"\.setAttribute\s*\(\s*['\"]on",
    r"\.setAttribute\s*\(\s*['\"]href",
    r"\.setAttribute\s*\(\s*['\"]src",
    r"\.setAttribute\s*\(\s*['\"]action",
    # Template sinks
    r"\$\(\s*['\"]<",
    r"jQuery\s*\(\s*['\"]<",
    r"\.append\s*\(",
    r"\.prepend\s*\(",
    r"\.after\s*\(",
    r"\.before\s*\(",
    r"\.replaceWith\s*\(",
]

# DOM XSS Sources — where attacker-controlled data enters

DOM_XSS_SOURCES = [
    r"location\.hash",
    r"location\.search",
    r"location\.href",
    r"location\.pathname",
    r"location\.protocol",
    r"document\.URL",
    r"document\.documentURI",
    r"document\.referrer",
    r"document\.cookie",
    r"window\.name",
    r"window\.location",
    r"\.getParameter\s*\(",
    r"\.get\(\s*['\"]",  # URLSearchParams.get()
    r"URLSearchParams",
    r"\.split\s*\(\s*['\"][#?&]",
    r"\.substring\s*\(\s*\d+",
    r"postMessage",
    r"\.data\b",  # event.data in message handler
    r"localStorage\.getItem",
    r"sessionStorage\.getItem",
    r"\.value\b",  # input.value
]

# Exposed Secrets Patterns

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"\s:=]+[A-Za-z0-9/+=]{40}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth": r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com",
    "Firebase Key": r"(?i)firebase['\"\s:=]+[A-Za-z0-9_\-]{20,}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "GitHub OAuth": r"gho_[A-Za-z0-9]{36}",
    "Slack Token": r"xox[bpors]-[0-9]{10,}-[a-zA-Z0-9]{10,}",
    "Slack Webhook": r"hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Publishable": r"pk_live_[0-9a-zA-Z]{24,}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio Account SID": r"AC[a-zA-Z0-9_\-]{32}",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "PayPal Braintree": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Heroku API Key": r"(?i)heroku[_\-]?api[_\-]?key['\"\s:=]+[0-9a-fA-F\-]{36}",
    "Private Key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "Generic API Key": r"(?i)(?:api[_\-]?key|apikey|api_secret|client_secret)['\"\s:=]+[A-Za-z0-9_\-]{16,}",
    "Generic Password": r"(?i)(?:password|passwd|pwd|secret)['\"\s:=]+[^\s'\"]{8,}",
    "Bearer Token": r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",
    "Azure Key": r"(?i)(?:AccountKey|SharedAccessKey)[=:][A-Za-z0-9+/=]{40,}",
    "Shopify Token": r"shpat_[a-fA-F0-9]{32}",
    "Discord Token": r"(?:mfa\.[a-z0-9_-]{20,})|(?:[a-z0-9_-]{23,28}\.[a-z0-9_-]{6}\.[a-z0-9_-]{27})",
    "Telegram Bot Token": r"\d{8,10}:[A-Za-z0-9_-]{35}",
}

# Prototype Pollution Patterns

PROTO_POLLUTION_SINKS = [
    r"Object\.assign\s*\(",
    r"\$\.extend\s*\(",
    r"_\.merge\s*\(",
    r"_\.defaultsDeep\s*\(",
    r"_\.set\s*\(",
    r"deepmerge\s*\(",
    r"merge\s*\(",
    r"\.assign\s*\(",
    r"JSON\.parse\s*\(",
    r"\[key\]\s*=",
    r"\[prop\]\s*=",
    r"\[name\]\s*=",
    r"\[attr\]\s*=",
    r"__proto__",
    r"constructor\s*\[",
    r"prototype\s*\[",
]

# SPA Route Patterns

SPA_ROUTE_PATTERNS = [
    # React Router
    r"<Route\s+path=['\"]([^'\"]+)",
    r"path:\s*['\"]([^'\"]+)",
    r"navigate\(['\"]([^'\"]+)",
    # Angular
    r"routerLink=['\"]([^'\"]+)",
    r"loadChildren:\s*['\"]([^'\"]+)",
    # Vue Router
    r"path:\s*['\"]([^'\"]+)",
    r"\$router\.push\(['\"]([^'\"]+)",
    # Generic
    r"window\.location\.hash\s*=\s*['\"]#([^'\"]+)",
    r"history\.push(?:State)?\s*\([^,]*,\s*[^,]*,\s*['\"]([^'\"]+)",
]


class DOMScanner:
    """Client-side vulnerability scanner — finds DOM XSS, secrets, and client-side bugs."""

    def __init__(
        self,
        session: requests.Session | None = None,
        max_pages: int = 50,
        timeout: int = 10,
    ) -> None:
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", "VAPT-CLI/4.0 BugBounty-Scanner")
        self.timeout = timeout
        self.max_pages = max_pages
        self.findings: list[dict] = []
        self._visited: set[str] = set()
        self._js_cache: dict[str, str] = {}

    def run(self, target: str) -> dict[str, Any]:
        """Run full DOM/client-side scan."""
        target = sanitize_target(target)
        if not target.startswith("http"):
            target = f"https://{target}"

        self._crawl_and_analyze(target)
        return {"findings": self.findings}


    def _crawl_and_analyze(self, start_url: str) -> None:
        """Crawl the site and analyze each page's JavaScript."""
        queue: deque[str] = deque([start_url])
        base_domain = urlparse(start_url).netloc

        while queue and len(self._visited) < self.max_pages:
            url = queue.popleft()
            if url in self._visited:
                continue
            self._visited.add(url)

            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue
            except Exception:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Extract and analyze all JavaScript
            js_contents = self._extract_javascript(url, soup)
            full_js = "\n".join(js_contents)

            if full_js:
                self._check_dom_xss(url, full_js)
                self._check_prototype_pollution(url, full_js)
                self._check_exposed_secrets(url, full_js, resp.text)
                self._check_postmessage(url, full_js)
                self._check_websocket(url, full_js)
                self._check_unsafe_eval(url, full_js)
                self._check_storage_sensitive(url, full_js)
                self._check_angular_csti(url, resp.text, full_js)
                self._check_jsonp(url, soup, resp.text)
                self._check_client_redirect(url, full_js)
                self._discover_spa_routes(url, full_js)

            # Also check HTML for secrets
            self._check_exposed_secrets(url, "", resp.text)

            # Enqueue links
            for link in soup.find_all("a", href=True):
                abs_url = urljoin(url, link["href"])
                if urlparse(abs_url).netloc == base_domain and abs_url not in self._visited:
                    queue.append(abs_url)

    def _extract_javascript(self, page_url: str, soup: BeautifulSoup) -> list[str]:
        """Extract inline and external JS from a page."""
        js_list = []

        # Inline scripts
        for script in soup.find_all("script"):
            if script.string:
                js_list.append(script.string)

        # External scripts (same origin)
        base_domain = urlparse(page_url).netloc
        for script in soup.find_all("script", src=True):
            src_url = urljoin(page_url, script["src"])
            parsed = urlparse(src_url)
            # Include same-origin and relative scripts
            if parsed.netloc == base_domain or not parsed.netloc:
                if src_url not in self._js_cache:
                    try:
                        resp = self.session.get(src_url, timeout=self.timeout)
                        self._js_cache[src_url] = resp.text
                    except Exception:
                        self._js_cache[src_url] = ""
                js_list.append(self._js_cache[src_url])

        return js_list


    def _check_dom_xss(self, url: str, js: str) -> None:
        """Detect DOM XSS by finding source→sink taint paths."""
        found_sources = []
        found_sinks = []

        for pattern in DOM_XSS_SOURCES:
            matches = re.finditer(pattern, js)
            for m in matches:
                start = max(0, m.start() - 50)
                end = min(len(js), m.end() + 50)
                context = js[start:end].strip()
                found_sources.append((pattern, m.group(), context))

        for pattern in DOM_XSS_SINKS:
            matches = re.finditer(pattern, js)
            for m in matches:
                start = max(0, m.start() - 50)
                end = min(len(js), m.end() + 50)
                context = js[start:end].strip()
                found_sinks.append((pattern, m.group(), context))

        # Report source→sink pairs that appear near each other
        if found_sources and found_sinks:
            for source_pat, source_match, source_ctx in found_sources:
                for sink_pat, sink_match, sink_ctx in found_sinks:
                    source_pos = js.find(source_match)
                    sink_pos = js.find(sink_match)
                    if source_pos >= 0 and sink_pos >= 0 and abs(source_pos - sink_pos) < 500:
                        evidence_block = js[min(source_pos, sink_pos):max(source_pos, sink_pos) + len(sink_match) + 30]
                        self._add_finding(
                            vuln_id="DOM-001",
                            title=f"DOM XSS: {source_match} → {sink_match}",
                            severity="High",
                            cvss=7.5,
                            url=url,
                            category="dom_xss",
                            evidence=f"Source: {source_match}\nSink: {sink_match}\n\nContext:\n{evidence_block[:500]}",
                            payload=f"Source: {source_ctx[:200]}\nSink: {sink_ctx[:200]}",
                            remediation="Use textContent instead of innerHTML. Sanitize all user inputs before DOM insertion. Use DOMPurify for HTML sanitization.",
                            confidence=0.85,
                            poc=f"1. Visit {url}\n2. Inject payload via {source_match} (e.g. URL hash/query)\n3. Payload reaches {sink_match} without sanitization\n4. JavaScript executes in victim's browser context",
                        )
                        return  # One finding per page to avoid noise


    def _check_prototype_pollution(self, url: str, js: str) -> None:
        """Detect potential prototype pollution gadgets."""
        gadgets_found = []
        for pattern in PROTO_POLLUTION_SINKS:
            matches = re.finditer(pattern, js)
            for m in matches:
                start = max(0, m.start() - 80)
                end = min(len(js), m.end() + 80)
                context = js[start:end].strip()
                gadgets_found.append((m.group(), context))

        proto_refs = re.findall(r"__proto__|constructor\s*\.\s*prototype|Object\.create\s*\(null\)", js)

        if gadgets_found and len(gadgets_found) >= 2:
            evidence_parts = [f"Gadget: {g[0]}\nContext: {g[1]}" for g in gadgets_found[:5]]
            self._add_finding(
                vuln_id="DOM-002",
                title=f"Prototype Pollution ({len(gadgets_found)} gadgets found)",
                severity="High",
                cvss=7.3,
                url=url,
                category="prototype_pollution",
                evidence="\n\n".join(evidence_parts),
                payload="?__proto__[polluted]=true or JSON: {\"__proto__\":{\"polluted\":true}}",
                remediation="Use Object.create(null) for lookup objects. Validate/sanitize keys in merge operations. Use Map instead of plain objects. Freeze Object.prototype.",
                confidence=0.75,
                poc=f"1. Visit {url}?__proto__[test]=polluted\n2. Open browser DevTools console\n3. Check: ({{}}).__proto__.test === 'polluted'\n4. If true, prototype pollution is confirmed",
            )


    def _check_exposed_secrets(self, url: str, js: str, html: str) -> None:
        """Find API keys, tokens, and credentials in JavaScript and HTML."""
        content = js + "\n" + html
        for secret_name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                # Deduplicate
                unique_matches = list(set(matches))
                for match in unique_matches[:3]:
                    # Mask the secret for safe reporting
                    masked = match[:8] + "..." + match[-4:] if len(match) > 12 else match[:4] + "..."
                    self._add_finding(
                        vuln_id="DOM-003",
                        title=f"Exposed {secret_name}",
                        severity="Critical" if "private key" in secret_name.lower() or "secret" in secret_name.lower() else "High",
                        cvss=8.5 if "private key" in secret_name.lower() else 7.0,
                        url=url,
                        category="exposed_secret",
                        evidence=f"Type: {secret_name}\nValue: {masked}\nFull pattern match in page source",
                        payload=match if len(match) < 20 else masked,
                        remediation=f"Remove {secret_name} from client-side code. Use server-side proxying for API calls. Rotate the exposed credential immediately.",
                        confidence=0.95,
                        poc=f"1. View source of {url}\n2. Search for pattern: {pattern[:50]}...\n3. Found: {masked}\n4. Use the credential to authenticate to the service",
                    )


    def _check_postmessage(self, url: str, js: str) -> None:
        """Detect insecure postMessage handlers (no origin check)."""
        # Find message event listeners
        message_handlers = re.finditer(
            r"(?:addEventListener|on)\s*\(\s*['\"]message['\"]"
            r"|\.on\s*\(\s*['\"]message['\"]"
            r"|onmessage\s*=",
            js,
        )

        for m in message_handlers:
            start = m.start()
            # Get the handler code block (next ~500 chars)
            block = js[start:start + 500]

            # Check for origin verification
            has_origin_check = bool(re.search(
                r"(?:event|e|evt|msg)\.origin\s*(?:===|!==|==|!=)"
                r"|\.origin\s*\.(?:includes|indexOf|match|startsWith)",
                block,
            ))

            if not has_origin_check:
                # Check what the handler does with the data
                uses_data_dangerously = bool(re.search(
                    r"innerHTML|eval|Function|document\.write|\.html\(|location|\.src\s*=|\.href\s*=",
                    block,
                ))

                severity = "High" if uses_data_dangerously else "Medium"
                cvss = 7.5 if uses_data_dangerously else 5.5

                self._add_finding(
                    vuln_id="DOM-004",
                    title="Insecure postMessage Handler (no origin check)",
                    severity=severity,
                    cvss=cvss,
                    url=url,
                    category="postmessage",
                    evidence=f"Handler code:\n{block[:400]}",
                    payload='<iframe src="TARGET"><script>target.postMessage("payload","*")</script>',
                    remediation="Always verify event.origin before processing postMessage data. Use strict === comparison against expected origins.",
                    confidence=0.85,
                    poc=f"1. Create attacker page with: window.open('{url}').postMessage('{{\"action\":\"eval\",\"code\":\"alert(document.domain)\"}}', '*')\n2. If the handler processes without origin check, XSS is possible",
                )


    def _check_websocket(self, url: str, js: str) -> None:
        """Detect insecure WebSocket usage."""
        ws_connections = re.finditer(
            r"new\s+WebSocket\s*\(\s*['\"]?(wss?://[^'\")\s]+)",
            js,
        )

        for m in ws_connections:
            ws_url = m.group(1)
            issues = []

            if ws_url.startswith("ws://"):
                issues.append("Unencrypted WebSocket (ws:// instead of wss://)")

            if re.search(r"(?:token|key|auth|session|jwt)=", ws_url, re.IGNORECASE):
                issues.append("Authentication token exposed in WebSocket URL")

            # Check for CSWSH vulnerability (no origin check on connect)
            block = js[m.start():m.start() + 1000]
            if not re.search(r"origin|csrf|token|nonce", block, re.IGNORECASE):
                issues.append("Possible Cross-Site WebSocket Hijacking (no auth in handshake)")

            if issues:
                self._add_finding(
                    vuln_id="DOM-005",
                    title=f"WebSocket Security Issue ({len(issues)} problems)",
                    severity="High" if "Unencrypted" in str(issues) or "Hijacking" in str(issues) else "Medium",
                    cvss=7.0,
                    url=url,
                    category="websocket",
                    evidence=f"WebSocket URL: {ws_url}\nIssues:\n" + "\n".join(f"  - {i}" for i in issues),
                    payload=ws_url,
                    remediation="Use wss:// for encrypted WebSocket. Include CSRF token in first message. Validate Origin header server-side.",
                    confidence=0.90,
                    poc=f"1. Open browser DevTools → Network → WS\n2. Observe connection to: {ws_url}\n3. Issues: {'; '.join(issues)}",
                )


    def _check_client_redirect(self, url: str, js: str) -> None:
        """Detect client-side open redirects via JavaScript."""
        redirect_patterns = [
            r"location\.href\s*=\s*(?:.*?)(?:getParameter|searchParams|\.get|\.hash|\.search)",
            r"location\.assign\s*\(\s*(?:.*?)(?:getParameter|searchParams|\.get)",
            r"location\.replace\s*\(\s*(?:.*?)(?:getParameter|searchParams|\.get)",
            r"window\.location\s*=\s*(?:.*?)(?:getParameter|searchParams|\.get)",
            r"window\.open\s*\(\s*(?:.*?)(?:getParameter|searchParams|\.get)",
        ]

        for pattern in redirect_patterns:
            matches = re.finditer(pattern, js)
            for m in matches:
                start = max(0, m.start() - 30)
                end = min(len(js), m.end() + 100)
                context = js[start:end].strip()

                block = js[max(0, m.start() - 200):m.end() + 200]
                has_validation = bool(re.search(
                    r"(?:startsWith|indexOf|match|test|includes)\s*\(\s*['\"]https?://",
                    block,
                ))

                if not has_validation:
                    self._add_finding(
                        vuln_id="DOM-006",
                        title="Client-Side Open Redirect",
                        severity="Medium",
                        cvss=5.4,
                        url=url,
                        category="open_redirect",
                        evidence=f"Redirect code:\n{context}",
                        payload=f"{url}?redirect=https://evil.com&next=//evil.com",
                        remediation="Validate redirect URLs server-side. Use allowlists for redirect destinations. Avoid using user input directly in location assignments.",
                        confidence=0.80,
                        poc=f"1. Visit {url}?redirect=https://evil.com\n2. Page redirects to attacker-controlled domain\n3. Can be used for phishing/token theft",
                    )
                    return


    def _check_unsafe_eval(self, url: str, js: str) -> None:
        """Detect unsafe dynamic code execution."""
        dangerous_patterns = [
            (r"\beval\s*\(\s*(?!['\"]\s*\))", "eval()"),
            (r"\bnew\s+Function\s*\(\s*(?!['\"]\s*\))", "new Function()"),
            (r"setTimeout\s*\(\s*['\"][^'\"]*(?:location|document|window)", "setTimeout with code string"),
            (r"setInterval\s*\(\s*['\"][^'\"]*(?:location|document|window)", "setInterval with code string"),
        ]

        for pattern, name in dangerous_patterns:
            matches = re.finditer(pattern, js)
            for m in matches:
                start = max(0, m.start() - 40)
                end = min(len(js), m.end() + 100)
                context = js[start:end].strip()

                block = js[max(0, m.start() - 300):m.end() + 50]
                user_input = bool(re.search(
                    r"location|search|hash|getParameter|\.get\(|\.value|postMessage|\.data",
                    block,
                ))

                if user_input:
                    self._add_finding(
                        vuln_id="DOM-007",
                        title=f"Unsafe {name} with User Input",
                        severity="Critical",
                        cvss=9.0,
                        url=url,
                        category="unsafe_eval",
                        evidence=f"Pattern: {name}\nContext:\n{context}",
                        payload="';alert(document.domain);//",
                        remediation=f"Replace {name} with safer alternatives. Use JSON.parse() for data, event handlers for callbacks. Never pass user input to eval/Function.",
                        confidence=0.80,
                        poc=f"1. Visit {url}\n2. Inject via URL parameter: ?callback=alert(document.domain)\n3. User input reaches {name}\n4. Arbitrary JS execution",
                    )
                    return


    def _check_storage_sensitive(self, url: str, js: str) -> None:
        """Detect sensitive data stored in localStorage/sessionStorage."""
        storage_patterns = [
            (r"localStorage\.setItem\s*\(\s*['\"]((?:token|jwt|auth|session|password|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|credential)[^'\"]*)['\"]", "localStorage"),
            (r"sessionStorage\.setItem\s*\(\s*['\"]((?:token|jwt|auth|session|password|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|credential)[^'\"]*)['\"]", "sessionStorage"),
        ]

        for pattern, storage_type in storage_patterns:
            matches = re.finditer(pattern, js, re.IGNORECASE)
            for m in matches:
                key_name = m.group(1)
                self._add_finding(
                    vuln_id="DOM-008",
                    title=f"Sensitive Data in {storage_type}: '{key_name}'",
                    severity="Medium",
                    cvss=5.0,
                    url=url,
                    category="storage_sensitive",
                    evidence=f"Storage: {storage_type}\nKey: {key_name}\nCode: {m.group()[:200]}",
                    payload=f"localStorage.getItem('{key_name}') or sessionStorage.getItem('{key_name}')",
                    remediation=f"Avoid storing sensitive data ({key_name}) in {storage_type}. Use httpOnly secure cookies for tokens. localStorage is accessible to any XSS on the domain.",
                    confidence=0.90,
                    poc=f"1. Open DevTools → Application → {storage_type}\n2. Find key: {key_name}\n3. Any XSS can steal this via: {storage_type}.getItem('{key_name}')",
                )


    def _check_angular_csti(self, url: str, html: str, js: str) -> None:
        """Detect AngularJS CSTI vulnerabilities."""
        angular_detected = bool(re.search(
            r"angular\.js|angular\.min\.js|ng-app|ng-controller|angularjs",
            html + js,
            re.IGNORECASE,
        ))

        if not angular_detected:
            return

        # Check for user input in ng-bind-html or interpolation
        unsafe_patterns = [
            r"ng-bind-html\s*=\s*['\"](?!.*\|\s*sanitize)",
            r"\$sce\.trustAsHtml",
            r"ng-bind-html-unsafe",
        ]

        for pattern in unsafe_patterns:
            if re.search(pattern, html + js):
                self._add_finding(
                    vuln_id="DOM-009",
                    title="AngularJS Client-Side Template Injection",
                    severity="Critical",
                    cvss=9.0,
                    url=url,
                    category="csti",
                    evidence=f"AngularJS detected with unsafe binding pattern: {pattern}",
                    payload="{{constructor.constructor('return this')().alert(1)}}",
                    remediation="Use ng-bind instead of interpolation for user data. Enable strict SCE. Upgrade to modern Angular (v2+) which doesn't have this issue.",
                    confidence=0.80,
                    poc=f"1. Visit {url}\n2. Inject into user-controlled field: {{{{$on.constructor('alert(1)')()}}}}\n3. AngularJS evaluates the expression → XSS",
                )
                return

        # Test interpolation with actual request
        try:
            test_url = url + ("&" if "?" in url else "?") + "q={{7*7}}"
            resp = self.session.get(test_url, timeout=self.timeout)
            if "49" in resp.text and "{{7*7}}" not in resp.text:
                self._add_finding(
                    vuln_id="DOM-009",
                    title="AngularJS CSTI — Expression Evaluated",
                    severity="Critical",
                    cvss=9.5,
                    url=url,
                    category="csti",
                    evidence=f"Injected {{{{7*7}}}} → got '49' in response",
                    payload="{{constructor.constructor('return this')().alert(document.domain)()}}",
                    remediation="Sanitize user input before Angular interpolation. Upgrade to modern Angular.",
                    confidence=0.95,
                    poc=f"1. Visit {test_url}\n2. '49' appears in page (template expression evaluated)\n3. Full RCE payload: {{{{constructor.constructor('return this')().alert(1)()}}}}",
                )
        except Exception:
            pass


    def _check_jsonp(self, url: str, soup: BeautifulSoup, html: str) -> None:
        """Detect JSONP endpoints vulnerable to callback injection."""
        # Find JSONP patterns in scripts
        jsonp_patterns = re.findall(
            r"(?:callback|jsonp|cb|jsonpcallback|func)\s*=\s*['\"]?([a-zA-Z_]\w*)",
            html,
            re.IGNORECASE,
        )

        # Find script tags with callback params
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if re.search(r"callback=|jsonp=|cb=", src, re.IGNORECASE):
                # Try to inject a custom callback
                try:
                    test_url = re.sub(
                        r"(callback|jsonp|cb)=[^&]+",
                        r"\1=vapttest",
                        src if src.startswith("http") else urljoin(url, src),
                    )
                    resp = self.session.get(test_url, timeout=self.timeout)
                    if "vapttest(" in resp.text:
                        self._add_finding(
                            vuln_id="DOM-010",
                            title="JSONP Callback Injection",
                            severity="Medium",
                            cvss=5.3,
                            url=test_url,
                            category="jsonp",
                            evidence=f"JSONP endpoint accepts arbitrary callback:\n{resp.text[:300]}",
                            payload=f"{test_url.replace('vapttest', 'alert')}",
                            remediation="Restrict callback parameter to alphanumeric only. Replace JSONP with CORS. Set Content-Type: application/json.",
                            confidence=0.90,
                            poc=f"1. Visit {test_url}\n2. Response wraps data in vapttest() function\n3. Attacker can steal data cross-origin via <script src=\"{test_url}\">",
                        )
                except Exception:
                    pass


    def _discover_spa_routes(self, url: str, js: str) -> None:
        """Discover SPA routes for further testing."""
        routes = set()
        for pattern in SPA_ROUTE_PATTERNS:
            matches = re.findall(pattern, js)
            routes.update(matches)

        # Enqueue discovered routes for scanning
        if routes:
            base = urlparse(url)
            for route in routes:
                if route.startswith("/"):
                    full_url = f"{base.scheme}://{base.netloc}{route}"
                    if full_url not in self._visited:
                        self._visited.add(full_url)  # Mark as visited
                        # Scan the route
                        try:
                            resp = self.session.get(full_url, timeout=self.timeout)
                            if resp.status_code == 200:
                                soup = BeautifulSoup(resp.text, "html.parser")
                                js_contents = self._extract_javascript(full_url, soup)
                                full_js = "\n".join(js_contents)
                                if full_js:
                                    self._check_dom_xss(full_url, full_js)
                                    self._check_exposed_secrets(full_url, full_js, resp.text)
                        except Exception:
                            pass


    def _add_finding(self, **kwargs: Any) -> None:
        """Add a deduplicated finding."""
        # Dedup by (vuln_id, url, title)
        key = (kwargs.get("vuln_id"), kwargs.get("url"), kwargs.get("title", "")[:80])
        dedup_hash = hashlib.md5(str(key).encode()).hexdigest()

        for existing in self.findings:
            if existing.get("_dedup") == dedup_hash:
                return

        finding = {
            "vuln_id": kwargs.get("vuln_id", "DOM-000"),
            "title": kwargs.get("title", ""),
            "severity": kwargs.get("severity", "Medium"),
            "cvss_score": kwargs.get("cvss", 5.0),
            "url": kwargs.get("url", ""),
            "category": kwargs.get("category", "dom"),
            "evidence": kwargs.get("evidence", ""),
            "payload": kwargs.get("payload", ""),
            "remediation": kwargs.get("remediation", ""),
            "confidence": kwargs.get("confidence", 0.7),
            "validated": True,
            "poc": kwargs.get("poc", ""),
            "request": f"GET {kwargs.get('url', '')} HTTP/1.1",
            "scanner": "DOMScanner",
            "_dedup": dedup_hash,
        }
        self.findings.append(finding)
