
from __future__ import annotations

import json
import random
import string
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from vapt.engine.evidence import (
    EvidenceCollector,
    enrich_finding,
)


class AdvancedScanner:

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout: int = 10,
        safety_config: dict | None = None,
    ) -> None:
        self.timeout = timeout
        self._session = session or requests.Session()
        self._session.headers.setdefault("User-Agent", "VAPT-CLI/4.0 Security Scanner")
        self.http = EvidenceCollector(self._session, timeout)
        self.safety_config = safety_config or {}
        self.findings: list[dict] = []

    def run(self, target: str) -> dict[str, Any]:
        self.findings = []
        base = target if target.startswith("http") else f"https://{target}"

        urls, forms, params = self._discover(base)

        self._test_nosql(base, urls, forms, params)

        self._test_ldap(base, urls, params)

        if not self.safety_config.get("skip_deserialization"):
            self._test_deserialization(base, urls)

        self._test_crlf(base, urls)

        if not self.safety_config.get("skip_cache_poisoning"):
            self._test_cache_poisoning(base, urls)

        self._test_host_header(base, urls)

        self._test_websocket(base)

        self._test_csp(base)

        return {"findings": self.findings}


    def _discover(self, base: str) -> tuple[list[str], list[dict], list[str]]:
        urls = [base]
        forms: list[dict] = []
        params: list[str] = []

        try:
            resp = self.http.get(base)
            soup = BeautifulSoup(resp.text, "html.parser")

            for a in soup.find_all("a", href=True):
                href = a["href"]
                full = urljoin(base, href)
                if urlparse(full).netloc == urlparse(base).netloc:
                    urls.append(full)
                    q = urlparse(full).query
                    if q:
                        for pair in q.split("&"):
                            if "=" in pair:
                                params.append(pair.split("=")[0])

            for form in soup.find_all("form"):
                action = urljoin(base, form.get("action", ""))
                method = form.get("method", "GET").upper()
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        inputs.append(name)
                        params.append(name)
                forms.append({"action": action, "method": method, "inputs": inputs})
        except Exception:
            pass

        return list(set(urls))[:30], forms, list(set(params))


    NOSQL_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
        '{"$exists": true}',
        "' || '1'=='1",
        "'; return true; var x='",
        '{"$gt": ""}',
        '{"$nin": []}',
        "'; sleep(5000); var x='",
        "1; sleep(5000)",
    ]

    NOSQL_ERROR_PATTERNS = [
        "MongoError", "mongo", "MongoDB", "BSON",
        "$where", "$regex", "operator", "OperatorNotAllowed",
        "BadValue", "unknown operator", "no matching",
        "unterminated string", "SyntaxError",
    ]

    def _test_nosql(self, base: str, urls: list[str], forms: list[dict], params: list[str]) -> None:
        test_params = params[:10] if params else ["username", "password", "email", "id", "search", "query"]

        for url in urls[:5]:
            for param in test_params[:5]:
                for payload in self.NOSQL_PAYLOADS[:5]:
                    try:
                        resp = self.http.get(url, params={param: payload})
                        if self._check_nosql_response(resp, payload):
                            self._add_finding(
                                vuln_id="ADV-001",
                                title=f"NoSQL Injection in '{param}'",
                                severity="Critical",
                                cvss_score=9.8,
                                url=url,
                                category="nosql_injection",
                                parameter=param,
                                payload=payload,
                                evidence=f"Response indicates NoSQL injection: status={resp.status_code}, length={len(resp.text)}",
                            )
                            break
                    except Exception:
                        continue

        for form in forms[:5]:
            if form["method"] == "POST" and form["inputs"]:
                json_payload = {}
                for inp in form["inputs"]:
                    json_payload[inp] = {"$gt": ""}
                try:
                    resp = self.http.post(
                        form["action"],
                        json=json_payload,
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code in (200, 302) and len(resp.text) > 100:
                        self._add_finding(
                            vuln_id="ADV-001",
                            title=f"NoSQL Injection via JSON body at {form['action']}",
                            severity="Critical",
                            cvss_score=9.8,
                            url=form["action"],
                            category="nosql_injection",
                            parameter=", ".join(form["inputs"]),
                            payload=json.dumps(json_payload),
                            evidence=f"JSON body with MongoDB operators accepted: status={resp.status_code}",
                        )
                except Exception:
                    continue

    def _check_nosql_response(self, resp: requests.Response, payload: str) -> bool:
        text = resp.text.lower()
        for pattern in self.NOSQL_ERROR_PATTERNS:
            if pattern.lower() in text:
                return True
        if "sleep" in payload.lower():
            return False
        return False


    LDAP_PAYLOADS = [
        "*)(objectClass=*",
        "*()|%26'",
        "admin)(&)",
        "admin)(|(password=*))",
        "*(|(objectclass=*))",
        "*)(%26",
        "*)(uid=*))(|(uid=*",
    ]

    LDAP_ERROR_PATTERNS = [
        "LDAP", "ldap", "Invalid DN", "javax.naming",
        "LDAPException", "bad search filter", "NamingException",
        "InvalidNameException", "SearchFilter",
    ]

    def _test_ldap(self, base: str, urls: list[str], params: list[str]) -> None:
        test_params = params[:5] if params else ["username", "user", "uid", "cn", "search"]

        for url in urls[:3]:
            for param in test_params[:3]:
                try:
                    baseline = self.http.get(url, params={param: "admin"})
                except Exception:
                    continue

                for payload in self.LDAP_PAYLOADS:
                    try:
                        resp = self.http.get(url, params={param: payload})
                        for pattern in self.LDAP_ERROR_PATTERNS:
                            if pattern in resp.text and pattern not in baseline.text:
                                self._add_finding(
                                    vuln_id="ADV-002",
                                    title=f"LDAP Injection in '{param}'",
                                    severity="High",
                                    cvss_score=8.1,
                                    url=url,
                                    category="ldap_injection",
                                    parameter=param,
                                    payload=payload,
                                    evidence=f"LDAP error pattern '{pattern}' found in response",
                                )
                                break
                    except Exception:
                        continue


    DESER_HEADERS = [
        "application/x-java-serialized-object",
        "application/x-php-serialized",
        "application/x-python-serialize",
    ]

    DESER_PAYLOADS = {
        "java": "rO0ABXNyABFqYXZhLmxhbmcuUnVudGltZQ==",
        "php": 'O:8:"stdClass":1:{s:4:"test";s:4:"VAPT";}',
        "python": "gASVDAAAAAAAAACMBHRlc3SFlC4=",
        "dotnet": "/wEPDwUKMTk3NjI2MTQzMWRk",
    }

    def _test_deserialization(self, base: str, urls: list[str]) -> None:
        for url in urls[:5]:
            for lang, payload in self.DESER_PAYLOADS.items():
                try:
                    resp = self.http.post(
                        url,
                        data=payload,
                        headers={"Content-Type": self.DESER_HEADERS[0] if lang == "java" else "application/octet-stream"},
                    )
                    error_patterns = [
                        "ClassNotFoundException", "InvalidClassException",
                        "unserialize()", "pickle", "UnpicklingError",
                        "SerializationException", "ObjectInputStream",
                        "ViewStateException", "__wakeup",
                    ]
                    for pattern in error_patterns:
                        if pattern in resp.text:
                            self._add_finding(
                                vuln_id="ADV-003",
                                title=f"Insecure Deserialization ({lang})",
                                severity="Critical",
                                cvss_score=9.8,
                                url=url,
                                category="deserialization",
                                payload=payload[:100],
                                evidence=f"Deserialization error '{pattern}' in response — server processes serialized data",
                            )
                            break
                except Exception:
                    continue

            deser_paths = [
                "/api/import", "/api/upload", "/api/restore",
                "/admin/import", "/xmlrpc.php", "/invoker/JMXInvokerServlet",
                "/jmx-console", "/web-console", "/_search",
            ]
            for path in deser_paths:
                try:
                    test_url = urljoin(base, path)
                    resp = self.http.get(test_url)
                    if resp.status_code in (200, 405, 500):
                        if any(h in resp.headers.get("Content-Type", "") for h in ["java", "serial", "octet"]):
                            self._add_finding(
                                vuln_id="ADV-003",
                                title=f"Deserialization Endpoint Found: {path}",
                                severity="High",
                                cvss_score=8.1,
                                url=test_url,
                                category="deserialization",
                                evidence=f"Endpoint accepts serialized data: {resp.headers.get('Content-Type', '')}",
                            )
                except Exception:
                    continue


    def _test_crlf(self, base: str, urls: list[str]) -> None:
        canary = "X-VAPT-Injected"
        payloads = [
            f"%0d%0a{canary}: true",
            "%0d%0aSet-Cookie: vapt=pwned",
            f"\r\n{canary}: true",
            "%0d%0a%0d%0a<script>alert(1)</script>",
            f"%E5%98%8A%E5%98%8D{canary}: true",
        ]

        for url in urls[:5]:
            for payload in payloads:
                try:
                    test_url = f"{url}/{payload}"
                    resp = self.http.get(test_url, allow_redirects=False)

                    if canary.lower() in str(resp.headers).lower():
                        self._add_finding(
                            vuln_id="ADV-004",
                            title="CRLF Injection / HTTP Response Splitting",
                            severity="Medium",
                            cvss_score=6.1,
                            url=url,
                            category="crlf_injection",
                            payload=payload,
                            evidence=f"Injected header '{canary}' found in response headers",
                        )
                        break

                    cookies = resp.headers.get("Set-Cookie", "")
                    if "vapt=pwned" in cookies:
                        self._add_finding(
                            vuln_id="ADV-004",
                            title="CRLF Injection — Cookie Injection",
                            severity="High",
                            cvss_score=7.5,
                            url=url,
                            category="crlf_injection",
                            payload=payload,
                            evidence="Injected cookie 'vapt=pwned' found in Set-Cookie header",
                        )
                        break
                except Exception:
                    continue


    def _test_cache_poisoning(self, base: str, urls: list[str]) -> None:
        canary = f"vapt-{''.join(random.choices(string.ascii_lowercase, k=6))}"
        poison_headers = [
            ("X-Forwarded-Host", f"{canary}.evil.com"),
            ("X-Original-URL", f"/{canary}"),
            ("X-Rewrite-URL", f"/{canary}"),
            ("X-Forwarded-Scheme", "nothttps"),
            ("X-Forwarded-Port", "1337"),
            ("X-Host", f"{canary}.evil.com"),
        ]

        for url in urls[:3]:
            try:
                baseline = self.http.get(url)
            except Exception:
                continue

            for header_name, header_val in poison_headers:
                try:
                    resp = self.http.get(url, headers={header_name: header_val})

                    if canary in resp.text and canary not in baseline.text:
                        self._add_finding(
                            vuln_id="ADV-005",
                            title=f"Cache Poisoning via {header_name}",
                            severity="High",
                            cvss_score=7.5,
                            url=url,
                            category="cache_poisoning",
                            payload=f"{header_name}: {header_val}",
                            evidence=f"Header value '{canary}' reflected in response body — if cached, all users affected",
                        )
                        break

                    if resp.text != baseline.text and abs(len(resp.text) - len(baseline.text)) > 50:
                        cache_headers = resp.headers.get("Cache-Control", "") + resp.headers.get("X-Cache", "")
                        if "public" in cache_headers.lower() or "HIT" in cache_headers:
                            self._add_finding(
                                vuln_id="ADV-005",
                                title=f"Potential Cache Poisoning via {header_name}",
                                severity="Medium",
                                cvss_score=5.3,
                                url=url,
                                category="cache_poisoning",
                                payload=f"{header_name}: {header_val}",
                                evidence=f"Response varies with unkeyed header and caching is enabled: {cache_headers[:100]}",
                            )
                except Exception:
                    continue


    def _test_host_header(self, base: str, urls: list[str]) -> None:
        evil_host = "evil.vapt-test.com"
        for url in urls[:3]:
            try:
                resp = self.http.get(url, headers={"Host": evil_host})
                if evil_host in resp.text:
                    self._add_finding(
                        vuln_id="ADV-006",
                        title="Host Header Injection — Reflected in Response",
                        severity="Medium",
                        cvss_score=6.1,
                        url=url,
                        category="header_injection",
                        payload=f"Host: {evil_host}",
                        evidence=f"Injected host '{evil_host}' reflected in response body",
                    )
            except Exception:
                pass

            try:
                resp = self.http.get(url, headers={"X-Forwarded-Host": evil_host})
                if evil_host in resp.text:
                    self._add_finding(
                        vuln_id="ADV-006",
                        title="Host Header Injection via X-Forwarded-Host",
                        severity="Medium",
                        cvss_score=6.1,
                        url=url,
                        category="header_injection",
                        payload=f"X-Forwarded-Host: {evil_host}",
                        evidence="Injected X-Forwarded-Host reflected in response",
                    )
            except Exception:
                pass


    def _test_websocket(self, base: str) -> None:
        ws_paths = ["/ws", "/websocket", "/socket", "/ws/", "/socket.io/", "/sockjs/", "/cable", "/hub"]

        for path in ws_paths:
            url = urljoin(base, path)
            try:
                resp = self.http.get(url, headers={
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Version": "13",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                })

                if resp.status_code == 101 or "upgrade" in resp.headers.get("Connection", "").lower():
                    resp2 = self.http.get(url, headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Version": "13",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Origin": "https://evil.com",
                    })
                    if resp2.status_code == 101:
                        self._add_finding(
                            vuln_id="ADV-007",
                            title=f"Cross-Site WebSocket Hijacking (CSWSH) at {path}",
                            severity="High",
                            cvss_score=8.1,
                            url=url,
                            category="websocket",
                            evidence="WebSocket endpoint accepts connections from arbitrary origins",
                        )

                elif resp.status_code in (200, 400, 426):
                    if "websocket" in resp.text.lower() or resp.status_code == 426:
                        self._add_finding(
                            vuln_id="ADV-007",
                            title=f"WebSocket Endpoint Detected: {path}",
                            severity="Info",
                            cvss_score=0,
                            url=url,
                            category="websocket",
                            evidence=f"WebSocket endpoint responds at {path} (status: {resp.status_code})",
                        )
            except Exception:
                continue


    CSP_DANGEROUS = {
        "unsafe-inline": "Allows inline scripts — XSS protection bypassed",
        "unsafe-eval": "Allows eval() — enables code injection",
        "unsafe-hashes": "Allows specific inline event handlers",
        "*": "Wildcard allows loading resources from any domain",
        "data:": "Allows data: URIs — can be used for XSS",
        "blob:": "Allows blob: URIs — can be used for code execution",
        "http:": "Allows insecure HTTP — enables MITM attacks",
    }

    def _test_csp(self, base: str) -> None:
        try:
            resp = self.http.get(base)
            csp = resp.headers.get("Content-Security-Policy", "")
            csp_ro = resp.headers.get("Content-Security-Policy-Report-Only", "")

            if not csp and not csp_ro:
                self._add_finding(
                    vuln_id="ADV-008",
                    title="Missing Content Security Policy",
                    severity="Medium",
                    cvss_score=5.3,
                    url=base,
                    category="security_header",
                    evidence="No Content-Security-Policy header found in response",
                    remediation="Implement a strict Content Security Policy. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';",
                )
                return

            policy = csp or csp_ro
            issues = []

            for directive in policy.split(";"):
                directive = directive.strip()
                for dangerous, reason in self.CSP_DANGEROUS.items():
                    if dangerous in directive:
                        issues.append(f"  • {directive.split()[0]}: '{dangerous}' — {reason}")

            important = ["default-src", "script-src", "object-src", "base-uri"]
            for d in important:
                if d not in policy:
                    issues.append(f"  • Missing '{d}' directive")

            if issues:
                self._add_finding(
                    vuln_id="ADV-008",
                    title="Weak Content Security Policy",
                    severity="Medium",
                    cvss_score=5.3,
                    url=base,
                    category="security_header",
                    evidence=f"CSP: {policy[:300]}\n\nIssues found:\n" + "\n".join(issues),
                    remediation="Tighten the CSP by removing 'unsafe-inline', 'unsafe-eval', and wildcards. Use nonces or hashes for inline scripts.",
                )
        except Exception:
            pass


    def _add_finding(self, **kwargs) -> None:
        finding = {
            "scanner": "AdvancedScanner",
            "request": self.http.last_request,
            "response": self.http.last_response,
            **kwargs,
        }
        dedup = f"{finding.get('vuln_id', '')}-{finding.get('url', '')}-{finding.get('parameter', '')}"
        for existing in self.findings:
            if existing.get("_dedup") == dedup:
                return
        finding["_dedup"] = dedup
        self.findings.append(enrich_finding(finding))
