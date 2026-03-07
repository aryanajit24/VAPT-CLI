"""REST/GraphQL API security scanner."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any

import requests
from requests.exceptions import RequestException

from vapt.utils.helpers import sanitize_target

COMMON_API_PATHS = [
    "/api/v1/users", "/api/v2/users", "/api/v3/users", "/api/users",
    "/api/v1/user", "/api/v2/user",
    "/api/v1/me", "/api/v2/me", "/api/me",
    "/api/v1/profile", "/api/v2/profile", "/api/profile",
    "/api/v1/account", "/api/v2/account", "/api/account",
    "/api/v1/auth", "/api/v2/auth", "/api/auth",
    "/api/v1/login", "/api/v2/login", "/api/login",
    "/api/v1/register", "/api/v2/register", "/api/register",
    "/api/v1/signup", "/api/v2/signup", "/api/signup",
    "/api/v1/logout", "/api/logout",
    "/api/v1/token", "/api/v2/token", "/api/token",
    "/api/v1/refresh", "/api/refresh",
    "/api/v1/password", "/api/password",
    "/api/v1/reset-password", "/api/reset-password",
    "/api/admin", "/api/v1/admin", "/api/v2/admin",
    "/api/admin/users", "/api/v1/admin/users",
    "/api/admin/config", "/api/v1/admin/config",
    "/api/admin/settings", "/api/v1/admin/settings",
    "/api/admin/dashboard", "/api/v1/admin/dashboard",
    "/api/internal", "/api/v1/internal",
    "/api/management", "/api/v1/management",
    "/api/superuser", "/api/root",
    "/api/config", "/api/v1/config", "/api/v2/config",
    "/api/settings", "/api/v1/settings",
    "/api/health", "/api/v1/health", "/api/status",
    "/api/version", "/api/v1/version",
    "/api/debug", "/api/v1/debug",
    "/api/env", "/api/v1/env",
    "/api/info", "/api/v1/info",
    "/api/docs", "/api/v1/docs", "/docs",
    "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/v1/api-docs", "/v2/api-docs",
    "/swagger-ui.html", "/swagger-ui/",
    "/api/swagger", "/api/openapi",
    "/redoc", "/api/redoc",
    "/graphql", "/api/graphql", "/v1/graphql",
    "/graphiql", "/api/graphiql",
    "/gql", "/api/gql",
    "/api/v1/orders", "/api/v2/orders", "/api/orders",
    "/api/v1/products", "/api/v2/products", "/api/products",
    "/api/v1/items", "/api/v2/items", "/api/items",
    "/api/v1/files", "/api/v2/files", "/api/files",
    "/api/v1/uploads", "/api/uploads",
    "/api/v1/reports", "/api/reports",
    "/api/v1/payments", "/api/payments",
    "/api/v1/invoices", "/api/invoices",
    "/api/v1/messages", "/api/messages",
    "/api/v1/notifications", "/api/notifications",
    "/api/v1/logs", "/api/logs",
    "/api/v1/events", "/api/events",
    "/api/v1/webhooks", "/api/webhooks",
    # Spring Boot actuator
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/beans", "/actuator/mappings", "/actuator/heapdump",
    "/actuator/logfile", "/actuator/metrics",
]

BOLA_TEST_IDS = ["1", "2", "100", "admin", "0", "-1", "me", "self"]

SENSITIVE_FIELDS = {
    "password", "passwd", "password_hash", "hashed_password",
    "secret", "token", "api_key", "apikey", "access_token",
    "refresh_token", "private_key", "secret_key",
    "credit_card", "card_number", "cvv", "ssn", "social_security",
    "aws_secret", "aws_access_key", "database_url", "connection_string",
}

MASS_ASSIGN_FIELDS = {
    "isAdmin": True, "is_admin": True, "admin": True,
    "role": "admin", "roles": ["admin"], "permissions": ["all"],
    "privilege": "admin", "level": 99, "verified": True,
    "email_verified": True, "active": True, "approved": True,
    "balance": 999999, "credit": 999999,
}

GRAPHQL_INTROSPECTION = json.dumps({
    "query": "{ __schema { queryType { name } types { name kind description } } }"
})

WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "admin", "test",
    "changeme", "key", "token", "jwt", "supersecret",
    "mysecret", "your-256-bit-secret", "qwerty",
]


class APIScanner:
    """Full bug-bounty-style API vulnerability scanner."""

    def __init__(self, timeout: int = 10, safety_config: dict | None = None, session=None) -> None:
        self.timeout = timeout
        self.safety_config = safety_config or {}
        if session is not None:
            self._raw_session = session
        else:
            self._raw_session = requests.Session()
            self._raw_session.verify = False  # noqa: S501
        from vapt.engine.evidence import EvidenceCollector
        self.session = EvidenceCollector(self._raw_session, timeout)

    def run(self, target: str, token: str | None = None) -> dict[str, Any]:
        """Discover and attack API endpoints on the target."""
        target = sanitize_target(target)
        base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"

        if token:
            self.session.headers.update({"Authorization": f"Bearer {token}"})

        results: dict[str, Any] = {
            "target": base_url,
            "category": "api",
            "endpoints_discovered": [],
            "findings": [],
        }

        discovered = self._discover_endpoints(base_url)
        results["endpoints_discovered"] = discovered

        spec_endpoints = self._parse_api_spec(base_url)
        all_endpoints = list(set(discovered + spec_endpoints))
        results["endpoints_discovered"] = all_endpoints

        for endpoint in all_endpoints:
            results["findings"] += self._test_data_exposure(base_url, endpoint)
            results["findings"] += self._test_bola(base_url, endpoint)
            results["findings"] += self._test_verb_tampering(base_url, endpoint)
            results["findings"] += self._test_verbose_errors(base_url, endpoint)

        results["findings"] += self._test_unauthed_admin(base_url)
        results["findings"] += self._test_cors(base_url)

        # SAFETY GATED — rapid-fire requests may trigger WAF / ban
        if not self.safety_config.get("skip_rate_limit_test"):
            results["findings"] += self._test_rate_limiting(base_url)

        results["findings"] += self._test_graphql(base_url)
        results["findings"] += self._test_jwt(token)

        # SAFETY GATED — writes admin=true, balance=999999 to endpoints
        if not self.safety_config.get("skip_file_write"):
            results["findings"] += self._test_mass_assignment(base_url, all_endpoints)

        seen: set[tuple] = set()
        unique: list[dict] = []
        for f in results["findings"]:
            key = (f.get("vuln_id", ""), f.get("title", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        results["findings"] = unique
        return results


    def _discover_endpoints(self, base_url: str) -> list[str]:
        """Probe common API paths and return responsive ones."""
        found = []
        for path in COMMON_API_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if resp.status_code not in (404, 410):
                    found.append(path)
            except RequestException:
                pass
        return found

    def _parse_api_spec(self, base_url: str) -> list[str]:
        """Try to fetch Swagger/OpenAPI spec and extract all endpoint paths."""
        spec_urls = [
            "/swagger.json", "/openapi.json", "/api-docs",
            "/v1/api-docs", "/v2/api-docs", "/api/swagger.json",
        ]
        paths: list[str] = []
        for spec_path in spec_urls:
            url = base_url.rstrip("/") + spec_path
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    # OpenAPI 3.x and Swagger 2.x both use "paths"
                    for path in data.get("paths", {}):
                        paths.append(path)
            except Exception:
                pass
        return paths


    def _test_data_exposure(self, base_url: str, path: str) -> list[dict]:
        """Check a discovered endpoint for sensitive field exposure."""
        url = base_url.rstrip("/") + path
        try:
            resp = self.session.get(url, timeout=self.timeout)
            try:
                data = resp.json()
            except ValueError:
                return []
            exposed = self._find_sensitive_fields(data)
            if exposed:
                return [self._f(
                    "API-002", "api",
                    f"Sensitive data exposed at {path}",
                    f"Fields: {', '.join(exposed)} found in response from {path}",
                    "medium", 5.9, endpoint=path, exposed_fields=exposed,
                )]
        except RequestException:
            pass
        return []

    def _test_bola(self, base_url: str, path: str) -> list[dict]:
        """Test for Broken Object Level Authorization by trying alternate IDs."""
        if not any(word in path for word in ["user", "order", "item", "product", "account", "file", "message"]):
            return []
        findings = []
        for test_id in BOLA_TEST_IDS:
            url = base_url.rstrip("/") + path.rstrip("/") + f"/{test_id}"
            try:
                no_auth = requests.Session()
                no_auth.verify = False
                resp = no_auth.get(url, timeout=self.timeout)
                if resp.status_code in (200, 201, 206):
                    try:
                        data = resp.json()
                    except ValueError:
                        data = {}
                    suspicious_fields = {"email", "username", "name", "phone", "address", "ssn"}
                    if isinstance(data, dict) and any(k.lower() in suspicious_fields for k in data):
                        findings.append(self._f(
                            "API-001", "api",
                            f"BOLA/IDOR — unauthenticated access to {path}/{test_id}",
                            f"Object at {url} returned without authentication (HTTP {resp.status_code})",
                            "critical", 9.1, endpoint=f"{path}/{test_id}", test_id=test_id,
                        ))
                        break
            except RequestException:
                pass
        return findings

    def _test_verb_tampering(self, base_url: str, path: str) -> list[dict]:
        """Try HTTP methods the API probably shouldn't allow."""
        findings = []
        url = base_url.rstrip("/") + path
        for method in ("DELETE", "PUT", "PATCH"):
            try:
                resp = self.session.request(method, url,
                    json={"test": "vapt"}, timeout=self.timeout)
                if resp.status_code in (200, 201, 204):
                    findings.append(self._f(
                        "API-007", "api",
                        f"HTTP verb tampering — {method} allowed on {path}",
                        f"{method} {url} returned HTTP {resp.status_code}",
                        "high", 7.5, endpoint=path, method=method,
                    ))
            except RequestException:
                pass
        return findings

    def _test_verbose_errors(self, base_url: str, path: str) -> list[dict]:
        """Send malformed requests and check for verbose error messages."""
        url = base_url.rstrip("/") + path
        error_patterns = re.compile(
            r"(stack trace|traceback|at line \d|exception in thread"
            r"|sqlexception|psqlexception|ora-\d{4}"
            r"|internal server error.*at.*\(|unhandled exception)",
            re.IGNORECASE,
        )
        try:
            resp = self.session.post(
                url,
                data="{{invalid_json::::",
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
            if error_patterns.search(resp.text):
                return [self._f(
                    "API-009", "api",
                    f"Verbose error disclosure at {path}",
                    f"Malformed request triggered detailed error at {url}",
                    "medium", 5.3, endpoint=path,
                )]
        except RequestException:
            pass
        return []


    def _test_unauthed_admin(self, base_url: str) -> list[dict]:
        """Try admin endpoints without any authentication."""
        findings = []
        admin_paths = [
            "/api/admin", "/api/v1/admin", "/api/v2/admin",
            "/api/admin/users", "/api/v1/admin/users",
            "/api/admin/config", "/api/v1/admin/config",
            "/api/internal", "/api/v1/internal",
            "/api/management", "/api/superuser",
        ]
        no_auth = requests.Session()
        no_auth.verify = False
        for path in admin_paths:
            url = base_url.rstrip("/") + path
            try:
                resp = no_auth.get(url, timeout=self.timeout)
                if resp.status_code in (200, 201, 206):
                    findings.append(self._f(
                        "API-003", "api",
                        f"Unauthenticated admin endpoint: {path}",
                        f"Admin endpoint accessible without auth: {url} (HTTP {resp.status_code})",
                        "critical", 9.1, endpoint=path,
                    ))
            except RequestException:
                pass
        return findings

    def _test_cors(self, base_url: str) -> list[dict]:
        """Check for overly permissive CORS policy."""
        findings = []
        try:
            resp = self.session.options(
                base_url,
                headers={"Origin": "https://evil.example.com"},
                timeout=self.timeout,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*":
                findings.append(self._f(
                    "WEB-005", "api",
                    "CORS wildcard — Access-Control-Allow-Origin: *",
                    "Any origin can make cross-origin requests to this API.",
                    "medium", 5.4,
                ))
            elif acao == "https://evil.example.com":
                sev = "high" if acac.lower() == "true" else "medium"
                findings.append(self._f(
                    "WEB-005", "api",
                    "CORS reflects arbitrary origin",
                    f"Server echoes attacker origin in ACAO header. "
                    f"Credentials allowed: {acac}",
                    sev, 8.1 if sev == "high" else 5.4,
                ))
        except RequestException:
            pass
        return findings

    def _test_rate_limiting(self, base_url: str) -> list[dict]:
        """Send 15 rapid requests and check if any get throttled (429)."""
        paths_to_test = ["/api/v1/users", "/api/users", "/api/v1/login", "/api/login"]
        for path in paths_to_test:
            url = base_url.rstrip("/") + path
            statuses: list[int] = []
            try:
                for _ in range(15):
                    resp = self.session.get(url, timeout=self.timeout)
                    statuses.append(resp.status_code)
                if statuses and 429 not in statuses and all(s < 500 for s in statuses):
                    return [self._f(
                        "API-008", "api",
                        "No rate limiting detected",
                        f"15 consecutive requests to {path} all succeeded without throttling. "
                        f"Vulnerable to brute-force and enumeration.",
                        "medium", 5.3, endpoint=path,
                    )]
            except RequestException:
                continue
        return []

    def _test_graphql(self, base_url: str) -> list[dict]:
        """Test GraphQL endpoints for introspection and injection."""
        findings = []
        gql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/gql"]
        for path in gql_paths:
            url = base_url.rstrip("/") + path
            try:
                resp = self.session.post(
                    url,
                    data=GRAPHQL_INTROSPECTION,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data.get("data", {}).get("__schema"):
                            findings.append(self._f(
                                "API-005", "api",
                                f"GraphQL introspection enabled at {path}",
                                f"Full schema exposed via introspection at {url}. "
                                "Attackers can map all types, queries, and mutations.",
                                "medium", 5.3, endpoint=path,
                            ))
                    except ValueError:
                        pass
            except RequestException:
                pass

            try:
                injection_query = json.dumps({"query": "{ user(id: \"1 OR 1=1\") { id email } }"})
                resp = self.session.post(
                    url,
                    data=injection_query,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                if resp.status_code == 200 and "errors" not in resp.text.lower():
                    findings.append(self._f(
                        "API-005", "api",
                        f"GraphQL injection probe at {path} did not error",
                        f"Injection-like query succeeded at {url}. Manual validation required.",
                        "low", 3.5, endpoint=path,
                    ))
            except RequestException:
                pass

        return findings

    def _test_jwt(self, token: str | None) -> list[dict]:
        """Test JWT for algorithm confusion and weak secrets."""
        if not token:
            return []

        findings: list[dict] = []

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return []
            header_b64, payload_b64, sig_b64 = parts
            header = json.loads(base64.b64decode(header_b64 + "=="))
            payload_data = json.loads(base64.b64decode(payload_b64 + "=="))
        except Exception:
            return []

        alg = header.get("alg", "")

        if alg.lower() == "none":
            findings.append(self._f(
                "API-006", "api",
                "JWT uses 'none' algorithm",
                "Token has alg=none — signature validation is bypassed entirely.",
                "critical", 9.8,
            ))

        if alg.startswith("HS"):
            signing_input = f"{header_b64}.{payload_b64}".encode()
            hash_func = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512,
            }.get(alg, hashlib.sha256)
            expected_sig = base64.urlsafe_b64decode(sig_b64 + "==")
            for secret in WEAK_JWT_SECRETS:
                sig = hmac.new(secret.encode(), signing_input, hash_func).digest()
                if sig == expected_sig:
                    findings.append(self._f(
                        "API-006", "api",
                        f"JWT signed with weak secret: '{secret}'",
                        f"The JWT is signed with the trivially guessable secret '{secret}'. "
                        "An attacker can forge arbitrary tokens.",
                        "critical", 9.8, discovered_secret=secret,
                    ))
                    break

        sensitive_jwt_fields = {"password", "secret", "private_key", "api_key"}
        for field in sensitive_jwt_fields:
            if field in payload_data:
                findings.append(self._f(
                    "API-006", "api",
                    f"Sensitive field '{field}' in JWT payload",
                    "JWT payload contains sensitive data. JWTs are base64-encoded, not encrypted.",
                    "medium", 5.3,
                ))

        return findings

    def _test_mass_assignment(self, base_url: str, endpoints: list[str]) -> list[dict]:
        """Attempt to set privileged fields via POST/PUT (mass assignment)."""
        findings = []
        for path in endpoints:
            if not any(w in path for w in ["user", "profile", "account", "register", "signup"]):
                continue
            url = base_url.rstrip("/") + path
            try:
                resp = self.session.post(
                    url,
                    json=MASS_ASSIGN_FIELDS,
                    timeout=self.timeout,
                )
                if resp.status_code in (200, 201):
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and any(
                            k in data for k in MASS_ASSIGN_FIELDS
                        ):
                            findings.append(self._f(
                                "API-004", "api",
                                f"Mass assignment vulnerability at {path}",
                                f"Server accepted privileged fields (isAdmin, role, etc.) at {url}",
                                "high", 8.1, endpoint=path,
                            ))
                    except ValueError:
                        pass
            except RequestException:
                pass
        return findings


    def _find_sensitive_fields(self, data: Any) -> list[str]:
        """Recursively find sensitive field names in a JSON object."""
        found: set[str] = set()
        if isinstance(data, dict):
            for key, value in data.items():
                if key.lower() in SENSITIVE_FIELDS:
                    found.add(key)
                found |= set(self._find_sensitive_fields(value))
        elif isinstance(data, list):
            for item in data:
                found |= set(self._find_sensitive_fields(item))
        return list(found)

    @staticmethod
    def _f(
        vuln_id: str, category: str, title: str,
        description: str, severity: str, cvss_score: float,
        **extra: Any,
    ) -> dict[str, Any]:
        d = {
            "vuln_id": vuln_id, "category": category, "title": title,
            "description": description, "severity": severity, "cvss_score": cvss_score,
            "scanner": "APIScanner",
        }
        d.update(extra)
        return d
