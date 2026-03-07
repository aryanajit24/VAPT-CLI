"""Authentication flow analyzer for session management vulnerabilities."""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from typing import Any
from urllib.parse import urljoin, urlparse, urlencode

import requests
from requests.exceptions import RequestException

from vapt.utils.helpers import sanitize_target


class AuthFlowScanner:
    """
    Scanner that tests authenticated application flows.
    
    Creates and manages test accounts, then systematically tests
    all authenticated functionality for authorization flaws.
    """

    def __init__(
        self,
        timeout: int = 15,
        safety_config: dict | None = None,
    ) -> None:
        self.timeout = timeout
        self.safety_config = safety_config or {}
        self.findings: list[dict] = []
        
        self.session_a: requests.Session | None = None  # Primary test user
        self.session_b: requests.Session | None = None  # Secondary test user (for IDOR)
        self.unauthenticated: requests.Session = requests.Session()
        self.unauthenticated.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        
        self.account_a: dict = {}
        self.account_b: dict = {}
        
        self.auth_endpoints: list[dict] = []
        self.unauth_endpoints: list[dict] = []

    def setup_session(
        self,
        session: requests.Session,
        label: str = "A",
        account_info: dict | None = None,
    ) -> None:
        """
        Set up an authenticated session to use for testing.
        
        Parameters
        ----------
        session : requests.Session
            Pre-authenticated session (with cookies/tokens).
        label : str
            "A" for primary user, "B" for secondary user.
        account_info : dict, optional
            Info about the account (email, user_id, etc).
        """
        if label == "A":
            self.session_a = session
            self.account_a = account_info or {}
        else:
            self.session_b = session
            self.account_b = account_info or {}

    def setup_from_credentials(
        self,
        login_url: str,
        email_a: str,
        password_a: str,
        email_b: str | None = None,
        password_b: str | None = None,
        custom_headers: dict | None = None,
    ) -> bool:
        """
        Create authenticated sessions from login credentials.
        
        Returns True if at least session A was created successfully.
        """
        self.session_a = self._login(login_url, email_a, password_a, custom_headers)
        if not self.session_a:
            return False
        
        self.account_a = {"email": email_a}
        
        if email_b and password_b:
            self.session_b = self._login(login_url, email_b, password_b, custom_headers)
            if self.session_b:
                self.account_b = {"email": email_b}
        
        return True

    def _login(
        self,
        login_url: str,
        email: str,
        password: str,
        custom_headers: dict | None = None,
    ) -> requests.Session | None:
        """Attempt login and return authenticated session."""
        session = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        if custom_headers:
            session.headers.update(custom_headers)
        
        login_payloads = [
            {"email": email, "password": password},
            {"username": email, "password": password},
            {"user": email, "pass": password},
            {"login": email, "password": password},
            {"email": email, "passwd": password},
        ]
        
        for payload in login_payloads:
            try:
                resp = session.post(
                    login_url,
                    json=payload,
                    timeout=self.timeout,
                    verify=False,
                )
                
                if resp.status_code in (200, 201):
                    try:
                        data = resp.json()
                        token = (
                            data.get("token") or data.get("access_token") or
                            data.get("accessToken") or data.get("jwt") or
                            data.get("session_token") or
                            data.get("data", {}).get("token") or
                            data.get("data", {}).get("access_token")
                        )
                        if token:
                            session.headers["Authorization"] = f"Bearer {token}"
                            return session
                    except (json.JSONDecodeError, ValueError):
                        pass
                    
                    if session.cookies:
                        return session
                
                # form-based logins often redirect on success
                if resp.status_code in (301, 302, 303):
                    return session
                    
            except RequestException:
                continue
        
        return None

    def run(
        self,
        target: str,
        endpoints: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Run the full authenticated flow scan.
        
        Parameters
        ----------
        target : str
            Base URL (e.g., https://api.example.com)
        endpoints : list[str], optional
            Pre-discovered endpoints from Deep JS Recon.
        """
        target = sanitize_target(target)
        started = time.time()
        
        if not self.session_a:
            return {
                "module": "Auth Flow Scanner",
                "error": "No authenticated session. Call setup_session() or setup_from_credentials() first.",
                "findings": [],
            }
        
        self._map_auth_surface(target, endpoints or [])
        
        if self.session_b:
            self._test_idor(target)
        
        self._test_privilege_escalation(target)
        
        self._test_session_management(target)
        
        self._test_token_handling(target)
        
        self._test_method_access_control(target)
        
        elapsed = time.time() - started
        
        return {
            "module": "Auth Flow Scanner",
            "target": target,
            "duration_sec": round(elapsed, 2),
            "auth_endpoints_found": len(self.auth_endpoints),
            "unauth_endpoints_found": len(self.unauth_endpoints),
            "has_second_account": self.session_b is not None,
            "findings": self.findings,
        }

    def _map_auth_surface(self, target: str, known_endpoints: list[str]) -> None:
        """
        Map which endpoints require authentication and which don't.
        
        For each endpoint, test with:
          1. No session → should return 401/403
          2. User A session → should return 200
          3. User B session → compare with User A (IDOR check)
        """
        endpoints_to_test = list(known_endpoints)
        
        auth_paths = [
            "/api/me", "/api/v1/me", "/api/user", "/api/v1/user",
            "/api/profile", "/api/v1/profile",
            "/api/account", "/api/v1/account",
            "/api/settings", "/api/v1/settings",
            "/api/dashboard", "/api/v1/dashboard",
            "/api/portfolio", "/api/v1/portfolio",
            "/api/transactions", "/api/v1/transactions",
            "/api/notifications", "/api/v1/notifications",
            "/api/balance", "/api/v1/balance",
            "/api/orders", "/api/v1/orders",
            "/api/investments", "/api/v1/investments",
            "/api/documents", "/api/v1/documents",
            "/api/statements", "/api/v1/statements",
            "/api/referrals", "/api/v1/referrals",
            "/api/rewards", "/api/v1/rewards",
            "/api/activity", "/api/v1/activity",
            "/api/preferences", "/api/v1/preferences",
            "/api/linked-accounts", "/api/v1/linked-accounts",
            "/api/beneficiaries", "/api/v1/beneficiaries",
            "/api/bank-accounts", "/api/v1/bank-accounts",
        ]
        
        for path in auth_paths:
            full_url = urljoin(target, path)
            if full_url not in endpoints_to_test:
                endpoints_to_test.append(full_url)
        
        for endpoint in endpoints_to_test:
            try:
                unauth_resp = self.unauthenticated.get(
                    endpoint, timeout=self.timeout, verify=False
                )
                
                auth_resp = self.session_a.get(
                    endpoint, timeout=self.timeout, verify=False
                )
                
                if auth_resp.status_code in (200, 201) and unauth_resp.status_code in (401, 403):
                    self.auth_endpoints.append({
                        "url": endpoint,
                        "unauth_status": unauth_resp.status_code,
                        "auth_status": auth_resp.status_code,
                        "response_size": len(auth_resp.text),
                        "content_type": auth_resp.headers.get("Content-Type", ""),
                    })
                elif auth_resp.status_code in (200, 201) and unauth_resp.status_code in (200, 201):
                    self.unauth_endpoints.append({
                        "url": endpoint,
                        "status": unauth_resp.status_code,
                    })
                    
                    if len(auth_resp.text) > len(unauth_resp.text) * 1.5:
                        self.findings.append({
                            "id": f"AUTH-LEAK-{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                            "title": f"Auth reveals more data: {urlparse(endpoint).path}",
                            "category": "info_disclosure",
                            "severity": "medium",
                            "cvss": 5.3,
                            "url": endpoint,
                            "description": (
                                f"Endpoint responds to both authenticated and unauthenticated requests, "
                                f"but authenticated response is {len(auth_resp.text)} bytes vs "
                                f"{len(unauth_resp.text)} bytes unauthenticated — "
                                f"auth reveals additional data that should be protected."
                            ),
                            "evidence": {
                                "unauth_response_size": len(unauth_resp.text),
                                "auth_response_size": len(auth_resp.text),
                                "unauth_body": unauth_resp.text[:300],
                                "auth_body": auth_resp.text[:300],
                            },
                            "requires_auth": True,
                            "authenticated": True,
                        })

            except RequestException:
                continue

    def _test_idor(self, target: str) -> None:
        """
        Test for IDOR using two authenticated sessions.
        
        For each authenticated endpoint:
          1. User A accesses their own data
          2. Extract resource identifiers (IDs, UUIDs)
          3. User B attempts to access User A's resources
          4. If User B succeeds → IDOR confirmed
        """
        if not self.session_b:
            return
        
        for ep_info in self.auth_endpoints:
            endpoint = ep_info["url"]
            
            try:
                resp_a = self.session_a.get(endpoint, timeout=self.timeout, verify=False)
                if resp_a.status_code != 200:
                    continue
                
                resp_b = self.session_b.get(endpoint, timeout=self.timeout, verify=False)
                if resp_b.status_code != 200:
                    continue
                
                if resp_a.text == resp_b.text and len(resp_a.text) > 50:
                    # Could be shared/public data — check for user-specific fields
                    try:
                        data_a = resp_a.json()
                        data_b = resp_b.json()
                        
                        if data_a == data_b:
                            text = json.dumps(data_a).lower()
                            if any(k in text for k in [
                                "email", "phone", "name", "address", "account",
                                "balance", "portfolio", "transaction",
                            ]):
                                self.findings.append({
                                    "id": f"IDOR-{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                                    "title": f"IDOR: Both users see same data on {urlparse(endpoint).path}",
                                    "category": "idor",
                                    "severity": "high",
                                    "cvss": 8.6,
                                    "url": endpoint,
                                    "description": (
                                        f"User A and User B receive identical responses from {endpoint}, "
                                        f"containing what appears to be user-specific data. "
                                        f"This indicates broken access control where both users "
                                        f"access the same account's information."
                                    ),
                                    "evidence": {
                                        "user_a_email": self.account_a.get("email", "unknown"),
                                        "user_b_email": self.account_b.get("email", "unknown"),
                                        "response_identical": True,
                                        "response_sample": resp_a.text[:500],
                                    },
                                    "requires_auth": True,
                                    "authenticated": True,
                                    "steps_to_reproduce": [
                                        "Create two separate user accounts (User A and User B)",
                                        f"As User A, GET {endpoint} — note the response",
                                        f"As User B, GET {endpoint} — note the response",
                                        "Compare: both responses are identical, exposing the same user's data",
                                    ],
                                })
                    except (json.JSONDecodeError, ValueError):
                        pass
                
                ids = self._extract_resource_ids(resp_a.text)
                for id_type, id_value in ids:
                    for id_url in self._build_id_urls(endpoint, id_type, id_value):
                        try:
                            resp_b_id = self.session_b.get(
                                id_url, timeout=self.timeout, verify=False
                            )
                            if resp_b_id.status_code == 200 and len(resp_b_id.text) > 50:
                                self.findings.append({
                                    "id": f"IDOR-ID-{hashlib.md5(id_url.encode()).hexdigest()[:8]}",
                                    "title": f"IDOR via {id_type}: User B accesses User A's resource",
                                    "category": "idor",
                                    "severity": "high",
                                    "cvss": 8.6,
                                    "url": id_url,
                                    "description": (
                                        f"User B can access User A's resource by using the {id_type} "
                                        f"'{id_value}' extracted from User A's response."
                                    ),
                                    "evidence": {
                                        "resource_id_type": id_type,
                                        "resource_id_value": id_value,
                                        "access_url": id_url,
                                        "user_b_response_status": resp_b_id.status_code,
                                        "user_b_response": resp_b_id.text[:500],
                                    },
                                    "requires_auth": True,
                                    "authenticated": True,
                                    "steps_to_reproduce": [
                                        "Log in as User A",
                                        f"Access {endpoint} and extract {id_type}: {id_value}",
                                        "Log in as User B (different account)",
                                        f"Access {id_url} as User B",
                                        "Observe: User A's data is returned to User B",
                                    ],
                                })
                        except RequestException:
                            continue
                            
            except RequestException:
                continue

    def _extract_resource_ids(self, response_text: str) -> list[tuple[str, str]]:
        """Extract resource identifiers from a JSON response."""
        ids = []
        
        patterns = [
            (r'"id"\s*:\s*(\d+)', "numeric_id"),
            (r'"id"\s*:\s*"([a-f0-9-]{36})"', "uuid"),
            (r'"user_id"\s*:\s*(\d+)', "user_id"),
            (r'"userId"\s*:\s*(\d+)', "user_id"),
            (r'"account_id"\s*:\s*"?(\w+)"?', "account_id"),
            (r'"accountId"\s*:\s*"?(\w+)"?', "account_id"),
            (r'"portfolio_id"\s*:\s*"?(\w+)"?', "portfolio_id"),
            (r'"portfolioId"\s*:\s*"?(\w+)"?', "portfolio_id"),
            (r'"order_id"\s*:\s*"?(\w+)"?', "order_id"),
            (r'"orderId"\s*:\s*"?(\w+)"?', "order_id"),
            (r'"transaction_id"\s*:\s*"?(\w+)"?', "transaction_id"),
            (r'"transactionId"\s*:\s*"?(\w+)"?', "transaction_id"),
            (r'"reference"\s*:\s*"([^"]+)"', "reference"),
        ]
        
        for pattern, id_type in patterns:
            matches = re.findall(pattern, response_text)
            for match in matches[:3]:  # Limit to 3 per type
                ids.append((id_type, match))
        
        return ids

    def _build_id_urls(self, base_endpoint: str, id_type: str, id_value: str) -> list[str]:
        """Build URLs with resource IDs for IDOR testing."""
        urls = []
        
        urls.append(f"{base_endpoint.rstrip('/')}/{id_value}")
        
        urls.append(f"{base_endpoint}?id={id_value}")
        urls.append(f"{base_endpoint}?{id_type}={id_value}")
        
        return urls

    def _test_privilege_escalation(self, target: str) -> None:
        """
        Test for vertical privilege escalation.
        
        Attempts to:
          1. Access admin-only endpoints with regular user session
          2. Modify role/permissions via API
          3. Access premium features without subscription
        """
        admin_paths = [
            "/api/admin", "/api/v1/admin",
            "/api/admin/users", "/api/v1/admin/users",
            "/api/admin/dashboard", "/api/v1/admin/dashboard",
            "/api/admin/settings", "/api/v1/admin/settings",
            "/api/internal", "/api/v1/internal",
            "/api/manage", "/api/v1/manage",
            "/api/system", "/api/v1/system",
            "/api/config", "/api/v1/config",
            "/api/debug", "/api/v1/debug",
            "/api/staff", "/api/v1/staff",
            "/api/operator", "/api/v1/operator",
            "/api/backoffice", "/api/v1/backoffice",
        ]
        
        for path in admin_paths:
            url = urljoin(target, path)
            try:
                resp = self.session_a.get(url, timeout=self.timeout, verify=False)
                if resp.status_code == 200 and len(resp.text) > 50:
                    body = resp.text.lower()
                    if not any(w in body for w in ["unauthorized", "forbidden", "access denied", "not allowed"]):
                        self.findings.append({
                            "id": f"PRIV-ESC-{hashlib.md5(url.encode()).hexdigest()[:8]}",
                            "title": f"Privilege Escalation: Regular user accesses {urlparse(url).path}",
                            "category": "privilege_escalation",
                            "severity": "critical",
                            "cvss": 9.1,
                            "url": url,
                            "description": (
                                f"Regular user session can access admin/internal endpoint: {url}. "
                                f"Response status: {resp.status_code}, body length: {len(resp.text)}"
                            ),
                            "evidence": {
                                "url": url,
                                "status": resp.status_code,
                                "response_sample": resp.text[:500],
                            },
                            "requires_auth": True,
                            "authenticated": True,
                            "steps_to_reproduce": [
                                "Create a regular (non-admin) user account",
                                "Authenticate and obtain a session token",
                                f"Access {url} with the regular user session",
                                "Observe: admin/internal data is returned without admin privileges",
                            ],
                        })
            except RequestException:
                continue

    def _test_session_management(self, target: str) -> None:
        """Test session management vulnerabilities."""
        if not self.session_a:
            return
        
        for ep_info in self.auth_endpoints[:5]:
            url = ep_info["url"]
            try:
                resp = self.session_a.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
                
                location = resp.headers.get("Location", "")
                if location:
                    token_patterns = [
                        r'(?:token|session|jwt|access_token|auth)=([a-zA-Z0-9._-]{20,})',
                    ]
                    for pattern in token_patterns:
                        match = re.search(pattern, location, re.IGNORECASE)
                        if match:
                            self.findings.append({
                                "id": f"SESSION-URL-{hashlib.md5(url.encode()).hexdigest()[:8]}",
                                "title": f"Session Token in URL: {urlparse(url).path}",
                                "category": "session",
                                "severity": "medium",
                                "cvss": 5.3,
                                "url": url,
                                "description": (
                                    f"Session token appears in redirect URL from {url}. "
                                    f"Token leaked via URL can be captured in Referer headers, "
                                    f"browser history, proxy logs, and server logs."
                                ),
                                "evidence": {
                                    "url": url,
                                    "location_header": location[:200],
                                    "token_match": match.group(0)[:50],
                                },
                                "requires_auth": True,
                                "authenticated": True,
                            })
            except RequestException:
                continue

    def _test_token_handling(self, target: str) -> None:
        """
        Test JWT/token-specific vulnerabilities.
        
        Tests: algorithm confusion, token forgery, expired token acceptance.
        """
        if not self.session_a:
            return
        
        auth_header = self.session_a.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return
        
        token = auth_header.split(" ", 1)[1]
        
        parts = token.split(".")
        if len(parts) != 3:
            return  # Not a JWT
        
        import base64
        
        try:
            header_pad = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_pad))
            
            payload_pad = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_pad))
            
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return
        
        none_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        none_token = f"{none_header}.{parts[1]}."
        
        test_url = self.auth_endpoints[0]["url"] if self.auth_endpoints else urljoin(target, "/api/me")
        
        try:
            none_session = requests.Session()
            none_session.headers.update(self.session_a.headers)
            none_session.headers["Authorization"] = f"Bearer {none_token}"
            
            resp = none_session.get(test_url, timeout=self.timeout, verify=False)
            if resp.status_code == 200 and len(resp.text) > 50:
                self.findings.append({
                    "id": f"JWT-NONE-{hashlib.md5(test_url.encode()).hexdigest()[:8]}",
                    "title": "JWT Algorithm None Bypass",
                    "category": "jwt",
                    "severity": "critical",
                    "cvss": 9.8,
                    "url": test_url,
                    "description": (
                        "The application accepts JWT tokens with alg=none, allowing "
                        "complete authentication bypass by creating unsigned tokens."
                    ),
                    "evidence": {
                        "original_algorithm": header.get("alg"),
                        "forged_token": none_token[:100] + "...",
                        "response_status": resp.status_code,
                    },
                    "requires_auth": False,
                    "authenticated": False,
                    "steps_to_reproduce": [
                        "Obtain a valid JWT token",
                        "Decode the header and change 'alg' to 'none'",
                        "Remove the signature (everything after the second dot)",
                        "Re-encode and use the forged token",
                        "Observe: the application accepts the unsigned token",
                    ],
                })
        except RequestException:
            pass
        
        sensitive_fields = ["password", "secret", "ssn", "credit_card", "card_number"]
        for field in sensitive_fields:
            if field in json.dumps(payload).lower():
                self.findings.append({
                    "id": f"JWT-DATA-{hashlib.md5(field.encode()).hexdigest()[:8]}",
                    "title": f"JWT contains sensitive data: {field}",
                    "category": "info_disclosure",
                    "severity": "high",
                    "cvss": 7.5,
                    "url": target,
                    "description": (
                        f"JWT token payload contains sensitive field '{field}'. "
                        f"JWT payloads are base64-encoded (not encrypted) and "
                        f"can be read by anyone with the token."
                    ),
                    "evidence": {"jwt_payload_keys": list(payload.keys())},
                    "requires_auth": True,
                    "authenticated": True,
                })

    def _test_method_access_control(self, target: str) -> None:
        """
        Test if different HTTP methods bypass access control.
        
        Some endpoints only check auth for GET but not POST/PUT/DELETE.
        """
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
        
        for ep_info in self.auth_endpoints[:10]:
            url = ep_info["url"]
            
            for method in methods:
                try:
                    resp = self.unauthenticated.request(
                        method, url,
                        timeout=self.timeout,
                        verify=False,
                    )
                    
                    if resp.status_code in (200, 201, 204) and method not in ("OPTIONS", "HEAD"):
                        if len(resp.text) > 50:
                            self.findings.append({
                                "id": f"METHOD-BYPASS-{hashlib.md5(f'{url}{method}'.encode()).hexdigest()[:8]}",
                                "title": f"Auth Bypass via {method} method on {urlparse(url).path}",
                                "category": "broken_auth",
                                "severity": "high",
                                "cvss": 8.1,
                                "url": url,
                                "description": (
                                    f"Endpoint {url} requires auth for GET but allows "
                                    f"unauthenticated {method} requests."
                                ),
                                "evidence": {
                                    "method": method,
                                    "url": url,
                                    "response_status": resp.status_code,
                                    "response_sample": resp.text[:500],
                                },
                                "requires_auth": False,
                                "authenticated": False,
                            })
                except RequestException:
                    continue
