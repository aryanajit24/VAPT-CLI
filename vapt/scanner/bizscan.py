
from __future__ import annotations

import json
import re
import time
import uuid
import threading
import hashlib
from typing import Any
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import RequestException

from vapt.utils.helpers import sanitize_target


FINANCIAL_ENDPOINTS = [
    "/api/transfer", "/api/v1/transfer", "/api/v2/transfer",
    "/api/payment", "/api/v1/payment", "/api/pay",
    "/api/send-money", "/api/v1/send", "/api/v1/send-money",
    "/api/withdraw", "/api/v1/withdraw", "/api/v1/withdrawal",
    "/api/deposit", "/api/v1/deposit",
    "/api/transaction", "/api/v1/transaction", "/api/v1/transactions",
    "/api/invest", "/api/v1/invest", "/api/v1/portfolio/invest",
    "/api/portfolio", "/api/v1/portfolio", "/api/v1/portfolios",
    "/api/trade", "/api/v1/trade", "/api/v1/trades",
    "/api/order", "/api/v1/order", "/api/v1/orders",
    "/api/redeem", "/api/v1/redeem",
    "/api/dividend", "/api/v1/dividend", "/api/v1/dividends",
    "/api/billing", "/api/v1/billing", "/api/subscribe",
    "/api/v1/subscribe", "/api/subscription", "/api/v1/subscription",
    "/api/checkout", "/api/v1/checkout",
    "/api/invoice", "/api/v1/invoice",
    "/api/refund", "/api/v1/refund",
]

PROMO_ENDPOINTS = [
    "/api/coupon", "/api/v1/coupon", "/api/coupon/apply",
    "/api/promo", "/api/v1/promo", "/api/promo/apply",
    "/api/promotion", "/api/v1/promotion/redeem",
    "/api/referral", "/api/v1/referral", "/api/v1/refer",
    "/api/reward", "/api/v1/reward", "/api/v1/rewards/claim",
    "/api/voucher", "/api/v1/voucher/redeem",
    "/api/gift", "/api/v1/gift", "/api/v1/gift-card/redeem",
    "/api/bonus", "/api/v1/bonus",
    "/api/cashback", "/api/v1/cashback",
    "/api/discount", "/api/v1/discount/apply",
]

ACCOUNT_ENDPOINTS = [
    "/api/user", "/api/v1/user", "/api/me", "/api/v1/me",
    "/api/profile", "/api/v1/profile",
    "/api/account", "/api/v1/account",
    "/api/settings", "/api/v1/settings",
    "/api/preferences", "/api/v1/preferences",
    "/api/kyc", "/api/v1/kyc", "/api/v1/kyc/verify",
    "/api/identity", "/api/v1/identity/verify",
    "/api/link-account", "/api/v1/link", "/api/v1/connect",
]

VERIFICATION_ENDPOINTS = [
    "/api/verify", "/api/v1/verify",
    "/api/otp/verify", "/api/v1/otp/verify",
    "/api/2fa/verify", "/api/v1/2fa/verify",
    "/api/mfa/verify", "/api/v1/mfa/verify",
    "/api/email/verify", "/api/v1/email/verify",
    "/api/phone/verify", "/api/v1/phone/verify",
    "/api/confirm", "/api/v1/confirm",
    "/api/approve", "/api/v1/approve",
]


class BusinessLogicScanner:

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout: int = 15,
        safety_config: dict | None = None,
        concurrency: int = 10,
    ) -> None:
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
        self.timeout = timeout
        self.safety_config = safety_config or {}
        self.concurrency = concurrency
        self.findings: list[dict] = []
        self._discovered_endpoints: list[dict] = []

    def run(
        self,
        target: str,
        endpoints: list[str] | None = None,
        auth_session: requests.Session | None = None,
        second_auth_session: requests.Session | None = None,
    ) -> dict[str, Any]:
        target = sanitize_target(target)
        if auth_session:
            self.session = auth_session
        
        started = time.time()
        
        discovered = self._discover_endpoints(target, endpoints)
        classified = self._classify_endpoints(discovered)
        
        self._test_race_conditions(target, classified.get("financial", []))
        self._test_negative_amounts(target, classified.get("financial", []))
        self._test_amount_manipulation(target, classified.get("financial", []))
        self._test_workflow_bypass(target, classified.get("verification", []))
        self._test_promo_abuse(target, classified.get("promo", []))
        self._test_parameter_tampering(target, classified.get("account", []))
        self._test_idempotency_bypass(target, classified.get("financial", []))
        self._test_mfa_bypass(target, classified.get("verification", []))
        self._test_feature_flag_bypass(target)
        
        if second_auth_session:
            self._test_idor_cross_account(
                target, classified, auth_session or self.session, second_auth_session
            )
        
        elapsed = time.time() - started
        
        return {
            "module": "Business Logic Scanner",
            "target": target,
            "duration_sec": round(elapsed, 2),
            "endpoints_discovered": len(discovered),
            "endpoints_classified": {k: len(v) for k, v in classified.items()},
            "findings": self.findings,
        }

    def _discover_endpoints(self, target: str, known_endpoints: list[str] | None) -> list[str]:
        discovered = list(known_endpoints or [])
        
        all_candidate_paths = (
            FINANCIAL_ENDPOINTS + PROMO_ENDPOINTS +
            ACCOUNT_ENDPOINTS + VERIFICATION_ENDPOINTS
        )
        
        for path in all_candidate_paths:
            url = urljoin(target, path)
            if url in discovered:
                continue
            try:
                resp = self.session.options(url, timeout=self.timeout, allow_redirects=False, verify=False)
                if resp.status_code not in (404, 502, 503):
                    discovered.append(url)
                    self._discovered_endpoints.append({
                        "url": url,
                        "status": resp.status_code,
                        "methods": resp.headers.get("Allow", "").split(", "),
                        "content_type": resp.headers.get("Content-Type", ""),
                    })
                    continue
            except RequestException:
                pass
            
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False, verify=False)
                if resp.status_code not in (404, 502, 503):
                    discovered.append(url)
                    self._discovered_endpoints.append({
                        "url": url,
                        "status": resp.status_code,
                        "methods": ["GET"],
                        "content_type": resp.headers.get("Content-Type", ""),
                    })
            except RequestException:
                pass
        
        return discovered

    def _classify_endpoints(self, endpoints: list[str]) -> dict[str, list[str]]:
        classified: dict[str, list[str]] = {
            "financial": [],
            "promo": [],
            "account": [],
            "verification": [],
            "admin": [],
            "other": [],
        }
        
        financial_re = re.compile(
            r"(?i)(?:payment|transfer|withdraw|deposit|invest|portfolio|trade|order|"
            r"redeem|billing|subscribe|checkout|invoice|refund|fund|balance|wallet|transaction)"
        )
        promo_re = re.compile(
            r"(?i)(?:coupon|promo|referral|reward|voucher|gift|bonus|cashback|discount)"
        )
        account_re = re.compile(
            r"(?i)(?:user|profile|account|settings|preferences|kyc|identity|link|connect|me$)"
        )
        verification_re = re.compile(
            r"(?i)(?:verify|otp|2fa|mfa|confirm|approve|email.*verify|phone.*verify)"
        )
        admin_re = re.compile(
            r"(?i)(?:admin|manage|internal|dashboard|control|system|config|debug)"
        )
        
        for ep in endpoints:
            path = urlparse(ep).path.lower()
            if financial_re.search(path):
                classified["financial"].append(ep)
            elif promo_re.search(path):
                classified["promo"].append(ep)
            elif verification_re.search(path):
                classified["verification"].append(ep)
            elif admin_re.search(path):
                classified["admin"].append(ep)
            elif account_re.search(path):
                classified["account"].append(ep)
            else:
                classified["other"].append(ep)
        
        return classified

    def _test_race_conditions(self, target: str, financial_endpoints: list[str]) -> None:
        if not financial_endpoints:
            return
        
        for endpoint in financial_endpoints[:5]:
            for method in ["POST", "PUT", "PATCH"]:
                test_body = {
                    "amount": 1,
                    "currency": "USD",
                    "reference": f"race-test-{uuid.uuid4().hex[:8]}",
                }
                
                barrier = threading.Barrier(self.concurrency)
                results = []
                errors = []
                
                def send_request(idx: int) -> dict | None:
                    try:
                        barrier.wait(timeout=5)
                        resp = self.session.request(
                            method, endpoint,
                            json=test_body,
                            timeout=self.timeout,
                            verify=False,
                        )
                        return {
                            "status": resp.status_code,
                            "body": resp.text[:500],
                            "headers": dict(resp.headers),
                            "time": time.time(),
                        }
                    except Exception as e:
                        errors.append(str(e))
                        return None
                
                with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                    futures = [pool.submit(send_request, i) for i in range(self.concurrency)]
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            results.append(result)
                
                if results:
                    success_count = sum(1 for r in results if r["status"] in (200, 201, 202))
                    if success_count > 1:
                        self.findings.append({
                            "id": f"BIZ-001-{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                            "title": f"Race Condition: {success_count} concurrent successes on {urlparse(endpoint).path}",
                            "category": "race_condition",
                            "severity": "high",
                            "cvss": 8.1,
                            "url": endpoint,
                            "description": (
                                f"Sent {self.concurrency} concurrent {method} requests to {endpoint}. "
                                f"{success_count} returned success (2xx), indicating a potential race condition. "
                                f"This could allow double-spend, duplicate transactions, or resource exhaustion."
                            ),
                            "evidence": {
                                "concurrent_requests": self.concurrency,
                                "success_responses": success_count,
                                "method": method,
                                "sample_responses": results[:3],
                            },
                            "impact": (
                                "An attacker could exploit this race condition to perform duplicate "
                                "financial operations, potentially leading to double-spending, "
                                "unauthorized fund transfers, or balance manipulation."
                            ),
                            "remediation": (
                                "Implement idempotency keys, database-level locks, or atomic "
                                "transactions to prevent concurrent duplicate operations."
                            ),
                            "requires_auth": True,
                            "authenticated": True,
                            "steps_to_reproduce": [
                                f"Authenticate to the application and obtain a valid session",
                                f"Prepare a {method} request to {endpoint} with a transaction payload",
                                f"Send {self.concurrency} identical requests simultaneously using a thread barrier",
                                f"Observe that {success_count} requests succeed instead of just 1",
                                f"Verify the duplicate transactions/credits in the account",
                            ],
                        })

    def _test_negative_amounts(self, target: str, financial_endpoints: list[str]) -> None:
        if not financial_endpoints:
            return
        
        negative_payloads = [
            {"amount": -1},
            {"amount": -100},
            {"amount": -0.01},
            {"amount": "-1"},
            {"amount": -999999},
            {"value": -1},
            {"total": -1},
            {"quantity": -1},
            {"units": -1},
        ]
        
        for endpoint in financial_endpoints[:5]:
            for payload in negative_payloads:
                try:
                    resp = self.session.post(
                        endpoint,
                        json=payload,
                        timeout=self.timeout,
                        verify=False,
                    )
                    
                    if resp.status_code in (200, 201, 202):
                        body = resp.text.lower()
                        if not any(w in body for w in ["invalid", "error", "negative", "must be positive", "validation"]):
                            self.findings.append({
                                "id": f"BIZ-002-{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                                "title": f"Negative Amount Accepted on {urlparse(endpoint).path}",
                                "category": "business_logic",
                                "severity": "critical",
                                "cvss": 9.1,
                                "url": endpoint,
                                "description": (
                                    f"The endpoint {endpoint} accepts negative amounts in the request body. "
                                    f"Payload: {json.dumps(payload)}. Response status: {resp.status_code}. "
                                    f"This could allow an attacker to reverse the direction of financial "
                                    f"operations (e.g., transfer -$100 = receive $100)."
                                ),
                                "evidence": {
                                    "request_payload": payload,
                                    "response_status": resp.status_code,
                                    "response_body": resp.text[:500],
                                },
                                "impact": (
                                    "An attacker could manipulate financial operations by sending negative "
                                    "amounts, potentially stealing funds, gaining unauthorized credits, "
                                    "or causing financial loss to other users."
                                ),
                                "remediation": "Validate all amount fields are positive. Reject negative values server-side.",
                                "requires_auth": True,
                                "authenticated": True,
                                "steps_to_reproduce": [
                                    "Authenticate and obtain a valid session",
                                    f"Send POST to {endpoint} with payload: {json.dumps(payload)}",
                                    f"Observe the response accepts the negative amount (HTTP {resp.status_code})",
                                    "Verify the account balance changed in the reverse direction",
                                ],
                            })
                            break
                except RequestException:
                    continue

    def _test_amount_manipulation(self, target: str, financial_endpoints: list[str]) -> None:
        if not financial_endpoints:
            return
        
        manipulation_payloads = [
            {"amount": 0},
            {"amount": 0.001},
            {"amount": 0.00001},
            {"amount": 99999999999},
            {"amount": 2147483647},
            {"amount": 9999999999999999},
            {"amount": "NaN"},
            {"amount": "Infinity"},
            {"amount": "1e10"},
            {"amount": "0x64"},
            {"amount": "100.000000000000001"},
            {"amount": "0.000000000000001"},
            {"amount": 1, "currency": "XXX"},
            {"amount": 1, "currency": ""},
            {"amount": 1, "currency": None},
        ]
        
        for endpoint in financial_endpoints[:3]:
            for payload in manipulation_payloads:
                try:
                    resp = self.session.post(
                        endpoint,
                        json=payload,
                        timeout=self.timeout,
                        verify=False,
                    )
                    
                    if resp.status_code in (200, 201, 202):
                        body = resp.text.lower()
                        if not any(w in body for w in ["invalid", "error", "validation", "unprocessable"]):
                            amount_str = str(payload.get("amount", ""))
                            if amount_str in ("0", "NaN", "Infinity", "1e10", "0x64") or \
                               (isinstance(payload.get("amount"), (int, float)) and 
                                (payload["amount"] > 2147483647 or payload["amount"] < 0.001)):
                                self.findings.append({
                                    "id": f"BIZ-003-{hashlib.md5(f'{endpoint}{amount_str}'.encode()).hexdigest()[:8]}",
                                    "title": f"Amount Manipulation: Unusual value accepted on {urlparse(endpoint).path}",
                                    "category": "business_logic",
                                    "severity": "high",
                                    "cvss": 7.5,
                                    "url": endpoint,
                                    "description": (
                                        f"The endpoint accepts unusual amount values that may cause "
                                        f"financial calculation errors. Payload: {json.dumps(payload)}. "
                                        f"This could lead to rounding exploitation, overflow behavior, "
                                        f"or currency manipulation."
                                    ),
                                    "evidence": {
                                        "request_payload": payload,
                                        "response_status": resp.status_code,
                                        "response_body": resp.text[:500],
                                    },
                                    "impact": "Financial calculation errors, rounding exploitation, or currency manipulation.",
                                    "remediation": "Validate amounts strictly: positive, within bounds, correct precision, valid currency.",
                                    "requires_auth": True,
                                    "authenticated": True,
                                })
                                break
                except RequestException:
                    continue

    def _test_workflow_bypass(self, target: str, verification_endpoints: list[str]) -> None:
        if not verification_endpoints:
            return
        
        post_verify_paths = [
            "/api/dashboard", "/api/v1/dashboard",
            "/api/portfolio", "/api/v1/portfolio",
            "/api/invest", "/api/v1/invest",
            "/api/transfer", "/api/v1/transfer",
            "/api/withdraw", "/api/v1/withdraw",
            "/api/account/full", "/api/v1/account/details",
            "/api/settings/sensitive", "/api/v1/settings/security",
            "/api/export", "/api/v1/export",
        ]
        
        for path in post_verify_paths:
            url = urljoin(target, path)
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                if resp.status_code in (200, 201) and len(resp.text) > 50:
                    body = resp.text.lower()
                    if not any(w in body for w in [
                        "verify", "verification required", "complete kyc",
                        "not verified", "pending verification",
                    ]):
                        self._discovered_endpoints.append({
                            "url": url,
                            "status": resp.status_code,
                            "note": "Accessible — may bypass verification",
                        })
            except RequestException:
                continue

    def _test_promo_abuse(self, target: str, promo_endpoints: list[str]) -> None:
        if not promo_endpoints:
            return
        
        test_codes = [
            "WELCOME", "FIRST", "FREE", "DISCOUNT", "TEST",
            "PROMO", "SAVE10", "VIP", "NEW", "SIGNUP",
            "REFERRAL", "BONUS", "CASHBACK",
        ]
        
        for endpoint in promo_endpoints[:3]:
            for code in test_codes[:3]:
                responses = []
                for attempt in range(3):
                    try:
                        resp = self.session.post(
                            endpoint,
                            json={"code": code, "coupon": code, "promo": code},
                            timeout=self.timeout,
                            verify=False,
                        )
                        responses.append({
                            "attempt": attempt + 1,
                            "status": resp.status_code,
                            "body": resp.text[:200],
                        })
                    except RequestException:
                        break
                
                successes = [r for r in responses if r["status"] in (200, 201)]
                if len(successes) > 1:
                    self.findings.append({
                        "id": f"BIZ-005-{hashlib.md5(f'{endpoint}{code}'.encode()).hexdigest()[:8]}",
                        "title": f"Promo Code Reuse: '{code}' accepted {len(successes)} times",
                        "category": "business_logic",
                        "severity": "medium",
                        "cvss": 6.5,
                        "url": endpoint,
                        "description": (
                            f"The promo code '{code}' was accepted {len(successes)} times on {endpoint}. "
                            f"This allows unlimited reuse of promotional codes."
                        ),
                        "evidence": {"responses": responses},
                        "impact": "Financial loss through unlimited promotional code reuse.",
                        "remediation": "Implement one-time-use validation for promotional codes.",
                        "requires_auth": True,
                        "authenticated": True,
                    })
                    break

    def _test_parameter_tampering(self, target: str, account_endpoints: list[str]) -> None:
        if not account_endpoints:
            return
        
        escalation_params = [
            {"role": "admin"},
            {"is_admin": True},
            {"isAdmin": True},
            {"admin": True},
            {"role_id": 1},
            {"user_type": "admin"},
            {"userType": "admin"},
            {"permissions": ["admin", "write", "delete"]},
            {"level": "premium"},
            {"tier": "enterprise"},
            {"verified": True},
            {"is_verified": True},
            {"kyc_status": "approved"},
            {"kycStatus": "verified"},
            {"email_verified": True},
            {"account_type": "premium"},
        ]
        
        for endpoint in account_endpoints[:5]:
            for params in escalation_params:
                for method in ["PUT", "PATCH", "POST"]:
                    try:
                        resp = self.session.request(
                            method, endpoint,
                            json=params,
                            timeout=self.timeout,
                            verify=False,
                        )
                        
                        if resp.status_code in (200, 201, 204):
                            body = resp.text.lower()
                            param_key = list(params.keys())[0]
                            param_val = str(list(params.values())[0]).lower()
                            if param_val in body or param_key.lower() in body:
                                try:
                                    verify_resp = self.session.get(endpoint, timeout=self.timeout, verify=False)
                                    if param_val in verify_resp.text.lower():
                                        self.findings.append({
                                            "id": f"BIZ-006-{hashlib.md5(f'{endpoint}{param_key}'.encode()).hexdigest()[:8]}",
                                            "title": f"Mass Assignment: '{param_key}' accepted on {urlparse(endpoint).path}",
                                            "category": "privilege_escalation",
                                            "severity": "critical",
                                            "cvss": 9.1,
                                            "url": endpoint,
                                            "description": (
                                                f"The endpoint {endpoint} accepts the parameter '{param_key}' "
                                                f"via {method} request, allowing privilege escalation. "
                                                f"The value '{param_val}' was persisted."
                                            ),
                                            "evidence": {
                                                "request_method": method,
                                                "request_payload": params,
                                                "response_status": resp.status_code,
                                                "response_body": resp.text[:500],
                                                "verify_response": verify_resp.text[:500],
                                            },
                                            "impact": (
                                                "Attacker can escalate privileges to admin/premium by "
                                                "injecting role parameters in profile update requests."
                                            ),
                                            "remediation": "Whitelist allowed fields. Never accept role/permission params from client.",
                                            "requires_auth": True,
                                            "authenticated": True,
                                            "steps_to_reproduce": [
                                                "Authenticate as a regular user",
                                                f"Send {method} to {endpoint} with payload: {json.dumps(params)}",
                                                "Observe the privileged parameter is accepted",
                                                "Verify the change persisted by fetching the profile",
                                            ],
                                        })
                                except RequestException:
                                    pass
                    except RequestException:
                        continue

    def _test_idempotency_bypass(self, target: str, financial_endpoints: list[str]) -> None:
        if not financial_endpoints:
            return
        
        idempotency_headers = [
            "Idempotency-Key",
            "X-Idempotency-Key",
            "X-Request-Id",
            "X-Idempotent-Key",
        ]
        
        for endpoint in financial_endpoints[:3]:
            test_body = {
                "amount": 0.01,
                "reference": f"idemp-test-{uuid.uuid4().hex[:8]}",
            }
            
            responses = []
            for i in range(5):
                try:
                    resp = self.session.post(
                        endpoint,
                        json=test_body,
                        timeout=self.timeout,
                        verify=False,
                    )
                    responses.append({
                        "attempt": i + 1,
                        "status": resp.status_code,
                        "body": resp.text[:300],
                    })
                except RequestException:
                    break
            
            successes = [r for r in responses if r["status"] in (200, 201, 202)]
            if len(successes) > 1:
                self.findings.append({
                    "id": f"BIZ-014-{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                    "title": f"Idempotency Bypass: Replay attack on {urlparse(endpoint).path}",
                    "category": "business_logic",
                    "severity": "high",
                    "cvss": 8.1,
                    "url": endpoint,
                    "description": (
                        f"The same POST request to {endpoint} was processed {len(successes)} times. "
                        f"The endpoint lacks idempotency protection, allowing replay attacks."
                    ),
                    "evidence": {
                        "replay_count": len(successes),
                        "responses": responses,
                    },
                    "impact": "Duplicate financial operations via request replay.",
                    "remediation": "Implement idempotency keys. Reject duplicate requests.",
                    "requires_auth": True,
                    "authenticated": True,
                })

    def _test_mfa_bypass(self, target: str, verification_endpoints: list[str]) -> None:
        if not verification_endpoints:
            return
        
        mfa_endpoints = [ep for ep in verification_endpoints if any(
            k in ep.lower() for k in ("otp", "2fa", "mfa", "verify")
        )]
        
        bypass_payloads = [
            {"otp": "", "code": ""},
            {"otp": None, "code": None},
            {"otp": "000000"},
            {"otp": "111111"},
            {"otp": "123456"},
            {"otp": "999999"},
            {"otp": 0},
            {"otp": True},
            {"otp": []},
            {"otp": {}},
            {"verified": True, "otp_verified": True},
            {"skip_2fa": True},
            {"bypass": True},
        ]
        
        for endpoint in mfa_endpoints[:3]:
            for payload in bypass_payloads:
                try:
                    resp = self.session.post(
                        endpoint,
                        json=payload,
                        timeout=self.timeout,
                        verify=False,
                    )
                    
                    if resp.status_code in (200, 201):
                        body = resp.text.lower()
                        if any(w in body for w in ["success", "verified", "token", "session", "access_token"]):
                            self.findings.append({
                                "id": f"BIZ-007-{hashlib.md5(f'{endpoint}{json.dumps(payload)}'.encode()).hexdigest()[:8]}",
                                "title": f"MFA Bypass: {urlparse(endpoint).path} accepts {json.dumps(payload)}",
                                "category": "mfa_bypass",
                                "severity": "critical",
                                "cvss": 9.8,
                                "url": endpoint,
                                "description": (
                                    f"The MFA/OTP verification at {endpoint} was bypassed with payload: "
                                    f"{json.dumps(payload)}. This allows complete authentication bypass."
                                ),
                                "evidence": {
                                    "request_payload": payload,
                                    "response_status": resp.status_code,
                                    "response_body": resp.text[:500],
                                },
                                "impact": "Complete authentication bypass. Attacker can access any account without 2FA.",
                                "remediation": "Never accept empty/null/special OTP values. Rate-limit OTP attempts.",
                                "requires_auth": True,
                                "authenticated": True,
                                "steps_to_reproduce": [
                                    "Initiate MFA/2FA verification flow",
                                    f"Send POST to {endpoint} with payload: {json.dumps(payload)}",
                                    "Observe successful verification response",
                                    "Access protected resources without valid OTP",
                                ],
                            })
                            break
                except RequestException:
                    continue

    def _test_feature_flag_bypass(self, target: str) -> None:
        feature_headers = [
            {"X-Feature-Flag": "premium"},
            {"X-Feature-Flag": "beta"},
            {"X-Feature-Flag": "internal"},
            {"X-Feature": "admin"},
            {"X-Internal": "true"},
            {"X-Beta": "true"},
            {"X-Debug": "true"},
            {"X-Premium": "true"},
            {"X-Test": "true"},
        ]
        
        feature_params = [
            "?feature=premium", "?beta=true", "?internal=true",
            "?debug=true", "?admin=true", "?dev=true",
            "?feature_flag=enable_all",
        ]
        
        feature_paths = [
            "/api/v1/features", "/api/features", "/api/v1/feature-flags",
            "/api/internal", "/api/v1/internal",
            "/api/beta", "/api/v1/beta",
            "/api/premium", "/api/v1/premium",
            "/api/debug", "/api/v1/debug",
        ]
        
        for path in feature_paths:
            url = urljoin(target, path)
            
            for headers in feature_headers:
                try:
                    resp = self.session.get(
                        url, headers=headers,
                        timeout=self.timeout, verify=False,
                    )
                    if resp.status_code in (200, 201) and len(resp.text) > 50:
                        body = resp.text.lower()
                        if any(w in body for w in [
                            "feature", "flag", "enabled", "premium", "beta",
                            "internal", "config", "setting",
                        ]):
                            self.findings.append({
                                "id": f"BIZ-015-{hashlib.md5(f'{url}{json.dumps(headers)}'.encode()).hexdigest()[:8]}",
                                "title": f"Feature Flag Bypass via {list(headers.keys())[0]} header",
                                "category": "business_logic",
                                "severity": "medium",
                                "cvss": 6.5,
                                "url": url,
                                "description": (
                                    f"Access to feature flag configuration at {url} via header manipulation. "
                                    f"Headers: {json.dumps(headers)}"
                                ),
                                "evidence": {
                                    "url": url,
                                    "headers": headers,
                                    "response_status": resp.status_code,
                                    "response_body": resp.text[:500],
                                },
                                "impact": "Access premium/internal features, bypass feature gating.",
                                "remediation": "Validate feature flags server-side. Don't accept client-side overrides.",
                                "requires_auth": False,
                                "authenticated": False,
                            })
                            break
                except RequestException:
                    continue

    def _test_idor_cross_account(
        self,
        target: str,
        classified: dict[str, list[str]],
        session_a: requests.Session,
        session_b: requests.Session,
    ) -> None:
        all_eps = []
        for category, eps in classified.items():
            if category != "other":
                all_eps.extend(eps)
        
        for endpoint in all_eps[:10]:
            try:
                resp_a = session_a.get(endpoint, timeout=self.timeout, verify=False)
                if resp_a.status_code != 200:
                    continue
                
                body_a = resp_a.text
                ids_found = set()
                
                for pattern in [
                    r'"id"\s*:\s*"?(\d+)"?',
                    r'"user_id"\s*:\s*"?(\d+)"?',
                    r'"account_id"\s*:\s*"?(\d+)"?',
                    r'"uuid"\s*:\s*"([a-f0-9-]{36})"',
                    r'"reference"\s*:\s*"([^"]+)"',
                ]:
                    ids_found.update(re.findall(pattern, body_a))
                
                if not ids_found:
                    continue
                
                for resource_id in list(ids_found)[:3]:
                    id_url = f"{endpoint.rstrip('/')}/{resource_id}"
                    try:
                        resp_b = session_b.get(id_url, timeout=self.timeout, verify=False)
                        if resp_b.status_code == 200 and len(resp_b.text) > 50:
                            if resp_b.text == body_a or resource_id in resp_b.text:
                                self.findings.append({
                                    "id": f"BIZ-IDOR-{hashlib.md5(f'{endpoint}{resource_id}'.encode()).hexdigest()[:8]}",
                                    "title": f"IDOR: User B accesses User A's resource on {urlparse(endpoint).path}/{resource_id}",
                                    "category": "idor",
                                    "severity": "high",
                                    "cvss": 8.6,
                                    "url": id_url,
                                    "description": (
                                        f"User B can access User A's resource at {id_url}. "
                                        f"Resource ID: {resource_id}. This is a horizontal "
                                        f"privilege escalation via IDOR."
                                    ),
                                    "evidence": {
                                        "user_a_endpoint": endpoint,
                                        "user_a_resource_id": resource_id,
                                        "user_b_access_url": id_url,
                                        "user_b_response_status": resp_b.status_code,
                                        "user_b_response": resp_b.text[:500],
                                    },
                                    "impact": "Unauthorized access to other users' data.",
                                    "remediation": "Implement proper authorization checks per resource.",
                                    "requires_auth": True,
                                    "authenticated": True,
                                    "steps_to_reproduce": [
                                        "Authenticate as User A and note their resource IDs",
                                        "Authenticate as User B in a separate session",
                                        f"As User B, request GET {id_url}",
                                        "Observe User A's data is returned",
                                    ],
                                })
                    except RequestException:
                        continue
            except RequestException:
                continue
