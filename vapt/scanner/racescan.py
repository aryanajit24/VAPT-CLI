
from __future__ import annotations

import time
import json
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from vapt.utils.helpers import sanitize_target


RACE_ENDPOINTS = {
    "double_spend": [
        "/api/coupon/apply", "/api/coupon/redeem", "/api/promo/apply",
        "/api/discount/apply", "/api/voucher/redeem", "/coupon",
        "/promo", "/redeem", "/apply-coupon", "/gift-card/apply",
        "/api/reward/claim", "/api/points/redeem",
    ],
    "financial": [
        "/api/transfer", "/api/withdraw", "/api/send",
        "/api/payment", "/api/purchase", "/api/checkout",
        "/api/wallet/transfer", "/api/balance/transfer",
        "/api/transaction", "/api/order/create",
        "/pay", "/checkout", "/transfer", "/send-money",
    ],
    "social": [
        "/api/follow", "/api/like", "/api/vote",
        "/api/upvote", "/api/downvote", "/api/rate",
        "/api/review", "/api/comment", "/api/share",
        "/api/subscribe", "/api/bookmark",
    ],
    "auth": [
        "/api/register", "/api/signup", "/register", "/signup",
        "/api/invite/accept", "/invite/accept",
        "/api/password/reset", "/password/reset",
        "/api/verify/email", "/api/activate",
        "/api/token/refresh",
    ],
    "resource": [
        "/api/upload", "/upload", "/api/file/upload",
        "/api/create", "/api/new", "/api/add",
        "/api/claim", "/claim",
    ],
    "rate_limited": [
        "/api/login", "/login", "/api/auth",
        "/api/otp/send", "/api/otp/verify",
        "/api/sms/send", "/api/email/send",
        "/api/password/reset",
    ],
}


class RaceScanner:

    def __init__(
        self,
        session: requests.Session | None = None,
        concurrent_threads: int = 20,
        timeout: int = 10,
    ) -> None:
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", "VAPT-CLI/4.0 RaceCondition-Scanner")
        self.timeout = timeout
        self.threads = concurrent_threads
        self.findings: list[dict] = []

    def run(self, target: str) -> dict[str, Any]:
        target = sanitize_target(target)
        if not target.startswith("http"):
            target = f"https://{target}"

        endpoints = self._discover_endpoints(target)

        self._test_double_spend(target, endpoints)
        self._test_rate_limit_bypass(target, endpoints)
        self._test_duplicate_creation(target, endpoints)
        self._test_session_race(target)

        return {"findings": self.findings}


    def _discover_endpoints(self, target: str) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}

        for category, paths in RACE_ENDPOINTS.items():
            category_hits: list[str] = []
            for path in paths:
                url = urljoin(target, path)
                try:
                    resp = self.session.options(url, timeout=self.timeout)
                    if resp.status_code < 500:
                        category_hits.append(url)
                        continue
                except Exception:
                    pass

                try:
                    resp = self.session.head(url, timeout=self.timeout)
                    if resp.status_code < 500 and resp.status_code != 404:
                        category_hits.append(url)
                except Exception:
                    pass

            if category_hits:
                found[category] = category_hits

        return found


    def _send_concurrent(
        self,
        url: str,
        method: str = "POST",
        data: dict | None = None,
        json_data: dict | None = None,
        headers: dict | None = None,
        count: int = 20,
    ) -> list[dict]:
        results: list[dict] = []
        lock = threading.Lock()
        barrier = threading.Barrier(min(count, self.threads))

        def _single_request(idx: int) -> dict:
            try:
                barrier.wait(timeout=5)
            except threading.BrokenBarrierError:
                pass

            try:
                start_time = time.time()
                if method.upper() == "POST":
                    if json_data:
                        resp = self.session.post(
                            url, json=json_data, headers=headers,
                            timeout=self.timeout,
                        )
                    else:
                        resp = self.session.post(
                            url, data=data, headers=headers,
                            timeout=self.timeout,
                        )
                else:
                    resp = self.session.get(
                        url, headers=headers, timeout=self.timeout,
                    )

                elapsed = time.time() - start_time

                return {
                    "idx": idx,
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "elapsed": elapsed,
                    "body": resp.text[:1000],
                    "headers": dict(resp.headers),
                }
            except Exception as e:
                return {
                    "idx": idx,
                    "status": 0,
                    "length": 0,
                    "elapsed": 0,
                    "body": str(e),
                    "headers": {},
                    "error": True,
                }

        with ThreadPoolExecutor(max_workers=min(count, self.threads)) as pool:
            futures = [pool.submit(_single_request, i) for i in range(count)]
            for f in as_completed(futures):
                result = f.result()
                with lock:
                    results.append(result)

        results.sort(key=lambda r: r["idx"])
        return results


    def _analyze_responses(self, results: list[dict]) -> dict[str, Any]:
        valid_results = [r for r in results if not r.get("error")]
        if not valid_results:
            return {"vulnerable": False, "reason": "All requests failed"}

        statuses = [r["status"] for r in valid_results]
        lengths = [r["length"] for r in valid_results]
        success_count = sum(1 for s in statuses if 200 <= s < 300)
        unique_statuses = set(statuses)
        unique_lengths = len(set(lengths))

        analysis = {
            "total": len(valid_results),
            "success_count": success_count,
            "unique_statuses": unique_statuses,
            "unique_response_sizes": unique_lengths,
            "status_distribution": {},
            "vulnerable": False,
            "indicators": [],
        }

        for s in statuses:
            analysis["status_distribution"][s] = analysis["status_distribution"].get(s, 0) + 1

        if success_count > 1:
            analysis["indicators"].append(f"{success_count} successful responses (expected 1)")

        if success_count == len(valid_results):
            analysis["indicators"].append("All requests succeeded — no concurrency protection")

        if len(unique_statuses) > 1 and success_count > 0:
            analysis["indicators"].append(f"Mixed status codes: {unique_statuses}")

        if unique_lengths > 2 and len(valid_results) > 5:
            analysis["indicators"].append(f"{unique_lengths} different response sizes — state changing")

        analysis["vulnerable"] = len(analysis["indicators"]) >= 1 and success_count > 1

        return analysis


    def _test_double_spend(self, target: str, endpoints: dict[str, list[str]]) -> None:
        test_urls = endpoints.get("double_spend", []) + endpoints.get("financial", [])

        for url in test_urls[:10]:
            test_payloads = [
                {"coupon": "TEST123", "code": "TEST123"},
                {"amount": "1", "recipient": "test@test.com"},
            ]

            for payload in test_payloads:
                results = self._send_concurrent(
                    url,
                    method="POST",
                    json_data=payload,
                    count=15,
                )

                analysis = self._analyze_responses(results)

                if analysis["vulnerable"]:
                    success_results = [r for r in results if 200 <= r["status"] < 300]
                    evidence_parts = [
                        f"Endpoint: {url}",
                        f"Concurrent requests: {len(results)}",
                        f"Successful: {analysis['success_count']}",
                        f"Status distribution: {analysis['status_distribution']}",
                        f"Indicators: {', '.join(analysis['indicators'])}",
                        "",
                        "Sample responses:",
                    ]
                    for r in success_results[:3]:
                        evidence_parts.append(f"  Response {r['idx']}: {r['status']} ({r['length']} bytes, {r['elapsed']:.3f}s)")
                        evidence_parts.append(f"  Body: {r['body'][:200]}")

                    self._add_finding(
                        vuln_id="RACE-001",
                        title=f"Double-Spend Race Condition on {urlparse(url).path}",
                        severity="Critical",
                        cvss=9.0,
                        url=url,
                        category="race_condition",
                        evidence="\n".join(evidence_parts),
                        payload=json.dumps(payload),
                        remediation="Implement database-level locking (SELECT FOR UPDATE). Use idempotency keys. Apply optimistic concurrency control with version checks.",
                        confidence=0.85,
                        poc=self._generate_race_poc(url, "POST", payload, analysis),
                    )


    def _test_rate_limit_bypass(self, target: str, endpoints: dict[str, list[str]]) -> None:
        test_urls = endpoints.get("rate_limited", []) + endpoints.get("auth", [])

        for url in test_urls[:5]:
            results = self._send_concurrent(
                url,
                method="POST",
                json_data={"username": "admin", "password": "test123"},
                count=30,
            )

            valid = [r for r in results if not r.get("error")]
            non_429 = [r for r in valid if r["status"] != 429]
            is_429 = [r for r in valid if r["status"] == 429]

            if is_429 and non_429 and len(non_429) > len(is_429):
                evidence = (
                    f"Endpoint: {url}\n"
                    f"Total requests: {len(valid)}\n"
                    f"Rate limited (429): {len(is_429)}\n"
                    f"Bypassed: {len(non_429)}\n"
                    f"Bypass rate: {len(non_429)/len(valid)*100:.1f}%\n"
                    f"\nSample bypassed responses:\n"
                )
                for r in non_429[:3]:
                    evidence += f"  #{r['idx']}: {r['status']} ({r['elapsed']:.3f}s)\n"

                self._add_finding(
                    vuln_id="RACE-003",
                    title=f"Rate Limit Bypass via Concurrency on {urlparse(url).path}",
                    severity="High",
                    cvss=7.5,
                    url=url,
                    category="race_condition",
                    evidence=evidence,
                    payload=f"Send {len(valid)} concurrent POST requests to {url}",
                    remediation="Implement atomic rate limiting (Redis INCR with TTL). Check rate limits before processing, not after. Use sliding window counters.",
                    confidence=0.85,
                    poc=f"1. Use curl or Python to send {len(valid)} simultaneous POST requests\n"
                        f"2. {len(non_429)} requests bypass rate limiting\n"
                        f"3. This allows brute-force attacks on login/OTP endpoints\n"
                        f"4. PoC command: for i in $(seq 1 30); do curl -X POST {url} -d 'user=admin&pass=test' & done; wait",
                )

            elif not is_429 and len(non_429) > 20:
                success = [r for r in non_429 if 200 <= r["status"] < 300]
                if len(success) == len(non_429):
                    self._add_finding(
                        vuln_id="RACE-003",
                        title=f"No Rate Limiting on {urlparse(url).path}",
                        severity="High",
                        cvss=7.0,
                        url=url,
                        category="race_condition",
                        evidence=f"Sent {len(valid)} concurrent requests — zero rate limited.\nAll returned 2xx status.",
                        payload=f"30 concurrent POST requests to {url}",
                        remediation="Implement rate limiting on authentication endpoints. Use Redis or token bucket algorithm. Apply per-IP and per-account limits.",
                        confidence=0.90,
                        poc=f"1. Send 30 concurrent requests to {url}\n2. All succeed with no 429 response\n3. Allows unlimited brute-force attempts",
                    )


    def _test_duplicate_creation(self, target: str, endpoints: dict[str, list[str]]) -> None:
        test_urls = endpoints.get("resource", []) + endpoints.get("social", [])

        for url in test_urls[:5]:
            unique_value = f"racetest_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
            payload = {
                "name": unique_value,
                "title": unique_value,
                "value": unique_value,
            }

            results = self._send_concurrent(
                url,
                method="POST",
                json_data=payload,
                count=10,
            )

            analysis = self._analyze_responses(results)
            success_results = [r for r in results if 200 <= r.get("status", 0) < 300 and not r.get("error")]

            if len(success_results) > 1:
                bodies = [r["body"] for r in success_results]
                unique_bodies = set(bodies)

                if len(unique_bodies) > 1 or len(success_results) > 1:
                    self._add_finding(
                        vuln_id="RACE-004",
                        title=f"Duplicate Object Creation on {urlparse(url).path}",
                        severity="Medium",
                        cvss=6.5,
                        url=url,
                        category="race_condition",
                        evidence=f"Endpoint: {url}\nPayload: {unique_value}\n"
                                 f"Success responses: {len(success_results)}\n"
                                 f"Unique response bodies: {len(unique_bodies)}\n"
                                 f"Indicates duplicate resource creation possible.",
                        payload=json.dumps(payload),
                        remediation="Use database UNIQUE constraints. Implement application-level deduplication. Use INSERT ... ON CONFLICT for upserts.",
                        confidence=0.70,
                        poc=f"1. Send 10 concurrent POST to {url} with identical data\n"
                            f"2. {len(success_results)} requests succeed\n"
                            f"3. Multiple identical resources created\n"
                            f"4. Can be exploited for fraud/abuse",
                    )


    def _test_session_race(self, target: str) -> None:
        login_urls = [
            urljoin(target, p)
            for p in ["/login", "/api/login", "/api/auth/login", "/auth/login"]
        ]

        for url in login_urls:
            try:
                resp = self.session.head(url, timeout=self.timeout)
                if resp.status_code in (404, 500):
                    continue
            except Exception:
                continue

            results = self._send_concurrent(
                url,
                method="POST",
                json_data={"username": "test", "password": "test"},
                count=10,
            )

            valid = [r for r in results if not r.get("error")]
            
            cookies_seen = set()
            tokens_seen = set()
            
            for r in valid:
                if "set-cookie" in r.get("headers", {}):
                    cookies_seen.add(r["headers"]["set-cookie"][:50])
                try:
                    body = json.loads(r["body"])
                    if isinstance(body, dict):
                        for key in ("token", "access_token", "jwt", "session_id"):
                            if key in body:
                                tokens_seen.add(str(body[key])[:20])
                except (json.JSONDecodeError, ValueError):
                    pass

            if len(tokens_seen) > 1 or len(cookies_seen) > 1:
                self._add_finding(
                    vuln_id="RACE-005",
                    title="Session Race Condition — Multiple Tokens Issued",
                    severity="High",
                    cvss=7.5,
                    url=url,
                    category="race_condition",
                    evidence=f"Endpoint: {url}\n"
                             f"Concurrent auth requests: {len(valid)}\n"
                             f"Unique session tokens: {len(tokens_seen)}\n"
                             f"Unique cookies: {len(cookies_seen)}\n"
                             f"Multiple simultaneous sessions may lead to session fixation.",
                    payload="10 concurrent POST login requests",
                    remediation="Invalidate existing sessions before creating new ones. Use database-level locking for session creation. Implement session binding.",
                    confidence=0.75,
                    poc=f"1. Send 10 concurrent login requests\n"
                        f"2. Receive {len(tokens_seen)} different session tokens\n"
                        f"3. Multiple valid sessions exist simultaneously\n"
                        f"4. Could lead to session fixation/hijacking",
                )


    def _generate_race_poc(
        self,
        url: str,
        method: str,
        payload: dict,
        analysis: dict,
    ) -> str:
        json_payload = json.dumps(payload)
        poc = f"""## Race Condition PoC

{url}

1. Prepare {analysis.get('total', 20)} concurrent HTTP {method} requests
2. Payload: {json_payload}
3. Fire all requests simultaneously using threading/asyncio
4. Observe: {analysis.get('success_count', 0)} requests succeed instead of expected 1

```python
import threading, requests

url = "{url}"
payload = {json_payload}
results = []
barrier = threading.Barrier({analysis.get('total', 20)})

def fire():
    barrier.wait()
    r = requests.post(url, json=payload)
    results.append(r.status_code)

threads = [threading.Thread(target=fire) for _ in range({analysis.get('total', 20)})]
for t in threads: t.start()
for t in threads: t.join()
print(f"Successes: {{results.count(200)}}")
```

```bash
for i in $(seq 1 20); do
  curl -s -X {method} {url} -H 'Content-Type: application/json' -d '{json_payload}' &
done
wait
```

- {analysis.get('success_count', 0)} out of {analysis.get('total', 20)} requests succeeded
- Indicators: {', '.join(analysis.get('indicators', []))}
"""
        return poc


    def _add_finding(self, **kwargs: Any) -> None:
        key = (kwargs.get("vuln_id"), kwargs.get("url"))
        dedup = hashlib.md5(str(key).encode()).hexdigest()

        for existing in self.findings:
            if existing.get("_dedup") == dedup:
                return

        finding = {
            "vuln_id": kwargs.get("vuln_id", "RACE-000"),
            "title": kwargs.get("title", ""),
            "severity": kwargs.get("severity", "High"),
            "cvss_score": kwargs.get("cvss", 7.0),
            "url": kwargs.get("url", ""),
            "category": kwargs.get("category", "race_condition"),
            "evidence": kwargs.get("evidence", ""),
            "payload": kwargs.get("payload", ""),
            "remediation": kwargs.get("remediation", ""),
            "confidence": kwargs.get("confidence", 0.7),
            "validated": True,
            "poc": kwargs.get("poc", ""),
            "request": f"POST {kwargs.get('url', '')} HTTP/1.1",
            "scanner": "RaceScanner",
            "_dedup": dedup,
        }
        self.findings.append(finding)
