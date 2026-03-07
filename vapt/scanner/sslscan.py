"""TLS/SSL configuration scanner."""

from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

import requests
from requests.exceptions import RequestException

from vapt.utils.helpers import sanitize_target

WEAK_CIPHERS = {
    "RC4", "RC2", "DES", "3DES", "DES-CBC3", "NULL", "EXPORT",
    "anon", "MD5",
}

# Protocols to test (in order of preference)
PROTOCOLS_TO_TEST = [
    ("SSLv3",  ssl.PROTOCOL_TLS_CLIENT, "SSLv3"),
    ("TLSv1",  ssl.PROTOCOL_TLS_CLIENT, "TLSv1"),
    ("TLSv1.1", ssl.PROTOCOL_TLS_CLIENT, "TLSv1.1"),
    ("TLSv1.2", ssl.PROTOCOL_TLS_CLIENT, "TLSv1.2"),
    ("TLSv1.3", ssl.PROTOCOL_TLS_CLIENT, "TLSv1.3"),
]


class SSLScanner:
    """Deep SSL/TLS analysis — certificates, protocols, ciphers, HSTS."""

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    def run(self, target: str) -> dict[str, Any]:
        """Run all SSL/TLS checks against the target."""
        target = sanitize_target(target)
        host = target.split(":")[0] if ":" in target else target
        port = 443

        results: dict[str, Any] = {
            "target": host,
            "category": "ssl_tls",
            "findings": [],
            "certificate": {},
            "protocols": [],
        }

        cert_info = self._get_certificate(host, port)
        if cert_info:
            results["certificate"] = cert_info
            results["findings"] += self._analyse_certificate(cert_info, host)

        proto_results = self._test_protocols(host, port)
        results["protocols"] = proto_results
        results["findings"] += self._analyse_protocols(proto_results)

        results["findings"] += self._check_weak_ciphers(host, port)

        results["findings"] += self._check_hsts(host)

        return results


    def _get_certificate(self, host: str, port: int = 443) -> dict[str, Any]:
        """Retrieve the server's TLS certificate and extract metadata."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert_bin = tls.getpeercert(binary_form=True)
                    cert_dict = tls.getpeercert()
                    cipher = tls.cipher()

            if not cert_dict and not cert_bin:
                return {}

            # Parse cert fields
            subject = dict(x[0] for x in cert_dict.get("subject", ()))
            issuer = dict(x[0] for x in cert_dict.get("issuer", ()))
            san_list = []
            for _entry_type, entry_value in cert_dict.get("subjectAltName", ()):
                san_list.append(entry_value)

            not_before = cert_dict.get("notBefore", "")
            not_after = cert_dict.get("notAfter", "")

            # Parse dates
            date_fmt = "%b %d %H:%M:%S %Y %Z"
            try:
                nb = datetime.strptime(not_before, date_fmt).replace(tzinfo=timezone.utc)
            except Exception:
                nb = None
            try:
                na = datetime.strptime(not_after, date_fmt).replace(tzinfo=timezone.utc)
            except Exception:
                na = None

            # Fingerprint
            sha256 = hashlib.sha256(cert_bin).hexdigest() if cert_bin else ""

            return {
                "subject": subject,
                "issuer": issuer,
                "common_name": subject.get("commonName", ""),
                "issuer_cn": issuer.get("commonName", ""),
                "issuer_org": issuer.get("organizationName", ""),
                "serial_number": cert_dict.get("serialNumber", ""),
                "not_before": not_before,
                "not_after": not_after,
                "not_before_dt": nb.isoformat() if nb else None,
                "not_after_dt": na.isoformat() if na else None,
                "days_until_expiry": (na - datetime.now(tz=timezone.utc)).days if na else None,
                "san": san_list,
                "signature_algorithm": cert_dict.get("signatureAlgorithm", "unknown"),
                "sha256_fingerprint": sha256,
                "cipher_suite": cipher[0] if cipher else "",
                "tls_version": cipher[1] if cipher else "",
            }
        except Exception:
            return {}


    def _analyse_certificate(self, cert: dict, host: str) -> list[dict]:
        """Inspect certificate for common weaknesses."""
        findings: list[dict] = []

        # Expiry
        days = cert.get("days_until_expiry")
        if days is not None:
            if days < 0:
                findings.append(self._f(
                    "SSL-001", "ssl_tls", "Certificate EXPIRED",
                    f"Certificate expired {abs(days)} days ago.",
                    "critical", 9.1,
                ))
            elif days < 30:
                findings.append(self._f(
                    "SSL-001", "ssl_tls", f"Certificate expires in {days} days",
                    "Certificate is expiring soon — renewal required.",
                    "high", 7.5,
                ))
            elif days < 90:
                findings.append(self._f(
                    "SSL-001", "ssl_tls", f"Certificate expires in {days} days",
                    "Certificate should be renewed proactively.",
                    "medium", 5.0,
                ))

        # Self-signed
        issuer_cn = cert.get("issuer_cn", "")
        cn = cert.get("common_name", "")
        if issuer_cn and cn and issuer_cn == cn:
            findings.append(self._f(
                "SSL-002", "ssl_tls", "Self-signed certificate detected",
                "The certificate issuer is the same as the subject — self-signed. "
                "Browsers will not trust this certificate.",
                "high", 7.4,
            ))

        # Hostname mismatch
        san_list = cert.get("san", [])
        all_names = set(san_list) | {cn}
        host_matched = False
        for name in all_names:
            if name == host:
                host_matched = True
                break
            # Wildcard matching
            if name.startswith("*.") and host.endswith(name[1:]):
                host_matched = True
                break
        if all_names and not host_matched:
            findings.append(self._f(
                "SSL-003", "ssl_tls", "Certificate hostname mismatch",
                f"Certificate is for {', '.join(sorted(all_names))} but "
                f"the target is {host}.",
                "high", 7.4,
            ))

        # Weak signature algorithm
        sig_alg = cert.get("signature_algorithm", "").lower()
        if "md5" in sig_alg or "md2" in sig_alg:
            findings.append(self._f(
                "SSL-004", "ssl_tls", f"Weak signature algorithm: {sig_alg}",
                "MD5/MD2 signatures are cryptographically broken.",
                "critical", 9.0,
            ))
        elif "sha1" in sig_alg:
            findings.append(self._f(
                "SSL-004", "ssl_tls", f"Weak signature algorithm: {sig_alg}",
                "SHA-1 signatures are deprecated and vulnerable to collision attacks.",
                "high", 7.5,
            ))

        # Wildcard cert (informational)
        if cn and cn.startswith("*."):
            findings.append(self._f(
                "SSL-008", "ssl_tls", "Wildcard certificate in use",
                f"Certificate uses wildcard CN: {cn}. If the private key is "
                "compromised, all subdomains are affected.",
                "info", 2.0,
            ))

        return findings


    def _test_protocols(self, host: str, port: int = 443) -> list[dict]:
        """Test which TLS/SSL protocol versions the server accepts."""
        results: list[dict] = []

        for name, _, _ in PROTOCOLS_TO_TEST:
            accepted = self._try_protocol(host, port, name)
            results.append({"protocol": name, "accepted": accepted})

        return results

    def _try_protocol(self, host: str, port: int, proto_name: str) -> bool:
        """Attempt to connect using a specific TLS/SSL protocol version."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Set min/max to force a specific version
            version_map = {
                "SSLv3": (ssl.TLSVersion.SSLv3, ssl.TLSVersion.SSLv3),
                "TLSv1": (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
                "TLSv1.1": (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
                "TLSv1.2": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
                "TLSv1.3": (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
            }

            if proto_name not in version_map:
                return False

            min_v, max_v = version_map[proto_name]
            try:
                ctx.minimum_version = min_v
                ctx.maximum_version = max_v
            except (ValueError, ssl.SSLError):
                return False

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False

    def _analyse_protocols(self, results: list[dict]) -> list[dict]:
        """Flag deprecated protocols that the server still accepts."""
        findings: list[dict] = []
        deprecated = {"SSLv3", "TLSv1", "TLSv1.1"}

        for proto in results:
            if proto["accepted"] and proto["protocol"] in deprecated:
                sev = "critical" if proto["protocol"] == "SSLv3" else "high"
                cvss = 9.0 if proto["protocol"] == "SSLv3" else 7.4
                findings.append(self._f(
                    "SSL-005", "ssl_tls",
                    f"Deprecated protocol accepted: {proto['protocol']}",
                    f"Server accepts {proto['protocol']} which is deprecated and "
                    "vulnerable to known attacks (POODLE, BEAST, etc.).",
                    sev, cvss,
                ))

        has_tls12 = any(p["accepted"] and p["protocol"] == "TLSv1.2" for p in results)
        has_tls13 = any(p["accepted"] and p["protocol"] == "TLSv1.3" for p in results)
        if not has_tls12 and not has_tls13:
            # No modern protocol — might just mean we couldn't connect
            accepts_any = any(p["accepted"] for p in results)
            if accepts_any:
                findings.append(self._f(
                    "SSL-005", "ssl_tls",
                    "No modern TLS version supported",
                    "Server does not accept TLS 1.2 or 1.3.",
                    "critical", 9.0,
                ))

        return findings


    def _check_weak_ciphers(self, host: str, port: int = 443) -> list[dict]:
        """Check if the server accepts known weak cipher suites."""
        findings: list[dict] = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cipher_name, _protocol, bits = tls.cipher()

                    # Check for weak key length
                    if bits and bits < 128:
                        findings.append(self._f(
                            "SSL-006", "ssl_tls",
                            f"Weak cipher key length: {bits}-bit ({cipher_name})",
                            f"Negotiated cipher {cipher_name} uses only {bits}-bit keys. "
                            "128-bit minimum is recommended.",
                            "high", 7.5,
                        ))

                    # Check cipher name for known weak algorithms
                    for weak in WEAK_CIPHERS:
                        if weak.upper() in cipher_name.upper():
                            findings.append(self._f(
                                "SSL-006", "ssl_tls",
                                f"Weak cipher suite: {cipher_name}",
                                f"Server negotiated cipher {cipher_name} which uses "
                                f"the weak {weak} algorithm.",
                                "high", 7.5,
                            ))
                            break

        except Exception:
            pass

        return findings


    def _check_hsts(self, host: str) -> list[dict]:
        """Check if the target enforces HTTP Strict Transport Security."""
        findings: list[dict] = []
        try:
            resp = requests.get(
                f"https://{host}",
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            hsts = resp.headers.get("Strict-Transport-Security", "")
            if not hsts:
                findings.append(self._f(
                    "SSL-007", "ssl_tls",
                    "HSTS header missing",
                    "The server does not send a Strict-Transport-Security header. "
                    "Users may be vulnerable to SSL-stripping attacks.",
                    "medium", 5.4,
                ))
            else:
                # Check for short max-age
                import re
                m = re.search(r"max-age=(\d+)", hsts)
                if m:
                    max_age = int(m.group(1))
                    if max_age < 15768000:  # ~6 months
                        findings.append(self._f(
                            "SSL-007", "ssl_tls",
                            f"HSTS max-age too short ({max_age}s)",
                            "HSTS max-age should be at least 6 months (15768000s). "
                            f"Current value: {max_age}s.",
                            "low", 3.1,
                        ))
                if "includesubdomains" not in hsts.lower():
                    findings.append(self._f(
                        "SSL-007", "ssl_tls",
                        "HSTS missing includeSubDomains",
                        "HSTS header does not include the includeSubDomains directive. "
                        "Subdomains may be vulnerable to SSL-stripping.",
                        "low", 3.1,
                    ))
        except RequestException:
            pass

        return findings


    @staticmethod
    def _f(
        vuln_id: str, category: str, title: str,
        description: str, severity: str, cvss_score: float,
    ) -> dict[str, Any]:
        return {
            "vuln_id": vuln_id,
            "category": category,
            "title": title,
            "description": description,
            "severity": severity,
            "cvss_score": cvss_score,
        }
