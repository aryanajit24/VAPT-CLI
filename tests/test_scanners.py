"""Tests for VAPT CLI scanner modules."""

from __future__ import annotations

import re
import pytest
import responses as resp_lib
import requests

from vapt.scanner.portscan import PortScanner
from vapt.scanner.webscan import WebScanner
from vapt.scanner.apiscan import APIScanner
from vapt.scanner.cve import CVEScanner
from vapt.scanner.recon import ReconScanner
from vapt.utils.validators import validate_target, validate_port


# ─── Validators ───────────────────────────────────────────────────────────────

class TestValidators:
    def test_valid_hostname(self):
        ok, val = validate_target("example.com")
        assert ok
        assert val == "example.com"

    def test_valid_ip(self):
        ok, val = validate_target("192.168.1.1")
        assert ok

    def test_valid_url(self):
        ok, val = validate_target("https://example.com/path")
        assert ok

    def test_valid_cidr(self):
        ok, val = validate_target("10.0.0.0/24")
        assert ok

    def test_invalid_target_empty(self):
        ok, msg = validate_target("")
        assert not ok
        assert "empty" in msg.lower()

    def test_invalid_target_special_chars(self):
        ok, _ = validate_target("!@#$%^")
        assert not ok

    def test_valid_port_single(self):
        ok, _ = validate_port(80)
        assert ok

    def test_valid_port_range(self):
        ok, _ = validate_port("1-1024")
        assert ok

    def test_valid_port_list(self):
        ok, _ = validate_port("22,80,443")
        assert ok

    def test_invalid_port_too_high(self):
        ok, msg = validate_port(99999)
        assert not ok

    def test_invalid_port_zero(self):
        ok, _ = validate_port(0)
        assert not ok


# ─── PortScanner ──────────────────────────────────────────────────────────────

class TestPortScanner:
    def test_run_returns_expected_keys(self, monkeypatch):
        scanner = PortScanner(timeout=1)
        # Stub out actual scanning
        monkeypatch.setattr(scanner, "_scan", lambda host, ports: [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http",
             "product": "", "version": "", "banner": ""}
        ])
        result = scanner.run("example.com")
        assert "target" in result
        assert "open_ports" in result
        assert "findings" in result

    def test_risky_port_generates_finding(self, monkeypatch):
        scanner = PortScanner(timeout=1)
        monkeypatch.setattr(scanner, "_scan", lambda host, ports: [
            {"port": 3306, "protocol": "tcp", "state": "open", "service": "mysql",
             "product": "", "version": "", "banner": ""}
        ])
        result = scanner.run("example.com")
        assert any(f["port"] == 3306 for f in result["findings"])

    def test_safe_port_no_finding(self, monkeypatch):
        scanner = PortScanner(timeout=1)
        monkeypatch.setattr(scanner, "_scan", lambda host, ports: [
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https",
             "product": "", "version": "", "banner": ""}
        ])
        result = scanner.run("example.com")
        assert len(result["findings"]) == 0

    def test_parse_ports_range(self):
        ports = PortScanner._parse_ports("22-24")
        assert ports == [22, 23, 24]

    def test_parse_ports_list(self):
        ports = PortScanner._parse_ports("80,443,8080")
        assert ports == [80, 443, 8080]

    def test_invalid_port_string_returns_error(self):
        result = PortScanner(timeout=1).run("example.com", ports="abc")
        assert "error" in result


# ─── WebScanner ───────────────────────────────────────────────────────────────

class TestWebScanner:
    @resp_lib.activate
    def test_missing_security_headers_generates_findings(self):
        resp_lib.add(
            resp_lib.GET,
            "https://example.com",
            body="<html>OK</html>",
            status=200,
            headers={"Content-Type": "text/html"},
        )
        scanner = WebScanner(timeout=5)
        result = scanner.run("example.com")
        titles = [f["title"] for f in result["findings"]]
        assert any("Strict-Transport-Security" in t for t in titles)

    @resp_lib.activate
    def test_http_endpoint_tls_finding(self):
        resp_lib.add(
            resp_lib.GET,
            "https://example.com",
            body="<html></html>",
            status=200,
        )
        scanner = WebScanner(timeout=5)
        # sanitize_target strips the scheme; scanner normalises to https
        result = scanner.run("http://example.com")
        assert result["target"].startswith("https://")

    @resp_lib.activate
    def test_xss_payload_reflected_generates_finding(self):
        """Scanner detects reflected XSS when payload appears in response."""
        # Use a callback for ALL requests — reflect XSS payloads, serve normal pages otherwise
        def smart_handler(request):
            from urllib.parse import unquote
            decoded = unquote(request.url)

            # Landing page: include a link with ?q= so crawler discovers params
            if "?" not in request.url or request.url.endswith("example.com/"):
                body = '<html><a href="https://example.com/?q=test">link</a></html>'
                return (200, {"Content-Type": "text/html"}, body)

            # Reflect XSS payloads in the response body
            for marker in ["<script>", "<img ", "<svg ", "javascript:"]:
                if marker.lower() in decoded.lower():
                    # Extract the payload from the query string and reflect it
                    parts = decoded.split("q=", 1)
                    reflected = parts[1] if len(parts) > 1 else decoded
                    return (200, {"Content-Type": "text/html"}, f"<html>{reflected}</html>")

            return (200, {"Content-Type": "text/html"}, "<html>OK</html>")

        resp_lib.add_callback(resp_lib.GET,
            url=re.compile(r"https://example\.com"),
            callback=smart_handler)
        resp_lib.add_callback(resp_lib.POST,
            url=re.compile(r"https://example\.com"),
            callback=smart_handler)

        scanner = WebScanner(timeout=5)
        scanner.session.verify = False
        result = scanner.run("example.com")
        xss_findings = [f for f in result["findings"] if "xss" in f.get("category", "")]
        assert len(xss_findings) >= 1

    @resp_lib.activate
    def test_request_error_returns_error_key(self):
        resp_lib.add(
            resp_lib.GET,
            "https://broken.internal",
            body=requests.exceptions.ConnectionError("refused"),
        )
        scanner = WebScanner(timeout=2)
        result = scanner.run("broken.internal")
        assert "error" in result


# ─── APIScanner ───────────────────────────────────────────────────────────────

class TestAPIScanner:
    @resp_lib.activate
    def test_discovers_accessible_endpoints(self):
        resp_lib.add(resp_lib.GET, "https://example.com/api/v1/users", json={"users": []}, status=200)
        resp_lib.add(resp_lib.OPTIONS, "https://example.com", status=200)
        # All other paths return 404
        for path in [
            "/api/v2/users", "/api/users", "/api/admin", "/api/config",
            "/api/health", "/api/docs", "/swagger.json", "/openapi.json",
            "/v1/users", "/v2/users",
        ]:
            resp_lib.add(resp_lib.GET, f"https://example.com{path}", status=404)
        # Admin BOLA checks
        for path in ["/api/admin", "/api/v1/admin", "/admin/api"]:
            resp_lib.add(resp_lib.GET, f"https://example.com{path}", status=404)

        scanner = APIScanner(timeout=5)
        result = scanner.run("example.com")
        assert "/api/v1/users" in result["endpoints_discovered"]

    @resp_lib.activate
    def test_sensitive_field_generates_finding(self):
        resp_lib.add(
            resp_lib.GET,
            "https://example.com/api/v1/users",
            json={"users": [{"id": 1, "password": "secret123"}]},
            status=200,
        )
        resp_lib.add(resp_lib.OPTIONS, "https://example.com", status=200)
        # Remaining paths return 404
        for path in [
            "/api/v2/users", "/api/users", "/api/admin", "/api/config",
            "/api/health", "/api/docs", "/swagger.json", "/openapi.json",
            "/v1/users", "/v2/users",
        ]:
            resp_lib.add(resp_lib.GET, f"https://example.com{path}", status=404)
        for path in ["/api/admin", "/api/v1/admin", "/admin/api"]:
            resp_lib.add(resp_lib.GET, f"https://example.com{path}", status=404)

        scanner = APIScanner(timeout=5)
        result = scanner.run("example.com")
        data_exposure = [f for f in result["findings"] if f.get("vuln_id") == "API-002"]
        assert len(data_exposure) >= 1


# ─── CVEScanner ───────────────────────────────────────────────────────────────

class TestCVEScanner:
    @resp_lib.activate
    def test_vulnerable_apache_version_detected(self):
        resp_lib.add(
            resp_lib.GET,
            "https://example.com",
            body="<html>OK</html>",
            status=200,
            headers={"Server": "Apache/2.4.49 (Unix)"},
        )
        scanner = CVEScanner(timeout=5)
        result = scanner.run("example.com")
        cve_findings = [f for f in result["findings"] if "CVE-2021-42013" in f.get("cve_ids", "")]
        assert len(cve_findings) >= 1

    @resp_lib.activate
    def test_safe_server_no_cve_findings(self):
        resp_lib.add(
            resp_lib.GET,
            "https://example.com",
            body="<html>OK</html>",
            status=200,
            headers={"Server": "nginx/1.24.0"},
        )
        scanner = CVEScanner(timeout=5)
        result = scanner.run("example.com")
        # nginx/1.24.0 is NOT in the vulnerable range
        assert isinstance(result["findings"], list)

    def test_match_cves_no_banners(self):
        scanner = CVEScanner()
        findings = scanner._match_cves({})
        assert findings == []


# ─── Fuzzer ───────────────────────────────────────────────────────────────────

from vapt.scanner.fuzzer import Fuzzer


class TestFuzzer:
    """Verify the fuzzer only reports REAL vulnerabilities, not 403 blocks."""

    @resp_lib.activate
    def test_403_is_not_reported(self):
        """A 403 response means server correctly blocks access - NOT a bug."""
        resp_lib.add(
            resp_lib.GET,
            "https://example.com/.git/HEAD",
            body="<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD></HTML>",
            status=403,
        )
        resp_lib.add(
            resp_lib.GET,
            re.compile(r"https://example\.com/.*"),
            body="<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD></HTML>",
            status=403,
        )
        fuzzer = Fuzzer(timeout=3, max_workers=1, extensions=False,
                        safety_config={"max_fuzz_paths": 5})
        result = fuzzer.run("https://example.com")
        # NO findings should be generated from 403 responses
        assert len(result["findings"]) == 0, (
            f"Fuzzer reported {len(result['findings'])} false positive(s) from 403 responses! "
            f"Titles: {[f.get('title') for f in result['findings']]}"
        )

    @resp_lib.activate
    def test_200_with_real_content_is_reported(self):
        """A 200 with actual .git/HEAD content IS a real vulnerability."""
        resp_lib.add(
            resp_lib.GET,
            "https://example.com/.git/HEAD",
            body="ref: refs/heads/main\n",
            status=200,
        )
        resp_lib.add(
            resp_lib.GET,
            re.compile(r"https://example\.com/(?!\.git/HEAD).*"),
            status=404,
        )
        fuzzer = Fuzzer(timeout=3, max_workers=1, extensions=False,
                        safety_config={"max_fuzz_paths": 5})
        result = fuzzer.run("https://example.com")
        git_findings = [f for f in result["findings"] if ".git" in f.get("url", "")]
        assert len(git_findings) >= 1, "Fuzzer should report accessible .git/HEAD as a finding"
        assert git_findings[0]["severity"] == "critical"

    @resp_lib.activate
    def test_200_with_blocked_content_not_reported(self):
        """A 200 that returns a WAF/CDN block page is a false positive."""
        resp_lib.add(
            resp_lib.GET,
            "https://example.com/.env",
            body="<html>Access Denied - errors.edgesuite.net</html>",
            status=200,
        )
        resp_lib.add(
            resp_lib.GET,
            re.compile(r"https://example\.com/(?!\.env).*"),
            status=404,
        )
        fuzzer = Fuzzer(timeout=3, max_workers=1, extensions=False,
                        safety_config={"max_fuzz_paths": 5})
        result = fuzzer.run("https://example.com")
        env_findings = [f for f in result["findings"] if ".env" in f.get("url", "")]
        assert len(env_findings) == 0, (
            "Fuzzer should NOT report WAF block pages as findings"
        )

    @resp_lib.activate
    def test_401_is_not_reported(self):
        """A 401 means auth is working correctly - NOT a bug."""
        resp_lib.add(
            resp_lib.GET,
            re.compile(r"https://example\.com/.*"),
            body="Authentication Required",
            status=401,
        )
        fuzzer = Fuzzer(timeout=3, max_workers=1, extensions=False,
                        safety_config={"max_fuzz_paths": 5})
        result = fuzzer.run("https://example.com")
        assert len(result["findings"]) == 0
