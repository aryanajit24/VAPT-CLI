import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class TestAITriage(unittest.TestCase):

    def setUp(self):
        from vapt.engine.ai_triage import AITriage
        self.triage = AITriage()

    def test_analyze_returns_list(self):
        findings = [{
            "title": "SQL Injection in login",
            "severity": "critical",
            "confidence": 0.9,
            "category": "injection",
            "url": "https://example.com/login",
            "evidence": "Error: MySQL syntax error near...",
        }]
        result = self.triage.analyze(findings)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertIn("triage", result[0])
        triage = result[0]["triage"]
        self.assertIn("report_score", triage)
        self.assertIn("duplicate_probability", triage)
        self.assertIn("recommendation", triage)

    def test_high_severity_gets_high_score(self):
        findings = [{
            "title": "Remote Code Execution via SSTI",
            "severity": "critical",
            "confidence": 0.95,
            "category": "injection",
            "url": "https://example.com/render",
            "evidence": "Output: 49 (7*7 evaluated)",
        }]
        result = self.triage.analyze(findings)
        self.assertGreater(result[0]["triage"]["report_score"], 50)

    def test_info_severity_gets_low_score(self):
        findings = [{
            "title": "Server Version Disclosure",
            "severity": "info",
            "confidence": 0.5,
            "category": "information_disclosure",
            "url": "https://example.com",
            "evidence": "Server: Apache/2.4.41",
        }]
        result = self.triage.analyze(findings)
        self.assertLess(result[0]["triage"]["report_score"], 50)

    def test_filter_reportable(self):
        findings = [
            {"title": "Critical SQLi", "severity": "critical", "confidence": 0.9,
             "category": "injection", "url": "https://x.com", "evidence": "err"},
            {"title": "Info disclosure", "severity": "info", "confidence": 0.3,
             "category": "information_disclosure", "url": "https://x.com", "evidence": "ver"},
        ]
        reportable = self.triage.filter_reportable(findings)
        self.assertIsInstance(reportable, list)

    def test_generate_report_text(self):
        finding = {
            "title": "Reflected XSS",
            "severity": "high",
            "confidence": 0.85,
            "category": "xss",
            "url": "https://example.com/search?q=test",
            "evidence": "Payload reflected: <script>alert(1)</script>",
        }
        report = self.triage.generate_report_text(finding)
        self.assertIn("title", report)
        self.assertIn("description", report)
        self.assertIn("impact", report)
        self.assertIn("steps_to_reproduce", report)

    def test_generate_summary(self):
        findings = [
            {"title": "XSS", "severity": "high", "confidence": 0.9,
             "category": "xss", "url": "https://x.com", "evidence": "e"},
            {"title": "SQLi", "severity": "critical", "confidence": 0.95,
             "category": "injection", "url": "https://x.com", "evidence": "e"},
        ]
        summary = self.triage.generate_summary(findings)
        self.assertIsInstance(summary, dict)

    def test_empty_findings(self):
        result = self.triage.analyze([])
        self.assertEqual(result, [])


class TestSessionManager(unittest.TestCase):

    def setUp(self):
        from vapt.engine.session_manager import SessionManager
        self.sm = SessionManager()

    def test_create_bearer_session(self):
        session = self.sm.create_session(
            name="test_bearer",
            auth_type="bearer",
            credentials={"token": "test_token_12345"},
        )
        self.assertIsNotNone(session)
        self.assertEqual(session.headers.get("Authorization"), "Bearer test_token_12345")

    def test_create_basic_session(self):
        session = self.sm.create_session(
            name="test_basic",
            auth_type="basic",
            credentials={"username": "admin", "password": "secret"},
        )
        self.assertIsNotNone(session)
        self.assertIn("test_basic", self.sm.list_sessions())

    def test_create_api_key_session(self):
        session = self.sm.create_session(
            name="test_apikey",
            auth_type="api_key",
            credentials={"token": "my-api-key", "header_name": "X-API-Key"},
        )
        self.assertIsNotNone(session)
        self.assertIn("test_apikey", self.sm.list_sessions())

    def test_list_sessions(self):
        self.sm.create_session(
            name="list_test",
            auth_type="bearer",
            credentials={"token": "abc"},
        )
        sessions = self.sm.list_sessions()
        self.assertIn("list_test", sessions)

    def test_get_nonexistent_session(self):
        result = self.sm.get_session("nonexistent_session_xyz")
        self.assertIsNone(result)

    def test_delete_session(self):
        self.sm.create_session(
            name="del_test",
            auth_type="bearer",
            credentials={"token": "abc"},
        )
        self.sm.delete_session("del_test")
        self.assertIsNone(self.sm.get_session("del_test"))


class TestOOBServer(unittest.TestCase):

    def setUp(self):
        from vapt.engine.oob_server import OOBServer
        self.oob = OOBServer(listen_port=0)

    def test_generate_token(self):
        token = self.oob.generate_token("sqli_blind", "https://target.com")
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 8)

    def test_generate_ssrf_payload(self):
        payload = self.oob.generate_payload("ssrf", "https://target.com", callback_host="localhost")
        self.assertIsInstance(payload, dict)
        self.assertIn("payloads", payload)

    def test_generate_xxe_payload(self):
        payload = self.oob.generate_payload("xxe", "https://target.com", callback_host="localhost")
        self.assertIsInstance(payload, dict)

    def test_generate_blind_xss_payload(self):
        payload = self.oob.generate_payload("blind_xss", "https://target.com", callback_host="localhost")
        self.assertIsInstance(payload, dict)

    def test_token_tracking(self):
        t1 = self.oob.generate_token("test1", "https://target1.com")
        t2 = self.oob.generate_token("test2", "https://target2.com")
        self.assertNotEqual(t1, t2)

    def test_has_callback_false(self):
        token = self.oob.generate_token("test", "https://target.com")
        self.assertFalse(self.oob.has_callback(token))


class TestExploitValidator(unittest.TestCase):

    def setUp(self):
        from vapt.engine.exploit_validator import ExploitValidator
        self.validator = ExploitValidator()

    @patch("vapt.engine.exploit_validator.requests")
    def test_validate_sqli_time_based(self, mock_requests):
        fast_response = MagicMock()
        fast_response.elapsed.total_seconds.return_value = 0.1
        fast_response.status_code = 200
        fast_response.text = "OK"

        slow_response = MagicMock()
        slow_response.elapsed.total_seconds.return_value = 5.5
        slow_response.status_code = 200
        slow_response.text = "OK"

        mock_requests.get.side_effect = [fast_response, slow_response]
        mock_requests.exceptions = __import__("requests").exceptions

        result = self.validator.validate_sqli(
            url="https://example.com/search?id=1",
            param="id",
        )
        self.assertIsInstance(result, (dict, type(None)))

    @patch("vapt.engine.exploit_validator.requests")
    def test_validate_cors(self, mock_requests):
        response = MagicMock()
        response.status_code = 200
        response.headers = {"Access-Control-Allow-Origin": "https://evil.com"}
        mock_requests.get.return_value = response
        mock_requests.exceptions = __import__("requests").exceptions

        result = self.validator.validate_cors(url="https://example.com/api")
        self.assertIsInstance(result, (dict, type(None)))

    def test_validate_all_with_unknown_type(self):
        finding = {"category": "unknown_type_xyz", "url": "https://x.com"}
        result = self.validator.validate_all(finding)
        self.assertIsNone(result)


class TestCodeScanner(unittest.TestCase):

    def setUp(self):
        from vapt.scanner.codescan import CodeScanner
        self.scanner = CodeScanner()

    def test_detect_aws_key_in_source(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "config.py"
            filepath.write_text('AWS_KEY = "AKIAJ5ZVWRONGKEYHNO2"\n')
            result = self.scanner.run(tmpdir)
            secrets = [f for f in result["findings"] if f["category"] == "secret_detection"]
            self.assertGreater(len(secrets), 0)
            self.assertEqual(secrets[0]["severity"], "critical")

    def test_detect_sqli_pattern(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "app.py"
            filepath.write_text('cursor.execute("SELECT * FROM users WHERE id=" + user_input)\n')
            result = self.scanner.run(tmpdir)
            sast = [f for f in result["findings"] if f["category"] == "sast"]
            self.assertGreater(len(sast), 0)

    def test_detect_private_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "keys.py"
            filepath.write_text('key = """-----BEGIN RSA PRIVATE KEY-----\nMIIBog...\n-----END RSA PRIVATE KEY-----"""\n')
            result = self.scanner.run(tmpdir)
            secrets = [f for f in result["findings"] if "Private Key" in f["title"]]
            self.assertGreater(len(secrets), 0)

    def test_skip_test_directories(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = Path(tmpdir) / "tests"
            test_dir.mkdir()
            (test_dir / "test_creds.py").write_text('secret = "AKIAJ5ZVWRONGKEYHNO2"\n')
            result = self.scanner.run(tmpdir)
            self.assertEqual(len(result["findings"]), 0)

    def test_scan_directory_counts_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "app.py").write_text("x = 1\n")
            (Path(tmpdir) / "utils.py").write_text("y = 2\n")
            result = self.scanner.run(tmpdir)
            self.assertEqual(result["files_scanned"], 2)

    def test_nonexistent_path(self):
        result = self.scanner.run("/nonexistent/path/xyz")
        self.assertIn("error", result)

    def test_detect_github_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "deploy.py"
            filepath.write_text('TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"\n')
            result = self.scanner.run(tmpdir)
            secrets = [f for f in result["findings"] if "GitHub" in f["title"]]
            self.assertGreater(len(secrets), 0)


class TestBrowserEngine(unittest.TestCase):

    def test_import(self):
        from vapt.engine.browser import BrowserEngine
        engine = BrowserEngine()
        self.assertIsNotNone(engine)


class TestMobileScanner(unittest.TestCase):

    def test_import(self):
        from vapt.scanner.mobilescan import MobileScanner
        scanner = MobileScanner()
        self.assertIsNotNone(scanner)

    def test_nonexistent_file(self):
        from vapt.scanner.mobilescan import MobileScanner
        scanner = MobileScanner()
        result = scanner.run("/nonexistent/file.apk")
        self.assertIn("error", result)

    def test_unsupported_extension(self):
        from vapt.scanner.mobilescan import MobileScanner
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"test")
            path = f.name
        try:
            scanner = MobileScanner()
            result = scanner.run(path)
            self.assertIn("error", result)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
