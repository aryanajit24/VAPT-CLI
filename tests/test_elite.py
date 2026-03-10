
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class TestEliteIntelligenceEngine(unittest.TestCase):

    def setUp(self):
        from vapt.engine.elite_intelligence import EliteIntelligenceEngine
        self.engine = EliteIntelligenceEngine()

    def test_analyze_returns_enriched_findings(self):
        findings = [
            {"title": "Missing X-Frame-Options", "category": "header", "severity": "low"},
        ]
        result = self.engine.analyze(findings)
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) > 0)
        f = result[0]
        self.assertIn("novelty_score", f)
        self.assertIn("duplicate_risk", f)
        self.assertIn("submission_readiness", f)

    def test_common_headers_get_high_duplicate_risk(self):
        findings = [
            {"title": "Missing X-Frame-Options", "category": "security_header", "severity": "low"},
        ]
        result = self.engine.analyze(findings)
        f = result[0]
        self.assertGreater(f["duplicate_risk"], 0.8)

    def test_cors_without_exfil_is_high_risk(self):
        findings = [
            {"title": "CORS Misconfiguration", "category": "cors", "severity": "medium"},
        ]
        result = self.engine.analyze(findings)
        f = result[0]
        self.assertGreater(f["duplicate_risk"], 0.7)

    def test_idor_financial_gets_high_novelty(self):
        findings = [
            {
                "title": "IDOR on /api/accounts/transfer",
                "category": "idor",
                "severity": "critical",
                "url": "https://api.example.com/api/accounts/transfer",
            },
        ]
        result = self.engine.analyze(findings)
        f = result[0]
        self.assertGreater(f["novelty_score"], 0.5)

    def test_skipped_findings_are_marked(self):
        findings = [
            {"title": "Missing Content-Security-Policy", "category": "security_header", "severity": "info"},
        ]
        result = self.engine.analyze(findings)
        f = result[0]
        self.assertEqual(f["submission_readiness"], "skip")

    def test_elite_summary_has_required_keys(self):
        findings = [
            {"title": "Test", "category": "xss", "severity": "high",
             "submission_readiness": "ready", "novelty_score": 0.8,
             "duplicate_risk": 0.2},
        ]
        summary = self.engine.generate_elite_summary(findings)
        self.assertIn("total_findings", summary)
        self.assertIn("ready_to_submit", summary)
        self.assertIn("recommendations", summary)

    def test_poc_completeness_for_cors_without_exfil(self):
        findings = [
            {
                "title": "CORS allows origin reflection",
                "category": "cors",
                "severity": "medium",
                "evidence": {"response_headers": "Access-Control-Allow-Origin: *"},
            },
        ]
        result = self.engine.analyze(findings)
        f = result[0]
        self.assertLess(f["poc_completeness"], 0.8)

    def test_findings_are_ranked(self):
        findings = [
            {"title": "Low finding", "category": "header", "severity": "info"},
            {"title": "High finding", "category": "idor", "severity": "critical",
             "url": "https://api.example.com/api/accounts/123"},
        ]
        result = self.engine.analyze(findings)
        ranks = [f.get("priority_rank", 999) for f in result]
        self.assertTrue(any(r == 1 for r in ranks))


class TestBusinessLogicScanner(unittest.TestCase):

    def setUp(self):
        from vapt.scanner.bizscan import BusinessLogicScanner
        self.scanner = BusinessLogicScanner(timeout=5)

    def test_has_financial_endpoints(self):
        from vapt.scanner.bizscan import FINANCIAL_ENDPOINTS
        self.assertTrue(len(FINANCIAL_ENDPOINTS) > 20)

    def test_has_promo_endpoints(self):
        from vapt.scanner.bizscan import PROMO_ENDPOINTS
        self.assertTrue(len(PROMO_ENDPOINTS) > 10)

    def test_run_returns_expected_keys(self):
        with patch.object(self.scanner, '_discover_endpoints', return_value=[]):
            result = self.scanner.run("https://example.com")
        self.assertIn("findings", result)
        self.assertIn("endpoints_discovered", result)

    def test_negative_amount_payloads_exist(self):
        self.assertTrue(hasattr(self.scanner, '_test_negative_amounts'))

    def test_race_condition_test_exists(self):
        self.assertTrue(hasattr(self.scanner, '_test_race_conditions'))


class TestDeepJSRecon(unittest.TestCase):

    def setUp(self):
        from vapt.scanner.deepjs import DeepJSRecon
        self.recon = DeepJSRecon(timeout=5)

    def test_has_api_call_patterns(self):
        from vapt.scanner.deepjs import API_CALL_PATTERNS
        self.assertTrue(len(API_CALL_PATTERNS) > 5)

    def test_has_route_patterns(self):
        from vapt.scanner.deepjs import ROUTE_PATTERNS
        self.assertTrue(len(ROUTE_PATTERNS) > 3)

    def test_run_returns_expected_keys(self):
        with patch.object(self.recon, '_discover_js_files', return_value=[]):
            result = self.recon.run("https://example.com")
        self.assertIn("api_endpoints", result)
        self.assertIn("client_routes", result)
        self.assertIn("graphql_operations", result)
        self.assertIn("websocket_urls", result)
        self.assertIn("findings", result)

    def test_get_endpoints_for_scanning(self):
        self.recon.all_api_endpoints = [
            {"endpoint": "/api/v1/users", "method": "GET"},
            {"endpoint": "/api/v1/accounts", "method": "POST"},
        ]
        endpoints = self.recon.get_endpoints_for_scanning()
        self.assertIsInstance(endpoints, list)
        self.assertTrue(all(isinstance(e, str) for e in endpoints))

    def test_extract_api_endpoints_from_fetch(self):
        js_content = """
        fetch('/api/v1/users', { method: 'GET' })
        fetch('/api/v2/accounts/me', { method: 'POST' })
        """
        self.recon._extract_api_endpoints(js_content, "https://example.com/app.js", "https://example.com")
        self.assertTrue(len(self.recon.api_endpoints) >= 2)


class TestOOBManager(unittest.TestCase):

    def setUp(self):
        from vapt.engine.oob import OOBManager
        self.manager = OOBManager()

    def test_get_callback_url(self):
        url = self.manager.get_callback_url("test-ssrf")
        self.assertIsInstance(url, str)
        self.assertTrue(len(url) > 0)

    def test_generate_ssrf_payloads(self):
        payloads = self.manager.generate_ssrf_payloads("test-endpoint")
        self.assertIsInstance(payloads, dict)
        self.assertIn("basic", payloads)
        self.assertIn("cloud_metadata", payloads)

    def test_correlation_tracking(self):
        url = self.manager.get_callback_url("my-test")
        self.assertTrue(len(self.manager._correlation_map) > 0)

    def test_has_oob_payload_categories(self):
        from vapt.engine.oob import OOB_PAYLOADS
        self.assertIn("ssrf", OOB_PAYLOADS)
        self.assertIn("xxe", OOB_PAYLOADS)
        self.assertIn("xss_blind", OOB_PAYLOADS)


class TestAuthFlowScanner(unittest.TestCase):

    def setUp(self):
        from vapt.scanner.authflow import AuthFlowScanner
        self.scanner = AuthFlowScanner(timeout=5)

    def test_run_returns_expected_keys(self):
        result = self.scanner.run("https://example.com")
        self.assertIn("findings", result)

    def test_has_idor_testing(self):
        self.assertTrue(hasattr(self.scanner, '_test_idor'))

    def test_has_privilege_escalation_testing(self):
        self.assertTrue(hasattr(self.scanner, '_test_privilege_escalation'))

    def test_has_session_management_testing(self):
        self.assertTrue(hasattr(self.scanner, '_test_session_management'))

    def test_has_token_handling_testing(self):
        self.assertTrue(hasattr(self.scanner, '_test_token_handling'))

    def test_setup_session(self):
        import requests
        session = requests.Session()
        self.scanner.setup_session(session, "A")
        self.assertEqual(self.scanner.session_a, session)


class TestSmartHuntOrchestrator(unittest.TestCase):

    def setUp(self):
        from vapt.engine.smart_hunt import SmartHuntOrchestrator
        self.hunt = SmartHuntOrchestrator(
            target="https://example.com",
            output_dir=tempfile.mkdtemp(),
        )

    def test_configure(self):
        self.hunt.configure(
            program_name="TestProgram",
            platform="HackerOne",
            scope_in=["https://example.com", "https://api.example.com"],
        )
        self.assertEqual(self.hunt.program_name, "TestProgram")
        self.assertEqual(self.hunt.platform, "HackerOne")
        self.assertEqual(len(self.hunt.scope_in), 2)

    def test_has_all_phases(self):
        self.assertTrue(hasattr(self.hunt, '_phase_1_js_recon'))
        self.assertTrue(hasattr(self.hunt, '_phase_2_endpoint_intel'))
        self.assertTrue(hasattr(self.hunt, '_phase_3_auth_testing'))
        self.assertTrue(hasattr(self.hunt, '_phase_4_business_logic'))
        self.assertTrue(hasattr(self.hunt, '_phase_5_oob_testing'))
        self.assertTrue(hasattr(self.hunt, '_phase_6_targeted_scanning'))
        self.assertTrue(hasattr(self.hunt, '_phase_7_elite_analysis'))
        self.assertTrue(hasattr(self.hunt, '_phase_8_reports'))

    def test_output_dir_created(self):
        self.assertTrue(Path(self.hunt.output_dir).exists())


class TestEliteReportGenerator(unittest.TestCase):

    def setUp(self):
        from vapt.reporting.elite_report import EliteReportGenerator
        self.tmpdir = tempfile.mkdtemp()
        self.gen = EliteReportGenerator(output_dir=self.tmpdir)

    def test_generate_reports_no_findings(self):
        paths = self.gen.generate_elite_reports(
            findings=[],
            program_name="Test",
            platform="HackerOne",
            target="https://example.com",
        )
        self.assertTrue(len(paths) > 0)
        self.assertTrue(any("summary" in p for p in paths))

    def test_generate_reports_with_ready_finding(self):
        findings = [
            {
                "title": "IDOR on /api/accounts",
                "category": "idor",
                "severity": "critical",
                "url": "https://api.example.com/api/accounts/123",
                "description": "User A can access User B's account data.",
                "steps_to_reproduce": [
                    "Login as User A",
                    "Access /api/accounts/456 (User B's ID)",
                    "Observe User B's data returned",
                ],
                "impact": "Full unauthorized access to any user's financial data.",
                "evidence": {"request": "GET /api/accounts/456", "response": '{"name": "User B"}'},
                "submission_readiness": "ready",
                "novelty_score": 0.85,
                "duplicate_risk": 0.15,
                "poc_completeness": 0.9,
                "elite_recommendation": "Strong finding. Submit immediately.",
            },
        ]
        paths = self.gen.generate_elite_reports(
            findings=findings,
            program_name="Test",
            platform="HackerOne",
            target="https://api.example.com",
        )
        self.assertTrue(len(paths) >= 3)
        md_files = [p for p in paths if p.endswith(".md") and "summary" not in p]
        self.assertTrue(len(md_files) > 0)
        content = Path(md_files[0]).read_text()
        self.assertIn("IDOR on /api/accounts", content)
        self.assertIn("READY TO SUBMIT", content)

    def test_generate_h1_field_format(self):
        findings = [
            {
                "title": "Test Finding",
                "category": "xss",
                "severity": "high",
                "url": "https://example.com/search",
                "description": "Reflected XSS in search parameter.",
                "steps_to_reproduce": ["Visit URL", "Execute payload"],
                "impact": "Session hijacking.",
                "evidence": {"curl": "curl 'https://example.com/search?q=<script>alert(1)</script>'"},
                "submission_readiness": "ready",
                "novelty_score": 0.7,
                "duplicate_risk": 0.3,
                "poc_completeness": 0.8,
                "elite_recommendation": "Good finding.",
            },
        ]
        paths = self.gen.generate_elite_reports(
            findings=findings,
            program_name="Test",
            platform="HackerOne",
            target="https://example.com",
        )
        field_files = [p for p in paths if p.endswith("_fields.txt")]
        self.assertTrue(len(field_files) > 0)
        content = Path(field_files[0]).read_text()
        self.assertIn("FIELD: Title", content)
        self.assertIn("FIELD: Severity", content)
        self.assertIn("FIELD: Description", content)
        self.assertIn("FIELD: Impact", content)

    def test_duplicate_warning_in_field_report(self):
        findings = [
            {
                "title": "Missing CSP Header",
                "category": "security_header",
                "severity": "low",
                "url": "https://example.com",
                "description": "Missing Content-Security-Policy header.",
                "submission_readiness": "needs_work",
                "novelty_score": 0.1,
                "duplicate_risk": 0.95,
                "poc_completeness": 0.3,
                "elite_recommendation": "Very high duplicate risk.",
            },
        ]
        paths = self.gen.generate_elite_reports(
            findings=findings,
            program_name="Test",
            platform="HackerOne",
            target="https://example.com",
        )
        field_files = [p for p in paths if p.endswith("_fields.txt")]
        self.assertTrue(len(field_files) > 0)
        content = Path(field_files[0]).read_text()
        self.assertIn("DUPLICATE RISK", content)

    def test_cvss4_vector_generation(self):
        finding = {"severity": "critical", "category": "rce", "requires_auth": False}
        vector = self.gen._build_cvss4_vector(finding)
        self.assertTrue(vector.startswith("CVSS:4.0/"))
        self.assertIn("AV:N", vector)

    def test_master_summary_generated(self):
        findings = [
            {
                "title": "Test", "category": "idor", "severity": "high",
                "url": "https://example.com", "description": "Test finding.",
                "submission_readiness": "ready", "novelty_score": 0.8,
                "duplicate_risk": 0.2, "poc_completeness": 0.9,
                "elite_recommendation": "Submit it.",
            },
        ]
        paths = self.gen.generate_elite_reports(
            findings=findings, program_name="Test",
            platform="HackerOne", target="https://example.com",
        )
        summary_files = [p for p in paths if "master_summary" in p]
        self.assertTrue(len(summary_files) > 0)
        content = Path(summary_files[0]).read_text()
        self.assertIn("Elite Hunt", content)
        self.assertIn("Ready to Submit", content)


class TestVersion(unittest.TestCase):

    def test_version_exists(self):
        from vapt import __version__
        self.assertTrue(len(__version__) > 0)


if __name__ == "__main__":
    unittest.main()
