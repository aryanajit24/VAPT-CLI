"""
Tests for VAPT CLI Gold Elite Edition modules.

Tests the 7 new modules:
  1. EliteIntelligenceEngine — novelty scoring, duplicate detection
  2. BusinessLogicScanner — business logic vuln detection
  3. DeepJSRecon — JavaScript analysis
  4. OOBManager — out-of-band testing
  5. AuthFlowScanner — authenticated flow testing
  6. SmartHuntOrchestrator — orchestration
  7. EliteReportGenerator — report generation
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 1. Elite Intelligence Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestEliteIntelligenceEngine(unittest.TestCase):
    """Test novelty scoring and duplicate detection."""

    def setUp(self):
        from vapt.engine.elite_intelligence import EliteIntelligenceEngine
        self.engine = EliteIntelligenceEngine()

    def test_analyze_returns_enriched_findings(self):
        """Findings should be enriched with novelty metadata."""
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
        """Missing security headers should be flagged as high duplicate risk."""
        findings = [
            {"title": "Missing X-Frame-Options", "category": "security_header", "severity": "low"},
        ]
        result = self.engine.analyze(findings)
        f = result[0]
        self.assertGreater(f["duplicate_risk"], 0.8)

    def test_cors_without_exfil_is_high_risk(self):
        """CORS without data exfiltration PoC should be high duplicate risk."""
        findings = [
            {"title": "CORS Misconfiguration", "category": "cors", "severity": "medium"},
        ]
        result = self.engine.analyze(findings)
        f = result[0]
        self.assertGreater(f["duplicate_risk"], 0.7)

    def test_idor_financial_gets_high_novelty(self):
        """IDOR on financial endpoints should have high novelty."""
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
        """Low-novelty common findings should be marked as skip."""
        findings = [
            {"title": "Missing Content-Security-Policy", "category": "security_header", "severity": "info"},
        ]
        result = self.engine.analyze(findings)
        f = result[0]
        self.assertEqual(f["submission_readiness"], "skip")

    def test_elite_summary_has_required_keys(self):
        """Elite summary should contain expected keys."""
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
        """CORS finding without HTML PoC should have low completeness."""
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
        """Multiple findings should be ranked by priority."""
        findings = [
            {"title": "Low finding", "category": "header", "severity": "info"},
            {"title": "High finding", "category": "idor", "severity": "critical",
             "url": "https://api.example.com/api/accounts/123"},
        ]
        result = self.engine.analyze(findings)
        # Higher severity should have lower rank number (higher priority)
        ranks = [f.get("priority_rank", 999) for f in result]
        self.assertTrue(any(r == 1 for r in ranks))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 2. Business Logic Scanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestBusinessLogicScanner(unittest.TestCase):
    """Test business logic vulnerability detection."""

    def setUp(self):
        from vapt.scanner.bizscan import BusinessLogicScanner
        self.scanner = BusinessLogicScanner(timeout=5)

    def test_has_financial_endpoints(self):
        """Scanner should have financial endpoint patterns."""
        from vapt.scanner.bizscan import FINANCIAL_ENDPOINTS
        self.assertTrue(len(FINANCIAL_ENDPOINTS) > 20)

    def test_has_promo_endpoints(self):
        """Scanner should have promo/coupon endpoint patterns."""
        from vapt.scanner.bizscan import PROMO_ENDPOINTS
        self.assertTrue(len(PROMO_ENDPOINTS) > 10)

    def test_run_returns_expected_keys(self):
        """Scanner run should return properly structured results."""
        with patch.object(self.scanner, '_discover_endpoints', return_value=[]):
            result = self.scanner.run("https://example.com")
        self.assertIn("findings", result)
        self.assertIn("endpoints_discovered", result)

    def test_negative_amount_payloads_exist(self):
        """Scanner should have negative amount test payloads."""
        # Access the method to verify it exists
        self.assertTrue(hasattr(self.scanner, '_test_negative_amounts'))

    def test_race_condition_test_exists(self):
        """Scanner should have race condition testing capability."""
        self.assertTrue(hasattr(self.scanner, '_test_race_conditions'))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3. Deep JS Recon
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestDeepJSRecon(unittest.TestCase):
    """Test JavaScript analysis capabilities."""

    def setUp(self):
        from vapt.scanner.deepjs import DeepJSRecon
        self.recon = DeepJSRecon(timeout=5)

    def test_has_api_call_patterns(self):
        """Should have regex patterns for API call detection."""
        from vapt.scanner.deepjs import API_CALL_PATTERNS
        self.assertTrue(len(API_CALL_PATTERNS) > 5)

    def test_has_route_patterns(self):
        """Should have regex patterns for client-side routes."""
        from vapt.scanner.deepjs import ROUTE_PATTERNS
        self.assertTrue(len(ROUTE_PATTERNS) > 3)

    def test_run_returns_expected_keys(self):
        """Recon run should return structured results."""
        with patch.object(self.recon, '_discover_js_files', return_value=[]):
            result = self.recon.run("https://example.com")
        self.assertIn("api_endpoints", result)
        self.assertIn("client_routes", result)
        self.assertIn("graphql_operations", result)
        self.assertIn("websocket_urls", result)
        self.assertIn("findings", result)

    def test_get_endpoints_for_scanning(self):
        """Should return flat list of endpoints."""
        self.recon.all_api_endpoints = [
            {"endpoint": "/api/v1/users", "method": "GET"},
            {"endpoint": "/api/v1/accounts", "method": "POST"},
        ]
        endpoints = self.recon.get_endpoints_for_scanning()
        self.assertIsInstance(endpoints, list)
        self.assertTrue(all(isinstance(e, str) for e in endpoints))

    def test_extract_api_endpoints_from_fetch(self):
        """Should extract API endpoints from fetch() calls."""
        js_content = """
        fetch('/api/v1/users', { method: 'GET' })
        fetch('/api/v2/accounts/me', { method: 'POST' })
        """
        self.recon._extract_api_endpoints(js_content, "https://example.com/app.js", "https://example.com")
        self.assertTrue(len(self.recon.api_endpoints) >= 2)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 4. OOB Manager
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestOOBManager(unittest.TestCase):
    """Test out-of-band testing capabilities."""

    def setUp(self):
        from vapt.engine.oob import OOBManager
        self.manager = OOBManager()

    def test_get_callback_url(self):
        """Should generate a callback URL with correlation ID."""
        url = self.manager.get_callback_url("test-ssrf")
        self.assertIsInstance(url, str)
        self.assertTrue(len(url) > 0)

    def test_generate_ssrf_payloads(self):
        """Should generate multiple SSRF payload categories."""
        payloads = self.manager.generate_ssrf_payloads("test-endpoint")
        self.assertIsInstance(payloads, dict)
        self.assertIn("basic", payloads)
        self.assertIn("cloud_metadata", payloads)

    def test_correlation_tracking(self):
        """Should track correlations between payloads and labels."""
        url = self.manager.get_callback_url("my-test")
        self.assertTrue(len(self.manager._correlation_map) > 0)

    def test_has_oob_payload_categories(self):
        """Should have payload templates for multiple vuln types."""
        from vapt.engine.oob import OOB_PAYLOADS
        self.assertIn("ssrf", OOB_PAYLOADS)
        self.assertIn("xxe", OOB_PAYLOADS)
        self.assertIn("xss_blind", OOB_PAYLOADS)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 5. Auth Flow Scanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestAuthFlowScanner(unittest.TestCase):
    """Test authenticated flow scanning."""

    def setUp(self):
        from vapt.scanner.authflow import AuthFlowScanner
        self.scanner = AuthFlowScanner(timeout=5)

    def test_run_returns_expected_keys(self):
        """Scanner should return structured results."""
        result = self.scanner.run("https://example.com")
        self.assertIn("findings", result)

    def test_has_idor_testing(self):
        """Scanner should have IDOR testing capability."""
        self.assertTrue(hasattr(self.scanner, '_test_idor'))

    def test_has_privilege_escalation_testing(self):
        """Scanner should have privilege escalation testing."""
        self.assertTrue(hasattr(self.scanner, '_test_privilege_escalation'))

    def test_has_session_management_testing(self):
        """Scanner should have session management testing."""
        self.assertTrue(hasattr(self.scanner, '_test_session_management'))

    def test_has_token_handling_testing(self):
        """Scanner should have token/JWT testing."""
        self.assertTrue(hasattr(self.scanner, '_test_token_handling'))

    def test_setup_session(self):
        """Should accept a requests session."""
        import requests
        session = requests.Session()
        self.scanner.setup_session(session, "A")
        self.assertEqual(self.scanner.session_a, session)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 6. Smart Hunt Orchestrator
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSmartHuntOrchestrator(unittest.TestCase):
    """Test the elite hunt orchestration."""

    def setUp(self):
        from vapt.engine.smart_hunt import SmartHuntOrchestrator
        self.hunt = SmartHuntOrchestrator(
            target="https://example.com",
            output_dir=tempfile.mkdtemp(),
        )

    def test_configure(self):
        """Should accept program configuration."""
        self.hunt.configure(
            program_name="TestProgram",
            platform="HackerOne",
            scope_in=["https://example.com", "https://api.example.com"],
        )
        self.assertEqual(self.hunt.program_name, "TestProgram")
        self.assertEqual(self.hunt.platform, "HackerOne")
        self.assertEqual(len(self.hunt.scope_in), 2)

    def test_has_all_phases(self):
        """Orchestrator should have all 8 phases."""
        self.assertTrue(hasattr(self.hunt, '_phase_1_js_recon'))
        self.assertTrue(hasattr(self.hunt, '_phase_2_endpoint_intel'))
        self.assertTrue(hasattr(self.hunt, '_phase_3_auth_testing'))
        self.assertTrue(hasattr(self.hunt, '_phase_4_business_logic'))
        self.assertTrue(hasattr(self.hunt, '_phase_5_oob_testing'))
        self.assertTrue(hasattr(self.hunt, '_phase_6_targeted_scanning'))
        self.assertTrue(hasattr(self.hunt, '_phase_7_elite_analysis'))
        self.assertTrue(hasattr(self.hunt, '_phase_8_reports'))

    def test_output_dir_created(self):
        """Output directory should be created on init."""
        self.assertTrue(Path(self.hunt.output_dir).exists())


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 7. Elite Report Generator
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestEliteReportGenerator(unittest.TestCase):
    """Test elite report generation."""

    def setUp(self):
        from vapt.reporting.elite_report import EliteReportGenerator
        self.tmpdir = tempfile.mkdtemp()
        self.gen = EliteReportGenerator(output_dir=self.tmpdir)

    def test_generate_reports_no_findings(self):
        """Should generate summary when no findings are reportable."""
        paths = self.gen.generate_elite_reports(
            findings=[],
            program_name="Test",
            platform="HackerOne",
            target="https://example.com",
        )
        self.assertTrue(len(paths) > 0)
        # Should create a summary-only file
        self.assertTrue(any("summary" in p for p in paths))

    def test_generate_reports_with_ready_finding(self):
        """Should generate full reports for ready findings."""
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
        # Should create .md report + _fields.txt + master summary
        self.assertTrue(len(paths) >= 3)
        # Check that markdown report exists
        md_files = [p for p in paths if p.endswith(".md") and "summary" not in p]
        self.assertTrue(len(md_files) > 0)
        # Verify content
        content = Path(md_files[0]).read_text()
        self.assertIn("IDOR on /api/accounts", content)
        self.assertIn("READY TO SUBMIT", content)

    def test_generate_h1_field_format(self):
        """Should generate HackerOne field format."""
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
        """High duplicate risk should show warning in field report."""
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
        """Should generate valid CVSS 4.0 vector strings."""
        finding = {"severity": "critical", "category": "rce", "requires_auth": False}
        vector = self.gen._build_cvss4_vector(finding)
        self.assertTrue(vector.startswith("CVSS:4.0/"))
        self.assertIn("AV:N", vector)

    def test_master_summary_generated(self):
        """Should generate master summary file."""
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 8. Version Check
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestVersion(unittest.TestCase):

    def test_version_is_8(self):
        from vapt import __version__
        self.assertTrue(__version__.startswith("8."))


if __name__ == "__main__":
    unittest.main()
