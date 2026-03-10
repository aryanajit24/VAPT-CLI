
from __future__ import annotations

import os
import tempfile
import json
import textwrap
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml


class TestScopeParser(unittest.TestCase):

    SAMPLE_YAML = textwrap.dedent("""\
        program:
          name: TestCorp
          platform: hackerone
          url: https://hackerone.com/testcorp

        scope:
          in_scope:
            - target: "*.testcorp.com"
              type: web
              eligible_for_bounty: true
              max_severity: critical
            - target: "api.testcorp.com"
              type: api
              eligible_for_bounty: true
          out_of_scope:
            - target: "blog.testcorp.com"
              type: web

        excluded_vulnerabilities:
          - category: missing_security_headers
            reason: Not eligible
            detail: X-Frame-Options etc considered informational
          - category: rate_limiting
            reason: Out of scope per policy

        bounty:
          - severity: critical
            min: 5000
            max: 20000
          - severity: high
            min: 2000
            max: 5000
          - severity: medium
            min: 500
            max: 2000
          - severity: low
            min: 100
            max: 500

        testing:
          max_requests_per_second: 10
          no_automated_scanners: false
          no_destructive_testing: true
          required_headers:
            X-Research: vapt-testing
    """)

    def _write_yaml(self, content: str) -> str:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        f.write(content)
        f.close()
        return f.name

    def setUp(self):
        self.path = self._write_yaml(self.SAMPLE_YAML)

    def tearDown(self):
        os.unlink(self.path)

    def test_load_program_scope(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        self.assertEqual(prog.program_name, "TestCorp")
        self.assertEqual(prog.platform, "hackerone")

    def test_in_scope_count(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        self.assertEqual(len(prog.in_scope_assets), 2)

    def test_out_of_scope_count(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        self.assertEqual(len(prog.out_of_scope_assets), 1)
        self.assertEqual(prog.out_of_scope_assets[0].target, "blog.testcorp.com")

    def test_bounty_eligible_targets(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        eligible = prog.bounty_eligible_targets
        self.assertEqual(len(eligible), 2)

    def test_web_targets(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        self.assertIn("*.testcorp.com", prog.web_targets)

    def test_api_targets(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        self.assertIn("api.testcorp.com", prog.api_targets)

    def test_excluded_categories(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        self.assertIn("missing_security_headers", prog.excluded_categories)
        self.assertIn("rate_limiting", prog.excluded_categories)

    def test_is_category_excluded(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        self.assertTrue(prog.is_category_excluded("missing_security_headers"))
        self.assertFalse(prog.is_category_excluded("xss"))

    def test_exclusion_reason(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        reason = prog.exclusion_reason("missing_security_headers")
        self.assertIn("Not eligible", reason)

    def test_bounty_tiers(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        self.assertEqual(len(prog.bounty_tiers), 4)
        crit_tier = [t for t in prog.bounty_tiers if t.severity == "critical"][0]
        self.assertEqual(crit_tier.min_usd, 5000)
        self.assertEqual(crit_tier.max_usd, 20000)

    def test_estimated_payout(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        mn, mx = prog.estimated_payout("critical")
        self.assertEqual(mn, 5000)
        self.assertEqual(mx, 20000)

    def test_estimated_payout_unknown_severity(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        mn, mx = prog.estimated_payout("none")
        self.assertEqual(mn, 0)
        self.assertEqual(mx, 0)

    def test_testing_rules(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        self.assertEqual(prog.testing.max_requests_per_second, 10)
        self.assertFalse(prog.testing.no_automated_scanners)
        self.assertTrue(prog.testing.no_destructive_testing)
        self.assertEqual(prog.testing.required_headers["X-Research"], "vapt-testing")

    def test_filter_findings_by_program(self):
        from vapt.engine.scope_parser import load_program_scope, filter_findings_by_program
        prog = load_program_scope(self.path)
        findings = [
            {"title": "XSS", "category": "xss", "severity": "high", "url": "https://test.testcorp.com"},
            {"title": "Missing Headers", "category": "missing_security_headers", "severity": "low"},
            {"title": "Rate Limit", "category": "rate_limiting", "severity": "info"},
        ]
        filtered = filter_findings_by_program(findings, prog)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["title"], "XSS")

    def test_missing_file_raises(self):
        from vapt.engine.scope_parser import load_program_scope
        with self.assertRaises(FileNotFoundError):
            load_program_scope("/nonexistent/scope.yaml")

    def test_scope_config_built(self):
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(self.path)
        self.assertIsNotNone(prog.scope_config)
        self.assertIn("*.testcorp.com", prog.scope_config.in_scope)

    def test_minimal_yaml(self):
        minimal = textwrap.dedent("""\
            scope:
              in_scope:
                - target: "example.com"
        """)
        path = self._write_yaml(minimal)
        from vapt.engine.scope_parser import load_program_scope
        prog = load_program_scope(path)
        self.assertEqual(len(prog.in_scope_assets), 1)
        os.unlink(path)


class TestRateController(unittest.TestCase):

    def test_default_profile(self):
        from vapt.engine.rate_controller import RateController
        rc = RateController()
        self.assertEqual(rc._profile.name, "normal")

    def test_aggressive_profile(self):
        from vapt.engine.rate_controller import RateController
        rc = RateController(profile="aggressive")
        self.assertEqual(rc._profile.name, "aggressive")

    def test_stealth_profile(self):
        from vapt.engine.rate_controller import RateController
        rc = RateController(profile="stealth")
        self.assertEqual(rc._profile.name, "stealth")

    def test_polite_profile(self):
        from vapt.engine.rate_controller import RateController
        rc = RateController(profile="polite")
        self.assertEqual(rc._profile.name, "polite")

    def test_invalid_profile_defaults(self):
        from vapt.engine.rate_controller import RateController
        rc = RateController(profile="invalid_name")
        self.assertEqual(rc._profile.name, "normal")

    def test_stats_returns_dict(self):
        from vapt.engine.rate_controller import RateController
        rc = RateController()
        s = rc.stats()
        self.assertIn("total_requests", s)
        self.assertIn("total_backoffs", s)
        self.assertEqual(s["total_requests"], 0)

    def test_required_headers_applied(self):
        from vapt.engine.rate_controller import RateController
        rc = RateController(required_headers={"X-Custom": "test123"})
        self.assertEqual(rc._required_headers["X-Custom"], "test123")

    def test_proxy_list_stored(self):
        from vapt.engine.rate_controller import RateController
        rc = RateController(proxies=["http://proxy1:8080", "http://proxy2:8080"])
        self.assertEqual(len(rc._proxies), 2)

    def test_ua_rotation_default_off(self):
        from vapt.engine.rate_controller import RateController
        rc = RateController()
        self.assertFalse(rc._rotate_ua)

    def test_ua_rotation_enabled(self):
        from vapt.engine.rate_controller import RateController
        rc = RateController(rotate_ua=True)
        self.assertTrue(rc._rotate_ua)


class TestDecisionEngine(unittest.TestCase):

    def setUp(self):
        from vapt.engine.decision import DecisionEngine
        self.engine = DecisionEngine(has_auth=True)

    def test_cors_escalation(self):
        findings = [{"title": "CORS Misconfiguration", "category": "cors", "severity": "medium"}]
        decisions = self.engine.decide(findings)
        self.assertTrue(len(decisions) > 0)
        d = decisions[0]
        self.assertEqual(d.action, "escalate")
        self.assertEqual(d.escalation.source_category, "cors")

    def test_xss_escalation(self):
        findings = [{"title": "Reflected XSS", "category": "xss", "severity": "high"}]
        decisions = self.engine.decide(findings)
        d = decisions[0]
        self.assertEqual(d.action, "escalate")

    def test_ssrf_escalation(self):
        findings = [{"title": "SSRF to Internal", "category": "ssrf", "severity": "high"}]
        decisions = self.engine.decide(findings)
        d = decisions[0]
        self.assertEqual(d.action, "escalate")

    def test_info_low_gets_reported_or_escalated(self):
        findings = [{"title": "Server Version Disclosure", "category": "information_disclosure", "severity": "info"}]
        decisions = self.engine.decide(findings)
        d = decisions[0]
        self.assertIn(d.action, ("report", "escalate"))

    def test_excluded_category_skipped(self):
        from vapt.engine.decision import DecisionEngine
        engine = DecisionEngine(has_auth=True, excluded_categories={"missing_security_headers"})
        findings = [{"title": "Missing X-Frame-Options", "category": "missing_security_headers", "severity": "low"}]
        decisions = engine.decide(findings)
        d = decisions[0]
        self.assertEqual(d.action, "skip")

    def test_no_auth_needs_auth(self):
        from vapt.engine.decision import DecisionEngine
        engine = DecisionEngine(has_auth=False)
        findings = [{"title": "IDOR", "category": "idor", "severity": "high"}]
        decisions = engine.decide(findings)
        d = decisions[0]
        self.assertEqual(d.action, "needs_auth")

    def test_escalation_tests_returned(self):
        findings = [{"title": "Open Redirect", "category": "redirect", "severity": "medium"}]
        decisions = self.engine.decide(findings)
        tests = self.engine.get_escalation_tests(decisions)
        self.assertIsInstance(tests, list)

    def test_summarise_returns_dict(self):
        findings = [
            {"title": "CORS", "category": "cors", "severity": "medium"},
            {"title": "XSS", "category": "xss", "severity": "high"},
        ]
        decisions = self.engine.decide(findings)
        summary = self.engine.summarise(decisions)
        self.assertIn("escalate", summary)
        self.assertIsInstance(summary, dict)

    def test_category_alias_matching(self):
        findings = [{"title": "Open Redirect", "category": "open_redirect", "severity": "medium"}]
        decisions = self.engine.decide(findings)
        d = decisions[0]
        self.assertEqual(d.action, "escalate")

    def test_empty_findings(self):
        decisions = self.engine.decide([])
        self.assertEqual(len(decisions), 0)


class TestDuplicateDetector(unittest.TestCase):

    def setUp(self):
        from vapt.engine.dedup import DuplicateDetector
        self.detector = DuplicateDetector(program_age_months=24, resolved_report_count=50)

    def test_missing_headers_very_high(self):
        finding = {"title": "Missing X-Frame-Options", "category": "missing_security_headers", "severity": "low"}
        score = self.detector.score(finding)
        self.assertGreaterEqual(score.probability, 0.75)
        self.assertEqual(score.risk_level, "very_high")

    def test_critical_idor_lower_risk(self):
        finding = {"title": "IDOR on /api/billing", "category": "idor", "severity": "critical"}
        score = self.detector.score(finding)
        self.assertLessEqual(score.probability, 0.7)

    def test_program_age_increases_risk(self):
        from vapt.engine.dedup import DuplicateDetector
        young = DuplicateDetector(program_age_months=1)
        old = DuplicateDetector(program_age_months=60)
        finding = {"title": "CORS", "category": "cors", "severity": "medium"}
        young_score = young.score(finding)
        old_score = old.score(finding)
        self.assertLess(young_score.probability, old_score.probability)

    def test_resolved_reports_increases_risk(self):
        from vapt.engine.dedup import DuplicateDetector
        few = DuplicateDetector(resolved_report_count=0)
        many = DuplicateDetector(resolved_report_count=200)
        finding = {"title": "XSS", "category": "xss", "severity": "high"}
        few_score = few.score(finding)
        many_score = many.score(finding)
        self.assertLess(few_score.probability, many_score.probability)

    def test_severity_discount(self):
        from vapt.engine.dedup import DuplicateDetector
        detector = DuplicateDetector()
        crit = {"title": "RCE via SSTI", "category": "ssti", "severity": "critical"}
        low = {"title": "SSTI info", "category": "ssti", "severity": "low"}
        crit_score = detector.score(crit)
        low_score = detector.score(low)
        self.assertLess(crit_score.probability, low_score.probability)

    def test_score_batch(self):
        findings = [
            {"title": "A", "category": "xss", "severity": "high"},
            {"title": "B", "category": "cors", "severity": "medium"},
        ]
        result = self.detector.score_batch(findings)
        self.assertEqual(len(result), 2)

    def test_filter_likely_duplicates(self):
        findings = [
            {"title": "Missing Headers", "category": "missing_security_headers", "severity": "low"},
            {"title": "IDOR critical", "category": "idor", "severity": "critical"},
        ]
        worth, dupes = self.detector.filter_likely_duplicates(findings, threshold=0.80)
        self.assertTrue(len(worth) >= 1)

    def test_probability_clamped(self):
        finding = {"title": "Missing headers everywhere", "category": "missing_security_headers", "severity": "info"}
        score = self.detector.score(finding)
        self.assertLessEqual(score.probability, 1.0)
        self.assertGreaterEqual(score.probability, 0.0)

    def test_empty_category_defaults(self):
        finding = {"title": "Unknown Vuln", "category": "something_random", "severity": "medium"}
        score = self.detector.score(finding)
        self.assertIsNotNone(score.probability)
        self.assertIn(score.risk_level, ("low", "medium", "high", "very_high"))


class TestProofGenerator(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from vapt.engine.proof import ProofGenerator
        self.gen = ProofGenerator(output_dir=self.tmpdir)

    def test_cors_poc_generation(self):
        finding = {
            "title": "CORS Misconfiguration",
            "category": "cors",
            "severity": "high",
            "url": "https://api.example.com/user",
        }
        artifacts = self.gen.generate(finding)
        self.assertIsInstance(artifacts, dict)
        self.assertIn("poc_html", artifacts)
        with open(artifacts["poc_html"]) as f:
            content = f.read()
        self.assertIn("fetch", content)
        self.assertIn("credentials", content)

    def test_csrf_poc_generation(self):
        finding = {
            "title": "CSRF on state change",
            "category": "csrf",
            "severity": "high",
            "url": "https://example.com/api/settings",
            "method": "POST",
        }
        artifacts = self.gen.generate(finding)
        self.assertIsInstance(artifacts, dict)
        self.assertIn("poc_html", artifacts)

    def test_xss_poc_generation(self):
        finding = {
            "title": "Reflected XSS",
            "category": "xss",
            "severity": "high",
            "url": "https://example.com/search?q=PAYLOAD",
            "payload": "<script>alert(1)</script>",
        }
        artifacts = self.gen.generate(finding)
        self.assertIsInstance(artifacts, dict)
        self.assertTrue(len(artifacts) > 0)

    def test_redirect_poc_generation(self):
        finding = {
            "title": "Open Redirect",
            "category": "redirect",
            "severity": "medium",
            "url": "https://example.com/redir?url=https://evil.com",
        }
        artifacts = self.gen.generate(finding)
        self.assertIsInstance(artifacts, dict)
        self.assertTrue(len(artifacts) > 0)

    def test_clickjacking_poc_generation(self):
        finding = {
            "title": "Clickjacking",
            "category": "clickjacking",
            "severity": "medium",
            "url": "https://example.com/settings",
        }
        artifacts = self.gen.generate(finding)
        self.assertIsInstance(artifacts, dict)
        self.assertIn("poc_html", artifacts)
        with open(artifacts["poc_html"]) as f:
            content = f.read()
        self.assertIn("iframe", content)

    def test_curl_command_generated(self):
        finding = {
            "title": "SSRF",
            "category": "ssrf",
            "severity": "high",
            "url": "https://example.com/fetch?url=http://169.254.169.254",
        }
        artifacts = self.gen.generate(finding)
        self.assertIn("curl", artifacts)

    def test_evidence_file_generated(self):
        finding = {
            "title": "Info Leak",
            "category": "information_disclosure",
            "severity": "medium",
            "url": "https://example.com/.env",
        }
        artifacts = self.gen.generate(finding)
        self.assertIn("evidence", artifacts)

    def test_generate_batch(self):
        findings = [
            {"title": "XSS", "category": "xss", "severity": "high", "url": "https://example.com/xss"},
            {"title": "CORS", "category": "cors", "severity": "medium", "url": "https://api.example.com"},
        ]
        all_artifacts = self.gen.generate_batch(findings)
        self.assertIsInstance(all_artifacts, list)
        self.assertEqual(len(all_artifacts), 2)

    def test_unknown_category_still_generates(self):
        finding = {
            "title": "Something Unusual",
            "category": "custom_vuln",
            "severity": "high",
            "url": "https://example.com/endpoint",
        }
        artifacts = self.gen.generate(finding)
        self.assertIsInstance(artifacts, dict)
        self.assertTrue(len(artifacts) > 0)


class TestHuntOrchestrator(unittest.TestCase):

    SCOPE_YAML = textwrap.dedent("""\
        program:
          name: TestTarget
          platform: hackerone

        scope:
          in_scope:
            - target: "test.example.com"
              type: web
              eligible_for_bounty: true
          out_of_scope:
            - target: "admin.example.com"

        excluded_vulnerabilities:
          - category: missing_security_headers

        testing:
          max_requests_per_second: 5
          no_destructive_testing: true
    """)

    def _write_scope(self) -> str:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        f.write(self.SCOPE_YAML)
        f.close()
        return f.name

    def test_orchestrator_loads(self):
        path = self._write_scope()
        try:
            from vapt.engine.hunt import HuntOrchestrator
            orch = HuntOrchestrator(scope_file=path, output_dir=tempfile.mkdtemp())
            self.assertEqual(orch.program.program_name, "TestTarget")
        finally:
            os.unlink(path)

    def test_phase1_understand(self):
        path = self._write_scope()
        try:
            from vapt.engine.hunt import HuntOrchestrator
            orch = HuntOrchestrator(scope_file=path, output_dir=tempfile.mkdtemp())
            strategy = orch._phase_1_understand()
            self.assertIn("program", strategy)
            self.assertIn("web_targets", strategy)
            self.assertIn("testing_constraints", strategy)
            self.assertEqual(strategy["program"], "TestTarget")
        finally:
            os.unlink(path)

    def test_orchestrator_respects_testing_rules(self):
        path = self._write_scope()
        try:
            from vapt.engine.hunt import HuntOrchestrator
            orch = HuntOrchestrator(scope_file=path, output_dir=tempfile.mkdtemp())
            self.assertTrue(orch.program.testing.no_destructive_testing)
        finally:
            os.unlink(path)

    def test_orchestrator_session_has_cookies(self):
        path = self._write_scope()
        try:
            from vapt.engine.hunt import HuntOrchestrator
            orch = HuntOrchestrator(
                scope_file=path,
                output_dir=tempfile.mkdtemp(),
                auth_cookies_a="session=abc123;token=xyz",
            )
            self.assertEqual(orch.session_a.cookies.get("session"), "abc123")
            self.assertEqual(orch.session_a.cookies.get("token"), "xyz")
        finally:
            os.unlink(path)

    def test_orchestrator_session_has_bearer(self):
        path = self._write_scope()
        try:
            from vapt.engine.hunt import HuntOrchestrator
            orch = HuntOrchestrator(
                scope_file=path,
                output_dir=tempfile.mkdtemp(),
                auth_bearer_a="eyJtoken",
            )
            self.assertIn("Authorization", orch.session_a.headers)
            self.assertEqual(orch.session_a.headers["Authorization"], "Bearer eyJtoken")
        finally:
            os.unlink(path)

    def test_missing_scope_file_raises(self):
        from vapt.engine.hunt import HuntOrchestrator
        with self.assertRaises(FileNotFoundError):
            HuntOrchestrator(scope_file="/nonexistent.yaml", output_dir=tempfile.mkdtemp())

    def test_output_dir_created(self):
        path = self._write_scope()
        tmpdir = tempfile.mkdtemp()
        out = os.path.join(tmpdir, "deep", "nested", "output")
        try:
            from vapt.engine.hunt import HuntOrchestrator
            orch = HuntOrchestrator(scope_file=path, output_dir=out)
            self.assertTrue(os.path.isdir(out))
        finally:
            os.unlink(path)


class TestIntegration(unittest.TestCase):

    def test_decision_then_dedup(self):
        from vapt.engine.decision import DecisionEngine
        from vapt.engine.dedup import DuplicateDetector

        engine = DecisionEngine(has_auth=True)
        detector = DuplicateDetector(program_age_months=24)

        findings = [
            {"title": "CORS on api endpoint", "category": "cors", "severity": "medium"},
            {"title": "Open Redirect", "category": "redirect", "severity": "medium"},
            {"title": "Missing X-Frame-Options", "category": "missing_security_headers", "severity": "low"},
        ]

        decisions = engine.decide(findings)
        escalated = [d.finding for d in decisions if d.action == "escalate"]
        self.assertTrue(len(escalated) >= 2)

        scores = detector.score_batch(escalated)
        for score in scores:
            self.assertIn(score.risk_level, ("low", "medium", "high", "very_high"))

    def test_dedup_then_proof(self):
        from vapt.engine.dedup import DuplicateDetector
        from vapt.engine.proof import ProofGenerator

        detector = DuplicateDetector()
        tmpdir = tempfile.mkdtemp()
        gen = ProofGenerator(output_dir=tmpdir)

        findings = [
            {"title": "Reflected XSS", "category": "xss", "severity": "high", "url": "https://example.com/xss"},
        ]

        worth, _ = detector.filter_likely_duplicates(findings, threshold=0.95)
        if worth:
            artifacts = gen.generate(worth[0])
            self.assertTrue(len(artifacts) > 0)

    def test_scope_then_decision(self):
        from vapt.engine.decision import DecisionEngine

        engine = DecisionEngine(has_auth=True, excluded_categories={"missing_security_headers"})

        findings = [
            {"title": "CORS", "category": "cors", "severity": "medium"},
            {"title": "Missing Headers", "category": "missing_security_headers", "severity": "low"},
        ]

        decisions = engine.decide(findings)
        actions = {d.action for d in decisions}
        self.assertIn("escalate", actions)
        self.assertIn("skip", actions)


if __name__ == "__main__":
    unittest.main()
