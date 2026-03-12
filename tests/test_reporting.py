
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from vapt.reporting.generator import ReportGenerator
from vapt.reporting.html import HTMLReporter
from vapt.reporting.json_report import JSONReporter


SAMPLE_SCAN = {
    "scan_id": "test-001",
    "target": "example.com",
    "started_at": "2026-01-01T00:00:00+00:00",
    "finished_at": "2026-01-01T00:05:00+00:00",
    "overall_score": 72.5,
    "risk_level": "high",
    "severity_counts": {"high": 2, "medium": 3},
    "findings": [
        {
            "vuln_id": "WEB-002",
            "category": "xss",
            "title": "Reflected XSS detected",
            "description": "Payload reflected in response.",
            "severity": "high",
            "cvss_score": 7.4,
            "risk_score": 74.0,
            "remediation": "Encode all output.",
        },
        {
            "vuln_id": "WEB-005",
            "category": "security_misconfiguration",
            "title": "Missing security header: Strict-Transport-Security",
            "description": "HSTS missing",
            "severity": "medium",
            "cvss_score": 5.3,
            "risk_score": 50.0,
            "remediation": "Add HSTS header.",
        },
    ],
    "attack_chains": [],
    "correlation_summary": [],
    "compliance": {
        "OWASP": {"triggered_controls": ["OWASP-A03"], "control_count": 1, "status": "non-compliant"},
    },
}


class TestJSONReporter:
    def test_generates_valid_json(self, tmp_path):
        path = str(tmp_path / "report.json")
        JSONReporter().generate(SAMPLE_SCAN, path)
        assert Path(path).exists()
        with open(path) as f:
            data = json.load(f)
        assert data["scan_result"]["target"] == "example.com"

    def test_json_contains_version(self, tmp_path):
        path = str(tmp_path / "report.json")
        JSONReporter().generate(SAMPLE_SCAN, path)
        with open(path) as f:
            data = json.load(f)
        assert "vapt_cli_version" in data

    def test_json_contains_generated_at(self, tmp_path):
        path = str(tmp_path / "report.json")
        JSONReporter().generate(SAMPLE_SCAN, path)
        with open(path) as f:
            data = json.load(f)
        assert "generated_at" in data

    def test_json_findings_preserved(self, tmp_path):
        path = str(tmp_path / "report.json")
        JSONReporter().generate(SAMPLE_SCAN, path)
        with open(path) as f:
            data = json.load(f)
        findings = data["scan_result"]["findings"]
        assert len(findings) == 2
        assert findings[0]["vuln_id"] == "WEB-002"


class TestHTMLReporter:
    def test_generates_html_file(self, tmp_path):
        path = str(tmp_path / "report.html")
        HTMLReporter().generate(SAMPLE_SCAN, path)
        assert Path(path).exists()

    def test_html_contains_target(self, tmp_path):
        path = str(tmp_path / "report.html")
        HTMLReporter().generate(SAMPLE_SCAN, path)
        content = Path(path).read_text(encoding="utf-8")
        assert "example.com" in content

    def test_html_contains_risk_level(self, tmp_path):
        path = str(tmp_path / "report.html")
        HTMLReporter().generate(SAMPLE_SCAN, path)
        content = Path(path).read_text(encoding="utf-8")
        assert "high" in content.lower()

    def test_html_contains_findings(self, tmp_path):
        path = str(tmp_path / "report.html")
        HTMLReporter().generate(SAMPLE_SCAN, path)
        content = Path(path).read_text(encoding="utf-8")
        assert "WEB-002" in content

    def test_recommendations_in_report(self, tmp_path):
        path = str(tmp_path / "report.html")
        HTMLReporter().generate(SAMPLE_SCAN, path)
        content = Path(path).read_text(encoding="utf-8")
        assert "Recommendations" in content


class TestReportGenerator:
    def test_generates_json_format(self, tmp_path):
        gen = ReportGenerator(output_dir=tmp_path)
        paths = gen.generate(SAMPLE_SCAN, formats=["json"])
        assert "json" in paths
        assert Path(paths["json"]).exists()

    def test_generates_html_format(self, tmp_path):
        gen = ReportGenerator(output_dir=tmp_path)
        paths = gen.generate(SAMPLE_SCAN, formats=["html"])
        assert "html" in paths
        assert Path(paths["html"]).exists()

    def test_generates_multiple_formats(self, tmp_path):
        gen = ReportGenerator(output_dir=tmp_path)
        paths = gen.generate(SAMPLE_SCAN, formats=["json", "html"])
        assert "json" in paths
        assert "html" in paths

    def test_custom_filename_prefix(self, tmp_path):
        gen = ReportGenerator(output_dir=tmp_path)
        paths = gen.generate(SAMPLE_SCAN, formats=["json"], filename_prefix="my_report")
        assert "my_report.json" in paths["json"]

    def test_output_dir_created_if_missing(self, tmp_path):
        nested = tmp_path / "deep" / "nested"
        gen = ReportGenerator(output_dir=nested)
        paths = gen.generate(SAMPLE_SCAN, formats=["json"])
        assert Path(paths["json"]).exists()
