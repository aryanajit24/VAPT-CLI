"""Tests for VAPT CLI knowledge base, risk scorer, correlator, and compliance engine."""

from __future__ import annotations

import pytest

from vapt.engine.knowledge_base import KnowledgeBase
from vapt.engine.risk_scorer import RiskScorer
from vapt.engine.correlator import Correlator
from vapt.engine.compliance import ComplianceEngine


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path):
    """Return a temporary SQLite database path and seed it."""
    db_path = str(tmp_path / "test_vapt.db")
    from vapt.database.seed_kb import seed
    seed(db_path)
    return db_path


@pytest.fixture
def kb(tmp_db):
    return KnowledgeBase(db_path=tmp_db)


@pytest.fixture
def compliance_engine(tmp_db):
    return ComplianceEngine(db_path=tmp_db)


SAMPLE_FINDINGS = [
    {
        "vuln_id": "WEB-001",
        "category": "injection",
        "title": "SQL Injection",
        "severity": "critical",
        "cvss_score": 9.8,
        "cve_ids": None,
    },
    {
        "vuln_id": "WEB-002",
        "category": "xss",
        "title": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "cvss_score": 7.4,
        "cve_ids": None,
    },
    {
        "vuln_id": "NET-001",
        "category": "network",
        "title": "Open Unnecessary Port",
        "severity": "medium",
        "cvss_score": 5.3,
        "cve_ids": None,
    },
]


# ─── KnowledgeBase ────────────────────────────────────────────────────────────

class TestKnowledgeBase:
    def test_get_all_returns_entries(self, kb):
        entries = kb.get_all()
        assert len(entries) > 0

    def test_get_by_category_injection(self, kb):
        entries = kb.get_by_category("injection")
        assert all(e["category"] == "injection" for e in entries)
        assert len(entries) >= 1

    def test_get_by_id_known_entry(self, kb):
        entry = kb.get_by_id("WEB-001")
        assert entry is not None
        assert entry["vuln_id"] == "WEB-001"

    def test_get_by_id_unknown_returns_none(self, kb):
        entry = kb.get_by_id("DOES-NOT-EXIST")
        assert entry is None

    def test_get_by_severity_critical(self, kb):
        entries = kb.get_by_severity("critical")
        assert all(e["severity"] == "critical" for e in entries)

    def test_search_finds_sql_injection(self, kb):
        entries = kb.search("SQL")
        titles = [e["title"] for e in entries]
        assert any("SQL" in t for t in titles)

    def test_search_empty_result(self, kb):
        entries = kb.search("xyzzy_nonexistent_9999")
        assert entries == []

    def test_match_findings_enriches_vuln_id(self, kb):
        findings = [{"vuln_id": "WEB-001", "category": "injection"}]
        enriched = kb.match_findings(findings)
        assert enriched[0]["title"] == "SQL Injection"

    def test_match_findings_fallback_to_category(self, kb):
        findings = [{"category": "xss"}]
        enriched = kb.match_findings(findings)
        assert enriched[0].get("severity") == "high"

    def test_match_findings_unknown_category(self, kb):
        findings = [{"category": "unknown_xyz"}]
        enriched = kb.match_findings(findings)
        # Should not raise, should return the finding as-is
        assert enriched[0]["category"] == "unknown_xyz"


# ─── RiskScorer ───────────────────────────────────────────────────────────────

class TestRiskScorer:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_score_finding_critical(self):
        score = self.scorer.score_finding({"severity": "critical", "cvss_score": 9.8})
        assert score > 80

    def test_score_finding_low(self):
        score = self.scorer.score_finding({"severity": "low"})
        assert score < 50

    def test_score_finding_capped_at_100(self):
        score = self.scorer.score_finding(
            {"severity": "critical", "cvss_score": 10.0, "internet_facing": True, "exploit_available": True}
        )
        assert score <= 100.0

    def test_score_scan_returns_expected_keys(self):
        result = self.scorer.score_scan(SAMPLE_FINDINGS)
        assert "overall_score" in result
        assert "severity_counts" in result
        assert "scored_findings" in result
        assert "risk_level" in result

    def test_score_scan_empty_findings(self):
        result = self.scorer.score_scan([])
        assert result["overall_score"] == 0.0
        # Spec: 0-19 = minimal
        assert result["risk_level"] == "minimal"

    def test_severity_counts_correct(self):
        result = self.scorer.score_scan(SAMPLE_FINDINGS)
        counts = result["severity_counts"]
        assert counts.get("critical", 0) == 1
        assert counts.get("high", 0) == 1
        assert counts.get("medium", 0) == 1

    def test_risk_level_critical_for_high_score(self):
        # Spec formula: raw = count × weight.  8 criticals → 8×10 = 80 → critical band.
        findings = [{"severity": "critical", "cvss_score": 10.0} for _ in range(8)]
        result = self.scorer.score_scan(findings)
        assert result["risk_level"] in ("critical", "high")

    def test_risk_level_low_for_low_score(self):
        # 1 info finding → raw = 0.2 → spec band 0-19 = minimal
        findings = [{"severity": "info"}]
        result = self.scorer.score_scan(findings)
        assert result["risk_level"] in ("low", "minimal")


# ─── Correlator ───────────────────────────────────────────────────────────────

class TestCorrelator:
    def setup_method(self):
        self.correlator = Correlator()

    def test_correlate_returns_expected_keys(self):
        result = self.correlator.correlate(SAMPLE_FINDINGS)
        assert "grouped_by_category" in result
        assert "attack_chains" in result
        assert "related_cves" in result
        assert "correlation_summary" in result

    def test_grouped_by_category(self):
        result = self.correlator.correlate(SAMPLE_FINDINGS)
        assert "injection" in result["grouped_by_category"]
        assert "xss" in result["grouped_by_category"]

    def test_attack_chain_detected(self):
        findings_with_auth = SAMPLE_FINDINGS + [
            {"vuln_id": "WEB-003", "category": "authentication", "severity": "high"}
        ]
        result = self.correlator.correlate(findings_with_auth)
        chains = result["attack_chains"]
        categories_in_chains = [set(c["categories"]) for c in chains]
        assert any({"injection", "authentication"} == cats for cats in categories_in_chains)

    def test_no_attack_chains_single_category(self):
        single = [{"category": "network", "vuln_id": "NET-001"}]
        result = self.correlator.correlate(single)
        assert result["attack_chains"] == []

    def test_cve_cluster_built(self):
        findings_with_cve = [
            {"vuln_id": "CVE-001", "category": "cve", "cve_ids": "CVE-2021-44228"},
        ]
        result = self.correlator.correlate(findings_with_cve)
        cve_ids = [c["cve_id"] for c in result["related_cves"]]
        assert "CVE-2021-44228" in cve_ids

    def test_empty_findings(self):
        result = self.correlator.correlate([])
        assert result["attack_chains"] == []
        assert result["grouped_by_category"] == {}


# ─── ComplianceEngine ─────────────────────────────────────────────────────────

class TestComplianceEngine:
    def test_map_findings_returns_frameworks(self, compliance_engine):
        mapped = compliance_engine.map_findings(SAMPLE_FINDINGS)
        assert isinstance(mapped, dict)
        assert len(mapped) > 0

    def test_injection_maps_to_iso27001(self, compliance_engine):
        findings = [{"vuln_id": "WEB-001", "category": "injection", "compliance_tags": "ISO27001-A.14.2"}]
        mapped = compliance_engine.map_findings(findings)
        iso = mapped.get("ISO27001", [])
        control_ids = [c["control_id"] for c in iso]
        assert any("A.14.2" in cid or "ISO27001-A.14.2" in cid for cid in control_ids)

    def test_generate_dashboard_returns_status(self, compliance_engine):
        dashboard = compliance_engine.generate_dashboard(SAMPLE_FINDINGS)
        for fw, info in dashboard.items():
            assert "status" in info
            assert info["status"] in ("compliant", "non-compliant")

    def test_compliant_when_no_findings(self, compliance_engine):
        dashboard = compliance_engine.generate_dashboard([])
        for fw, info in dashboard.items():
            assert info["status"] == "compliant"

    def test_non_compliant_with_findings(self, compliance_engine):
        findings = [
            {"category": "injection", "compliance_tags": "OWASP-A03,ISO27001-A.14.2", "vuln_id": "WEB-001"}
        ]
        dashboard = compliance_engine.generate_dashboard(findings)
        statuses = [info["status"] for info in dashboard.values()]
        assert "non-compliant" in statuses
