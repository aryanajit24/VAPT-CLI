"""Risk scoring engine with aggregate metrics."""

from __future__ import annotations

from typing import Any

# Per-severity weights — these come directly from the spec.
# A single critical finding adds 10 points; info findings barely register.
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
    "info": 0.2,
}

# We bucket findings into broad groups so the report can show
# a per-category breakdown ("Web is your biggest problem").
CATEGORY_GROUPS: dict[str, list[str]] = {
    "Web": ["xss", "injection", "ssrf", "xxe", "authentication", "csrf", "web"],
    "Network": ["network", "tls", "port", "service"],
    "API": ["api", "bola", "graphql", "rate_limiting"],
    "Config": ["security_misconfiguration", "config", "headers", "disclosure"],
}


class RiskScorer:
    """Compute risk scores — both per-finding and across an entire scan."""

    def score_finding(self, finding: dict[str, Any]) -> float:
        """
        Score a single finding on a 0–100 scale.

        If the finding already has a CVSS score, we use it directly
        (multiplied by 10 to fit our 0–100 range).  Otherwise we
        fall back to the severity band weight × 10.
        """
        severity = (finding.get("severity") or "info").lower()
        cvss = finding.get("cvss_score")
        if cvss is not None:
            try:
                return round(min(float(cvss) * 10.0, 100.0), 2)
            except (ValueError, TypeError):
                pass
        return round(SEVERITY_WEIGHTS.get(severity, 0.2) * 10.0, 2)

    def score_scan(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Roll up all findings into a single scan-level risk report.

        This is the main entry point.  It counts severities, applies the
        spec formula, computes per-category breakdowns, and returns
        everything the report generator needs to render a dashboard.
        """
        if not findings:
            return {
                "overall_score": 0.0,
                "severity_counts": {},
                "scored_findings": [],
                "risk_level": "minimal",
                "category_scores": {},
            }

        severity_counts: dict[str, int] = {}
        scored: list[dict[str, Any]] = []

        for finding in findings:
            score = self.score_finding(finding)
            enriched = dict(finding)
            enriched["risk_score"] = score
            scored.append(enriched)

            sev = (finding.get("severity") or "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Spec formula — sum the weighted severity counts, cap at 100.
        # Why cap?  Because a score of 300 isn't more useful than 100.
        raw = (
            severity_counts.get("critical", 0) * 10.0
            + severity_counts.get("high", 0) * 7.0
            + severity_counts.get("medium", 0) * 4.0
            + severity_counts.get("low", 0) * 1.0
            + severity_counts.get("info", 0) * 0.2
        )
        overall = round(min(raw, 100.0), 2)

        # Per-category breakdown
        category_scores = self._category_scores(findings)

        return {
            "overall_score": overall,
            "severity_counts": severity_counts,
            "scored_findings": scored,
            "risk_level": self._risk_level(overall),
            "category_scores": category_scores,
        }

    def _category_scores(self, findings: list[dict[str, Any]]) -> dict[str, float]:
        """Calculate per-category risk scores (Web, Network, API, Config)."""
        bucket: dict[str, list[dict]] = {k: [] for k in CATEGORY_GROUPS}

        for finding in findings:
            cat = (finding.get("category") or "").lower()
            for group, keywords in CATEGORY_GROUPS.items():
                if any(kw in cat for kw in keywords):
                    bucket[group].append(finding)
                    break

        result: dict[str, float] = {}
        for group, group_findings in bucket.items():
            if not group_findings:
                result[group] = 0.0
                continue
            counts: dict[str, int] = {}
            for f in group_findings:
                sev = (f.get("severity") or "info").lower()
                counts[sev] = counts.get(sev, 0) + 1
            raw = (
                counts.get("critical", 0) * 10.0
                + counts.get("high", 0) * 7.0
                + counts.get("medium", 0) * 4.0
                + counts.get("low", 0) * 1.0
                + counts.get("info", 0) * 0.2
            )
            result[group] = round(min(raw, 100.0), 2)
        return result

    @staticmethod
    def _risk_level(score: float) -> str:
        """Map a numeric score to a risk band label per the spec."""
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "minimal"
