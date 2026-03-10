
from __future__ import annotations

from typing import Any

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
    "info": 0.2,
}

CATEGORY_GROUPS: dict[str, list[str]] = {
    "Web": ["xss", "injection", "ssrf", "xxe", "authentication", "csrf", "web"],
    "Network": ["network", "tls", "port", "service"],
    "API": ["api", "bola", "graphql", "rate_limiting"],
    "Config": ["security_misconfiguration", "config", "headers", "disclosure"],
}


class RiskScorer:

    def score_finding(self, finding: dict[str, Any]) -> float:
        severity = (finding.get("severity") or "info").lower()
        cvss = finding.get("cvss_score")
        if cvss is not None:
            try:
                return round(min(float(cvss) * 10.0, 100.0), 2)
            except (ValueError, TypeError):
                pass
        return round(SEVERITY_WEIGHTS.get(severity, 0.2) * 10.0, 2)

    def score_scan(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
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

        raw = (
            severity_counts.get("critical", 0) * 10.0
            + severity_counts.get("high", 0) * 7.0
            + severity_counts.get("medium", 0) * 4.0
            + severity_counts.get("low", 0) * 1.0
            + severity_counts.get("info", 0) * 0.2
        )
        overall = round(min(raw, 100.0), 2)

        category_scores = self._category_scores(findings)

        return {
            "overall_score": overall,
            "severity_counts": severity_counts,
            "scored_findings": scored,
            "risk_level": self._risk_level(overall),
            "category_scores": category_scores,
        }

    def _category_scores(self, findings: list[dict[str, Any]]) -> dict[str, float]:
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
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "minimal"
