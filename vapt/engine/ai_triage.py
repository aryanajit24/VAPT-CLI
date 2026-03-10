
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from rich.console import Console

console = Console()

COMMON_DUPLICATES = {
    "security_headers": 0.95,
    "missing_csp": 0.90,
    "missing_hsts": 0.85,
    "cookie_no_httponly": 0.80,
    "cookie_no_secure": 0.80,
    "directory_listing": 0.75,
    "server_version_disclosure": 0.85,
    "x_powered_by": 0.90,
    "cors_wildcard": 0.60,
    "clickjacking": 0.70,
    "info_disclosure": 0.65,
    "tls_weak_cipher": 0.60,
    "ssl_expired": 0.50,
}

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
    "info": 0.5,
}

NOISE_PATTERNS = [
    r"missing.*header",
    r"cookie.*flag",
    r"server.*version",
    r"x-powered-by",
    r"robots\.txt",
    r"sitemap\.xml",
]

HIGH_VALUE_PATTERNS = [
    r"sql.*inject",
    r"remote.*code.*exec",
    r"command.*inject",
    r"ssrf",
    r"idor",
    r"privilege.*escal",
    r"authentication.*bypass",
    r"account.*takeover",
    r"race.*condition",
    r"deserialization",
    r"ssti",
    r"xxe",
    r"path.*traversal",
]


class AITriage:

    def __init__(self, program_context: dict[str, Any] | None = None):
        self.program_context = program_context or {}
        self.seen_findings: list[dict[str, Any]] = []

    def analyze(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        scored = []
        for finding in findings:
            analysis = self._analyze_single(finding)
            finding["triage"] = analysis
            scored.append(finding)

        scored.sort(key=lambda f: f["triage"]["report_score"], reverse=True)
        return scored

    def _analyze_single(self, finding: dict[str, Any]) -> dict[str, Any]:
        vuln_type = finding.get("type", finding.get("category", "unknown"))
        severity = finding.get("severity", "info").lower()
        raw_confidence = finding.get("confidence", "medium")
        if isinstance(raw_confidence, (int, float)):
            if raw_confidence >= 0.85:
                confidence = "confirmed"
            elif raw_confidence >= 0.7:
                confidence = "high"
            elif raw_confidence >= 0.4:
                confidence = "medium"
            else:
                confidence = "low"
        else:
            confidence = str(raw_confidence).lower()
        title = finding.get("title", "")
        url = finding.get("url", "")

        dup_score = self._duplicate_probability(vuln_type, title)
        novelty_score = self._novelty_score(vuln_type, title, url)
        impact_score = self._impact_score(vuln_type, severity)
        exploit_score = self._exploitability_score(finding)
        noise_score = self._noise_score(title, vuln_type)

        confidence_mult = {"confirmed": 1.0, "high": 0.85, "medium": 0.6, "low": 0.3}.get(
            confidence, 0.5
        )

        report_score = (
            (impact_score * 0.35)
            + (novelty_score * 0.25)
            + (exploit_score * 0.20)
            + ((1 - dup_score) * 0.20)
        ) * confidence_mult * (1 - noise_score * 0.5)

        report_score = max(0, min(100, report_score * 10))

        recommendation = self._recommendation(report_score, dup_score, finding)

        return {
            "report_score": round(report_score, 1),
            "duplicate_probability": round(dup_score, 2),
            "novelty_score": round(novelty_score, 2),
            "impact_score": round(impact_score, 2),
            "exploitability_score": round(exploit_score, 2),
            "noise_score": round(noise_score, 2),
            "recommendation": recommendation,
            "report_worthy": report_score >= 40,
            "needs_poc": confidence != "confirmed",
            "estimated_severity": self._estimated_severity(impact_score),
        }

    def _duplicate_probability(self, vuln_type: str, title: str) -> float:
        base_dup = COMMON_DUPLICATES.get(vuln_type, 0.3)

        if any(re.search(p, title, re.IGNORECASE) for p in HIGH_VALUE_PATTERNS):
            base_dup *= 0.5

        for seen in self.seen_findings:
            if seen.get("type") == vuln_type:
                base_dup = min(base_dup + 0.1, 0.99)

        return min(base_dup, 0.99)

    def _novelty_score(self, vuln_type: str, title: str, url: str) -> float:
        score = 5.0

        if any(re.search(p, title, re.IGNORECASE) for p in HIGH_VALUE_PATTERNS):
            score += 3.0

        if any(re.search(p, title, re.IGNORECASE) for p in NOISE_PATTERNS):
            score -= 3.0

        asset_reports = self.program_context.get("asset_reports", {})
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain in asset_reports:
            report_count = asset_reports[domain]
            if report_count == 0:
                score += 2.0
            elif report_count < 5:
                score += 1.0
            elif report_count > 20:
                score -= 2.0

        return max(0, min(10, score))

    def _impact_score(self, vuln_type: str, severity: str) -> float:
        base = SEVERITY_WEIGHTS.get(severity, 2)

        high_impact_types = {
            "sql_injection": 10,
            "command_injection": 10,
            "ssrf": 9,
            "idor": 9,
            "ssti": 9,
            "xxe": 8,
            "deserialization": 9,
            "privilege_escalation": 10,
            "authentication_bypass": 10,
            "account_takeover": 10,
            "race_condition": 8,
            "path_traversal": 8,
            "xss": 7,
        }

        type_score = high_impact_types.get(vuln_type, base)
        return max(base, type_score)

    def _exploitability_score(self, finding: dict[str, Any]) -> float:
        score = 5.0

        if finding.get("evidence"):
            score += 2.0
        if finding.get("payload"):
            score += 1.5
        if finding.get("screenshot"):
            score += 1.0
        if finding.get("response_snippet"):
            score += 0.5

        confidence = finding.get("confidence", "medium")
        if isinstance(confidence, (int, float)):
            if confidence >= 0.85:
                confidence_str = "confirmed"
            elif confidence >= 0.7:
                confidence_str = "high"
            else:
                confidence_str = "medium"
        else:
            confidence_str = str(confidence).lower()
        if confidence_str == "confirmed":
            score += 2.0
        elif confidence_str == "high":
            score += 1.0

        return min(10, score)

    def _noise_score(self, title: str, vuln_type: str) -> float:
        for pattern in NOISE_PATTERNS:
            if re.search(pattern, title, re.IGNORECASE):
                return 0.8
        if vuln_type in ("info_disclosure", "security_headers", "cookie_no_httponly"):
            return 0.6
        return 0.0

    def _recommendation(
        self,
        score: float,
        dup_prob: float,
        finding: dict[str, Any],
    ) -> str:
        if score >= 70:
            return "REPORT — High-value finding with strong evidence"
        elif score >= 50:
            if dup_prob > 0.7:
                return "REPORT WITH CAUTION — Moderate value but high duplicate risk"
            return "REPORT — Solid finding, gather additional proof if possible"
        elif score >= 30:
            if finding.get("confidence") == "confirmed":
                return "CONSIDER — Low novelty but confirmed exploitable"
            return "SKIP — Likely noise or duplicate"
        else:
            return "SKIP — Informational or high false-positive risk"

    def _estimated_severity(self, impact: float) -> str:
        if impact >= 9:
            return "critical"
        elif impact >= 7:
            return "high"
        elif impact >= 4:
            return "medium"
        elif impact >= 2:
            return "low"
        return "info"

    def filter_reportable(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        analyzed = self.analyze(findings)
        return [f for f in analyzed if f.get("triage", {}).get("report_worthy", False)]

    def generate_summary(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        analyzed = self.analyze(findings)

        total = len(analyzed)
        reportable = sum(1 for f in analyzed if f.get("triage", {}).get("report_worthy"))
        skipped = total - reportable

        by_severity = {}
        for f in analyzed:
            sev = f.get("triage", {}).get("estimated_severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        top_findings = [
            {
                "title": f.get("title", ""),
                "type": f.get("type", ""),
                "score": f.get("triage", {}).get("report_score", 0),
                "recommendation": f.get("triage", {}).get("recommendation", ""),
            }
            for f in analyzed[:10]
        ]

        return {
            "total_findings": total,
            "reportable": reportable,
            "skipped": skipped,
            "by_severity": by_severity,
            "top_findings": top_findings,
        }

    def generate_report_text(self, finding: dict[str, Any]) -> dict[str, str]:
        vuln_type = finding.get("type", "vulnerability")
        severity = finding.get("severity", "medium")
        url = finding.get("url", "")
        param = finding.get("param", "")
        evidence = finding.get("evidence", "")
        payload = finding.get("payload", "")

        title = finding.get("title") or f"{vuln_type.replace('_', ' ').title()} at {urlparse(url).path}"

        description = (
            f"A {severity}-severity {vuln_type.replace('_', ' ')} vulnerability "
            f"was identified at `{url}`"
        )
        if param:
            description += f" in the `{param}` parameter"
        description += "."

        if evidence:
            description += f"\n\n**Evidence:** {evidence}"
        if payload:
            description += f"\n\n**Payload:** `{payload}`"

        impact = self._generate_impact_text(vuln_type)
        steps = self._generate_steps(finding)

        return {
            "title": title,
            "description": description,
            "impact": impact,
            "steps_to_reproduce": steps,
        }

    def _generate_impact_text(self, vuln_type: str) -> str:
        impacts = {
            "sql_injection": (
                "An attacker can extract, modify, or delete arbitrary data from "
                "the backend database. In severe cases, this can lead to full "
                "server compromise via OS command execution."
            ),
            "xss": (
                "An attacker can execute arbitrary JavaScript in victims' browsers, "
                "enabling session hijacking, account takeover, and credential theft."
            ),
            "ssrf": (
                "An attacker can make the server send requests to internal services, "
                "potentially accessing cloud metadata, internal APIs, and sensitive "
                "infrastructure not exposed to the internet."
            ),
            "command_injection": (
                "An attacker can execute arbitrary OS commands on the server, "
                "leading to full system compromise."
            ),
            "idor": (
                "An attacker can access or modify data belonging to other users "
                "by manipulating resource identifiers."
            ),
            "ssti": (
                "An attacker can execute arbitrary code on the server through "
                "template injection, leading to remote code execution."
            ),
            "path_traversal": (
                "An attacker can read arbitrary files from the server filesystem, "
                "potentially exposing credentials, configuration, and source code."
            ),
            "cors_misconfiguration": (
                "An attacker can read authenticated responses cross-origin, "
                "stealing sensitive user data via a malicious website."
            ),
        }
        return impacts.get(
            vuln_type,
            "This vulnerability may allow an attacker to compromise the "
            "confidentiality, integrity, or availability of the application."
        )

    def _generate_steps(self, finding: dict[str, Any]) -> str:
        url = finding.get("url", "")
        param = finding.get("param", "")
        payload = finding.get("payload", "")
        method = finding.get("method", "GET")

        steps = f"1. Navigate to `{url}`\n"

        if param and payload:
            if method.upper() == "GET":
                steps += f"2. Set the `{param}` parameter to: `{payload}`\n"
                steps += f"3. Send the request and observe the response\n"
            else:
                steps += f"2. Send a {method} request with `{param}={payload}`\n"
                steps += f"3. Observe the server response\n"

        evidence = finding.get("evidence", "")
        if evidence:
            steps += f"4. Confirm: {evidence}\n"

        return steps
