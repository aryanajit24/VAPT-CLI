
from __future__ import annotations

import re
from typing import Any

from vapt.engine.mega_kb import (
    MEGA_KB,
    FALSE_POSITIVE_RULES,
)


SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

CVSS_RANGES = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "info": (0.0, 0.0),
}

ATTACK_CHAINS = [
    {
        "name": "Complete Account Takeover Chain",
        "requires": [
            {"category_match": "authentication|oauth|jwt", "any": True},
            {"category_match": "xss|csrf|cors", "any": True},
        ],
        "impact": "Full account takeover — attacker chains auth weakness with client-side vuln to steal sessions",
        "severity": "critical",
        "cvss": 9.8,
    },
    {
        "name": "SSRF to Internal Service Access",
        "requires": [
            {"vuln_match": "ssrf|SSRF", "any": True},
            {"category_match": "infrastructure|cloud|database", "any": True},
        ],
        "impact": "SSRF pivots to internal services, enabling data exfiltration or RCE",
        "severity": "critical",
        "cvss": 9.6,
    },
    {
        "name": "Privilege Escalation via IDOR + Info Disclosure",
        "requires": [
            {"vuln_match": "idor|IDOR|WEB-020|WEB-021", "any": True},
            {"category_match": "info|disclosure|exposed", "any": True},
        ],
        "impact": "IDOR combined with info disclosure enables full privilege escalation",
        "severity": "critical",
        "cvss": 9.1,
    },
    {
        "name": "SQL Injection to Data Breach",
        "requires": [
            {"vuln_match": "sqli|sql.*inject|WEB-001|WEB-002|WEB-003", "any": True},
        ],
        "conditions": ["database_accessible"],
        "impact": "SQL injection with database access enables complete data breach",
        "severity": "critical",
        "cvss": 9.8,
    },
    {
        "name": "XSS + CORS = Cross-Origin Data Theft",
        "requires": [
            {"vuln_match": "xss|XSS|WEB-005|WEB-006|WEB-007", "any": True},
            {"vuln_match": "cors|CORS|WEB-031|WEB-032", "any": True},
        ],
        "impact": "XSS combined with CORS misconfiguration enables cross-origin data theft",
        "severity": "critical",
        "cvss": 9.3,
    },
    {
        "name": "Source Map + Exposed Secrets = Code Execution",
        "requires": [
            {"vuln_match": "source.map|INFRA-013", "any": True},
            {"vuln_match": "secret|key|token|credential|API.key", "any": True},
        ],
        "impact": "Source maps reveal secrets embedded in code, enabling API abuse or auth bypass",
        "severity": "high",
        "cvss": 8.5,
    },
    {
        "name": "Actuator + WAF Bypass = Internal Exposure",
        "requires": [
            {"vuln_match": "actuator|INFRA-001", "any": True},
            {"evidence_match": "bypass|waf|403.*200|trailing.slash", "any": True},
        ],
        "impact": "WAF bypass exposes Spring Boot actuator endpoints, leaking configs and metrics",
        "severity": "critical",
        "cvss": 9.2,
    },
    {
        "name": "Feature Flag + Config Exposure = Business Logic Bypass",
        "requires": [
            {"vuln_match": "feature.flag|launchdarkly|INFRA-015", "any": True},
            {"vuln_match": "config|INFRA-002|actuator", "any": True},
        ],
        "impact": "Feature flag enumeration + config exposure enables business logic manipulation",
        "severity": "high",
        "cvss": 8.2,
    },
    {
        "name": "Race Condition + Payment = Financial Loss",
        "requires": [
            {"vuln_match": "race|RACE-001|RACE-002", "any": True},
        ],
        "conditions": ["payment_endpoint"],
        "impact": "Race condition on financial endpoint enables double-spending or balance manipulation",
        "severity": "critical",
        "cvss": 9.5,
    },
    {
        "name": "Request Smuggling + Auth = Credential Theft",
        "requires": [
            {"vuln_match": "smuggl|SMUG-001", "any": True},
            {"category_match": "authentication|auth|session", "any": True},
        ],
        "impact": "Request smuggling poisons caches or steals credentials from other users",
        "severity": "critical",
        "cvss": 9.7,
    },
]


CRITICAL_IMPACT_KEYWORDS = [
    r"password", r"token", r"secret", r"api.key", r"private.key",
    r"credit.card", r"ssn", r"social.security", r"bank.account",
    r"admin", r"root", r"heapdump", r"env", r"database.*url",
    r"aws.*key|aws.*secret", r"session", r"cookie",
    r"rce|remote.code.execution", r"shell", r"command.injection",
]

HIGH_IMPACT_KEYWORDS = [
    r"email", r"phone", r"address", r"user.*id", r"account",
    r"metric", r"prometheus", r"grafana", r"internal",
    r"debug", r"trace", r"stack", r"config",
]

PAYMENT_KEYWORDS = [
    r"payment", r"checkout", r"cart", r"order", r"wallet",
    r"balance", r"credit", r"transfer", r"billing", r"invoice",
    r"subscription", r"charge",
]


class IntelligenceEngine:

    def __init__(self) -> None:
        self._kb_cache: dict[str, dict] = {}
        self._build_kb_index()

    def _build_kb_index(self) -> None:
        for entry in MEGA_KB:
            self._kb_cache[entry["vuln_id"]] = entry


    def analyze(
        self,
        findings: list[dict[str, Any]],
        target_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        context = target_context or {}

        enriched = [self._enrich_finding(f) for f in findings]

        enriched = [self._analyze_severity(f, context) for f in enriched]

        confirmed = self._eliminate_false_positives(enriched)

        chains = self._detect_chains(confirmed, context)

        confirmed = [self._assess_impact(f) for f in confirmed]

        risk_summary = self._generate_risk_summary(confirmed, chains)

        recommendations = self._generate_recommendations(confirmed, chains)

        return {
            "findings": confirmed,
            "chains": chains,
            "risk_summary": risk_summary,
            "recommendations": recommendations,
        }


    def _enrich_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        enriched = dict(finding)
        vuln_id = finding.get("vuln_id", "")

        kb_entry = self._kb_cache.get(vuln_id)
        if kb_entry:
            for key in ("cwe", "owasp", "detection", "validation", "impact",
                        "remediation", "is_critical_when", "is_not_critical_when"):
                if key in kb_entry and key not in enriched:
                    enriched[f"kb_{key}"] = kb_entry[key]

            enriched["kb_matched"] = True
            enriched["kb_vuln_id"] = vuln_id
        else:
            enriched["kb_matched"] = False

        return enriched


    def _analyze_severity(
        self, finding: dict[str, Any], context: dict[str, Any],
    ) -> dict[str, Any]:
        enriched = dict(finding)
        severity = (finding.get("severity") or "info").lower()
        evidence = (finding.get("evidence") or "").lower()
        title = (finding.get("title") or "").lower()
        url = (finding.get("url") or "").lower()
        vuln_id = finding.get("vuln_id", "")

        upgrade_reason = self._check_severity_upgrade(
            finding, evidence, title, url, context,
        )
        if upgrade_reason and SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["critical"]:
            enriched["original_severity"] = severity
            enriched["severity"] = "critical"
            enriched["severity_reason"] = upgrade_reason
            enriched["severity_adjusted"] = True

        downgrade_reason = self._check_severity_downgrade(
            finding, evidence, title, url, context,
        )
        if downgrade_reason:
            enriched["original_severity"] = severity
            enriched["severity_reason"] = downgrade_reason
            enriched["severity_adjusted"] = True
            if severity == "critical":
                enriched["severity"] = "high"
            elif severity == "high":
                enriched["severity"] = "medium"

        kb_critical_when = finding.get("kb_is_critical_when", "")
        if kb_critical_when and severity != "critical":
            conditions = kb_critical_when.split(";")
            for condition in conditions:
                condition = condition.strip().lower()
                if condition and condition in evidence:
                    enriched["original_severity"] = severity
                    enriched["severity"] = "critical"
                    enriched["severity_reason"] = f"KB critical condition met: {condition}"
                    enriched["severity_adjusted"] = True
                    break

        return enriched

    def _check_severity_upgrade(
        self,
        finding: dict,
        evidence: str,
        title: str,
        url: str,
        context: dict,
    ) -> str | None:
        severity = (finding.get("severity") or "info").lower()

        for pattern in CRITICAL_IMPACT_KEYWORDS:
            if re.search(pattern, evidence, re.IGNORECASE):
                return f"Critical data exposed: matches '{pattern}' in evidence"

        if "actuator" in title or "actuator" in evidence:
            for sensitive in ("env", "configprops", "heapdump", "shutdown"):
                if sensitive in evidence or sensitive in url:
                    return f"Spring Boot actuator /{sensitive} exposes sensitive configuration"

        if "no auth" in evidence or "without authentication" in evidence:
            if any(kw in title.lower() for kw in ("admin", "database", "redis", "mongo", "elastic")):
                return "Critical service accessible without authentication"

        if "bypass" in title.lower() or "bypass" in evidence:
            if severity in ("medium", "low", "info"):
                return "WAF bypass confirmed — security control circumvented"

        for pattern in PAYMENT_KEYWORDS:
            if re.search(pattern, url, re.IGNORECASE) or re.search(pattern, evidence, re.IGNORECASE):
                if severity in ("medium", "high"):
                    return f"Financial endpoint affected: matches '{pattern}'"

        return None

    def _check_severity_downgrade(
        self,
        finding: dict,
        evidence: str,
        title: str,
        url: str,
        context: dict,
    ) -> str | None:
        severity = (finding.get("severity") or "info").lower()
        vuln_id = finding.get("vuln_id", "")

        kb_not_critical = finding.get("kb_is_not_critical_when", "")
        if kb_not_critical and severity == "critical":
            conditions = kb_not_critical.split(";")
            for condition in conditions:
                condition = condition.strip().lower()
                if condition and condition in evidence:
                    return f"KB downgrade rule: {condition}"

        if "actuator" in title.lower() and "health" in evidence:
            if "env" not in evidence and "heapdump" not in evidence and "configprops" not in evidence:
                if severity == "critical":
                    return "Actuator health-only exposure is informational, not critical"

        if "header" in title.lower() and "missing" in title.lower():
            if severity in ("high", "critical"):
                return "Missing security headers are Medium at most without demonstrated exploit"

        if "disclosure" in title.lower() or "information" in title.lower():
            has_sensitive = any(
                re.search(p, evidence, re.IGNORECASE)
                for p in CRITICAL_IMPACT_KEYWORDS
            )
            if not has_sensitive and severity in ("high", "critical"):
                return "Information disclosure without sensitive data exposure"

        if "error" in evidence and "stack" not in evidence and "sql" not in evidence:
            if severity == "high":
                return "Generic error messages without stack trace are Low severity"

        return None


    def _eliminate_false_positives(
        self, findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        confirmed = []

        for finding in findings:
            if self._is_false_positive(finding, FALSE_POSITIVE_RULES):
                finding["eliminated"] = True
                finding["fp_reason"] = finding.get("_fp_reason", "Matched FP pattern")
                continue
            confirmed.append(finding)

        return confirmed

    def _is_false_positive(
        self, finding: dict[str, Any], fp_rules: dict,
    ) -> bool:
        category = (finding.get("category") or "").lower()
        evidence = (finding.get("evidence") or "").lower()
        title = (finding.get("title") or "").lower()
        vuln_id = (finding.get("vuln_id") or "")

        for fp_category, rules in fp_rules.items():
            if fp_category in category or fp_category in vuln_id.lower():
                indicators = rules.get("false_if", [])
                for indicator in indicators:
                    if indicator.lower() in evidence or indicator.lower() in title:
                        finding["_fp_reason"] = f"FP rule [{fp_category}]: {indicator}"
                        return True

        if self._is_generic_fp(finding):
            return True

        return False

    def _is_generic_fp(self, finding: dict[str, Any]) -> bool:
        evidence = (finding.get("evidence") or "").lower()
        confidence = finding.get("confidence", 0.5)

        if confidence < 0.3:
            finding["_fp_reason"] = f"Confidence too low: {confidence}"
            return True

        if not evidence.strip():
            finding["_fp_reason"] = "No evidence provided"
            return True

        waf_indicators = ["captcha", "challenge", "blocked by", "access denied",
                          "cloudflare", "akamai", "incapsula"]
        if any(ind in evidence for ind in waf_indicators):
            if finding.get("severity", "").lower() in ("critical", "high"):
                finding["_fp_reason"] = "WAF/CDN interference detected in evidence"
                return True

        return False


    def _detect_chains(
        self,
        findings: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        chains = []

        for chain_def in ATTACK_CHAINS:
            matching_findings = self._match_chain(chain_def, findings, context)
            if matching_findings:
                chains.append({
                    "name": chain_def["name"],
                    "severity": chain_def["severity"],
                    "cvss": chain_def["cvss"],
                    "impact": chain_def["impact"],
                    "findings": matching_findings,
                    "finding_count": len(matching_findings),
                })

        return chains

    def _match_chain(
        self,
        chain_def: dict,
        findings: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> list[dict[str, Any]] | None:
        requirements = chain_def.get("requires", [])
        all_matched = []

        for req in requirements:
            matched = False
            for finding in findings:
                if self._finding_matches_requirement(finding, req):
                    if finding not in all_matched:
                        all_matched.append(finding)
                    matched = True

            if not matched and not req.get("optional"):
                return None

        conditions = chain_def.get("conditions", [])
        for condition in conditions:
            if condition == "database_accessible":
                if not any(f.get("category", "").lower() in ("database", "infrastructure")
                          for f in findings):
                    return None
            elif condition == "payment_endpoint":
                has_payment = any(
                    any(re.search(p, f.get("url", ""), re.IGNORECASE)
                        for p in PAYMENT_KEYWORDS)
                    for f in findings
                )
                if not has_payment:
                    return None

        return all_matched if all_matched else None

    def _finding_matches_requirement(
        self, finding: dict[str, Any], req: dict,
    ) -> bool:
        for key, pattern in req.items():
            if key == "any":
                continue

            if key == "category_match":
                value = (finding.get("category") or "")
                if not re.search(pattern, value, re.IGNORECASE):
                    return False

            elif key == "vuln_match":
                combined = " ".join([
                    finding.get("vuln_id", ""),
                    finding.get("title", ""),
                    finding.get("category", ""),
                ])
                if not re.search(pattern, combined, re.IGNORECASE):
                    return False

            elif key == "evidence_match":
                value = (finding.get("evidence") or "")
                if not re.search(pattern, value, re.IGNORECASE):
                    return False

        return True


    def _assess_impact(self, finding: dict[str, Any]) -> dict[str, Any]:
        enriched = dict(finding)
        evidence = (finding.get("evidence") or "").lower()
        title = (finding.get("title") or "").lower()
        severity = (finding.get("severity") or "info").lower()

        impacts = []

        data_patterns = {
            "PII exposure": [r"email", r"phone", r"address", r"name", r"user"],
            "Credential leak": [r"password", r"token", r"secret", r"api.key", r"session"],
            "Financial data": [r"credit.card", r"bank", r"payment", r"balance", r"account.number"],
            "Infrastructure secrets": [r"aws", r"azure", r"gcp", r"database.*url", r"connection.*string"],
            "Source code exposure": [r"source.map", r"\.git", r"backup.*\.zip", r"\.sql"],
        }

        for impact_type, patterns in data_patterns.items():
            for pattern in patterns:
                if re.search(pattern, evidence, re.IGNORECASE):
                    impacts.append(impact_type)
                    break

        if severity == "critical":
            enriched["business_impact"] = "CRITICAL — Immediate remediation required"
            if impacts:
                enriched["business_impact"] += f". Risk of: {', '.join(impacts)}"
        elif severity == "high":
            enriched["business_impact"] = "HIGH — Significant security risk"
            if impacts:
                enriched["business_impact"] += f". Potential: {', '.join(impacts)}"
        elif severity == "medium":
            enriched["business_impact"] = "MEDIUM — Should be addressed in next sprint"
        else:
            enriched["business_impact"] = "LOW — Track and remediate during maintenance"

        enriched["impact_categories"] = impacts

        return enriched


    def _generate_risk_summary(
        self,
        findings: list[dict[str, Any]],
        chains: list[dict[str, Any]],
    ) -> dict[str, Any]:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        total = len(findings)
        chain_count = len(chains)

        raw_score = (
            severity_counts["critical"] * 10
            + severity_counts["high"] * 7
            + severity_counts["medium"] * 4
            + severity_counts["low"] * 1
        )
        raw_score += chain_count * 15
        overall_score = min(raw_score, 100)

        if overall_score >= 80:
            risk_level = "CRITICAL"
            executive_summary = (
                f"The target has {severity_counts['critical']} critical and "
                f"{severity_counts['high']} high severity vulnerabilities with "
                f"{chain_count} attack chains detected. Immediate remediation required."
            )
        elif overall_score >= 60:
            risk_level = "HIGH"
            executive_summary = (
                f"Significant security issues found: {total} vulnerabilities "
                f"including {severity_counts['high']}+ high severity findings."
            )
        elif overall_score >= 40:
            risk_level = "MEDIUM"
            executive_summary = (
                f"Moderate security posture: {total} findings detected. "
                f"Key issues should be addressed within current sprint."
            )
        elif overall_score >= 20:
            risk_level = "LOW"
            executive_summary = f"Generally good security posture with {total} minor findings."
        else:
            risk_level = "MINIMAL"
            executive_summary = "Target appears well-secured. Minimal issues found."

        return {
            "risk_level": risk_level,
            "risk_score": overall_score,
            "severity_counts": severity_counts,
            "total_findings": total,
            "attack_chains": chain_count,
            "executive_summary": executive_summary,
            "adjusted_findings": sum(
                1 for f in findings if f.get("severity_adjusted")
            ),
        }


    def _generate_recommendations(
        self,
        findings: list[dict[str, Any]],
        chains: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        recs = []

        for chain in chains:
            recs.append({
                "priority": 1,
                "type": "attack_chain",
                "title": f"Break attack chain: {chain['name']}",
                "description": chain["impact"],
                "severity": chain["severity"],
                "affected_findings": [
                    f.get("vuln_id", "unknown") for f in chain["findings"]
                ],
            })

        critical = [f for f in findings if f.get("severity") == "critical"]
        for finding in critical:
            remediation = finding.get("kb_remediation") or finding.get("remediation", "")
            recs.append({
                "priority": 2,
                "type": "critical_finding",
                "title": f"Fix: {finding.get('title', 'Unknown')}",
                "description": remediation or "Immediate remediation required.",
                "severity": "critical",
                "vuln_id": finding.get("vuln_id", ""),
            })

        high = [f for f in findings if f.get("severity") == "high"]
        for finding in high:
            remediation = finding.get("kb_remediation") or finding.get("remediation", "")
            recs.append({
                "priority": 3,
                "type": "high_finding",
                "title": f"Address: {finding.get('title', 'Unknown')}",
                "description": remediation or "Should be addressed promptly.",
                "severity": "high",
                "vuln_id": finding.get("vuln_id", ""),
            })

        medium = [f for f in findings if f.get("severity") == "medium"]
        quick_win_keywords = ["header", "cookie", "cors", "disclosure", "config"]
        for finding in medium:
            title_lower = (finding.get("title") or "").lower()
            if any(kw in title_lower for kw in quick_win_keywords):
                recs.append({
                    "priority": 4,
                    "type": "quick_win",
                    "title": f"Quick fix: {finding.get('title', 'Unknown')}",
                    "description": finding.get("remediation", ""),
                    "severity": "medium",
                    "vuln_id": finding.get("vuln_id", ""),
                })

        return sorted(recs, key=lambda r: r["priority"])


    @staticmethod
    def is_more_severe(sev_a: str, sev_b: str) -> bool:
        return SEVERITY_RANK.get(sev_a.lower(), 0) > SEVERITY_RANK.get(sev_b.lower(), 0)

    @staticmethod
    def get_severity_rank(severity: str) -> int:
        return SEVERITY_RANK.get(severity.lower(), 0)
