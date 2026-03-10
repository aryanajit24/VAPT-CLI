
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EscalationPath:
    name: str
    source_category: str
    target_test: str
    description: str
    severity_if_confirmed: str
    requires_auth: bool = False


ESCALATION_PATHS: list[EscalationPath] = [
    EscalationPath(
        name="CORS → Data Exfiltration",
        source_category="cors",
        target_test="cors_exfil",
        description="CORS misconfiguration with credentials — attempt to read sensitive data cross-origin",
        severity_if_confirmed="high",
    ),
    EscalationPath(
        name="Open Redirect → OAuth Token Theft",
        source_category="open_redirect",
        target_test="oauth_redirect_chain",
        description="Chain open redirect with OAuth callback to steal authorization code",
        severity_if_confirmed="critical",
    ),
    EscalationPath(
        name="XSS → Session Hijack",
        source_category="xss",
        target_test="xss_session_theft",
        description="Reflected/Stored XSS — escalate to session cookie theft",
        severity_if_confirmed="critical",
    ),
    EscalationPath(
        name="SSRF → Cloud Metadata",
        source_category="ssrf",
        target_test="ssrf_metadata",
        description="SSRF to internal cloud metadata endpoint",
        severity_if_confirmed="critical",
    ),
    EscalationPath(
        name="IDOR → PII Exposure",
        source_category="idor",
        target_test="idor_pii",
        description="IDOR that leaks personally identifiable information",
        severity_if_confirmed="high",
        requires_auth=True,
    ),
    EscalationPath(
        name="GraphQL Batching → OTP Brute Force",
        source_category="graphql_batching",
        target_test="graphql_otp_brute",
        description="Use GraphQL batching to bypass rate limits on OTP verification",
        severity_if_confirmed="high",
    ),
    EscalationPath(
        name="JWT None Algorithm",
        source_category="jwt",
        target_test="jwt_none_alg",
        description="JWT accepts 'none' algorithm — forge arbitrary tokens",
        severity_if_confirmed="critical",
    ),
    EscalationPath(
        name="Host Header → Password Reset Poisoning",
        source_category="host_header_injection",
        target_test="host_reset_poison",
        description="Host header injection in password reset flow",
        severity_if_confirmed="high",
    ),
    EscalationPath(
        name="Race Condition → Double Spend",
        source_category="race_condition",
        target_test="race_double_spend",
        description="Race condition on financial endpoint — duplicate transaction",
        severity_if_confirmed="critical",
        requires_auth=True,
    ),
    EscalationPath(
        name="Exposed Actuator → RCE",
        source_category="actuator",
        target_test="actuator_rce",
        description="Spring Boot actuator env endpoint may leak secrets or allow RCE",
        severity_if_confirmed="critical",
    ),
    EscalationPath(
        name="SSTI → RCE",
        source_category="ssti",
        target_test="ssti_rce",
        description="Server-Side Template Injection — escalate to remote code execution",
        severity_if_confirmed="critical",
    ),
    EscalationPath(
        name="Subdomain Takeover → Phishing",
        source_category="subdomain_takeover",
        target_test="takeover_phishing",
        description="Dangling CNAME pointing to claimable service",
        severity_if_confirmed="high",
    ),
    EscalationPath(
        name="OAuth Misconfiguration → Account Takeover",
        source_category="oauth",
        target_test="oauth_ato",
        description="OAuth state/PKCE missing — hijack authorization flow",
        severity_if_confirmed="critical",
    ),
    EscalationPath(
        name="CSRF → State-Changing Action",
        source_category="csrf",
        target_test="csrf_state_change",
        description="CSRF on sensitive action (password change, email change, payment)",
        severity_if_confirmed="high",
        requires_auth=True,
    ),
    EscalationPath(
        name="Information Disclosure → Credential Theft",
        source_category="info_disclosure",
        target_test="info_creds",
        description="Exposed config/env/debug page may contain API keys or passwords",
        severity_if_confirmed="critical",
    ),
]

_CATEGORY_ALIASES: dict[str, str] = {
    "cors_misconfiguration": "cors",
    "cors": "cors",
    "redirect": "open_redirect",
    "open_redirect": "open_redirect",
    "reflected_xss": "xss",
    "stored_xss": "xss",
    "dom_xss": "xss",
    "xss": "xss",
    "ssrf": "ssrf",
    "server_side_request_forgery": "ssrf",
    "idor": "idor",
    "broken_access_control": "idor",
    "graphql_batching": "graphql_batching",
    "jwt": "jwt",
    "jwt_vulnerability": "jwt",
    "host_header_injection": "host_header_injection",
    "host_header": "host_header_injection",
    "race_condition": "race_condition",
    "double_spend": "race_condition",
    "actuator": "actuator",
    "exposed_debug_endpoint": "actuator",
    "ssti": "ssti",
    "template_injection": "ssti",
    "subdomain_takeover": "subdomain_takeover",
    "oauth": "oauth",
    "oauth_misconfiguration": "oauth",
    "csrf": "csrf",
    "missing_csrf": "csrf",
    "info_disclosure": "info_disclosure",
    "information_disclosure": "info_disclosure",
    "exposed_secret": "info_disclosure",
    "sensitive_file": "info_disclosure",
}


@dataclass
class Decision:
    action: str
    finding: dict
    escalation: EscalationPath | None = None
    reason: str = ""
    priority: int = 0


class DecisionEngine:

    def __init__(self, has_auth: bool = False, excluded_categories: set[str] | None = None) -> None:
        self.has_auth = has_auth
        self._excluded = excluded_categories or set()

    def decide(self, findings: list[dict]) -> list[Decision]:
        decisions: list[Decision] = []

        for finding in findings:
            raw_cat = finding.get("category", "").lower()
            cat = _CATEGORY_ALIASES.get(raw_cat, raw_cat)

            if cat in self._excluded:
                decisions.append(Decision(
                    action="skip", finding=finding,
                    reason=f"Category '{cat}' excluded by program rules",
                ))
                continue

            matched_paths = [p for p in ESCALATION_PATHS if p.source_category == cat]

            if not matched_paths:
                sev = finding.get("severity", "info").lower()
                priority = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 5}.get(sev, 0)
                decisions.append(Decision(
                    action="report", finding=finding,
                    reason="No escalation path — report as-is",
                    priority=priority,
                ))
                continue

            for path in matched_paths:
                if path.requires_auth and not self.has_auth:
                    decisions.append(Decision(
                        action="needs_auth", finding=finding,
                        escalation=path,
                        reason=f"Escalation '{path.name}' requires authenticated session",
                        priority=30,
                    ))
                else:
                    sev_score = {
                        "critical": 100, "high": 75, "medium": 50, "low": 25,
                    }.get(path.severity_if_confirmed, 10)
                    decisions.append(Decision(
                        action="escalate", finding=finding,
                        escalation=path,
                        reason=f"Can escalate via '{path.name}'",
                        priority=sev_score,
                    ))

        decisions.sort(key=lambda d: d.priority, reverse=True)
        return decisions

    def get_escalation_tests(self, decisions: list[Decision]) -> list[dict]:
        tests: list[dict] = []
        seen: set[str] = set()

        for d in decisions:
            if d.action != "escalate" or d.escalation is None:
                continue
            key = f"{d.escalation.target_test}:{d.finding.get('url', '')}"
            if key in seen:
                continue
            seen.add(key)
            tests.append({
                "test": d.escalation.target_test,
                "url": d.finding.get("url", ""),
                "finding": d.finding,
                "escalation": d.escalation.name,
                "expected_severity": d.escalation.severity_if_confirmed,
            })

        return tests

    def summarise(self, decisions: list[Decision]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for d in decisions:
            counts[d.action] = counts.get(d.action, 0) + 1
        return counts
