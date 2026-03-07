"""Elite intelligence engine with attack chain detection and duplicate prediction."""

from __future__ import annotations

import re
import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from pathlib import Path


# COMMONLY DUPLICATED VULNERABILITY PATTERNS
# These are what every researcher and automated tool finds first.
# Findings matching these patterns get HIGH duplicate_risk scores.

COMMON_DUPLICATES = {
    "missing_security_headers": {
        "patterns": [
            r"(?i)missing.*header", r"(?i)x-frame-options",
            r"(?i)content-security-policy", r"(?i)strict-transport",
            r"(?i)x-content-type", r"(?i)referrer-policy",
            r"(?i)permissions-policy", r"(?i)hsts",
        ],
        "duplicate_risk": 0.99,
        "reason": "Every automated scanner reports missing headers. Programs mark these informative.",
    },
    "cors_without_exfil": {
        "patterns": [
            r"(?i)cors.*wildcard", r"(?i)cors.*misconfig",
            r"(?i)access-control-allow-origin.*\*",
            r"(?i)cors.*reflect",
        ],
        "duplicate_risk": 0.95,
        "reason": "CORS requires full data exfiltration PoC. Header reflection alone is informative.",
    },
    "exposed_actuator": {
        "patterns": [
            r"(?i)actuator", r"(?i)/health", r"(?i)/info",
            r"(?i)/env", r"(?i)/metrics", r"(?i)spring.*boot",
            r"(?i)prometheus.*endpoint",
        ],
        "duplicate_risk": 0.97,
        "reason": "Actuator/health endpoints are #1 most reported. Every scanner checks /actuator.",
    },
    "telemetry_injection": {
        "patterns": [
            r"(?i)otel|opentelemetry", r"(?i)sentry.*dsn",
            r"(?i)telemetry.*inject", r"(?i)log.*inject",
            r"(?i)trace.*inject",
        ],
        "duplicate_risk": 0.90,
        "reason": "Telemetry keys in JS source are easily found by any JS secret scanner.",
    },
    "software_version_disclosure": {
        "patterns": [
            r"(?i)version.*disclos", r"(?i)server.*header",
            r"(?i)x-powered-by", r"(?i)technology.*disclos",
        ],
        "duplicate_risk": 0.99,
        "reason": "Version disclosure is always informative unless it leads to a specific CVE exploit.",
    },
    "directory_listing": {
        "patterns": [r"(?i)directory.*listing", r"(?i)index.*of"],
        "duplicate_risk": 0.95,
        "reason": "Directory listing is trivially found by any scanner.",
    },
    "robots_sitemap_exposure": {
        "patterns": [r"(?i)robots\.txt", r"(?i)sitemap\.xml"],
        "duplicate_risk": 0.99,
        "reason": "robots.txt/sitemap.xml are public by design. Not a vulnerability.",
    },
    "generic_info_disclosure": {
        "patterns": [
            r"(?i)stack.*trace", r"(?i)error.*message",
            r"(?i)debug.*mode", r"(?i)verbose.*error",
        ],
        "duplicate_risk": 0.85,
        "reason": "Error disclosure is commonly reported. Only impactful if it leaks secrets/paths.",
    },
    "clickjacking": {
        "patterns": [r"(?i)clickjack", r"(?i)x-frame-options.*missing"],
        "duplicate_risk": 0.98,
        "reason": "Clickjacking alone is almost always marked informative or N/A.",
    },
    "ssl_tls_issues": {
        "patterns": [
            r"(?i)weak.*cipher", r"(?i)tls.*1\.[01]",
            r"(?i)ssl.*vuln", r"(?i)certificate.*issue",
        ],
        "duplicate_risk": 0.92,
        "reason": "TLS/SSL issues are found by every SSL scanner. Rarely accepted as valid bounty.",
    },
    "open_redirect_basic": {
        "patterns": [r"(?i)open.*redirect.*(?:url|redirect|next|return|goto)"],
        "duplicate_risk": 0.80,
        "reason": "Basic open redirects on common params are heavily reported. Novel only if chained.",
    },
    "email_enumeration": {
        "patterns": [r"(?i)email.*enum", r"(?i)user.*enum"],
        "duplicate_risk": 0.88,
        "reason": "User/email enumeration is widely deprioritized by most programs.",
    },
    "rate_limiting_missing": {
        "patterns": [r"(?i)rate.*limit.*miss", r"(?i)no.*rate.*limit", r"(?i)brute.*force"],
        "duplicate_risk": 0.85,
        "reason": "Missing rate limiting alone is usually informative without full exploit chain.",
    },
    "public_api_key_exposure": {
        "patterns": [
            r"(?i)google.*maps.*key", r"(?i)publishable.*key",
            r"(?i)firebase.*api.*key", r"(?i)analytics.*key",
            r"(?i)public.*key.*expos",
        ],
        "duplicate_risk": 0.90,
        "reason": "Public-by-design API keys (Maps, GA, Firebase public) are not vulnerabilities.",
    },
    "password_reset_token_in_response": {
        "patterns": [
            r"(?i)password.*reset.*token.*response",
            r"(?i)reset.*token.*leak",
            r"(?i)forgot.*password.*token",
        ],
        "duplicate_risk": 0.85,
        "reason": "Auth endpoint token leaks are commonly tested. Often found within first few months.",
    },
    "default_credentials": {
        "patterns": [r"(?i)default.*cred", r"(?i)admin.*admin", r"(?i)test.*account"],
        "duplicate_risk": 0.90,
        "reason": "Default credentials are trivially tested by every researcher.",
    },
    "subdomain_takeover_cname": {
        "patterns": [r"(?i)subdomain.*takeover", r"(?i)dangling.*cname", r"(?i)cname.*unclaim"],
        "duplicate_risk": 0.80,
        "reason": "Subdomain takeover via CNAME is heavily hunted. Often reported within days.",
    },
}

# HIGH-VALUE FINDING PATTERNS
# These are what the top 1% of bounty hunters find — rarely duplicated.

HIGH_VALUE_PATTERNS = {
    "idor_financial": {
        "indicators": [
            r"(?i)idor.*(?:payment|transfer|withdraw|balance|account|portfolio|invest)",
            r"(?i)(?:payment|transfer|withdraw|balance|portfolio).*(?:id|uuid|ref)",
        ],
        "novelty_bonus": 0.40,
        "reason": "IDOR on financial operations = critical bug, rarely found by automated tools.",
    },
    "race_condition_financial": {
        "indicators": [
            r"(?i)race.*(?:payment|transfer|withdraw|deposit|redeem|coupon)",
            r"(?i)(?:double|duplicate).*(?:spend|transfer|withdraw)",
        ],
        "novelty_bonus": 0.50,
        "reason": "Race conditions on money operations are extremely high impact + hard to find.",
    },
    "privilege_escalation_authenticated": {
        "indicators": [
            r"(?i)privilege.*escalat", r"(?i)horizontal.*access",
            r"(?i)vertical.*access", r"(?i)admin.*access.*unauth",
        ],
        "novelty_bonus": 0.35,
        "reason": "Requires authenticated testing — most researchers don't bother creating accounts.",
    },
    "business_logic_bypass": {
        "indicators": [
            r"(?i)business.*logic", r"(?i)workflow.*bypass",
            r"(?i)approval.*bypass", r"(?i)verification.*bypass",
            r"(?i)kyc.*bypass", r"(?i)2fa.*bypass",
        ],
        "novelty_bonus": 0.45,
        "reason": "Business logic flaws can't be found by scanners — inherently novel.",
    },
    "ssrf_with_impact": {
        "indicators": [
            r"(?i)ssrf.*(?:internal|metadata|cloud|169\.254|127\.0)",
            r"(?i)ssrf.*(?:rce|read|exfil)",
        ],
        "novelty_bonus": 0.30,
        "reason": "SSRF with demonstrated internal access/data exfiltration is high impact.",
    },
    "auth_bypass_chain": {
        "indicators": [
            r"(?i)auth.*bypass", r"(?i)session.*(?:fixat|hijack)",
            r"(?i)oauth.*(?:redirect|steal|token)",
        ],
        "novelty_bonus": 0.35,
        "reason": "Authentication bypass requires deep understanding of auth flow.",
    },
    "sqli_confirmed": {
        "indicators": [
            r"(?i)(?:blind|time.*based|union|error.*based).*sql",
            r"(?i)sql.*inject.*(?:confirm|verify|extract)",
        ],
        "novelty_bonus": 0.25,
        "reason": "Confirmed SQLi with data extraction is always valid.",
    },
    "rce_any": {
        "indicators": [
            r"(?i)(?:remote|arbitrary).*(?:code|command).*exec",
            r"(?i)rce", r"(?i)command.*inject.*confirm",
        ],
        "novelty_bonus": 0.50,
        "reason": "RCE is always critical and accepted. The holy grail.",
    },
    "account_takeover_chain": {
        "indicators": [
            r"(?i)account.*takeover", r"(?i)ato",
            r"(?i)steal.*session", r"(?i)impersonat",
        ],
        "novelty_bonus": 0.40,
        "reason": "Full ATO chain typically requires multiple steps — hard to automate.",
    },
    "api_mass_assignment": {
        "indicators": [
            r"(?i)mass.*assign", r"(?i)parameter.*pollution",
            r"(?i)role.*escalat.*api", r"(?i)is_admin.*true",
        ],
        "novelty_bonus": 0.35,
        "reason": "Mass assignment requires understanding of API object schemas.",
    },
    "graphql_deep": {
        "indicators": [
            r"(?i)graphql.*(?:idor|inject|auth|bypass|mutation)",
            r"(?i)graphql.*(?:introspect.*sensitive|batch.*attack)",
        ],
        "novelty_bonus": 0.30,
        "reason": "Deep GraphQL bugs beyond basic introspection are valuable.",
    },
    "websocket_hijack": {
        "indicators": [
            r"(?i)websocket.*(?:hijack|inject|auth|cswsh)",
            r"(?i)cross.*site.*websocket",
        ],
        "novelty_bonus": 0.40,
        "reason": "WebSocket attacks are rarely tested — low competition.",
    },
    "prototype_pollution_to_rce": {
        "indicators": [
            r"(?i)prototype.*pollut.*(?:rce|xss|bypass)",
            r"(?i)__proto__.*(?:rce|exec|command)",
        ],
        "novelty_bonus": 0.45,
        "reason": "Prototype pollution with RCE/XSS chain is extremely high value.",
    },
    "cache_poisoning": {
        "indicators": [
            r"(?i)cache.*(?:poison|deception)",
            r"(?i)web.*cache.*(?:poison|key)",
        ],
        "novelty_bonus": 0.40,
        "reason": "Web cache poisoning requires deep understanding of caching layers.",
    },
    "request_smuggling_confirmed": {
        "indicators": [
            r"(?i)request.*smuggl.*(?:confirm|cl\.te|te\.cl|desync)",
            r"(?i)http.*desync",
        ],
        "novelty_bonus": 0.45,
        "reason": "Confirmed request smuggling is extremely high impact.",
    },
}

# POC COMPLETENESS REQUIREMENTS
# Each vulnerability type needs specific PoC elements to be accepted.

POC_REQUIREMENTS = {
    "cors": {
        "required": [
            "HTML PoC page that demonstrates data exfiltration",
            "Actual sensitive data extracted (not just header reflection)",
            "Victim scenario: user visits attacker page → data stolen",
        ],
        "insufficient": [
            "Only showing Access-Control-Allow-Origin header reflects origin",
            "curl command showing CORS headers",
            "Screenshot of headers without data theft",
        ],
    },
    "xss": {
        "required": [
            "Working payload that executes in browser",
            "Demonstration of impact (cookie theft, session hijack, or account action)",
            "Bypass of any CSP/sanitization present",
        ],
        "insufficient": [
            "alert(1) only without impact demonstration",
            "Self-XSS only (requires victim to paste code)",
            "XSS in non-sensitive context (404 page, etc)",
        ],
    },
    "ssrf": {
        "required": [
            "Demonstration of internal resource access",
            "Evidence of server-side request (metadata endpoint, internal IP, etc)",
            "Impact: data read, service interaction, or cloud credential theft",
        ],
        "insufficient": [
            "DNS interaction only (use OOB server to confirm)",
            "External URL fetch without internal pivot",
            "Redirect to external site",
        ],
    },
    "idor": {
        "required": [
            "Two different user accounts demonstrating cross-access",
            "Sensitive data or action performed on victim account",
            "Request/response showing unauthorized access",
        ],
        "insufficient": [
            "ID enumeration without demonstrating access to another user's data",
            "Public data accessible via sequential IDs",
            "Access to own data via different parameter",
        ],
    },
    "sqli": {
        "required": [
            "Evidence of database interaction (data extraction, time delay, error)",
            "Payload that demonstrates control over query",
            "Impact assessment (what data is accessible)",
        ],
        "insufficient": [
            "Error message mentioning SQL without injection proof",
            "WAF block message (this means it's protected)",
            "Generic 500 error on special characters",
        ],
    },
    "race_condition": {
        "required": [
            "Multiple concurrent requests demonstrating the race",
            "Evidence of unexpected state (double credit, duplicate resource, etc)",
            "Quantified impact (how much money/resources can be gained)",
        ],
        "insufficient": [
            "Slow endpoint without demonstrating race",
            "Theoretical race without working exploit",
            "Rate limit bypass without business impact",
        ],
    },
    "exposed_secret": {
        "required": [
            "Proof that the key/secret is valid and grants access",
            "Demonstration of what the key can do (API calls, data access)",
            "Evidence it's a production key (not test/demo)",
        ],
        "insufficient": [
            "API key pattern match without validation",
            "Public/publishable keys (Maps, GA, Stripe pk_)",
            "Keys that return 401/403 when used",
        ],
    },
}

# SENSITIVE ENDPOINT PATTERNS
# Endpoints that handle money, PII, or auth are the highest priority targets.

SENSITIVE_ENDPOINT_PATTERNS = {
    "financial": {
        "patterns": [
            r"/(?:api/)?v?\d*/?(payment|pay|transfer|withdraw|deposit|balance|wallet|transaction|invoice|billing|subscribe|checkout|order|fund|invest|portfolio|trade|dividend|redeem|coupon|promo|refund)",
            r"/(?:api/)?v?\d*/?(bank|card|iban|routing|swift|ach|wire|crypto)",
        ],
        "priority": "critical",
        "test_for": ["idor", "race_condition", "mass_assignment", "business_logic", "auth_bypass"],
    },
    "authentication": {
        "patterns": [
            r"/(?:api/)?v?\d*/?(auth|login|signup|register|password|reset|verify|otp|2fa|mfa|sso|oauth|token|session|logout)",
            r"/(?:api/)?v?\d*/?(forgot|recover|confirm|activate|deactivate)",
        ],
        "priority": "high",
        "test_for": ["token_leak", "brute_force", "bypass", "fixation", "enumeration"],
    },
    "user_data": {
        "patterns": [
            r"/(?:api/)?v?\d*/?(user|users|profile|account|settings|preferences|personal|kyc|identity|document|address)",
            r"/(?:api/)?v?\d*/?(me|self|my(?:-|_)?)",
        ],
        "priority": "high",
        "test_for": ["idor", "mass_assignment", "data_exposure", "privilege_escalation"],
    },
    "admin": {
        "patterns": [
            r"/(?:api/)?v?\d*/?(admin|manage|internal|dashboard|control|panel|backoffice|moderator|staff|operator)",
            r"/(?:api/)?v?\d*/?(system|config|configuration|debug|monitoring)",
        ],
        "priority": "critical",
        "test_for": ["auth_bypass", "privilege_escalation", "info_disclosure"],
    },
    "file_operations": {
        "patterns": [
            r"/(?:api/)?v?\d*/?(upload|download|file|attachment|media|image|document|export|import|csv)",
            r"/(?:api/)?v?\d*/?(report|generate|render|template)",
        ],
        "priority": "high",
        "test_for": ["ssrf", "xxe", "path_traversal", "unrestricted_upload", "command_injection"],
    },
    "communication": {
        "patterns": [
            r"/(?:api/)?v?\d*/?(message|chat|notification|email|sms|webhook|callback|event)",
        ],
        "priority": "medium",
        "test_for": ["idor", "injection", "ssrf_via_webhook"],
    },
    "search_filter": {
        "patterns": [
            r"/(?:api/)?v?\d*/?(search|filter|query|list|find|lookup|suggest|autocomplete)",
        ],
        "priority": "medium",
        "test_for": ["sqli", "nosql_injection", "idor_via_filter", "data_exposure"],
    },
    "graphql": {
        "patterns": [r"/graphql", r"/gql", r"/api/graphql"],
        "priority": "high",
        "test_for": ["introspection", "batch_attack", "nested_query_dos", "idor", "auth_bypass"],
    },
}

# PROGRAM RESPONSE PATTERNS — learn from H1/Bugcrowd analyst responses

PROGRAM_RESPONSE_INTELLIGENCE = {
    "informative_patterns": [
        "This is informative",
        "does not demonstrate sufficient impact",
        "please provide a working proof of concept",
        "this alone does not constitute a vulnerability",
        "out of scope",
        "accepted risk",
        "by design",
        "public information",
        "not a security issue",
    ],
    "duplicate_patterns": [
        "previously reported",
        "duplicate of",
        "already reported",
        "submitted previously",
        "original report",
    ],
    "rejection_reasons": {
        "no_poc": "Finding requires a complete working PoC demonstrating real impact",
        "no_impact": "Finding needs to show actual security impact, not just misconfiguration",
        "oos": "Finding is out of scope for the program",
        "by_design": "The behavior is intentional/accepted risk",
        "no_auth": "Need to test with authenticated session to demonstrate real impact",
        "incomplete_chain": "CORS/redirect/etc needs full exploit chain, not just header manipulation",
    },
}


class EliteIntelligenceEngine:
    """
    The brain that transforms VAPT-CLI from a broad scanner into a targeted bounty hunter.
    
    Analyzes findings through multiple lenses:
      1. Novelty Score (0.0 - 1.0): How likely is this finding to be novel?
      2. Duplicate Risk (0.0 - 1.0): How likely is this already reported?
      3. PoC Completeness (0.0 - 1.0): Is the proof of concept sufficient?
      4. Chain Potential: Can this finding be combined with others for higher impact?
      5. Submission Readiness: Is this finding ready for submission?
    """

    def __init__(self, program_history_file: str | None = None) -> None:
        """
        Parameters
        ----------
        program_history_file : str, optional
            Path to JSON file containing past submissions and their outcomes.
            This enables learning from previous duplicate/informative responses.
        """
        self.program_history: list[dict] = []
        self.suppressed_patterns: list[str] = []
        
        if program_history_file:
            self._load_program_history(program_history_file)

    def _load_program_history(self, filepath: str) -> None:
        """Load past submission outcomes to avoid repeating mistakes."""
        try:
            with open(filepath) as f:
                data = json.load(f)
            self.program_history = data.get("submissions", [])
            self.suppressed_patterns = data.get("suppressed_patterns", [])
        except (OSError, json.JSONDecodeError):
            pass

    def analyze(self, findings: list[dict], target_context: dict | None = None) -> list[dict]:
        """
        Run the full elite analysis pipeline on all findings.
        
        Returns findings enriched with:
          - novelty_score (float 0-1)
          - duplicate_risk (float 0-1)
          - poc_completeness (float 0-1)
          - chain_potential (list of potential chains)
          - submission_readiness (str: ready, needs_work, skip)
          - elite_recommendation (str: detailed recommendation)
          - priority_rank (int: 1=highest priority to submit)
        """
        target_context = target_context or {}
        
        for finding in findings:
            # Phase 1: Score novelty
            finding["novelty_score"] = self._score_novelty(finding)
            
            # Phase 2: Assess duplicate risk
            finding["duplicate_risk"] = self._assess_duplicate_risk(finding)
            
            # Phase 3: Check PoC completeness
            finding["poc_completeness"] = self._check_poc_completeness(finding)
            
            # Phase 4: Identify chain potential
            finding["chain_potential"] = self._find_chain_potential(finding, findings)
            
            # Phase 5: Calculate submission readiness
            finding["submission_readiness"] = self._assess_submission_readiness(finding)
            
            # Phase 6: Generate recommendation
            finding["elite_recommendation"] = self._generate_recommendation(finding)
        
        # Phase 7: Rank by priority
        findings = self._rank_findings(findings)
        
        return findings

    def _score_novelty(self, finding: dict) -> float:
        """
        Score how novel/unique a finding is likely to be.
        
        Higher score = more likely to be novel (not yet reported).
        
        Factors that INCREASE novelty:
          - Requires authentication (fewer researchers test these)
          - Business logic flaw (scanners can't find these)
          - Complex attack chain (requires manual analysis)
          - Non-obvious endpoint (not /login, /admin, etc.)
          - Race condition on specific business flow
          
        Factors that DECREASE novelty:
          - Surface-level finding (headers, CORS, info disclosure)
          - Unauthenticated discovery
          - Common endpoint (/actuator, /health, /robots.txt)
          - Pattern matches known common duplicates
        """
        score = 0.50  # Start at neutral
        
        category = finding.get("category", "").lower()
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        url = finding.get("url", "").lower()
        evidence = json.dumps(finding.get("evidence", {})).lower()
        search_text = f"{title} {description} {category} {evidence}"
        
        for pattern_name, config in HIGH_VALUE_PATTERNS.items():
            for indicator in config["indicators"]:
                if re.search(indicator, search_text):
                    score += config["novelty_bonus"]
                    break  # Only add bonus once per pattern category
        
        for dup_name, config in COMMON_DUPLICATES.items():
            for pattern in config["patterns"]:
                if re.search(pattern, search_text):
                    score -= config["duplicate_risk"] * 0.5
                    break
        
        if finding.get("requires_auth") or finding.get("authenticated"):
            score += 0.25  # Authenticated findings are rarer
        else:
            score -= 0.10  # Unauthenticated = more competition
        
        for ep_type, config in SENSITIVE_ENDPOINT_PATTERNS.items():
            for pattern in config["patterns"]:
                if re.search(pattern, url):
                    if config["priority"] == "critical":
                        score += 0.15
                    elif config["priority"] == "high":
                        score += 0.10
                    break
        
        steps = finding.get("steps_to_reproduce", [])
        if isinstance(steps, list) and len(steps) > 3:
            score += 0.10  # Multi-step findings are harder to find
        
        for pattern in self.suppressed_patterns:
            if re.search(pattern, search_text, re.IGNORECASE):
                score -= 0.40  # Previously rejected pattern
        
        return max(0.0, min(1.0, score))

    def _assess_duplicate_risk(self, finding: dict) -> float:
        """
        Estimate the probability that this finding has already been reported.
        
        Returns 0.0 (unique) to 1.0 (certainly duplicate).
        """
        risk = 0.20  # Base risk (20% of everything has been found)
        
        category = finding.get("category", "").lower()
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        search_text = f"{title} {description} {category}"
        
        max_dup_risk = 0.0
        matched_reason = None
        for dup_name, config in COMMON_DUPLICATES.items():
            for pattern in config["patterns"]:
                if re.search(pattern, search_text):
                    if config["duplicate_risk"] > max_dup_risk:
                        max_dup_risk = config["duplicate_risk"]
                        matched_reason = config["reason"]
                    break
        
        if max_dup_risk > 0:
            risk = max_dup_risk
            finding["_dup_reason"] = matched_reason
        
        if not finding.get("requires_auth") and not finding.get("authenticated"):
            risk = min(1.0, risk + 0.10)
        
        severity = finding.get("severity", "").lower()
        if severity in ("info", "low"):
            risk = min(1.0, risk + 0.15)
        
        # If we know the program has been running for years, increase risk
        program_age_months = finding.get("_program_age_months", 12)
        if program_age_months > 24:
            risk = min(1.0, risk + 0.10)
        elif program_age_months > 12:
            risk = min(1.0, risk + 0.05)
        
        return max(0.0, min(1.0, risk))

    def _check_poc_completeness(self, finding: dict) -> float:
        """
        Verify that the proof of concept is sufficient for submission.
        
        Returns 0.0 (no PoC) to 1.0 (complete, working PoC).
        """
        score = 0.0
        category = finding.get("category", "").lower()
        
        # Find the closest PoC requirement category
        poc_req = None
        for poc_cat, requirements in POC_REQUIREMENTS.items():
            if poc_cat in category or category in poc_cat:
                poc_req = requirements
                break
        
        if not poc_req:
            # No specific requirements — check general PoC presence
            evidence = finding.get("evidence", {})
            if evidence:
                score += 0.30
            if finding.get("request"):
                score += 0.20
            if finding.get("response"):
                score += 0.20
            if finding.get("payload"):
                score += 0.15
            if finding.get("steps_to_reproduce"):
                score += 0.15
            return min(1.0, score)
        
        # Check specific requirements
        evidence = finding.get("evidence", {})
        evidence_text = json.dumps(evidence).lower() if evidence else ""
        description = finding.get("description", "").lower()
        full_text = f"{evidence_text} {description}"
        
        # Has the basic evidence
        if evidence:
            score += 0.25
        
        # Has request/response pair
        if finding.get("request") and finding.get("response"):
            score += 0.25
        elif finding.get("request") or finding.get("response"):
            score += 0.10
        
        # Check for insufficient PoC indicators
        for insufficient in poc_req["insufficient"]:
            if insufficient.lower() in full_text:
                score -= 0.20
        
        # Has steps to reproduce
        steps = finding.get("steps_to_reproduce", [])
        if isinstance(steps, list) and len(steps) >= 3:
            score += 0.25
        elif isinstance(steps, list) and len(steps) >= 1:
            score += 0.10
        
        # Has impact demonstration
        if finding.get("impact") and len(str(finding["impact"])) > 50:
            score += 0.25
        
        return max(0.0, min(1.0, score))

    def _find_chain_potential(self, finding: dict, all_findings: list[dict]) -> list[dict]:
        """
        Identify potential attack chains that combine this finding with others.
        
        Multi-step chains are MUCH more likely to be novel and high-impact.
        """
        chains = []
        category = finding.get("category", "").lower()
        
        # Chain: CORS + sensitive endpoint → data exfiltration
        if "cors" in category:
            sensitive_eps = [
                f for f in all_findings
                if any(re.search(p, f.get("url", ""), re.IGNORECASE)
                       for patterns in SENSITIVE_ENDPOINT_PATTERNS.values()
                       for p in patterns["patterns"])
            ]
            if sensitive_eps:
                chains.append({
                    "chain": f"CORS → Data Exfiltration via {len(sensitive_eps)} sensitive endpoints",
                    "impact": "Steal user data cross-origin",
                    "severity_boost": "critical",
                    "required_poc": "HTML page demonstrating data theft from authenticated user",
                })
        
        # Chain: Open Redirect + OAuth → Token Theft
        if "redirect" in category:
            oauth_findings = [f for f in all_findings if "oauth" in f.get("category", "").lower()]
            if oauth_findings:
                chains.append({
                    "chain": "Open Redirect → OAuth Token Theft",
                    "impact": "Steal OAuth tokens via redirect manipulation",
                    "severity_boost": "critical",
                    "required_poc": "URL that redirects OAuth callback to attacker server",
                })
        
        # Chain: XSS + Session → Account Takeover
        if "xss" in category:
            chains.append({
                "chain": "XSS → Account Takeover",
                "impact": "Steal session cookies/tokens via XSS",
                "severity_boost": "critical",
                "required_poc": "XSS payload that exfiltrates auth cookies to attacker server",
            })
        
        # Chain: SSRF + Cloud Metadata → Cloud Credential Theft
        if "ssrf" in category:
            chains.append({
                "chain": "SSRF → Cloud Credential Theft",
                "impact": "Access cloud metadata to steal IAM credentials",
                "severity_boost": "critical",
                "required_poc": "SSRF payload reaching 169.254.169.254 or cloud metadata URL",
            })
        
        # Chain: IDOR + Financial Endpoint → Unauthorized Financial Access
        if "idor" in category:
            financial_eps = [
                f for f in all_findings
                if any(re.search(p, f.get("url", ""), re.IGNORECASE)
                       for p in SENSITIVE_ENDPOINT_PATTERNS.get("financial", {}).get("patterns", []))
            ]
            if financial_eps:
                chains.append({
                    "chain": "IDOR → Unauthorized Financial Access",
                    "impact": "Access other users' financial data/perform unauthorized transactions",
                    "severity_boost": "critical",
                    "required_poc": "Two accounts demonstrating cross-access to financial data",
                })
        
        # Chain: Info Disclosure + Internal URL → SSRF pivot
        if "info" in category or "disclosure" in category:
            ssrf_findings = [f for f in all_findings if "ssrf" in f.get("category", "").lower()]
            if ssrf_findings:
                chains.append({
                    "chain": "Info Disclosure → SSRF Internal Pivot",
                    "impact": "Use leaked internal URLs as SSRF targets",
                    "severity_boost": "high",
                    "required_poc": "Internal URL discovered + SSRF accessing it",
                })
        
        return chains

    def _assess_submission_readiness(self, finding: dict) -> str:
        """
        Determine if a finding is ready for submission.
        
        Returns:
          - "ready": High novelty, low duplicate risk, complete PoC → SUBMIT
          - "needs_work": Good finding but needs better PoC or chain → IMPROVE
          - "skip": High duplicate risk or low impact → DON'T SUBMIT
        """
        novelty = finding.get("novelty_score", 0)
        dup_risk = finding.get("duplicate_risk", 1)
        poc = finding.get("poc_completeness", 0)
        chains = finding.get("chain_potential", [])
        
        # Automatic skip conditions
        if dup_risk >= 0.90:
            return "skip"
        
        severity = finding.get("severity", "").lower()
        if severity in ("info", "low") and not chains:
            return "skip"
        
        # Ready conditions
        if novelty >= 0.60 and dup_risk < 0.50 and poc >= 0.60:
            return "ready"
        
        # Has chains that could elevate it
        if chains and novelty >= 0.40:
            return "needs_work"
        
        # Decent novelty but needs better PoC
        if novelty >= 0.50 and poc < 0.50:
            return "needs_work"
        
        # High dup risk but might still be worth it if severity is critical
        if severity == "critical" and dup_risk < 0.70:
            return "needs_work"
        
        if novelty < 0.35:
            return "skip"
        
        return "needs_work"

    def _generate_recommendation(self, finding: dict) -> str:
        """Generate a detailed recommendation for the finding."""
        readiness = finding.get("submission_readiness", "skip")
        novelty = finding.get("novelty_score", 0)
        dup_risk = finding.get("duplicate_risk", 0)
        poc = finding.get("poc_completeness", 0)
        chains = finding.get("chain_potential", [])
        
        parts = []
        
        if readiness == "skip":
            if dup_risk >= 0.90:
                reason = finding.get("_dup_reason", "commonly reported vulnerability pattern")
                parts.append(f"SKIP — High duplicate risk ({dup_risk:.0%}): {reason}")
            else:
                parts.append(f"SKIP — Low novelty ({novelty:.0%}) and/or insufficient impact.")
            parts.append("Focus your effort on higher-value targets instead.")
            
        elif readiness == "needs_work":
            parts.append(f"NEEDS WORK — Promising but not ready for submission.")
            if poc < 0.50:
                parts.append(f"  → PoC is incomplete ({poc:.0%}). Build a full working exploit.")
            if chains:
                parts.append(f"  → Chain potential detected! Combine with:")
                for chain in chains[:3]:
                    parts.append(f"    • {chain['chain']} → {chain['impact']}")
            if not finding.get("requires_auth"):
                parts.append(f"  → Consider testing with authenticated session for deeper access.")
                
        elif readiness == "ready":
            parts.append(f"READY TO SUBMIT — Novelty: {novelty:.0%}, Dup Risk: {dup_risk:.0%}, PoC: {poc:.0%}")
            if chains:
                parts.append(f"  → Can be elevated further by chaining:")
                for chain in chains[:2]:
                    parts.append(f"    • {chain['chain']}")
        
        return "\n".join(parts)

    def _rank_findings(self, findings: list[dict]) -> list[dict]:
        """
        Rank all findings by priority for submission.
        
        Priority formula:
          score = (novelty × 3) + (1 - duplicate_risk) × 2 + poc_completeness + severity_weight + chain_bonus
        """
        severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        
        for finding in findings:
            novelty = finding.get("novelty_score", 0)
            dup_risk = finding.get("duplicate_risk", 1)
            poc = finding.get("poc_completeness", 0)
            severity = severity_weights.get(finding.get("severity", "info").lower(), 0)
            chain_bonus = len(finding.get("chain_potential", [])) * 0.5
            
            priority_score = (
                (novelty * 3.0) +
                ((1.0 - dup_risk) * 2.0) +
                poc +
                (severity / 4.0) +
                chain_bonus
            )
            finding["_priority_score"] = priority_score
        
        # Sort by priority score (highest first)
        findings.sort(key=lambda f: f.get("_priority_score", 0), reverse=True)
        
        # Assign rank
        for idx, finding in enumerate(findings, 1):
            finding["priority_rank"] = idx
        
        return findings

    def generate_elite_summary(self, findings: list[dict]) -> dict:
        """
        Generate an executive summary of the elite analysis.
        
        Returns a dict with:
          - total_findings: int
          - ready_to_submit: int
          - needs_work: int
          - skipped: int
          - top_findings: list (top 5 by priority)
          - recommendations: list of overall recommendations
        """
        ready = [f for f in findings if f.get("submission_readiness") == "ready"]
        needs_work = [f for f in findings if f.get("submission_readiness") == "needs_work"]
        skipped = [f for f in findings if f.get("submission_readiness") == "skip"]
        
        recommendations = []
        
        if not ready and not needs_work:
            recommendations.append(
                "No novel findings detected. This suggests the target has been "
                "heavily tested. Focus on: 1) Authenticated testing with a real account, "
                "2) Business logic flaws in financial/transactional flows, "
                "3) Race conditions on state-changing operations, "
                "4) Deep JS analysis for hidden API endpoints."
            )
        
        if needs_work:
            recommendations.append(
                f"{len(needs_work)} finding(s) have potential but need work. "
                "Build full PoCs and look for attack chains before submitting."
            )
        
        if ready:
            recommendations.append(
                f"{len(ready)} finding(s) are ready to submit. "
                "Start with the highest priority finding and submit one at a time."
            )
        
        auth_findings = [f for f in findings if f.get("authenticated") or f.get("requires_auth")]
        if not auth_findings:
            recommendations.append(
                "NO AUTHENTICATED FINDINGS. This is the #1 reason for duplicates. "
                "Create a test account and test all authenticated endpoints."
            )
        
        return {
            "total_findings": len(findings),
            "ready_to_submit": len(ready),
            "needs_work": len(needs_work),
            "skipped": len(skipped),
            "top_findings": findings[:5],
            "recommendations": recommendations,
        }

    def save_program_history(self, filepath: str, submissions: list[dict]) -> None:
        """Save submission history for future duplicate avoidance."""
        data = {
            "submissions": submissions,
            "suppressed_patterns": self.suppressed_patterns,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    def add_suppressed_pattern(self, pattern: str) -> None:
        """Add a pattern to suppress (e.g., after getting a duplicate response)."""
        if pattern not in self.suppressed_patterns:
            self.suppressed_patterns.append(pattern)
