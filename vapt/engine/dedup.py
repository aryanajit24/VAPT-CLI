"""Duplicate detector — scores the likelihood a finding is already reported.

Uses pattern-based heuristics:
  - Common vulnerability patterns per program age/type
  - Well-known "first thing everyone reports" patterns
  - Category-based duplicate probability tables
  - Simple keyword matching against known common reports
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DuplicateScore:
    """Result of duplicate analysis for a single finding."""
    finding_id: str
    probability: float       # 0.0 – 1.0 (1.0 = almost certainly a duplicate)
    risk_level: str          # "low" | "medium" | "high" | "very_high"
    reasons: list[str] = field(default_factory=list)
    recommendation: str = ""


# Base duplicate probability per category.
# Higher values = more commonly reported, higher duplicate risk.
_CATEGORY_BASE_PROBABILITY: dict[str, float] = {
    "cors": 0.75,
    "open_redirect": 0.80,
    "clickjacking": 0.90,
    "missing_header": 0.85,
    "security_header": 0.85,
    "cookie_flags": 0.80,
    "info_disclosure": 0.65,
    "ssl": 0.70,
    "tls": 0.70,
    "server_info": 0.80,
    "technology_disclosure": 0.85,
    "actuator": 0.60,
    "exposed_debug_endpoint": 0.55,
    "exposed_file": 0.60,
    "sensitive_file": 0.65,
    "directory_listing": 0.70,
    "subdomain_takeover": 0.50,
    "xss": 0.40,
    "reflected_xss": 0.45,
    "dom_xss": 0.35,
    "stored_xss": 0.25,
    "sqli": 0.30,
    "ssrf": 0.30,
    "idor": 0.35,
    "csrf": 0.55,
    "jwt": 0.45,
    "ssti": 0.25,
    "race_condition": 0.30,
    "request_smuggling": 0.20,
    "oauth": 0.40,
    "host_header_injection": 0.50,
    "graphql_batching": 0.55,
    "prototype_pollution": 0.35,
    "crlf_injection": 0.40,
    "xxe": 0.25,
    "business_logic": 0.20,
    "privilege_escalation": 0.25,
    "account_takeover": 0.20,
}

# Keywords in finding titles/descriptions that indicate high-duplicate
_HIGH_DUPLICATE_KEYWORDS: list[tuple[str, float]] = [
    ("missing x-frame-options", 0.95),
    ("missing x-content-type", 0.95),
    ("missing strict-transport", 0.90),
    ("hsts", 0.85),
    ("content-security-policy", 0.80),
    ("cors wildcard", 0.80),
    ("clickjacking", 0.90),
    ("server version", 0.85),
    ("technology disclosure", 0.85),
    ("open redirect without", 0.85),
    ("self-xss", 0.95),
    ("autocomplete", 0.95),
    ("cookie without secure", 0.80),
    ("cookie without httponly", 0.75),
    ("rate limit", 0.70),
    ("brute force", 0.70),
    ("email enumeration", 0.60),
    ("username enumeration", 0.55),
    ("robots.txt", 0.90),
    ("sitemap.xml", 0.90),
    (".well-known", 0.85),
    ("source map", 0.60),
    ("stack trace", 0.55),
    ("verbose error", 0.55),
    ("graphql introspection", 0.65),
    ("version disclosure", 0.85),
    ("mixed content", 0.90),
    ("no rate limit", 0.65),
    ("password policy", 0.80),
    ("weak password", 0.80),
]

# Programs older than this (in months) get a penalty
_PROGRAM_AGE_PENALTY: list[tuple[int, float]] = [
    (36, 0.20),   # 3+ years: +20% duplicate risk
    (24, 0.15),   # 2+ years: +15%
    (12, 0.10),   # 1+ year: +10%
    (6, 0.05),    # 6+ months: +5%
]


class DuplicateDetector:
    """Rates the duplicate probability of each finding.

    The probability is a heuristic score between 0 and 1.
    It does NOT query external databases — it uses pattern matching
    against common vulnerability report patterns.
    """

    def __init__(
        self,
        program_age_months: int = 12,
        resolved_report_count: int = 0,
        custom_patterns: list[tuple[str, float]] | None = None,
    ) -> None:
        self._program_age = program_age_months
        self._resolved_count = resolved_report_count
        self._custom = custom_patterns or []

    def _age_penalty(self) -> float:
        for threshold, penalty in _PROGRAM_AGE_PENALTY:
            if self._program_age >= threshold:
                return penalty
        return 0.0

    def _resolved_penalty(self) -> float:
        if self._resolved_count >= 500:
            return 0.15
        if self._resolved_count >= 200:
            return 0.10
        if self._resolved_count >= 50:
            return 0.05
        return 0.0

    def score(self, finding: dict) -> DuplicateScore:
        """Score a single finding for duplicate probability."""
        fid = finding.get("id", finding.get("title", "unknown"))
        cat = finding.get("category", "").lower()
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        sev = finding.get("severity", "info").lower()
        text = f"{title} {desc} {cat}"

        reasons: list[str] = []
        base = _CATEGORY_BASE_PROBABILITY.get(cat, 0.30)
        reasons.append(f"Base probability for '{cat}': {base:.0%}")

        # Keyword matching
        keyword_boost = 0.0
        for keyword, prob in _HIGH_DUPLICATE_KEYWORDS + self._custom:
            if keyword in text:
                if prob > base + keyword_boost:
                    keyword_boost = max(keyword_boost, prob - base)
                    reasons.append(f"Matches common pattern: '{keyword}'")

        # Age and resolved count adjustments
        age_pen = self._age_penalty()
        if age_pen > 0:
            reasons.append(f"Program age ({self._program_age}mo): +{age_pen:.0%}")

        resolved_pen = self._resolved_penalty()
        if resolved_pen > 0:
            reasons.append(f"Resolved reports ({self._resolved_count}): +{resolved_pen:.0%}")

        # Severity discount — critical/high bugs are less likely to be dupes
        sev_discount = {"critical": 0.15, "high": 0.10, "medium": 0.05}.get(sev, 0.0)
        if sev_discount > 0:
            reasons.append(f"Severity discount ({sev}): -{sev_discount:.0%}")

        # Calculate final probability
        prob = min(1.0, max(0.0, base + keyword_boost + age_pen + resolved_pen - sev_discount))

        if prob >= 0.75:
            risk = "very_high"
            rec = "SKIP — almost certainly a duplicate. Find a unique angle or move on."
        elif prob >= 0.55:
            risk = "high"
            rec = "CAUTION — likely reported before. Only submit with strong PoC and unique impact."
        elif prob >= 0.35:
            risk = "medium"
            rec = "WORTH TRYING — moderate duplicate risk. Ensure PoC demonstrates clear impact."
        else:
            risk = "low"
            rec = "SUBMIT — low duplicate risk. Likely a novel finding."

        return DuplicateScore(
            finding_id=str(fid),
            probability=round(prob, 3),
            risk_level=risk,
            reasons=reasons,
            recommendation=rec,
        )

    def score_batch(self, findings: list[dict]) -> list[DuplicateScore]:
        return [self.score(f) for f in findings]

    def filter_likely_duplicates(
        self,
        findings: list[dict],
        threshold: float = 0.75,
    ) -> tuple[list[dict], list[dict]]:
        """Split findings into (worth_submitting, likely_duplicates)."""
        worth = []
        dupes = []
        for f in findings:
            s = self.score(f)
            f["_duplicate_score"] = s.probability
            f["_duplicate_risk"] = s.risk_level
            f["_duplicate_recommendation"] = s.recommendation
            if s.probability >= threshold:
                dupes.append(f)
            else:
                worth.append(f)
        return worth, dupes
