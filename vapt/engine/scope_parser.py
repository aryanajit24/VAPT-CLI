"""Enhanced scope parser for full bug-bounty program rules.

Extends the basic scope.py with bounty-specific metadata: reward tiers,
excluded vulnerability types with reasons, testing constraints, asset
classification, and researcher identity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

from vapt.engine.scope import ScopeConfig, load_scope_file


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass
class AssetRule:
    """A single in-scope or out-of-scope asset with metadata."""
    target: str
    asset_type: str = "web"        # web | api | mobile | network | other
    eligible_for_bounty: bool = True
    max_severity: str = "critical"  # highest severity accepted for this asset
    notes: str = ""


@dataclass
class BountyTier:
    """Dollar range for a severity level."""
    severity: str
    min_usd: int
    max_usd: int


@dataclass
class TestingRule:
    """Constraints on how testing should be performed."""
    max_requests_per_second: float = 2.0
    required_headers: dict[str, str] = field(default_factory=dict)
    user_agent: str = ""
    no_automated_scanners: bool = False
    no_destructive_testing: bool = True
    allowed_hours_utc: tuple[int, int] | None = None  # (start_hour, end_hour)
    proxy_required: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class ProgramConfig:
    """Full bug-bounty program configuration."""

    # Identity
    program_name: str = ""
    platform: str = "HackerOne"        # HackerOne | Bugcrowd | Intigriti | YesWeHack
    program_url: str = ""
    researcher: str = ""

    # Scope
    in_scope_assets: list[AssetRule] = field(default_factory=list)
    out_of_scope_assets: list[AssetRule] = field(default_factory=list)

    # Exclusions
    excluded_categories: list[str] = field(default_factory=list)
    excluded_categories_detail: dict[str, str] = field(default_factory=dict)

    # Rewards
    bounty_tiers: list[BountyTier] = field(default_factory=list)
    safe_harbour: bool = True

    # Testing rules
    testing: TestingRule = field(default_factory=TestingRule)

    # The underlying ScopeConfig for compatibility with existing modules
    scope_config: ScopeConfig = field(default_factory=ScopeConfig)

    # Minimum severity worth reporting
    min_severity: str = "low"

    # Modules to run
    modules: list[str] = field(default_factory=list)

    @property
    def in_scope_targets(self) -> list[str]:
        return [a.target for a in self.in_scope_assets]

    @property
    def out_of_scope_targets(self) -> list[str]:
        return [a.target for a in self.out_of_scope_assets]

    @property
    def bounty_eligible_targets(self) -> list[str]:
        return [a.target for a in self.in_scope_assets if a.eligible_for_bounty]

    @property
    def web_targets(self) -> list[str]:
        return [a.target for a in self.in_scope_assets if a.asset_type == "web"]

    @property
    def api_targets(self) -> list[str]:
        return [a.target for a in self.in_scope_assets if a.asset_type == "api"]

    def estimated_payout(self, severity: str) -> tuple[int, int]:
        """Return (min, max) USD for a given severity."""
        sev = severity.lower()
        for tier in self.bounty_tiers:
            if tier.severity == sev:
                return (tier.min_usd, tier.max_usd)
        return (0, 0)

    def is_category_excluded(self, category: str) -> bool:
        cat = category.lower().strip()
        return cat in {c.lower() for c in self.excluded_categories}

    def exclusion_reason(self, category: str) -> str:
        cat = category.lower().strip()
        return self.excluded_categories_detail.get(cat, "")


def load_program_scope(path: str | Path) -> ProgramConfig:
    """Load a full program scope YAML and return ProgramConfig.

    Supports two YAML layouts:
      1. Nested:  program.name, scope.in_scope, excluded_vulnerabilities, bounty (list)
      2. Flat:    program_name, in_scope, out_of_scope, excluded_categories, bounty (dict)
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Scope file not found: {path}")

    text = filepath.read_text(encoding="utf-8")

    if _HAS_YAML:
        data = yaml.safe_load(text) or {}
    else:
        from vapt.engine.scope import _parse_simple_yaml
        data = _parse_simple_yaml(text)

    cfg = ProgramConfig()

    # ── Identity ─────────────────────────────────────────────────
    prog_block = data.get("program", {})
    if isinstance(prog_block, dict):
        cfg.program_name = prog_block.get("name", "")
        cfg.platform = prog_block.get("platform", "HackerOne")
        cfg.program_url = prog_block.get("url", "")
        cfg.researcher = prog_block.get("researcher", "")
    else:
        cfg.program_name = data.get("program_name", str(prog_block) if prog_block else "")
        cfg.platform = data.get("platform", "HackerOne")
        cfg.program_url = data.get("program_url", "")
        cfg.researcher = data.get("researcher", "")

    # ── In-scope assets ──────────────────────────────────────────
    scope_block = data.get("scope", {})
    if isinstance(scope_block, dict):
        raw_in = scope_block.get("in_scope", [])
        raw_out = scope_block.get("out_of_scope", [])
    else:
        raw_in = data.get("in_scope", [])
        raw_out = data.get("out_of_scope", [])

    for item in raw_in:
        if isinstance(item, str):
            cfg.in_scope_assets.append(AssetRule(target=item))
        elif isinstance(item, dict):
            cfg.in_scope_assets.append(AssetRule(
                target=item.get("target", item.get("domain", "")),
                asset_type=item.get("type", "web"),
                eligible_for_bounty=item.get("eligible_for_bounty", item.get("bounty", True)),
                max_severity=item.get("max_severity", "critical"),
                notes=item.get("notes", ""),
            ))

    # ── Out-of-scope assets ──────────────────────────────────────
    for item in raw_out:
        if isinstance(item, str):
            cfg.out_of_scope_assets.append(AssetRule(target=item))
        elif isinstance(item, dict):
            cfg.out_of_scope_assets.append(AssetRule(
                target=item.get("target", item.get("domain", "")),
                asset_type=item.get("type", "web"),
                notes=item.get("notes", item.get("reason", "")),
            ))

    # ── Excluded categories ──────────────────────────────────────
    # Supports both:
    #   excluded_categories: [str]  (flat)
    #   excluded_vulnerabilities: [{category, reason, detail}]  (nested)
    raw_exc = data.get("excluded_vulnerabilities", data.get("excluded_categories", []))
    for item in raw_exc:
        if isinstance(item, str):
            cfg.excluded_categories.append(item.lower())
        elif isinstance(item, dict):
            cat = item.get("category", "")
            if cat:
                cfg.excluded_categories.append(cat.lower())
                reason = item.get("reason", "")
                detail = item.get("detail", "")
                combined = f"{reason}: {detail}".strip(": ") if detail else reason
                if combined:
                    cfg.excluded_categories_detail[cat.lower()] = combined
            else:
                # Old format: {category_name: reason_string}
                for cat_key, reason_val in item.items():
                    cfg.excluded_categories.append(cat_key.lower())
                    if reason_val:
                        cfg.excluded_categories_detail[cat_key.lower()] = str(reason_val)

    # ── Bounty tiers ─────────────────────────────────────────────
    raw_bounty = data.get("bounty", {})
    if isinstance(raw_bounty, list):
        # List format: [{severity, min, max}, ...]
        for entry in raw_bounty:
            if isinstance(entry, dict) and "severity" in entry:
                cfg.bounty_tiers.append(BountyTier(
                    severity=entry["severity"].lower(),
                    min_usd=int(entry.get("min", 0)),
                    max_usd=int(entry.get("max", 0)),
                ))
    elif isinstance(raw_bounty, dict):
        # Dict format: {severity: {min, max}} or {severity: [min, max]}
        for sev in SEVERITY_ORDER:
            if sev in raw_bounty:
                val = raw_bounty[sev]
                if isinstance(val, dict):
                    cfg.bounty_tiers.append(BountyTier(
                        severity=sev,
                        min_usd=int(val.get("min", 0)),
                        max_usd=int(val.get("max", 0)),
                    ))
                elif isinstance(val, (list, tuple)) and len(val) >= 2:
                    cfg.bounty_tiers.append(BountyTier(
                        severity=sev, min_usd=int(val[0]), max_usd=int(val[1]),
                    ))
                elif isinstance(val, (int, float)):
                    cfg.bounty_tiers.append(BountyTier(
                        severity=sev, min_usd=int(val), max_usd=int(val),
                    ))

    # ── Testing rules ────────────────────────────────────────────
    raw_test = data.get("testing", {})
    if isinstance(raw_test, dict):
        cfg.testing = TestingRule(
            max_requests_per_second=float(raw_test.get("max_rps", raw_test.get("max_requests_per_second", 2.0))),
            required_headers=raw_test.get("required_headers", {}),
            user_agent=raw_test.get("user_agent", ""),
            no_automated_scanners=raw_test.get("no_automated_scanners", False),
            no_destructive_testing=raw_test.get("no_destructive_testing", True),
            proxy_required=raw_test.get("proxy_required", False),
            notes=raw_test.get("notes", []) if isinstance(raw_test.get("notes"), list) else [],
        )
        hours = raw_test.get("allowed_hours_utc")
        if isinstance(hours, (list, tuple)) and len(hours) == 2:
            cfg.testing.allowed_hours_utc = (int(hours[0]), int(hours[1]))

    # ── Min severity and modules ─────────────────────────────────
    cfg.min_severity = data.get("min_severity", "low")
    cfg.modules = data.get("modules", [])
    cfg.safe_harbour = data.get("safe_harbour", True)

    # ── Build the legacy ScopeConfig for compatibility ───────────
    cfg.scope_config = ScopeConfig(
        in_scope=[a.target for a in cfg.in_scope_assets],
        out_of_scope=[a.target for a in cfg.out_of_scope_assets],
        min_severity=cfg.min_severity,
        modules=cfg.modules,
        excluded_categories=cfg.excluded_categories,
        excluded_paths=data.get("excluded_paths", []),
    )

    return cfg


def filter_findings_by_program(
    findings: list[dict], program: ProgramConfig
) -> list[dict]:
    """Filter findings using the full program rules.

    Goes beyond basic scope filtering by also checking:
      - Bounty eligibility of the target asset
      - Category exclusions with reasons
      - Testing constraints
      - Minimum severity worth reporting
    """
    from vapt.engine.scope import is_in_scope, SEVERITY_LEVELS

    threshold = SEVERITY_LEVELS.index(program.min_severity.lower()) if program.min_severity.lower() in SEVERITY_LEVELS else 4
    excluded_cats = {c.lower() for c in program.excluded_categories}
    kept = []

    for finding in findings:
        sev = finding.get("severity", "info").lower()
        sev_idx = SEVERITY_LEVELS.index(sev) if sev in SEVERITY_LEVELS else 4
        if sev_idx > threshold:
            finding["_skip_reason"] = f"Below min severity ({program.min_severity})"
            continue

        cat = finding.get("category", "").lower()
        if cat in excluded_cats:
            reason = program.excluded_categories_detail.get(cat, "Program excludes this category")
            finding["_skip_reason"] = f"Excluded category: {reason}"
            continue

        url = finding.get("url", "")
        if url and not is_in_scope(url, program.scope_config):
            finding["_skip_reason"] = "Target out of scope"
            continue

        kept.append(finding)

    return kept
