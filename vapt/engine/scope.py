"""Scope enforcement for bug bounty program rules."""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Try YAML import — optional dependency
try:
    import yaml  # type: ignore
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# All available scanner module names
ALL_MODULES = [
    "recon", "port", "ssl", "web", "dom", "auth",
    "api", "fuzz", "jsscan", "race", "smuggle", "advanced",
    "cloud", "cve", "plugins",
]

# Severity levels in order of priority
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]


@dataclass
class ScopeConfig:
    """Holds in-scope / out-of-scope rules and filters."""

    # What to include
    in_scope: list[str] = field(default_factory=list)

    # What to exclude
    out_of_scope: list[str] = field(default_factory=list)

    # Only report findings at this severity or above
    min_severity: str = "info"

    # Only run these modules (empty = all)
    modules: list[str] = field(default_factory=list)

    # Exclude specific vulnerability categories
    excluded_categories: list[str] = field(default_factory=list)

    # Exclude specific paths from testing
    excluded_paths: list[str] = field(default_factory=list)

    @property
    def severity_threshold(self) -> int:
        """Return numeric threshold (0=critical, 4=info)."""
        level = self.min_severity.lower()
        if level in SEVERITY_LEVELS:
            return SEVERITY_LEVELS.index(level)
        return 4  # default: show everything

    @property
    def active_modules(self) -> list[str]:
        """Return list of modules to run. Empty input = all modules."""
        if not self.modules:
            return list(ALL_MODULES)
        return [m.lower().strip() for m in self.modules if m.lower().strip() in ALL_MODULES]


def load_scope_file(path: str) -> ScopeConfig:
    """Load scope configuration from a YAML file.

    Example scope.yaml::

        in_scope:
          - "*.example.com"
          - "api.example.com"
        out_of_scope:
          - "blog.example.com"
        min_severity: medium
        modules: [web, api, fuzz]
        excluded_categories: []
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Scope file not found: {path}")

    text = filepath.read_text(encoding="utf-8")

    if HAS_YAML:
        data = yaml.safe_load(text) or {}
    else:
        # Minimal fallback parser for simple YAML
        data = _parse_simple_yaml(text)

    return ScopeConfig(
        in_scope=data.get("in_scope", []),
        out_of_scope=data.get("out_of_scope", []),
        min_severity=data.get("min_severity", "info"),
        modules=data.get("modules", []),
        excluded_categories=data.get("excluded_categories", []),
        excluded_paths=data.get("excluded_paths", []),
    )


def build_scope_from_flags(
    scope_in: str | None = None,
    scope_out: str | None = None,
    min_severity: str = "info",
    modules: str | None = None,
    exclude_categories: str | None = None,
    scope_file: str | None = None,
) -> ScopeConfig:
    """Build a ScopeConfig from CLI flags.

    If --scope-file is provided, it takes priority and CLI flags
    merge on top (CLI flags override file values).
    """
    # Start from file if provided
    if scope_file:
        config = load_scope_file(scope_file)
    else:
        config = ScopeConfig()

    # CLI flags override/extend file settings
    if scope_in:
        extras = [s.strip() for s in scope_in.split(",") if s.strip()]
        config.in_scope.extend(extras)

    if scope_out:
        extras = [s.strip() for s in scope_out.split(",") if s.strip()]
        config.out_of_scope.extend(extras)

    if min_severity and min_severity != "info":
        config.min_severity = min_severity

    if modules:
        config.modules = [m.strip() for m in modules.split(",") if m.strip()]

    if exclude_categories:
        config.excluded_categories = [c.strip() for c in exclude_categories.split(",") if c.strip()]

    return config


def is_in_scope(target: str, scope: ScopeConfig) -> bool:
    """Check whether a host/URL is within the defined scope.

    Rules:
      1. If no in_scope rules defined, everything is in scope.
      2. If in_scope rules exist, target must match at least one.
      3. Target must NOT match any out_of_scope rule.
    """
    hostname = _extract_hostname(target)
    url_path = _extract_path(target)

    # Check out-of-scope first (always takes priority)
    for pattern in scope.out_of_scope:
        if _matches_rule(hostname, url_path, pattern):
            return False

    # If no in-scope rules, everything is allowed
    if not scope.in_scope:
        return True

    # Must match at least one in-scope rule
    for pattern in scope.in_scope:
        if _matches_rule(hostname, url_path, pattern):
            return True

    return False


def should_run_module(module_name: str, scope: ScopeConfig) -> bool:
    """Check if a scanner module should run based on scope config."""
    active = scope.active_modules
    return module_name.lower() in active


def filter_findings_by_scope(
    findings: list[dict],
    scope: ScopeConfig,
) -> list[dict]:
    """Remove findings that fall outside the defined scope.

    Filters by:
      - Severity threshold
      - Out-of-scope URLs
      - Excluded vulnerability categories
    """
    threshold = scope.severity_threshold
    excluded_cats = {c.lower() for c in scope.excluded_categories}
    filtered = []

    for finding in findings:
        # Severity filter
        sev = finding.get("severity", "info").lower()
        sev_idx = SEVERITY_LEVELS.index(sev) if sev in SEVERITY_LEVELS else 4
        if sev_idx > threshold:
            continue

        # Category filter
        cat = finding.get("category", "").lower()
        if cat in excluded_cats:
            continue

        # URL scope filter
        url = finding.get("url", "")
        if url and scope.out_of_scope:
            hostname = _extract_hostname(url)
            url_path = _extract_path(url)
            out_of_scope = False
            for pattern in scope.out_of_scope:
                if _matches_rule(hostname, url_path, pattern):
                    out_of_scope = True
                    break
            if out_of_scope:
                continue

        filtered.append(finding)

    return filtered


def print_scope_summary(scope: ScopeConfig, console: Any) -> None:
    """Print a human-readable scope summary to the console."""
    from rich.table import Table

    table = Table(
        title="[bold cyan]Scan Scope Configuration[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Setting", style="bold")
    table.add_column("Value")

    if scope.in_scope:
        table.add_row("In Scope", ", ".join(scope.in_scope))
    else:
        table.add_row("In Scope", "[dim]Everything (no restrictions)[/dim]")

    if scope.out_of_scope:
        table.add_row("Out of Scope", ", ".join(scope.out_of_scope))
    else:
        table.add_row("Out of Scope", "[dim]None[/dim]")

    table.add_row("Min Severity", scope.min_severity.upper())

    if scope.modules:
        table.add_row("Modules", ", ".join(scope.active_modules))
    else:
        table.add_row("Modules", "[dim]All modules[/dim]")

    if scope.excluded_categories:
        table.add_row("Excluded Categories", ", ".join(scope.excluded_categories))

    if scope.excluded_paths:
        table.add_row("Excluded Paths", ", ".join(scope.excluded_paths))

    console.print(table)
    console.print()


def _extract_hostname(target: str) -> str:
    """Extract hostname from a URL or plain domain/IP."""
    if "://" in target:
        return urlparse(target).hostname or target
    # Could be domain:port or plain domain
    return target.split(":")[0].split("/")[0]


def _extract_path(target: str) -> str:
    """Extract URL path if present."""
    if "://" in target:
        return urlparse(target).path or "/"
    if "/" in target:
        return "/" + target.split("/", 1)[1]
    return "/"


def _matches_rule(hostname: str, url_path: str, pattern: str) -> bool:
    """Check if hostname+path matches a scope pattern.

    Supported patterns:
      - "example.com"           — exact domain match
      - "*.example.com"         — wildcard subdomain match
      - "10.0.0.0/24"           — CIDR IP range
      - "example.com/admin"     — domain + path prefix
      - "192.168.1.1"           — exact IP
    """
    pattern = pattern.strip()

    # Path pattern: "example.com/something"
    if "/" in pattern and not pattern.startswith("/"):
        parts = pattern.split("/", 1)
        domain_part = parts[0]
        path_part = "/" + parts[1]
        if not fnmatch.fnmatch(hostname, domain_part):
            return False
        if not url_path.startswith(path_part):
            return False
        return True

    # CIDR range
    if "/" in pattern:
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            ip = ipaddress.ip_address(hostname)
            return ip in network
        except ValueError:
            pass

    # Wildcard domain pattern
    if "*" in pattern:
        return fnmatch.fnmatch(hostname, pattern)

    # Exact match
    return hostname == pattern


def _parse_simple_yaml(text: str) -> dict:
    """Very minimal YAML-ish parser for when PyYAML is not installed.

    Handles flat keys and simple lists only. For complex configs,
    install PyYAML: pip install pyyaml
    """
    result: dict[str, Any] = {}
    current_key = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # List item under current key
        if stripped.startswith("- ") and current_key is not None:
            val = stripped[2:].strip().strip("'\"")
            if current_key not in result:
                result[current_key] = []
            result[current_key].append(val)
            continue

        # Key: value or Key:
        if ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()
            current_key = key

            if value:
                # Inline list: [a, b, c]
                if value.startswith("[") and value.endswith("]"):
                    items = value[1:-1].split(",")
                    result[key] = [i.strip().strip("'\"") for i in items if i.strip()]
                else:
                    result[key] = value.strip("'\"")
            else:
                result[key] = []

    return result
