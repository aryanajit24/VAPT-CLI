"""YAML-based plugin system for custom security checks."""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
from rich.console import Console

console = Console()


# Base Plugin interface


class BasePlugin(ABC):
    """Abstract base class for all VAPT plugins."""

    name: str = "Unnamed Plugin"
    description: str = ""
    version: str = "1.0.0"
    author: str = ""
    category: str = "custom"

    @abstractmethod
    def run(
        self,
        target: str,
        session: requests.Session,
        config: dict[str, Any] | None = None,
    ) -> list[dict]:
        """
        Execute the plugin against a target.

        Args:
            target: The target URL or host.
            session: A requests.Session (may include auth, rate limiting, etc.)
            config: Optional configuration dict.

        Returns:
            List of finding dicts with keys:
              vuln_id, title, severity, category, url, evidence, remediation
        """
        ...

    def validate(self) -> bool:
        """Optional validation hook — return False to skip this plugin."""
        return True


# YAML Plugin (declarative checks defined in YAML)

import re


@dataclass
class YAMLCheck:
    """A single check defined in a YAML plugin."""
    path: str = "/"
    method: str = "GET"
    match_body: str = ""        # Regex pattern to match in response body
    match_header: str = ""      # Header name to check
    match_header_value: str = ""  # Expected header value pattern (regex)
    match_status: int = 0       # Expected status code (0 = any)
    not_match_body: str = ""    # Body pattern that should NOT be present
    not_match_header: str = ""  # Header that should NOT be present
    vuln_id: str = "PLUGIN-001"
    title: str = "Custom Check"
    severity: str = "Medium"
    remediation: str = ""


class YAMLPlugin(BasePlugin):
    """
    Plugin defined by a YAML configuration file.

    YAML format:
    ```yaml
    name: My Custom Scanner
    description: Checks for custom vulnerabilities
    version: 1.0.0
    author: User
    checks:
      - path: /admin
        match_status: 200
        vuln_id: CUSTOM-001
        title: Admin panel accessible
        severity: High
        remediation: Restrict admin access
      - path: /
        match_header: X-Powered-By
        vuln_id: CUSTOM-002
        title: Technology disclosure via X-Powered-By
        severity: Low
        remediation: Remove X-Powered-By header
    ```
    """

    def __init__(self, yaml_data: dict[str, Any]) -> None:
        self.name = yaml_data.get("name", "YAML Plugin")
        self.description = yaml_data.get("description", "")
        self.version = yaml_data.get("version", "1.0.0")
        self.author = yaml_data.get("author", "")
        self.category = yaml_data.get("category", "custom")

        self.checks: list[YAMLCheck] = []
        for check_data in yaml_data.get("checks", []):
            self.checks.append(YAMLCheck(**{
                k: v for k, v in check_data.items()
                if k in YAMLCheck.__dataclass_fields__
            }))

    def run(
        self,
        target: str,
        session: requests.Session,
        config: dict[str, Any] | None = None,
    ) -> list[dict]:
        findings: list[dict] = []

        for check in self.checks:
            url = target.rstrip("/") + check.path
            try:
                resp = session.request(
                    check.method,
                    url,
                    timeout=config.get("timeout", 10) if config else 10,
                    allow_redirects=True,
                )

                hit = False

                # Status code check
                if check.match_status and resp.status_code == check.match_status:
                    hit = True

                # Body pattern check
                if check.match_body:
                    if re.search(check.match_body, resp.text, re.I):
                        hit = True

                # Header check
                if check.match_header:
                    header_val = resp.headers.get(check.match_header, "")
                    if header_val:
                        if check.match_header_value:
                            if re.search(check.match_header_value, header_val, re.I):
                                hit = True
                        else:
                            hit = True

                # Negative body check (should NOT match)
                if check.not_match_body:
                    if re.search(check.not_match_body, resp.text, re.I):
                        hit = False

                # Negative header check
                if check.not_match_header:
                    if resp.headers.get(check.not_match_header):
                        hit = False

                if hit:
                    findings.append({
                        "vuln_id": check.vuln_id,
                        "title": check.title,
                        "severity": check.severity,
                        "category": self.category,
                        "url": url,
                        "evidence": f"Status: {resp.status_code}, Body length: {len(resp.text)}",
                        "remediation": check.remediation,
                    })

            except requests.RequestException:
                continue

        return findings


# Plugin Loader — discovers and loads all plugins


class PluginLoader:
    """
    Discovers and loads plugins from the plugins directory.

    Searches:
      1. vapt/plugins/ for .py files containing BasePlugin subclasses
      2. vapt/plugins/ for .yaml/.yml files with check definitions
      3. Custom directory specified by user
    """

    def __init__(self, plugin_dirs: list[str | Path] | None = None) -> None:
        base_dir = Path(__file__).parent
        self.plugin_dirs = [base_dir]
        if plugin_dirs:
            self.plugin_dirs.extend(Path(d) for d in plugin_dirs)

        self.plugins: list[BasePlugin] = []

    def discover(self) -> list[BasePlugin]:
        """Scan all plugin directories and load plugins."""
        self.plugins = []

        for plugin_dir in self.plugin_dirs:
            if not plugin_dir.exists():
                continue

            for py_file in plugin_dir.glob("*.py"):
                if py_file.name.startswith("_") or py_file.name == "loader.py":
                    continue
                self._load_python_plugin(py_file)

            for yaml_file in list(plugin_dir.glob("*.yaml")) + list(plugin_dir.glob("*.yml")):
                self._load_yaml_plugin(yaml_file)

        return self.plugins

    def _load_python_plugin(self, path: Path) -> None:
        """Load a Python plugin file and extract BasePlugin subclasses."""
        try:
            module_name = f"vapt_plugin_{path.stem}"
            spec = importlib.util.spec_from_file_location(module_name, path)
            if not spec or not spec.loader:
                return

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BasePlugin)
                    and attr is not BasePlugin
                ):
                    plugin = attr()
                    if plugin.validate():
                        self.plugins.append(plugin)
                        console.print(
                            f"  [green]✓[/green] Loaded plugin: {plugin.name} v{plugin.version}"
                        )
        except Exception as exc:
            console.print(f"  [red]✗[/red] Failed to load plugin {path.name}: {exc}")

    def _load_yaml_plugin(self, path: Path) -> None:
        """Load a YAML plugin file."""
        try:
            import yaml
        except ImportError:
            # PyYAML not installed — try basic parsing
            console.print(f"  [dim]Skipping YAML plugin {path.name} (PyYAML not installed)[/dim]")
            return

        try:
            with open(path) as f:
                data = yaml.safe_load(f)

            if not isinstance(data, dict) or "checks" not in data:
                return

            plugin = YAMLPlugin(data)
            if plugin.validate():
                self.plugins.append(plugin)
                console.print(
                    f"  [green]✓[/green] Loaded YAML plugin: {plugin.name} v{plugin.version}"
                )
        except Exception as exc:
            console.print(f"  [red]✗[/red] Failed to load YAML plugin {path.name}: {exc}")

    def run_all(
        self,
        target: str,
        session: requests.Session,
        config: dict[str, Any] | None = None,
    ) -> list[dict]:
        """Run all loaded plugins and aggregate findings."""
        all_findings: list[dict] = []

        for plugin in self.plugins:
            try:
                findings = plugin.run(target, session, config)
                all_findings.extend(findings)
                if findings:
                    console.print(
                        f"  [yellow]→[/yellow] {plugin.name}: {len(findings)} findings"
                    )
            except Exception as exc:
                console.print(
                    f"  [red]✗[/red] Plugin {plugin.name} failed: {exc}"
                )

        return all_findings
