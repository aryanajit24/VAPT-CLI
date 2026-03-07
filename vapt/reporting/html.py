"""
HTML report writer — the prettiest output format.

Uses Jinja2 to render a dark-themed HTML report with finding cards,
severity badges, compliance dashboards, and attack-chain diagrams.
The templates live in the 'templates/' subdirectory.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from vapt.utils.helpers import format_timestamp

TEMPLATES_DIR = Path(__file__).parent / "templates"


class HTMLReporter:
    """Render a full HTML security report from scan results.

    Supports both the detailed finding report (report.html) and the
    one-page executive summary (executive.html).
    """

    def __init__(self, template: str = "report.html") -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        self._template_name = template

    def generate(self, scan_result: dict[str, Any], output_path: str) -> None:
        """Render the Jinja2 template and write to output_path."""
        tmpl = self._env.get_template(self._template_name)
        context = {
            "scan": scan_result,
            "generated_at": format_timestamp(),
            "findings": scan_result.get("findings", []),
            "risk_level": scan_result.get("risk_level", "info"),
            "overall_score": scan_result.get("overall_score", 0),
            "target": scan_result.get("target", ""),
            "compliance": scan_result.get("compliance", {}),
            "attack_chains": scan_result.get("attack_chains", []),
        }
        html = tmpl.render(**context)
        Path(output_path).write_text(html, encoding="utf-8")
