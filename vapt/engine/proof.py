"""Proof generator — creates browser-based PoCs, screenshots, and evidence bundles.

For each confirmed finding, generates:
  - Standalone HTML exploit page (for CORS, XSS, CSRF)
  - cURL reproduction command
  - Screenshot of the vulnerability (via Playwright if available)
  - Request/response evidence file
"""

from __future__ import annotations

import html
import json
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

_HAS_PLAYWRIGHT = False
try:
    from playwright.sync_api import sync_playwright
    _HAS_PLAYWRIGHT = True
except ImportError:
    pass


class ProofGenerator:
    """Generate proof-of-concept artifacts for vulnerability findings."""

    def __init__(self, output_dir: str = "./vapt-reports/proofs") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, finding: dict) -> dict[str, str]:
        """Generate all applicable proof artifacts for a finding.

        Returns a dict mapping artifact type to file path:
            {"curl": "path/to/curl.sh", "poc_html": "path/to/poc.html", ...}
        """
        cat = finding.get("category", "").lower()
        title_safe = self._safe_filename(finding.get("title", "finding"))
        artifacts: dict[str, str] = {}

        curl = self._generate_curl(finding)
        if curl:
            path = self.output_dir / f"{title_safe}_curl.sh"
            path.write_text(curl, encoding="utf-8")
            artifacts["curl"] = str(path)

        evidence = self._generate_evidence(finding)
        path = self.output_dir / f"{title_safe}_evidence.txt"
        path.write_text(evidence, encoding="utf-8")
        artifacts["evidence"] = str(path)

        poc_html = self._generate_poc_html(finding)
        if poc_html:
            path = self.output_dir / f"{title_safe}_poc.html"
            path.write_text(poc_html, encoding="utf-8")
            artifacts["poc_html"] = str(path)

        screenshot = self._take_screenshot(finding)
        if screenshot:
            artifacts["screenshot"] = screenshot

        finding["_proof_artifacts"] = artifacts
        return artifacts

    def generate_batch(self, findings: list[dict]) -> list[dict[str, str]]:
        return [self.generate(f) for f in findings]

    def _safe_filename(self, title: str) -> str:
        safe = "".join(c if c.isalnum() or c in " -_" else "" for c in title)
        return safe.strip().replace(" ", "_")[:60]

    def _generate_curl(self, finding: dict) -> str | None:
        url = finding.get("url", "")
        if not url:
            return None

        method = finding.get("method", "GET").upper()
        lines = ["#!/bin/bash", f"# PoC for: {finding.get('title', '')}", ""]

        cmd_parts = ["curl", "-v", "-k"]

        if method != "GET":
            cmd_parts.extend(["-X", method])

        headers = finding.get("request_headers", {})
        if isinstance(headers, dict):
            for k, v in headers.items():
                cmd_parts.extend(["-H", f"'{k}: {v}'"])

        body = finding.get("request_body", "")
        if body:
            if isinstance(body, dict):
                body = json.dumps(body)
            cmd_parts.extend(["-d", f"'{body}'"])

        cmd_parts.append(f"'{url}'")
        lines.append(" \\\n  ".join(cmd_parts))
        return "\n".join(lines)

    def _generate_evidence(self, finding: dict) -> str:
        lines = [
            f"{'='*60}",
            f"VULNERABILITY EVIDENCE",
            f"{'='*60}",
            f"Title:     {finding.get('title', 'N/A')}",
            f"Category:  {finding.get('category', 'N/A')}",
            f"Severity:  {finding.get('severity', 'N/A')}",
            f"URL:       {finding.get('url', 'N/A')}",
            f"CVSS:      {finding.get('cvss', 'N/A')}",
            f"Timestamp: {datetime.now(timezone.utc).isoformat()}",
            "",
            "DESCRIPTION:",
            finding.get("description", "No description"),
            "",
        ]

        evidence = finding.get("evidence", "")
        if evidence:
            lines.extend(["EVIDENCE:", str(evidence), ""])

        req = finding.get("request_raw", "")
        if req:
            lines.extend(["REQUEST:", str(req), ""])

        resp = finding.get("response_raw", "")
        if resp:
            lines.extend(["RESPONSE (first 2000 chars):", str(resp)[:2000], ""])

        steps = finding.get("reproduction_steps", [])
        if steps:
            lines.append("REPRODUCTION STEPS:")
            for i, step in enumerate(steps, 1):
                lines.append(f"  {i}. {step}")
            lines.append("")

        return "\n".join(lines)

    def _generate_poc_html(self, finding: dict) -> str | None:
        """Generate a standalone HTML PoC file based on vulnerability category."""
        cat = finding.get("category", "").lower()
        url = finding.get("url", "")
        title = html.escape(finding.get("title", "PoC"))

        generators = {
            "cors": self._poc_cors,
            "cors_misconfiguration": self._poc_cors,
            "csrf": self._poc_csrf,
            "missing_csrf": self._poc_csrf,
            "xss": self._poc_xss,
            "reflected_xss": self._poc_xss,
            "open_redirect": self._poc_redirect,
            "redirect": self._poc_redirect,
            "clickjacking": self._poc_clickjack,
        }

        gen = generators.get(cat)
        if gen:
            return gen(finding)
        return None

    def _poc_cors(self, finding: dict) -> str:
        url = finding.get("url", "https://TARGET")
        return textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html>
        <head><title>CORS PoC — {html.escape(finding.get('title', ''))}</title></head>
        <body>
        <h2>CORS Data Exfiltration PoC</h2>
        <p>Target: <code>{html.escape(url)}</code></p>
        <pre id="result">Loading...</pre>
        <script>
        fetch("{url}", {{credentials: "include"}})
          .then(r => r.text())
          .then(data => {{
            document.getElementById("result").textContent = data.substring(0, 2000);
          }})
          .catch(e => {{
            document.getElementById("result").textContent = "CORS blocked: " + e;
          }});
        </script>
        </body>
        </html>""")

    def _poc_csrf(self, finding: dict) -> str:
        url = finding.get("url", "https://TARGET")
        method = finding.get("method", "POST").upper()
        body = finding.get("request_body", {})

        inputs = ""
        if isinstance(body, dict):
            for k, v in body.items():
                inputs += f'  <input type="hidden" name="{html.escape(str(k))}" value="{html.escape(str(v))}">\n'
        elif isinstance(body, str):
            inputs = f'  <input type="hidden" name="data" value="{html.escape(body)}">\n'

        return textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html>
        <head><title>CSRF PoC — {html.escape(finding.get('title', ''))}</title></head>
        <body>
        <h2>CSRF PoC — Auto-submitting form</h2>
        <form id="csrf" action="{html.escape(url)}" method="{method}">
        {inputs}</form>
        <script>document.getElementById("csrf").submit();</script>
        </body>
        </html>""")

    def _poc_xss(self, finding: dict) -> str:
        url = finding.get("url", "")
        payload = finding.get("evidence", finding.get("payload", ""))
        return textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html>
        <head><title>XSS PoC — {html.escape(finding.get('title', ''))}</title></head>
        <body>
        <h2>Reflected XSS PoC</h2>
        <p>Click the link below to trigger the XSS:</p>
        <a href="{html.escape(str(url))}" target="_blank">Trigger</a>
        <pre>Payload: {html.escape(str(payload)[:500])}</pre>
        </body>
        </html>""")

    def _poc_redirect(self, finding: dict) -> str:
        url = finding.get("url", "")
        return textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html>
        <head><title>Open Redirect PoC</title></head>
        <body>
        <h2>Open Redirect PoC</h2>
        <p>Click to be redirected to attacker-controlled site:</p>
        <a href="{html.escape(str(url))}" target="_blank">Click here (victim link)</a>
        </body>
        </html>""")

    def _poc_clickjack(self, finding: dict) -> str:
        url = finding.get("url", "https://TARGET")
        return textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html>
        <head><title>Clickjacking PoC</title>
        <style>
        iframe {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%;
                 opacity: 0.3; z-index: 2; }}
        button {{ position: absolute; top: 200px; left: 200px; z-index: 1;
                 font-size: 24px; padding: 20px; }}
        </style>
        </head>
        <body>
        <h2>Clickjacking PoC</h2>
        <button>Click to win a prize!</button>
        <iframe src="{html.escape(url)}"></iframe>
        </body>
        </html>""")

    def _take_screenshot(self, finding: dict) -> str | None:
        if not _HAS_PLAYWRIGHT:
            return None

        url = finding.get("url", "")
        if not url or not url.startswith("http"):
            return None

        title_safe = self._safe_filename(finding.get("title", "finding"))
        screenshot_path = self.output_dir / f"{title_safe}_screenshot.png"

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
                page.wait_for_timeout(2000)
                page.screenshot(path=str(screenshot_path), full_page=False)
                browser.close()
            return str(screenshot_path)
        except Exception:
            return None
