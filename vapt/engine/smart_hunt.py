
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from vapt.engine.elite_intelligence import EliteIntelligenceEngine
from vapt.engine.oob import OOBManager
from vapt.scanner.deepjs import DeepJSRecon
from vapt.scanner.bizscan import BusinessLogicScanner
from vapt.scanner.authflow import AuthFlowScanner
from vapt.utils.helpers import sanitize_target

console = Console()


class SmartHuntOrchestrator:

    def __init__(
        self,
        target: str,
        output_dir: str = "./vapt-reports",
        custom_headers: dict | None = None,
        timeout: int = 15,
    ) -> None:
        self.target = sanitize_target(target)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.custom_headers = custom_headers or {}
        self.timeout = timeout
        
        self.program_name: str = ""
        self.platform: str = "HackerOne"
        self.scope_in: list[str] = []
        self.scope_out: list[str] = []
        
        self.elite_engine = EliteIntelligenceEngine()
        self.oob_manager = OOBManager()
        self.js_recon = DeepJSRecon(timeout=timeout)
        self.biz_scanner = BusinessLogicScanner(timeout=timeout)
        self.auth_scanner = AuthFlowScanner(timeout=timeout)
        
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        if custom_headers:
            self.session.headers.update(custom_headers)
        self.session.verify = False
        
        self.all_findings: list[dict] = []
        self.phase_results: dict[str, Any] = {}
        self.discovered_endpoints: list[str] = []
        self.sensitive_endpoints: list[dict] = []

    def configure(
        self,
        program_name: str = "",
        platform: str = "HackerOne",
        scope_in: list[str] | None = None,
        scope_out: list[str] | None = None,
        program_history_file: str | None = None,
    ) -> None:
        self.program_name = program_name
        self.platform = platform
        self.scope_in = scope_in or [self.target]
        self.scope_out = scope_out or []
        
        if program_history_file:
            self.elite_engine = EliteIntelligenceEngine(program_history_file)

    def setup_auth(
        self,
        session_a: requests.Session | None = None,
        session_b: requests.Session | None = None,
        login_url: str | None = None,
        email_a: str | None = None,
        password_a: str | None = None,
        email_b: str | None = None,
        password_b: str | None = None,
    ) -> None:
        if session_a:
            self.auth_scanner.setup_session(session_a, "A")
            self.biz_scanner.session = session_a
        elif login_url and email_a and password_a:
            self.auth_scanner.setup_from_credentials(
                login_url, email_a, password_a,
                email_b, password_b,
                self.custom_headers,
            )
        
        if session_b:
            self.auth_scanner.setup_session(session_b, "B")

    def execute(self) -> dict[str, Any]:
        started = time.time()
        
        console.print(Panel(
            "[bold]VAPT CLI — Gold Elite Edition[/bold]\n\n"
            f"Target:  {self.target}\n"
            f"Program: {self.program_name or 'N/A'}\n"
            f"Platform: {self.platform}\n"
            f"Auth: {'Yes (2 accounts)' if self.auth_scanner.session_b else 'Yes (1 account)' if self.auth_scanner.session_a else 'No'}\n\n"
            "[dim]Running strategic 8-phase elite hunt...[/dim]",
            title="[bold yellow]Elite Hunt[/bold yellow]",
            border_style="yellow",
        ))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            
            task = progress.add_task("[cyan]Phase 1: Deep JS Reconnaissance...", total=None)
            self._phase_1_js_recon()
            progress.update(task, description="[green]Phase 1: JS Recon Complete ✓")
            progress.remove_task(task)
            
            task = progress.add_task("[cyan]Phase 2: Endpoint Intelligence...", total=None)
            self._phase_2_endpoint_intel()
            progress.update(task, description="[green]Phase 2: Endpoint Intel Complete ✓")
            progress.remove_task(task)
            
            task = progress.add_task("[cyan]Phase 3: Authenticated Flow Testing...", total=None)
            self._phase_3_auth_testing()
            progress.update(task, description="[green]Phase 3: Auth Testing Complete ✓")
            progress.remove_task(task)
            
            task = progress.add_task("[cyan]Phase 4: Business Logic Scanner...", total=None)
            self._phase_4_business_logic()
            progress.update(task, description="[green]Phase 4: Business Logic Complete ✓")
            progress.remove_task(task)
            
            task = progress.add_task("[cyan]Phase 5: Out-of-Band Testing...", total=None)
            self._phase_5_oob_testing()
            progress.update(task, description="[green]Phase 5: OOB Testing Complete ✓")
            progress.remove_task(task)
            
            task = progress.add_task("[cyan]Phase 6: Targeted Vulnerability Scanning...", total=None)
            self._phase_6_targeted_scanning()
            progress.update(task, description="[green]Phase 6: Targeted Scanning Complete ✓")
            progress.remove_task(task)
            
            task = progress.add_task("[cyan]Phase 7: Elite Intelligence Analysis...", total=None)
            self._phase_7_elite_analysis()
            progress.update(task, description="[green]Phase 7: Elite Analysis Complete ✓")
            progress.remove_task(task)
            
            task = progress.add_task("[cyan]Phase 8: Elite Report Generation...", total=None)
            self._phase_8_reports()
            progress.update(task, description="[green]Phase 8: Reports Generated ✓")
            progress.remove_task(task)
        
        elapsed = time.time() - started
        
        self._display_results(elapsed)
        
        return {
            "target": self.target,
            "program": self.program_name,
            "duration_sec": round(elapsed, 2),
            "total_findings": len(self.all_findings),
            "phase_results": self.phase_results,
            "findings": self.all_findings,
        }

    def _phase_1_js_recon(self) -> None:
        self.js_recon.session = self.session
        results = self.js_recon.run(self.target)
        
        self.phase_results["js_recon"] = {
            "js_files": results["js_files_analyzed"],
            "api_endpoints": len(results["api_endpoints"]),
            "client_routes": len(results["client_routes"]),
            "graphql_ops": len(results["graphql_operations"]),
            "websocket_urls": len(results["websocket_urls"]),
            "internal_urls": len(results["internal_urls"]),
            "source_maps": len(results["source_maps"]),
        }
        
        self.discovered_endpoints = self.js_recon.get_endpoints_for_scanning()
        self.sensitive_endpoints = self.js_recon.get_sensitive_endpoints()
        
        self.all_findings.extend(results.get("findings", []))

    def _phase_2_endpoint_intel(self) -> None:
        self.phase_results["endpoint_intel"] = {
            "total_endpoints": len(self.discovered_endpoints),
            "sensitive_endpoints": len(self.sensitive_endpoints),
            "by_type": {},
        }
        
        for ep in self.sensitive_endpoints:
            ep_type = ep.get("sensitivity_type", "other")
            self.phase_results["endpoint_intel"]["by_type"][ep_type] = \
                self.phase_results["endpoint_intel"]["by_type"].get(ep_type, 0) + 1

    def _phase_3_auth_testing(self) -> None:
        results = self.auth_scanner.run(
            self.target,
            endpoints=self.discovered_endpoints,
        )
        
        self.phase_results["auth_testing"] = {
            "auth_endpoints": results.get("auth_endpoints_found", 0),
            "unauth_endpoints": results.get("unauth_endpoints_found", 0),
            "has_second_account": results.get("has_second_account", False),
            "findings": len(results.get("findings", [])),
        }
        
        self.all_findings.extend(results.get("findings", []))

    def _phase_4_business_logic(self) -> None:
        sensitive_urls = [ep.get("full_url", ep.get("endpoint", "")) for ep in self.sensitive_endpoints]
        
        results = self.biz_scanner.run(
            self.target,
            endpoints=sensitive_urls,
            auth_session=self.auth_scanner.session_a,
            second_auth_session=self.auth_scanner.session_b,
        )
        
        self.phase_results["business_logic"] = {
            "endpoints_discovered": results.get("endpoints_discovered", 0),
            "endpoints_classified": results.get("endpoints_classified", {}),
            "findings": len(results.get("findings", [])),
        }
        
        self.all_findings.extend(results.get("findings", []))

    def _phase_5_oob_testing(self) -> None:
        oob_payloads_sent = 0
        
        for ep in self.sensitive_endpoints:
            if ep.get("sensitivity_type") in ("file_operations", "communication"):
                payloads = self.oob_manager.generate_payloads("ssrf", ep.get("endpoint", ""))
                for payload in payloads[:3]:
                    try:
                        self.session.post(
                            ep.get("full_url", ep.get("endpoint", "")),
                            json={"url": payload, "file": payload, "webhook": payload},
                            timeout=self.timeout,
                            verify=False,
                        )
                        oob_payloads_sent += 1
                    except Exception:
                        pass
        
        interactions = []
        if oob_payloads_sent > 0:
            interactions = self.oob_manager.poll_interactions(wait_seconds=5)
        
        confirmed = self.oob_manager.get_confirmed_findings()
        
        self.phase_results["oob_testing"] = {
            "payloads_sent": oob_payloads_sent,
            "interactions_received": len(interactions),
            "confirmed_findings": len(confirmed),
        }
        
        for conf in confirmed:
            self.all_findings.append({
                "id": f"OOB-{conf['label'][:20]}",
                "title": f"OOB Confirmed: {conf['label']}",
                "category": "ssrf" if "ssrf" in conf["label"] else "blind_vuln",
                "severity": "high",
                "cvss": 8.6,
                "url": self.target,
                "description": f"Out-of-band interaction confirmed for {conf['label']}.",
                "evidence": conf["evidence"],
                "requires_auth": False,
            })

    def _phase_6_targeted_scanning(self) -> None:
        findings_count = 0
        
        try:
            from vapt.scanner.apiscan import APIScanner
            api_scanner = APIScanner(session=self.session, timeout=self.timeout)
            
            for ep in self.sensitive_endpoints[:20]:
                url = ep.get("full_url", ep.get("endpoint", ""))
                if url:
                    try:
                        result = api_scanner.run(url)
                        findings = result.get("findings", [])
                        for f in findings:
                            f["authenticated"] = self.auth_scanner.session_a is not None
                            f["requires_auth"] = self.auth_scanner.session_a is not None
                        self.all_findings.extend(findings)
                        findings_count += len(findings)
                    except Exception:
                        pass
        except ImportError:
            pass
        
        try:
            from vapt.scanner.jsscan import JSSecretScanner
            js_scanner = JSSecretScanner(session=self.session, timeout=self.timeout)
            result = js_scanner.run(self.target)
            self.all_findings.extend(result.get("findings", []))
            findings_count += len(result.get("findings", []))
        except (ImportError, Exception):
            pass
        
        self.phase_results["targeted_scanning"] = {
            "endpoints_tested": min(20, len(self.sensitive_endpoints)),
            "findings": findings_count,
        }

    def _phase_7_elite_analysis(self) -> None:
        self.all_findings = self.elite_engine.analyze(
            self.all_findings,
            target_context={
                "target": self.target,
                "program": self.program_name,
                "platform": self.platform,
            },
        )
        
        summary = self.elite_engine.generate_elite_summary(self.all_findings)
        self.phase_results["elite_analysis"] = summary

    def _phase_8_reports(self) -> None:
        ready_findings = [
            f for f in self.all_findings
            if f.get("submission_readiness") in ("ready", "needs_work")
        ]
        
        if not ready_findings:
            self.phase_results["reports"] = {"generated": 0, "note": "No novel findings to report"}
            return
        
        reports_generated = 0
        
        for i, finding in enumerate(ready_findings[:10], 1):
            report = self._generate_elite_report(finding, i)
            
            safe_title = "".join(c if c.isalnum() or c in " -_" else "" for c in finding.get("title", "finding"))[:50]
            report_path = self.output_dir / f"elite_{i}_{safe_title.strip().replace(' ', '_')}.md"
            report_path.write_text(report, encoding="utf-8")
            
            fields = self._generate_h1_fields(finding)
            fields_path = self.output_dir / f"elite_{i}_{safe_title.strip().replace(' ', '_')}_fields.txt"
            fields_path.write_text(fields, encoding="utf-8")
            
            reports_generated += 1
        
        self.phase_results["reports"] = {"generated": reports_generated}

    def _generate_elite_report(self, finding: dict, rank: int) -> str:
        title = finding.get("title", "Vulnerability Finding")
        severity = finding.get("severity", "medium").upper()
        cvss = finding.get("cvss", 0)
        category = finding.get("category", "")
        url = finding.get("url", self.target)
        description = finding.get("description", "")
        evidence = finding.get("evidence", {})
        impact = finding.get("impact", "")
        remediation = finding.get("remediation", "")
        steps = finding.get("steps_to_reproduce", [])
        novelty = finding.get("novelty_score", 0)
        dup_risk = finding.get("duplicate_risk", 0)
        poc = finding.get("poc_completeness", 0)
        recommendation = finding.get("elite_recommendation", "")
        chains = finding.get("chain_potential", [])
        
        lines = [
            f"# {title}",
            "",
            f"**Severity:** {severity} (CVSS {cvss})",
            f"**Asset:** {url}",
            f"**Category:** {category}",
            f"**Novelty Score:** {novelty:.0%} | **Duplicate Risk:** {dup_risk:.0%} | **PoC Completeness:** {poc:.0%}",
            f"**Priority Rank:** #{rank}",
            "",
            "---",
            "",
            "## Summary",
            "",
            description,
            "",
        ]
        
        if steps:
            lines.extend([
                "## Steps To Reproduce",
                "",
            ])
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")
        
        if evidence:
            lines.extend([
                "## Supporting Material / References",
                "",
                "```json",
                json.dumps(evidence, indent=2, default=str)[:2000],
                "```",
                "",
            ])
        
        if chains:
            lines.extend([
                "## Attack Chain Potential",
                "",
            ])
            for chain in chains:
                lines.append(f"- **{chain['chain']}**: {chain['impact']}")
            lines.append("")
        
        if impact:
            lines.extend([
                "## Impact",
                "",
                "### Summary",
                "",
                impact,
                "",
            ])
        
        if remediation:
            lines.extend([
                "## Remediation",
                "",
                remediation,
                "",
            ])
        
        lines.extend([
            "---",
            "",
            "## Elite Intelligence Assessment",
            "",
            recommendation,
            "",
        ])
        
        return "\n".join(lines)

    def _generate_h1_fields(self, finding: dict) -> str:
        title = finding.get("title", "")[:150]
        severity = finding.get("severity", "medium").lower()
        cvss = finding.get("cvss", 0)
        url = finding.get("url", self.target)
        description = finding.get("description", "")
        steps = finding.get("steps_to_reproduce", [])
        impact = finding.get("impact", "")
        evidence = finding.get("evidence", {})
        category = finding.get("category", "")
        
        from vapt.reporting.bounty_report import VULN_REFERENCES
        refs = VULN_REFERENCES.get(category, {})
        weakness = refs.get("cwe", "CWE-284")
        
        cvss_vector = self._calculate_cvss4_vector(finding)
        
        steps_text = ""
        if steps:
            steps_text = "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
        
        evidence_text = ""
        if evidence:
            evidence_text = f"\n```json\n{json.dumps(evidence, indent=2, default=str)[:1500]}\n```"
        
        return (
            f"FIELD: Title\n"
            f"{title}\n\n"
            f"FIELD: Asset\n"
            f"{url}\n\n"
            f"FIELD: Weakness\n"
            f"{weakness}\n\n"
            f"FIELD: Severity\n"
            f"{severity.capitalize()}\n"
            f"CVSS 4.0: {cvss_vector}\n\n"
            f"FIELD: Description\n"
            f"## Summary\n\n"
            f"{description}\n\n"
            f"## Steps To Reproduce\n\n"
            f"{steps_text}\n\n"
            f"## Supporting Material/References\n"
            f"{evidence_text}\n\n"
            f"FIELD: Impact\n"
            f"## Summary\n\n"
            f"{impact}\n"
        )

    def _calculate_cvss4_vector(self, finding: dict) -> str:
        severity = finding.get("severity", "medium").lower()
        requires_auth = finding.get("requires_auth", False)
        category = finding.get("category", "").lower()
        
        av = "N"
        ac = "L"
        at = "N"
        pr = "L" if requires_auth else "N"
        ui = "N"
        
        if severity == "critical":
            vc, vi, va = "H", "H", "H"
        elif severity == "high":
            vc, vi, va = "H", "H", "N"
        elif severity == "medium":
            vc, vi, va = "L", "L", "N"
        else:
            vc, vi, va = "N", "L", "N"
        
        sc = si = sa = "N"
        if "ssrf" in category or "rce" in category:
            sc, si, sa = "H", "H", "H"
        elif "idor" in category or "privilege" in category:
            sc = "H"
        
        if "xss" in category or "cors" in category:
            ui = "P"
        if "race" in category:
            ac = "H"
        if "business" in category:
            at = "P"
        
        return f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}/VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}"

    def _display_results(self, elapsed: float) -> None:
        table = Table(title="Elite Hunt — Phase Results", border_style="cyan")
        table.add_column("Phase", style="bold")
        table.add_column("Result", style="cyan")
        
        pr = self.phase_results
        
        if "js_recon" in pr:
            jr = pr["js_recon"]
            table.add_row(
                "1. JS Recon",
                f"{jr['api_endpoints']} API endpoints, {jr['graphql_ops']} GraphQL ops, "
                f"{jr['websocket_urls']} WebSockets, {jr['internal_urls']} internal URLs"
            )
        
        if "endpoint_intel" in pr:
            ei = pr["endpoint_intel"]
            table.add_row(
                "2. Endpoint Intel",
                f"{ei['total_endpoints']} total, {ei['sensitive_endpoints']} sensitive"
            )
        
        if "auth_testing" in pr:
            at = pr["auth_testing"]
            table.add_row(
                "3. Auth Testing",
                f"{at['auth_endpoints']} auth endpoints, {at['findings']} findings"
            )
        
        if "business_logic" in pr:
            bl = pr["business_logic"]
            table.add_row(
                "4. Business Logic",
                f"{bl['endpoints_discovered']} endpoints, {bl['findings']} findings"
            )
        
        if "oob_testing" in pr:
            oob = pr["oob_testing"]
            table.add_row(
                "5. OOB Testing",
                f"{oob['payloads_sent']} payloads, {oob['interactions_received']} interactions"
            )
        
        if "targeted_scanning" in pr:
            ts = pr["targeted_scanning"]
            table.add_row(
                "6. Targeted Scanning",
                f"{ts['endpoints_tested']} endpoints, {ts['findings']} findings"
            )
        
        if "elite_analysis" in pr:
            ea = pr["elite_analysis"]
            table.add_row(
                "7. Elite Analysis",
                f"Ready: {ea['ready_to_submit']}, Needs Work: {ea['needs_work']}, Skip: {ea['skipped']}"
            )
        
        if "reports" in pr:
            rp = pr["reports"]
            table.add_row("8. Reports", f"{rp['generated']} reports generated")
        
        console.print()
        console.print(table)
        
        if self.all_findings:
            console.print()
            findings_table = Table(title="Top Findings by Priority", border_style="yellow")
            findings_table.add_column("#", style="bold", width=3)
            findings_table.add_column("Status", width=10)
            findings_table.add_column("Title", style="cyan")
            findings_table.add_column("Severity", width=10)
            findings_table.add_column("Novelty", width=8)
            findings_table.add_column("Dup Risk", width=8)
            
            for finding in self.all_findings[:15]:
                rank = finding.get("priority_rank", "-")
                status = finding.get("submission_readiness", "?")
                title = finding.get("title", "")[:60]
                severity = finding.get("severity", "?")
                novelty = f"{finding.get('novelty_score', 0):.0%}"
                dup_risk = f"{finding.get('duplicate_risk', 0):.0%}"
                
                status_style = {
                    "ready": "[bold green]READY[/bold green]",
                    "needs_work": "[yellow]WORK[/yellow]",
                    "skip": "[dim]SKIP[/dim]",
                }.get(status, status)
                
                severity_style = {
                    "critical": "[bold red]CRITICAL[/bold red]",
                    "high": "[red]HIGH[/red]",
                    "medium": "[yellow]MEDIUM[/yellow]",
                    "low": "[dim]LOW[/dim]",
                    "info": "[dim]INFO[/dim]",
                }.get(severity.lower(), severity)
                
                findings_table.add_row(str(rank), status_style, title, severity_style, novelty, dup_risk)
            
            console.print(findings_table)
        
        if "elite_analysis" in pr:
            console.print()
            for rec in pr["elite_analysis"].get("recommendations", []):
                console.print(Panel(rec, border_style="yellow", title="[bold]Recommendation[/bold]"))
        
        ready = sum(1 for f in self.all_findings if f.get("submission_readiness") == "ready")
        console.print(Panel(
            f"[bold]Findings:[/bold] {len(self.all_findings)} total, {ready} ready to submit\n"
            f"[bold]Duration:[/bold] {elapsed:.1f} seconds\n"
            f"[bold]Reports:[/bold] {self.output_dir}\n\n"
            f"[dim]Elite findings are in: {self.output_dir}/elite_*.md[/dim]",
            title="[bold green]Elite Hunt Complete[/bold green]",
            border_style="green",
        ))
