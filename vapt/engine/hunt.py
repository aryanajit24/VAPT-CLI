"""Autonomous hunt orchestrator — `vapt hunt-auto` pipeline.

Reads a program scope YAML, runs the full 5-phase pipeline, and
generates submission-ready reports — all without interactive prompts.

Pipeline:
  Phase 1  UNDERSTAND  — parse scope, plan strategy
  Phase 2  DISCOVER    — recon, JS mining, endpoint extraction
  Phase 3  TEST        — run scanners on discovered surface
  Phase 4  VALIDATE    — false-positive filtering, escalation, dedup
  Phase 5  REPORT      — PoC generation, screenshots, bounty reports
"""

from __future__ import annotations

import json
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from vapt.engine.scope_parser import ProgramConfig, load_program_scope, filter_findings_by_program
from vapt.engine.rate_controller import RateController
from vapt.engine.decision import DecisionEngine
from vapt.engine.dedup import DuplicateDetector
from vapt.engine.proof import ProofGenerator
from vapt.engine.validator import FalsePositiveValidator
from vapt.engine.scope import is_in_scope
from vapt.utils.helpers import sanitize_target

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

console = Console()


class HuntOrchestrator:
    """Non-interactive autonomous hunt pipeline.

    Usage::

        orch = HuntOrchestrator("scopes/doordash.yaml", output_dir="./hunt-output")
        results = orch.run()
    """

    def __init__(
        self,
        scope_file: str,
        output_dir: str = "./vapt-reports",
        rate_profile: str = "normal",
        proxies: list[str] | None = None,
        auth_cookies_a: str | None = None,
        auth_cookies_b: str | None = None,
        auth_bearer_a: str | None = None,
        auth_bearer_b: str | None = None,
        program_age_months: int = 12,
        resolved_reports: int = 0,
    ) -> None:
        self.scope_file = scope_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Load program config
        self.program: ProgramConfig = load_program_scope(scope_file)

        # Rate controller
        self.rate = RateController(
            profile=rate_profile,
            proxies=proxies,
            rotate_ua=rate_profile in ("stealth", "polite"),
            required_headers=self.program.testing.required_headers,
        )

        # Decision engine
        self.has_auth = bool(auth_cookies_a or auth_bearer_a)
        self.decision = DecisionEngine(
            has_auth=self.has_auth,
            excluded_categories=set(self.program.excluded_categories),
        )

        # Duplicate detector
        self.dedup = DuplicateDetector(
            program_age_months=program_age_months,
            resolved_report_count=resolved_reports,
        )

        # Proof generator
        self.proof = ProofGenerator(output_dir=str(self.output_dir / "proofs"))

        # Validator
        self.validator = FalsePositiveValidator(timeout=15)

        # Sessions
        self.session_a = self._build_session(auth_cookies_a, auth_bearer_a)
        self.session_b = self._build_session(auth_cookies_b, auth_bearer_b)

        # Results
        self.all_findings: list[dict] = []
        self.phase_timings: dict[str, float] = {}
        self.discovered_endpoints: list[str] = []
        self.discovered_subdomains: list[str] = []

    def _build_session(self, cookies: str | None, bearer: str | None) -> requests.Session:
        s = requests.Session()
        s.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        s.verify = False
        for k, v in self.program.testing.required_headers.items():
            s.headers[k] = v
        if bearer:
            s.headers["Authorization"] = f"Bearer {bearer}"
        if cookies:
            for pair in cookies.split(";"):
                if "=" in pair:
                    k, v = pair.strip().split("=", 1)
                    s.cookies.set(k.strip(), v.strip())
        return s

    # ── Phase 1: UNDERSTAND ──────────────────────────────────────────

    def _phase_1_understand(self) -> dict:
        """Parse scope and build the hunt strategy."""
        p = self.program
        strategy = {
            "program": p.program_name,
            "platform": p.platform,
            "total_in_scope": len(p.in_scope_assets),
            "total_out_of_scope": len(p.out_of_scope_assets),
            "excluded_categories": len(p.excluded_categories),
            "bounty_eligible": len(p.bounty_eligible_targets),
            "has_auth": self.has_auth,
            "web_targets": p.web_targets,
            "api_targets": p.api_targets,
            "modules_to_run": p.modules or ["all"],
            "testing_constraints": {
                "max_rps": p.testing.max_requests_per_second,
                "no_automated": p.testing.no_automated_scanners,
                "no_destructive": p.testing.no_destructive_testing,
            },
        }

        if p.bounty_tiers:
            strategy["bounty_tiers"] = {
                t.severity: f"${t.min_usd}-${t.max_usd}" for t in p.bounty_tiers
            }

        return strategy

    # ── Phase 2: DISCOVER ────────────────────────────────────────────

    def _phase_2_discover(self, progress: Progress) -> dict:
        """Run recon and endpoint discovery on all in-scope targets."""
        results: dict[str, Any] = {
            "subdomains": [],
            "endpoints": [],
            "js_files": [],
            "technologies": [],
        }

        for asset in self.program.in_scope_assets:
            target = sanitize_target(asset.target)
            if not target:
                continue

            task = progress.add_task(f"[cyan]Recon: {target}...", total=None)

            # Subdomain enumeration
            try:
                from vapt.scanner.recon import ReconScanner
                recon = ReconScanner()
                recon_result = recon.run(target)

                subs = recon_result.get("ct_subdomains", [])
                for sub in subs:
                    if is_in_scope(sub, self.program.scope_config):
                        results["subdomains"].append(sub)

                techs = recon_result.get("technologies", {})
                if techs:
                    results["technologies"].append({"target": target, "tech": techs})

                self.all_findings.extend(recon_result.get("findings", []))
            except Exception:
                pass

            # JS file mining
            try:
                from vapt.scanner.deepjs import DeepJSRecon
                js_recon = DeepJSRecon(timeout=15)
                js_recon.session = self.session_a
                js_result = js_recon.run(target)

                results["js_files"].extend(js_result.get("js_files", [])[:50])

                endpoints = js_result.get("api_endpoints", [])
                for ep in endpoints:
                    if isinstance(ep, str):
                        results["endpoints"].append(ep)
                    elif isinstance(ep, dict):
                        results["endpoints"].append(ep.get("endpoint", ep.get("url", "")))

                self.all_findings.extend(js_result.get("findings", []))
            except Exception:
                pass

            # JS secret scanning
            try:
                from vapt.scanner.jsscan import JSSecretScanner
                js_scanner = JSSecretScanner(session=self.session_a, timeout=15)
                js_sec_result = js_scanner.run(target)
                self.all_findings.extend(js_sec_result.get("findings", []))
            except Exception:
                pass

            progress.update(task, description=f"[green]Recon: {target} ✓")
            progress.remove_task(task)

        self.discovered_endpoints = list(set(results["endpoints"]))
        self.discovered_subdomains = list(set(results["subdomains"]))
        return results

    # ── Phase 3: TEST ────────────────────────────────────────────────

    def _phase_3_test(self, progress: Progress) -> dict:
        """Run vulnerability scanners on discovered attack surface."""
        stats: dict[str, int] = {}

        for asset in self.program.in_scope_assets:
            target = sanitize_target(asset.target)
            if not target:
                continue

            task = progress.add_task(f"[cyan]Scanning: {target}...", total=None)

            scanners_to_run = self._get_scanners_for_asset(asset)

            for scanner_name, scanner_fn in scanners_to_run:
                try:
                    result = scanner_fn(target)
                    findings = result.get("findings", [])
                    for f in findings:
                        f["source_scanner"] = scanner_name
                        f["target_asset"] = target
                    self.all_findings.extend(findings)
                    stats[scanner_name] = stats.get(scanner_name, 0) + len(findings)
                except Exception:
                    pass

            progress.update(task, description=f"[green]Scanning: {target} ✓")
            progress.remove_task(task)

        return stats

    def _get_scanners_for_asset(self, asset) -> list[tuple[str, Any]]:
        """Return list of (name, scan_function) pairs for an asset."""
        scanners = []
        modules = self.program.modules or ["web", "api", "ssl", "dom", "auth", "fuzz", "jsscan", "cve", "advanced"]

        if "web" in modules:
            try:
                from vapt.scanner.webscan import WebScanner
                ws = WebScanner(session=self.session_a, timeout=15)
                scanners.append(("web", lambda t, s=ws: s.run(t)))
            except ImportError:
                pass

        if "ssl" in modules:
            try:
                from vapt.scanner.sslscan import SSLScanner
                ss = SSLScanner()
                scanners.append(("ssl", lambda t, s=ss: s.run(t)))
            except ImportError:
                pass

        if "api" in modules:
            try:
                from vapt.scanner.apiscan import APIScanner
                api = APIScanner(session=self.session_a, timeout=15)
                scanners.append(("api", lambda t, s=api: s.run(t)))
            except ImportError:
                pass

        if "dom" in modules:
            try:
                from vapt.scanner.domscan import DOMScanner
                ds = DOMScanner(session=self.session_a, timeout=15)
                scanners.append(("dom", lambda t, s=ds: s.run(t)))
            except ImportError:
                pass

        if "auth" in modules and self.has_auth:
            try:
                from vapt.scanner.authscan import AuthScanner
                auth = AuthScanner(session=self.session_a, timeout=15)
                scanners.append(("auth", lambda t, s=auth: s.run(t)))
            except ImportError:
                pass

        if "fuzz" in modules:
            try:
                from vapt.scanner.fuzzer import Fuzzer
                fz = Fuzzer(session=self.session_a, timeout=15)
                scanners.append(("fuzz", lambda t, s=fz: s.run(t)))
            except ImportError:
                pass

        if "cve" in modules:
            try:
                from vapt.scanner.cve import CVEScanner
                cve = CVEScanner()
                scanners.append(("cve", lambda t, s=cve: s.run(t)))
            except ImportError:
                pass

        if "advanced" in modules:
            try:
                from vapt.scanner.advanced import AdvancedScanner
                adv = AdvancedScanner(session=self.session_a, timeout=15)
                scanners.append(("advanced", lambda t, s=adv: s.run(t)))
            except ImportError:
                pass

        if "race" in modules:
            try:
                from vapt.scanner.racescan import RaceScanner
                rs = RaceScanner(session=self.session_a, timeout=15)
                scanners.append(("race", lambda t, s=rs: s.run(t)))
            except ImportError:
                pass

        if "smuggle" in modules:
            try:
                from vapt.scanner.smuggler import SmuggleScanner
                sm = SmuggleScanner(timeout=15)
                scanners.append(("smuggle", lambda t, s=sm: s.run(t)))
            except ImportError:
                pass

        if "cloud" in modules:
            try:
                from vapt.scanner.cloudscan import CloudScanner
                cs = CloudScanner(session=self.session_a, timeout=15)
                scanners.append(("cloud", lambda t, s=cs: s.run(t)))
            except ImportError:
                pass

        return scanners

    # ── Phase 4: VALIDATE ────────────────────────────────────────────

    def _phase_4_validate(self, progress: Progress) -> dict:
        """Filter false positives, run decision engine, and deduplicate."""
        stats: dict[str, Any] = {}

        task = progress.add_task("[cyan]Validating findings...", total=None)
        initial_count = len(self.all_findings)

        # Step 1: Scope filter
        self.all_findings = filter_findings_by_program(self.all_findings, self.program)
        stats["after_scope_filter"] = len(self.all_findings)

        # Step 2: False positive validation
        try:
            validated = self.validator.validate_findings(self.all_findings, self.session_a)
            confirmed = []
            for v in validated:
                if v.confirmed:
                    for f in self.all_findings:
                        fid = f.get("id", f.get("title", ""))
                        if str(fid) == v.vuln_id:
                            f["_validated"] = True
                            f["_confidence"] = v.confidence
                            f["severity"] = v.adjusted_severity
                            confirmed.append(f)
                            break
            if confirmed:
                self.all_findings = confirmed
        except Exception:
            pass

        stats["after_validation"] = len(self.all_findings)

        # Step 3: Decision engine — identify escalation opportunities
        decisions = self.decision.decide(self.all_findings)
        escalations = self.decision.get_escalation_tests(decisions)
        stats["escalation_opportunities"] = len(escalations)
        stats["decision_summary"] = self.decision.summarise(decisions)

        # Tag findings with their action
        action_map: dict[str, str] = {}
        for d in decisions:
            fid = d.finding.get("id", d.finding.get("title", ""))
            action_map[str(fid)] = d.action

        for f in self.all_findings:
            fid = str(f.get("id", f.get("title", "")))
            f["_decision"] = action_map.get(fid, "report")

        # Step 4: Duplicate detection
        worth, dupes = self.dedup.filter_likely_duplicates(self.all_findings, threshold=0.80)
        stats["likely_duplicates"] = len(dupes)
        stats["worth_submitting"] = len(worth)
        self.all_findings = worth

        progress.update(task, description=f"[green]Validation: {initial_count} → {len(self.all_findings)} findings ✓")
        progress.remove_task(task)

        return stats

    # ── Phase 5: REPORT ──────────────────────────────────────────────

    def _phase_5_report(self, progress: Progress) -> dict:
        """Generate PoCs, screenshots, and bounty reports."""
        stats: dict[str, Any] = {"reports": 0, "proofs": 0}

        if not self.all_findings:
            return stats

        task = progress.add_task("[cyan]Generating reports...", total=None)

        # Generate proofs for top findings
        top_findings = sorted(
            self.all_findings,
            key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                f.get("severity", "info").lower(), 5
            ),
        )[:15]

        for f in top_findings:
            try:
                artifacts = self.proof.generate(f)
                if artifacts:
                    stats["proofs"] += 1
            except Exception:
                pass

        # Generate bounty reports
        try:
            from vapt.reporting.bounty_report import BountyReportGenerator
            gen = BountyReportGenerator(output_dir=str(self.output_dir))

            aggregate = {
                "scan_id": f"hunt-{int(time.time())}",
                "target": self.program.program_name or "hunt",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "findings": self.all_findings,
                "total_findings": len(self.all_findings),
            }

            gen.generate_full_report(aggregate, output_format="md")
            gen.generate_full_report(aggregate, output_format="field")
            if self.all_findings:
                gen.generate_per_finding_reports(aggregate)
            stats["reports"] += 1
        except Exception:
            pass

        # Save raw JSON
        json_path = self.output_dir / "hunt_findings.json"
        json_path.write_text(
            json.dumps(self.all_findings, indent=2, default=str),
            encoding="utf-8",
        )

        # Save summary
        summary = self._build_summary()
        summary_path = self.output_dir / "hunt_summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

        progress.update(task, description=f"[green]Reports generated ✓")
        progress.remove_task(task)

        return stats

    # ── Main entry point ─────────────────────────────────────────────

    def run(self) -> dict[str, Any]:
        """Execute the full autonomous hunt pipeline."""
        started = time.time()

        # Banner
        console.print(Panel(
            f"[bold]VAPT CLI — Autonomous Hunt[/bold]\n\n"
            f"Program:  {self.program.program_name or 'N/A'}\n"
            f"Platform: {self.program.platform}\n"
            f"Scope:    {self.scope_file}\n"
            f"Targets:  {len(self.program.in_scope_assets)} in-scope\n"
            f"Auth:     {'Yes' if self.has_auth else 'No'}\n"
            f"Rate:     {self.rate._profile.name}",
            title="[bold cyan]Autonomous Hunt[/bold cyan]",
            border_style="cyan",
        ))

        results: dict[str, Any] = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:

            # Phase 1
            t1 = time.time()
            phase1_task = progress.add_task("[cyan]Phase 1: Understanding program...", total=None)
            strategy = self._phase_1_understand()
            results["strategy"] = strategy
            progress.update(phase1_task, description="[green]Phase 1: Program understood ✓")
            progress.remove_task(phase1_task)
            self.phase_timings["understand"] = time.time() - t1

            self._show_strategy(strategy)

            # Phase 2
            t2 = time.time()
            results["discovery"] = self._phase_2_discover(progress)
            self.phase_timings["discover"] = time.time() - t2

            # Phase 3
            t3 = time.time()
            results["testing"] = self._phase_3_test(progress)
            self.phase_timings["test"] = time.time() - t3

            # Phase 4
            t4 = time.time()
            results["validation"] = self._phase_4_validate(progress)
            self.phase_timings["validate"] = time.time() - t4

            # Phase 5
            t5 = time.time()
            results["reporting"] = self._phase_5_report(progress)
            self.phase_timings["report"] = time.time() - t5

        elapsed = time.time() - started
        results["duration_sec"] = round(elapsed, 2)
        results["total_findings"] = len(self.all_findings)
        results["rate_stats"] = self.rate.stats()

        self._show_results(results, elapsed)

        return results

    # ── Display helpers ──────────────────────────────────────────────

    def _show_strategy(self, strategy: dict) -> None:
        table = Table(title="[bold]Hunt Strategy[/bold]", show_header=True)
        table.add_column("Setting", style="bold")
        table.add_column("Value")
        table.add_row("Program", strategy.get("program", "N/A"))
        table.add_row("Platform", strategy.get("platform", "N/A"))
        table.add_row("In-scope targets", str(strategy.get("total_in_scope", 0)))
        table.add_row("Bounty-eligible", str(strategy.get("bounty_eligible", 0)))
        table.add_row("Excluded categories", str(strategy.get("excluded_categories", 0)))
        table.add_row("Auth available", "Yes" if strategy.get("has_auth") else "No")

        bounty = strategy.get("bounty_tiers", {})
        if bounty:
            for sev, rng in bounty.items():
                table.add_row(f"  {sev.title()} bounty", rng)

        constraints = strategy.get("testing_constraints", {})
        if constraints.get("no_automated"):
            table.add_row("⚠ No automated scanners", "Enabled — using polite mode")
        table.add_row("Max RPS", str(constraints.get("max_rps", "N/A")))

        console.print(table)
        console.print()

    def _show_results(self, results: dict, elapsed: float) -> None:
        # Phase timings
        timing_table = Table(title="[bold]Phase Timings[/bold]", show_header=True)
        timing_table.add_column("Phase", style="cyan")
        timing_table.add_column("Duration", style="green")
        for phase, dur in self.phase_timings.items():
            timing_table.add_row(phase.title(), f"{dur:.1f}s")
        timing_table.add_row("[bold]Total[/bold]", f"[bold]{elapsed:.1f}s[/bold]")
        console.print(timing_table)

        # Findings summary
        if self.all_findings:
            findings_table = Table(title="[bold]Confirmed Findings[/bold]", show_header=True)
            findings_table.add_column("#", style="dim")
            findings_table.add_column("Severity", style="bold")
            findings_table.add_column("Title")
            findings_table.add_column("Duplicate Risk")
            findings_table.add_column("Payout")

            sev_colors = {"critical": "red", "high": "yellow", "medium": "blue", "low": "dim", "info": "dim"}
            dedup_colors = {"low": "green", "medium": "yellow", "high": "red", "very_high": "bold red"}

            for i, f in enumerate(self.all_findings[:20], 1):
                sev = f.get("severity", "info").lower()
                dedup_risk = f.get("_duplicate_risk", "?")
                payout = self.program.estimated_payout(sev)
                payout_str = f"${payout[0]}-${payout[1]}" if payout[1] > 0 else "-"

                findings_table.add_row(
                    str(i),
                    f"[{sev_colors.get(sev, 'white')}]{sev.upper()}[/]",
                    f.get("title", "")[:60],
                    f"[{dedup_colors.get(dedup_risk, 'white')}]{dedup_risk}[/]",
                    payout_str,
                )

            console.print(findings_table)

        # Validation summary
        val = results.get("validation", {})
        if val:
            console.print(f"\n  Scope filtered:  {val.get('after_scope_filter', '?')}")
            console.print(f"  FP validated:    {val.get('after_validation', '?')}")
            console.print(f"  Likely dupes:    {val.get('likely_duplicates', '?')}")
            console.print(f"  Worth submitting: [bold green]{val.get('worth_submitting', '?')}[/bold green]")

        # Final panel
        console.print(Panel(
            f"[bold green]Hunt complete![/bold green]\n\n"
            f"Program: {self.program.program_name}\n"
            f"Duration: {elapsed:.1f}s\n"
            f"Findings: {len(self.all_findings)}\n"
            f"Reports: {self.output_dir}\n\n"
            f"[dim]Review hunt_findings.json and per-finding .md reports.[/dim]\n"
            f"[dim]PoC files are in {self.output_dir}/proofs/[/dim]",
            title=f"[bold cyan]{self.program.platform} Hunt — Complete[/bold cyan]",
            border_style="green",
        ))

    def _build_summary(self) -> dict:
        sev_counts: dict[str, int] = {}
        for f in self.all_findings:
            sev = f.get("severity", "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        return {
            "program": self.program.program_name,
            "platform": self.program.platform,
            "scope_file": self.scope_file,
            "total_findings": len(self.all_findings),
            "severity_breakdown": sev_counts,
            "phase_timings": self.phase_timings,
            "rate_stats": self.rate.stats(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
