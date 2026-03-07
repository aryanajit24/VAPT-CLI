"""VAPT CLI entry point and command definitions."""

from __future__ import annotations

import json as _json
import subprocess
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from vapt import __version__
from vapt.banner import print_banner
from vapt.config import app as config_app
from vapt.database.db import init_db
from vapt.database.seed_kb import seed
from vapt.engine.compliance import ComplianceEngine
from vapt.engine.correlator import Correlator
from vapt.engine.evidence import enrich_all_findings
from vapt.engine.knowledge_base import KnowledgeBase
from vapt.engine.risk_scorer import RiskScorer
from vapt.engine.safe_mode import (
    build_safety_config,
    filter_findings_by_safety,
    format_safety_summary,
    get_safety_profile,
)
from vapt.engine.scope import (
    build_scope_from_flags,
    filter_findings_by_scope,
    is_in_scope,
    print_scope_summary,
    should_run_module,
)
from vapt.engine.validator import FalsePositiveValidator
from vapt.engine.waf import detect_and_prepare
from vapt.plugins.loader import PluginLoader
from vapt.reporting.bounty_report import BountyReportGenerator
from vapt.reporting.generator import ReportGenerator
from vapt.scanner.advanced import AdvancedScanner
from vapt.scanner.apiscan import APIScanner
from vapt.scanner.authscan import AuthScanner
from vapt.scanner.cloudscan import CloudScanner
from vapt.scanner.cve import CVEScanner
from vapt.scanner.dbscan import DatabaseScanner
from vapt.scanner.domscan import DOMScanner
from vapt.scanner.fuzzer import Fuzzer
from vapt.scanner.infrascan import InfraScanner
from vapt.scanner.jsscan import JSSecretScanner
from vapt.scanner.mobilescan import MobileScanner
from vapt.scanner.portscan import PortScanner
from vapt.scanner.racescan import RaceScanner
from vapt.scanner.recon import ReconScanner
from vapt.scanner.smuggler import SmuggleScanner
from vapt.scanner.sslscan import SSLScanner
from vapt.scanner.takeover import SubdomainTakeoverScanner
from vapt.scanner.webscan import WebScanner
from vapt.engine.intelligence import IntelligenceEngine
from vapt.engine.elite_intelligence import EliteIntelligenceEngine
from vapt.engine.smart_hunt import SmartHuntOrchestrator
from vapt.scanner.bizscan import BusinessLogicScanner
from vapt.scanner.deepjs import DeepJSRecon
from vapt.scanner.authflow import AuthFlowScanner
from vapt.engine.oob import OOBManager
from vapt.reporting.elite_report import EliteReportGenerator
from vapt.utils.auth import AuthManager
from vapt.utils.helpers import generate_scan_id, utcnow
from vapt.utils.notifications import dispatch_alerts
from vapt.utils.ratelimit import StealthSession, PROFILES as STEALTH_PROFILES
from vapt.utils.validators import validate_target

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
app = typer.Typer(
    name="vapt",
    help="VAPT CLI — The ultimate vulnerability assessment & penetration testing toolkit.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(config_app, name="config")


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]VAPT CLI[/bold cyan] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True
    ),
) -> None:
    """VAPT CLI — The ultimate vulnerability assessment toolkit."""


# Shared helpers

def _risk_color(level: str) -> str:
    """Return a Rich colour tag for severity."""
    return {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "yellow",
        "low": "green",
        "minimal": "bright_green",
        "info": "blue",
    }.get(level.lower(), "white")


def _build_aggregate(
    scan_id: str,
    target: str,
    started_at: datetime,
    all_findings: list[dict],
) -> dict:
    """Enrich, score, correlate, and map findings to compliance frameworks."""
    kb = KnowledgeBase()
    enriched = kb.match_findings(all_findings)

    # Intelligence engine — deep severity analysis, chain detection, FP elimination
    intel = IntelligenceEngine()
    intel_result = intel.analyze(enriched)
    enriched = intel_result["findings"]

    scorer = RiskScorer()
    score_result = scorer.score_scan(enriched)

    correlator = Correlator()
    correlation = correlator.correlate(enriched)

    compliance_engine = ComplianceEngine()
    compliance = compliance_engine.generate_dashboard(enriched)

    finished_at = utcnow()

    # Merge attack chains from both correlator and intelligence engine
    all_chains = correlation["attack_chains"] + intel_result.get("chains", [])

    return {
        "scan_id": scan_id,
        "target": target,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": (finished_at - started_at).total_seconds(),
        "overall_score": score_result["overall_score"],
        "risk_level": score_result["risk_level"],
        "severity_counts": score_result["severity_counts"],
        "total_findings": len(score_result["scored_findings"]),
        "findings": score_result["scored_findings"],
        "attack_chains": all_chains,
        "correlation_summary": correlation["correlation_summary"],
        "compliance": compliance,
        "intelligence": intel_result.get("risk_summary", {}),
        "recommendations": intel_result.get("recommendations", []),
    }


def _show_findings_table(findings: list[dict]) -> None:
    """Print a rich table of the most important findings."""
    if not findings:
        console.print("[dim]No findings to display.[/dim]")
        return

    # Sort by severity weight then CVSS
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: (sev_order.get(f.get("severity", "info"), 5), -(f.get("cvss_score", 0))),
    )

    tbl = Table(
        title="[bold]Vulnerability Findings[/bold]",
        show_header=True,
        header_style="bold magenta",
        show_lines=False,
        title_style="bold white",
        expand=True,
    )
    tbl.add_column("#", style="dim", width=4, justify="right")
    tbl.add_column("Severity", width=10)
    tbl.add_column("CVSS", width=5, justify="right")
    tbl.add_column("ID", width=10)
    tbl.add_column("Title", ratio=3)
    tbl.add_column("Category", width=14)

    for idx, f in enumerate(sorted_findings[:50], 1):  # Show top 50
        sev = f.get("severity", "info")
        cvss = f.get("cvss_score", 0)
        tbl.add_row(
            str(idx),
            f"[{_risk_color(sev)}]{sev.upper()}[/]",
            f"{cvss:.1f}",
            f.get("vuln_id", ""),
            f.get("title", "")[:80],
            f.get("category", ""),
        )

    console.print(tbl)
    if len(sorted_findings) > 50:
        console.print(f"  [dim]… and {len(sorted_findings) - 50} more (see full report)[/dim]")


def _generate_and_display(
    aggregate: dict,
    output_dir: str,
    report_format: str,
    executive: bool,
    notify: bool,
    auto_open: bool = True,
) -> None:
    """Generate reports, display summary dashboard, optionally open in browser."""
    # Always include JSON for re-reporting
    formats = list({f.strip() for f in report_format.split(",")})
    if "json" not in formats:
        formats.append("json")

    generator = ReportGenerator(output_dir=output_dir)
    paths = generator.generate(aggregate, formats=formats)

    if executive:
        try:
            from vapt.reporting.html import HTMLReporter
            exec_path = Path(output_dir) / f"{aggregate['scan_id']}_executive.html"
            HTMLReporter(template="executive.html").generate(aggregate, str(exec_path))
            paths["executive_html"] = str(exec_path)
        except Exception:
            pass

    duration = aggregate.get("duration_seconds", 0)
    risk = aggregate["risk_level"]
    score = aggregate["overall_score"]
    total = aggregate.get("total_findings", len(aggregate.get("findings", [])))
    sev_counts = aggregate.get("severity_counts", {})

    # Header panel
    header_text = Text()
    header_text.append("  SCAN COMPLETE  ", style="bold white on green")
    header_text.append(f"\n\n  Target:   {aggregate['target']}")
    header_text.append(f"\n  Scan ID:  {aggregate['scan_id']}")
    header_text.append(f"\n  Duration: {duration:.0f}s")
    header_text.append(f"\n  Findings: {total}")
    header_text.append("\n  Risk:     ")
    header_text.append(risk.upper(), style=_risk_color(risk))
    header_text.append(f"  ({score}/100)")
    console.print(Panel(header_text, title="[bold cyan]VAPT CLI Results[/bold cyan]", border_style="cyan"))

    # Severity breakdown
    sev_tbl = Table(show_header=True, header_style="bold magenta", width=40)
    sev_tbl.add_column("Severity", style="bold")
    sev_tbl.add_column("Count", justify="right")
    sev_tbl.add_column("Bar", width=15)
    max_count = max(sev_counts.values()) if sev_counts else 1
    for sev_name, color in [
        ("critical", "red"),
        ("high", "orange3"),
        ("medium", "yellow"),
        ("low", "green"),
        ("info", "blue"),
    ]:
        cnt = sev_counts.get(sev_name, 0)
        bar_len = int((cnt / max(max_count, 1)) * 15) if cnt else 0
        bar = f"[{color}]{'█' * bar_len}{'░' * (15 - bar_len)}[/{color}]"
        tbl_row_sev = f"[{color}]{sev_name.capitalize()}[/{color}]"
        sev_tbl.add_row(tbl_row_sev, str(cnt), bar)
    console.print(sev_tbl)

    # Top findings table
    _show_findings_table(aggregate.get("findings", []))

    # Attack chains
    chains = aggregate.get("attack_chains", [])
    if chains:
        console.print(f"\n[bold red]⚠ {len(chains)} attack chain(s) detected[/bold red]")
        for chain in chains[:5]:
            console.print(f"  [red]→[/red] {chain.get('name', chain.get('description', ''))}")

    # Intelligence recommendations
    recs = aggregate.get("recommendations", [])
    if recs:
        console.print(f"\n[bold yellow]Prioritized Recommendations ({len(recs)}):[/bold yellow]")
        for rec in recs[:10]:
            priority = rec.get("priority", 9)
            sev = rec.get("severity", "medium")
            p_label = {1: "🔴 P1", 2: "🟠 P2", 3: "🟡 P3", 4: "🟢 P4"}.get(priority, f"P{priority}")
            console.print(f"  {p_label} [{_risk_color(sev)}]{rec.get('title', '')}[/]")

    # Report paths
    console.print("\n[bold]Reports generated:[/bold]")
    for fmt, path in paths.items():
        console.print(f"  [dim]{fmt:18}[/dim] → {path}")
        if auto_open and fmt in ("html", "executive_html") and path.endswith(".html"):
            try:
                webbrowser.open(f"file://{Path(path).resolve()}")
            except Exception:
                pass

    if notify:
        try:
            from vapt.config import load_config as _lc
            dispatch_alerts(aggregate, _lc())
        except Exception:
            pass


def _run_module(
    name: str,
    fn,
    prog: Progress,
    all_findings: list[dict],
    timings: dict[str, float],
) -> dict | None:
    """Run a single scanner module inside the progress bar.

    Returns the raw result dict (for recon chaining) or None on error.
    """
    label = f"[cyan]{name}…"
    task = prog.add_task(label, total=None)
    t0 = time.time()
    result = None
    try:
        result = fn()
        all_findings.extend(result.get("findings", []))
        elapsed = time.time() - t0
        timings[name] = elapsed
        count = len(result.get("findings", []))
        prog.update(task, description=f"[green]✓ {name} ({count} findings, {elapsed:.1f}s)")
    except Exception as exc:
        elapsed = time.time() - t0
        timings[name] = elapsed
        console.print(f"[yellow]  ⚠ {name} error (continuing): {exc}[/yellow]")
        prog.update(task, description=f"[yellow]⚠ {name} (error, {elapsed:.1f}s)")
    return result


# vapt scan — THE ULTIMATE ONE-COMMAND SCANNER

@app.command("scan")
def cmd_scan(
    target: str = typer.Option(
        ..., "--target", "-t",
        help="Target — domain, IP, or URL.  One command scans everything.",
    ),
    ports: str = typer.Option(
        "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5900,6379,8080,8443,9200,27017",
        "--ports", "-p",
        help="Ports to scan (comma-separated or range like 1-65535).",
    ),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option(
        "html", "--format", "-f",
        help="Report format(s): html,pdf,json (comma-separated).",
    ),
    api_token: Optional[str] = typer.Option(
        None, "--token",
        help="Bearer token for authenticated API scanning.",
    ),
    deep: bool = typer.Option(
        False, "--deep", "-d",
        help="Deep mode: also scan discovered subdomains (slower, more thorough).",
    ),
    max_subdomains: int = typer.Option(
        5, "--max-subs",
        help="Max subdomains to deep-scan (used with --deep).",
    ),
    auth_method: str = typer.Option(
        "none", "--auth",
        help="Auth method: none|bearer|cookie|form|basic|digest|oauth2|header.",
    ),
    login_url: Optional[str] = typer.Option(
        None, "--login-url",
        help="Login URL for form-based auth.",
    ),
    username: Optional[str] = typer.Option(None, "--username", "-u"),
    password: Optional[str] = typer.Option(None, "--password", "-P"),
    cookies: Optional[str] = typer.Option(
        None, "--cookies",
        help="Cookies string (name=val; name2=val2) for cookie auth.",
    ),
    stealth: str = typer.Option(
        "normal", "--stealth", "-s",
        help="Stealth profile: aggressive|normal|polite|stealth.",
    ),
    waf_bypass: bool = typer.Option(
        False, "--waf-bypass",
        help="Enable WAF detection and bypass techniques.",
    ),
    validate_findings: bool = typer.Option(
        False, "--validate",
        help="Re-test findings to filter false positives.",
    ),
    cloud: bool = typer.Option(
        True, "--cloud/--no-cloud",
        help="Run cloud misconfiguration checks (S3, Azure, GCP, Firebase).",
    ),
    plugins_dir: Optional[str] = typer.Option(
        None, "--plugins",
        help="Extra directory to load custom plugins from.",
    ),
    executive: bool = typer.Option(False, "--executive", help="Also generate executive summary."),
    notify: bool = typer.Option(False, "--notify", help="Send alerts after scan (uses config)."),
    scope_in: Optional[str] = typer.Option(
        None, "--scope-in",
        help="In-scope targets (comma-separated): *.example.com,api.example.com",
    ),
    scope_out: Optional[str] = typer.Option(
        None, "--scope-out",
        help="Out-of-scope targets: blog.example.com,*.cdn.example.com",
    ),
    scope_file: Optional[str] = typer.Option(
        None, "--scope-file",
        help="Path to YAML scope file (see docs for format).",
    ),
    min_severity: str = typer.Option(
        "info", "--min-severity",
        help="Minimum severity to report: critical|high|medium|low|info.",
    ),
    fast: bool = typer.Option(
        False, "--fast",
        help="Fast mode: skip slow modules behind WAF (auth, race, smuggle, advanced), use normal stealth.",
    ),
    show_all: bool = typer.Option(
        False, "--show-all",
        help="Show ALL findings including out-of-scope ones (for research). Filtered findings marked as informational.",
    ),
    modules: Optional[str] = typer.Option(
        None, "--modules",
        help="Only run these modules: recon,port,ssl,web,dom,auth,api,fuzz,race,smuggle,advanced,cloud,cve,infra,db,plugins",
    ),
    exclude_categories: Optional[str] = typer.Option(
        None, "--exclude-categories",
        help="Exclude vuln categories: info_disclosure,security_header,etc.",
    ),
    custom_headers: Optional[str] = typer.Option(
        None, "--headers",
        help="Custom headers for every request (key:value,key2:value2). E.g. 'X-Hackerone:myuser,BUGCROWD:myuser'",
    ),
    safety: str = typer.Option(
        "standard", "--safety",
        help="Safety profile: aggressive|standard|meesho|optus|hackerone|bugcrowd. Controls which attacks are allowed.",
    ),
) -> None:
    """
    Run a FULL vulnerability assessment — everything in one command.

    \b
    This single command runs ALL of these modules automatically:
      1. Authentication    — login with form/bearer/cookie/OAuth2/basic/digest
      2. WAF Detection     — detect & bypass Cloudflare, AWS WAF, Akamai, etc.
      3. Reconnaissance    — DNS, WHOIS, subdomains, tech fingerprinting
      4. Port Scanning     — open ports, banners, default credentials
      5. SSL/TLS Analysis  — certificates, protocols, ciphers, HSTS
      6. Web Scanning      — crawl + attack: SQLi, XSS, SSTI, SSRF, XXE, RCE…
      7. DOM/Client Scan   — DOM XSS, prototype pollution, exposed secrets, postMessage…
      8. Auth Scanning     — CSRF, CORS, IDOR, JWT, OAuth, session, defaults, MFA bypass…
      9. API Scanning      — BOLA, JWT, GraphQL, mass assignment, verb tampering…
     10. Fuzzing           — directory brute-force, hidden files, IDOR testing
     11. Race Conditions   — double-spend, rate limit bypass, TOCTOU exploits
     12. HTTP Smuggling    — CL.TE, TE.CL, TE.TE, H2 downgrade, CRLF splitting
     13. Cloud Scanning    — S3 buckets, Azure blobs, GCP, Firebase, subdomain takeover
     14. CVE Detection     — banner fingerprinting + NVD API lookups
     15. Plugin Checks     — custom YAML/Python security checks
     16. Validation        — re-confirm ALL findings with HIGH confidence
     17. Correlation       — chain findings into attack paths
     18. Compliance        — OWASP Top 10, SANS 25, PCI-DSS mapping
     19. Reporting         — HTML + JSON + Bug Bounty markdown + per-finding reports

    \b
    With --deep, discovered subdomains will ALSO be scanned (web + API + fuzz).
    With --stealth, requests are throttled and randomized to avoid detection.
    With --waf-bypass, payloads are encoded/mutated to evade WAF rules.
    With --validate, findings are re-tested to filter false positives.

    \b
    Examples:
      vapt scan -t example.com
      vapt scan -t https://api.example.com --token "Bearer eyJ…"
      vapt scan -t 192.168.1.1 -p 1-65535 --deep
      vapt scan -t example.com --auth form --login-url https://example.com/login -u admin -P pass
      vapt scan -t example.com --stealth stealth --waf-bypass --validate
      vapt scan -t example.com --deep --format html,pdf,json --executive --notify
    """

    print_banner(console)

    if fast:
        if stealth == "polite" or stealth == "stealth":
            stealth = "normal"  # upgrade to faster rate
            console.print("  [yellow]⚡ Fast mode: stealth upgraded to 'normal' (10 req/s)[/yellow]")

    ok, normalized = validate_target(target)
    if not ok:
        console.print(f"[bold red]Invalid target:[/bold red] {normalized}")
        raise typer.Exit(1)
    target = normalized

    scan_id = generate_scan_id()
    started_at = utcnow()

    credentials = None
    if username or password:
        credentials = {"username": username or "", "password": password or ""}
    cookie_dict = None
    if cookies:
        cookie_dict = dict(pair.split("=", 1) for pair in cookies.split(";") if "=" in pair)
    auth_mgr = AuthManager(
        method=auth_method,
        token=api_token,
        credentials=credentials,
        login_url=login_url,
        cookies=cookie_dict,
    )
    session = auth_mgr.get_session()

    if custom_headers:
        for pair in custom_headers.split(","):
            pair = pair.strip()
            if ":" in pair:
                key, val = pair.split(":", 1)
                session.headers[key.strip()] = val.strip()
        console.print(
            f"  [dim]↳ Custom headers: {', '.join(k for k in session.headers if k.startswith(('X-', 'BUGCROWD')))}[/dim]"
        )

    stealth_session = StealthSession(profile=stealth, session=session)
    stealth_info = STEALTH_PROFILES.get(stealth, STEALTH_PROFILES["normal"])

    scope = build_scope_from_flags(
        scope_in=scope_in,
        scope_out=scope_out,
        min_severity=min_severity,
        modules=modules,
        exclude_categories=exclude_categories,
        scope_file=scope_file,
    )
    print_scope_summary(scope, console)

    try:
        safety_profile = get_safety_profile(safety)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1)
    console.print(Panel(
        format_safety_summary(safety_profile),
        title=f"[bold yellow]Safety Profile: {safety_profile.name}[/bold yellow]",
        border_style="yellow",
    ))
    safety_config = build_safety_config(safety_profile)

    mode_parts = []
    if deep:
        mode_parts.append("[bold red]DEEP[/bold red]")
    if stealth != "normal":
        mode_parts.append(f"[bold yellow]{stealth.upper()}[/bold yellow]")
    if waf_bypass:
        mode_parts.append("[bold magenta]WAF-BYPASS[/bold magenta]")
    if auth_method != "none":
        mode_parts.append(f"[bold green]AUTH:{auth_method.upper()}[/bold green]")
    if safety != "aggressive":
        mode_parts.append(f"[bold yellow]SAFE:{safety.upper()}[/bold yellow]")
    mode = " + ".join(mode_parts) if mode_parts else "[bold cyan]STANDARD[/bold cyan]"

    console.print(Panel(
        f"[bold]Scan ID:[/bold]  {scan_id}\n"
        f"[bold]Target:[/bold]   {target}\n"
        f"[bold]Ports:[/bold]    {ports}\n"
        f"[bold]Mode:[/bold]     {mode}\n"
        f"[bold]Safety:[/bold]   {safety_profile.name}\n"
        f"[bold]Stealth:[/bold]  {stealth_info.name} ({stealth_info.requests_per_second} req/s)\n"
        f"[bold]Started:[/bold]  {started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        title="[bold cyan]VAPT CLI — Full Vulnerability Assessment[/bold cyan]",
        border_style="cyan",
    ))

    all_findings: list[dict] = []
    timings: dict[str, float] = {}
    discovered_subdomains: list[str] = []
    waf_result = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as prog:

        if waf_bypass:
            waf_task = prog.add_task("[cyan]WAF Detection…", total=None)
            t0 = time.time()
            try:
                waf_result, _waf_engine = detect_and_prepare(target, session)
                elapsed = time.time() - t0
                timings["WAF Detection"] = elapsed
                if waf_result.detected:
                    console.print(
                        f"  [yellow]⚠ WAF detected: {waf_result.waf_name} "
                        f"(confidence: {waf_result.confidence:.0%})[/yellow]"
                    )
                    console.print("  [dim]↳ WAF bypass techniques activated[/dim]")
                    prog.update(waf_task, description=f"[yellow]⚠ WAF: {waf_result.waf_name} ({elapsed:.1f}s)")
                else:
                    prog.update(waf_task, description=f"[green]✓ No WAF detected ({elapsed:.1f}s)")
            except Exception as exc:
                timings["WAF Detection"] = time.time() - t0
                prog.update(waf_task, description=f"[yellow]⚠ WAF detection error ({exc})")

        if should_run_module("recon", scope):
            recon_result = _run_module(
                "Reconnaissance",
                lambda: ReconScanner().run(target),
                prog, all_findings, timings,
            )
            if recon_result:
                discovered_subdomains = recon_result.get("subdomains", [])
                techs = recon_result.get("technologies", [])
                # Filter discovered subdomains through scope
                if scope.out_of_scope:
                    discovered_subdomains = [
                        s for s in discovered_subdomains if is_in_scope(s, scope)
                    ]
                if discovered_subdomains:
                    console.print(
                        f"  [dim]↳ Discovered {len(discovered_subdomains)} in-scope subdomains[/dim]"
                    )
                if techs:
                    console.print(f"  [dim]↳ Technologies: {', '.join(techs[:5])}[/dim]")

        if should_run_module("port", scope) and safety_profile.allow_port_scan:
            _run_module(
                "Port Scanning",
                lambda: PortScanner().run(target, ports),
                prog, all_findings, timings,
            )
        elif should_run_module("port", scope) and not safety_profile.allow_port_scan:
            console.print("  [yellow]⊘ Port Scanning SKIPPED (blocked by safety profile)[/yellow]")

        if should_run_module("ssl", scope):
            _run_module(
                "SSL/TLS Analysis",
                lambda: SSLScanner().run(target),
                prog, all_findings, timings,
            )

        if should_run_module("web", scope):
            _run_module(
                "Web Scanning",
                lambda: WebScanner(safety_config=safety_config, session=stealth_session).run(target),
                prog, all_findings, timings,
            )

        if should_run_module("dom", scope):
            _run_module(
                "DOM/Client-Side",
                lambda: DOMScanner(session=session).run(target),
                prog, all_findings, timings,
            )

        _skip_auth = fast and waf_result and waf_result.detected
        if should_run_module("auth", scope) and not _skip_auth:
            _run_module(
                "Auth Scanning",
                lambda: AuthScanner(session=stealth_session, safety_config=safety_config).run(target),
                prog, all_findings, timings,
            )
        elif _skip_auth:
            console.print("  [yellow]⚡ Auth Scanning SKIPPED (fast mode + WAF detected)[/yellow]")

        if should_run_module("api", scope):
            _run_module(
                "API Scanning",
                lambda: APIScanner(safety_config=safety_config, session=stealth_session).run(target, token=api_token),
                prog, all_findings, timings,
            )

        if should_run_module("fuzz", scope):
            _run_module(
                "Dir/File Fuzzing",
                lambda: Fuzzer(safety_config=safety_config, session=stealth_session).run(target),
                prog, all_findings, timings,
            )

        if should_run_module("jsscan", scope):
            _run_module(
                "JS Secrets Mining",
                lambda: JSSecretScanner(session=stealth_session).run(target),
                prog, all_findings, timings,
            )

        _skip_race = fast and waf_result and waf_result.detected
        if should_run_module("race", scope) and safety_profile.allow_race_conditions and not _skip_race:
            _run_module(
                "Race Conditions",
                lambda: RaceScanner(session=session).run(target),
                prog, all_findings, timings,
            )
        elif _skip_race:
            console.print("  [yellow]⚡ Race Conditions SKIPPED (fast mode + WAF detected)[/yellow]")
        elif should_run_module("race", scope) and not safety_profile.allow_race_conditions:
            console.print("  [yellow]⊘ Race Conditions SKIPPED (blocked by safety profile)[/yellow]")

        _skip_smuggle = fast and waf_result and waf_result.detected
        if should_run_module("smuggle", scope) and safety_profile.allow_http_smuggling and not _skip_smuggle:
            _run_module(
                "HTTP Smuggling",
                lambda: SmuggleScanner().run(target),
                prog, all_findings, timings,
            )
        elif _skip_smuggle:
            console.print("  [yellow]⚡ HTTP Smuggling SKIPPED (fast mode + WAF detected)[/yellow]")
        elif should_run_module("smuggle", scope) and not safety_profile.allow_http_smuggling:
            console.print("  [yellow]⊘ HTTP Smuggling SKIPPED (blocked by safety profile)[/yellow]")

        if cloud and should_run_module("cloud", scope) and safety_profile.allow_cloud_scan:
            _run_module(
                "Cloud Scanning",
                lambda: {"findings": CloudScanner(target, session=session).run()},
                prog, all_findings, timings,
            )
        elif cloud and should_run_module("cloud", scope) and not safety_profile.allow_cloud_scan:
            console.print("  [yellow]⊘ Cloud Scanning SKIPPED (blocked by safety profile)[/yellow]")

        if should_run_module("infra", scope):
            _run_module(
                "Infrastructure Scanning",
                lambda: InfraScanner(session=stealth_session, timeout=10, safety_config=safety_config).run(target),
                prog, all_findings, timings,
            )

        if should_run_module("db", scope):
            _run_module(
                "Database Scanning",
                lambda: DatabaseScanner(session=stealth_session, timeout=5, safety_config=safety_config).run(target, ports=ports),
                prog, all_findings, timings,
            )

        if should_run_module("cve", scope):
            _run_module(
                "CVE Detection",
                lambda: CVEScanner().run(target),
                prog, all_findings, timings,
            )

        if discovered_subdomains:
            _run_module(
                f"Subdomain Takeover ({len(discovered_subdomains)} subs)",
                lambda: SubdomainTakeoverScanner(session=stealth_session).run(
                    target, subdomains=discovered_subdomains
                ),
                prog, all_findings, timings,
            )

        if should_run_module("plugins", scope):
            plugin_dirs = [plugins_dir] if plugins_dir else None
            loader = PluginLoader(plugin_dirs=plugin_dirs)
            plugins = loader.discover()
            if plugins:
                _run_module(
                    f"Plugins ({len(plugins)})",
                    lambda: {"findings": loader.run_all(target, session)},
                    prog, all_findings, timings,
                )

        if deep and discovered_subdomains:
            subs_to_scan = discovered_subdomains[:max_subdomains]
            console.print(
                f"\n[bold cyan]Deep mode:[/bold cyan] scanning "
                f"{len(subs_to_scan)} subdomains…"
            )
            for sub in subs_to_scan:
                console.print(f"\n  [bold]◆ Subdomain:[/bold] {sub}")

                _run_module(
                    f"SSL ({sub})",
                    lambda s=sub: SSLScanner().run(s),
                    prog, all_findings, timings,
                )

                _run_module(
                    f"Web ({sub})",
                    lambda s=sub: WebScanner(safety_config=safety_config, session=stealth_session).run(s),
                    prog, all_findings, timings,
                )

                _run_module(
                    f"API ({sub})",
                    lambda s=sub: APIScanner(safety_config=safety_config, session=stealth_session).run(s, token=api_token),
                    prog, all_findings, timings,
                )

                _run_module(
                    f"Fuzz ({sub})",
                    lambda s=sub: Fuzzer(safety_config=safety_config, session=stealth_session).run(s),
                    prog, all_findings, timings,
                )

                if cloud and safety_profile.allow_cloud_scan:
                    _run_module(
                        f"Cloud ({sub})",
                        lambda s=sub: {"findings": CloudScanner(s, session=session).run()},
                        prog, all_findings, timings,
                    )

        _skip_advanced = fast and waf_result and waf_result.detected
        if should_run_module("advanced", scope) and not _skip_advanced:
            if not safety_profile.allow_deserialization or not safety_profile.allow_cache_poisoning:
                console.print("  [yellow]⊘ Dangerous advanced tests gated by safety profile[/yellow]")
                console.print("  [dim]↳ Deserialization/cache poisoning controlled via safety_config[/dim]")
            _run_module(
                "Advanced (NoSQL/LDAP/Deser/CRLF/Cache/CSP)",
                lambda: AdvancedScanner(session=stealth_session, safety_config=safety_config).run(target),
                prog, all_findings, timings,
            )
        elif _skip_advanced:
            console.print("  [yellow]⚡ Advanced Scanner SKIPPED (fast mode + WAF detected)[/yellow]")

    if all_findings:
        console.print(f"\n[bold cyan]Enriching {len(all_findings)} findings with PoC, CWE, CVSS, steps…[/bold cyan]")
        all_findings = enrich_all_findings(all_findings)
        console.print("  [green]✓ All findings enriched with professional evidence[/green]")

    pre_safety_count = len(all_findings)
    if show_all:
        # --show-all: keep filtered findings but mark them
        _, safety_removed = filter_findings_by_safety(all_findings, safety_profile)
        if safety_removed:
            console.print(
                f"  [yellow]⊘ {safety_removed} findings would be removed by safety profile "
                f"(kept because --show-all)[/yellow]"
            )
            # Mark out-of-scope findings
            kept, _ = filter_findings_by_safety(all_findings, safety_profile)
            kept_set = {id(f) for f in kept}
            for f in all_findings:
                if id(f) not in kept_set:
                    f["out_of_scope"] = True
                    f["filter_reason"] = "safety_profile"
    else:
        all_findings, safety_removed = filter_findings_by_safety(all_findings, safety_profile)
        if safety_removed:
            console.print(
                f"  [yellow]⊘ {safety_removed} findings removed by safety profile[/yellow]"
            )

    pre_scope_count = len(all_findings)
    if show_all:
        scope_filtered = filter_findings_by_scope(all_findings, scope)
        scope_removed = pre_scope_count - len(scope_filtered)
        if scope_removed:
            console.print(
                f"  [yellow]✗ {scope_removed} findings would be filtered by scope "
                f"(kept because --show-all)[/yellow]"
            )
            scope_set = {id(f) for f in scope_filtered}
            for f in all_findings:
                if id(f) not in scope_set and not f.get("out_of_scope"):
                    f["out_of_scope"] = True
                    f["filter_reason"] = "scope"
    else:
        all_findings = filter_findings_by_scope(all_findings, scope)
        scope_removed = pre_scope_count - len(all_findings)
        if scope_removed:
            console.print(
                f"  [yellow]✗ {scope_removed} findings filtered (out-of-scope or below {min_severity} severity)[/yellow]"
            )

    pre_validation_count = len(all_findings)
    if validate_findings and all_findings:
        console.print(f"\n[bold cyan]Validating {len(all_findings)} findings for HIGH confidence…[/bold cyan]")
        validator = FalsePositiveValidator(session=session)
        confirmed, _validation_details = validator.validate_findings(all_findings)
        rejected = pre_validation_count - len(confirmed)
        all_findings = confirmed
        console.print(
            f"  [green]✓ {len(confirmed)} confirmed (HIGH confidence)[/green]  "
            f"[yellow]✗ {rejected} false positives removed[/yellow]"
        )

    total_elapsed = sum(timings.values())
    console.print(f"\n[dim]Module timings (total {total_elapsed:.1f}s):[/dim]")
    for mod, secs in timings.items():
        console.print(f"  [dim]{mod:30} {secs:6.1f}s[/dim]")

    # Show stealth/rate limiter stats
    if stealth != "normal" or waf_bypass:
        rl_stats = stealth_session.stats
        console.print(f"\n[dim]Rate limiter: {rl_stats['total_requests']} requests, "
                       f"{rl_stats['effective_rps']:.1f} req/s, "
                       f"{rl_stats['total_backoffs']} backoffs[/dim]")

    aggregate = _build_aggregate(scan_id, target, started_at, all_findings)

    # Add extra metadata
    if discovered_subdomains:
        aggregate["subdomains_discovered"] = discovered_subdomains
        aggregate["subdomains_scanned"] = (
            discovered_subdomains[:max_subdomains] if deep else []
        )

    if waf_result and waf_result.detected:
        aggregate["waf_detected"] = waf_result.waf_name
        aggregate["waf_confidence"] = waf_result.confidence

    if validate_findings:
        aggregate["validation"] = {
            "enabled": True,
            "pre_validation": pre_validation_count,
            "post_validation": len(all_findings),
            "false_positives_removed": pre_validation_count - len(all_findings),
        }

    aggregate["scan_config"] = {
        "auth_method": auth_method,
        "stealth_profile": stealth,
        "safety_profile": safety,
        "waf_bypass": waf_bypass,
        "cloud_scanning": cloud,
        "deep_mode": deep,
        "validation": validate_findings,
    }

    _generate_and_display(
        aggregate, output_dir, report_format,
        executive=executive or deep,  # always executive in deep mode
        notify=notify,
    )

    try:
        bounty_gen = BountyReportGenerator(output_dir=output_dir)
        bounty_md_path = bounty_gen.generate_full_report(aggregate, output_format="md")
        console.print(f"  [bold green]Bug Bounty Report:[/bold green] {bounty_md_path}")

        # Generate FIELD: format reports for HackerOne copy-paste
        if aggregate.get("findings"):
            bounty_gen.generate_full_report(aggregate, output_format="field")
            console.print(f"  [bold green]HackerOne Reports:[/bold green] FIELD: format (.txt) generated")

        # Generate per-finding individual reports for HackerOne/Bugcrowd
        if aggregate.get("findings"):
            indiv_paths = bounty_gen.generate_per_finding_reports(aggregate)
            console.print(f"  [bold green]Individual Reports:[/bold green] {len(indiv_paths)} files")
    except Exception as exc:
        console.print(f"  [yellow]⚠ Bounty report warning: {exc}[/yellow]")


# Individual module commands (still available if someone wants one thing)

def _single_module_scan(
    module_name: str,
    runner_fn,
    target: str,
    output_dir: str,
    report_format: str,
    safety: str = "standard",
) -> None:
    """Shared logic for single-module commands."""
    print_banner(console)
    ok, normalized = validate_target(target)
    if not ok:
        console.print(f"[bold red]Invalid target:[/bold red] {normalized}")
        raise typer.Exit(1)

    try:
        safety_profile = get_safety_profile(safety)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1)
    safety_config = build_safety_config(safety_profile)
    console.print(f"[dim]Safety: {safety_profile.name}[/dim]")

    scan_id = generate_scan_id()
    started_at = utcnow()
    console.print(f"[bold cyan]{module_name}[/bold cyan] → {normalized}\n")

    all_findings: list[dict] = []
    timings: dict[str, float] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        _run_module(module_name, lambda: runner_fn(normalized, safety_config), prog, all_findings, timings)

    # Enrich findings with evidence & PoC
    if all_findings:
        all_findings = enrich_all_findings(all_findings)

    # Safety filtering
    all_findings, _ = filter_findings_by_safety(all_findings, safety_profile)

    aggregate = _build_aggregate(scan_id, normalized, started_at, all_findings)
    _generate_and_display(aggregate, output_dir, report_format, False, False)


@app.command("recon")
def cmd_recon(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
) -> None:
    """Recon and asset discovery only."""
    print_banner(console)
    ok, normalized = validate_target(target)
    if not ok:
        console.print(f"[bold red]Invalid target:[/bold red] {normalized}")
        raise typer.Exit(1)

    scan_id = generate_scan_id()
    started_at = utcnow()
    console.print(f"[bold cyan]Recon[/bold cyan] → {normalized}\n")

    all_findings: list[dict] = []
    timings: dict[str, float] = {}

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), TimeElapsedColumn(), console=console) as prog:
        result = _run_module("Reconnaissance", lambda: ReconScanner().run(normalized), prog, all_findings, timings)

    if result:
        subs = result.get("subdomains", [])
        techs = result.get("technologies", [])
        dns_info = result.get("dns", {})
        console.print(f"\n[bold]Subdomains:[/bold] {len(subs)}")
        for s in subs:
            console.print(f"  [cyan]{s}[/cyan]")
        console.print(f"[bold]Technologies:[/bold] {', '.join(techs) or 'none'}")
        console.print(f"[bold]DNS A:[/bold] {', '.join(dns_info.get('A', [])) or 'none'}")

    aggregate = _build_aggregate(scan_id, normalized, started_at, all_findings)
    _generate_and_display(aggregate, output_dir, report_format, False, False)


@app.command("portscan")
def cmd_portscan(
    target: str = typer.Option(..., "--target", "-t"),
    ports: str = typer.Option("1-65535", "--ports", "-p"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
    safety: str = typer.Option("standard", "--safety", help="Safety profile name"),
) -> None:
    """Port and service scan only."""
    _single_module_scan("Port Scan", lambda t, sc: PortScanner().run(t, ports), target, output_dir, report_format, safety)


@app.command("sslscan")
def cmd_sslscan(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
    safety: str = typer.Option("standard", "--safety", help="Safety profile name"),
) -> None:
    """SSL/TLS deep analysis only."""
    _single_module_scan("SSL/TLS Scan", lambda t, sc: SSLScanner().run(t), target, output_dir, report_format, safety)


@app.command("webscan")
def cmd_webscan(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
    safety: str = typer.Option("standard", "--safety", help="Safety profile name"),
) -> None:
    """Web vulnerability scan only."""
    _single_module_scan("Web Scan", lambda t, sc: WebScanner(safety_config=sc).run(t), target, output_dir, report_format, safety)


@app.command("apiscan")
def cmd_apiscan(
    target: str = typer.Option(..., "--target", "-t"),
    token: Optional[str] = typer.Option(None, "--token"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
    safety: str = typer.Option("standard", "--safety", help="Safety profile name"),
) -> None:
    """API security scan only."""
    _single_module_scan("API Scan", lambda t, sc: APIScanner(safety_config=sc).run(t, token=token), target, output_dir, report_format, safety)


@app.command("fuzz")
def cmd_fuzz(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
    safety: str = typer.Option("standard", "--safety", help="Safety profile name"),
) -> None:
    """Directory brute-force, file enumeration, and IDOR testing."""
    _single_module_scan("Fuzzer", lambda t, sc: Fuzzer(safety_config=sc).run(t), target, output_dir, report_format, safety)


@app.command("cloudscan")
def cmd_cloudscan(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
    safety: str = typer.Option("standard", "--safety", help="Safety profile name"),
) -> None:
    """Cloud misconfiguration scanner (S3, Azure, GCP, Firebase, subdomain takeover)."""
    _single_module_scan(
        "Cloud Scan",
        lambda t, sc: {"findings": CloudScanner(t).run()},
        target, output_dir, report_format, safety,
    )


@app.command("domscan")
def cmd_domscan(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
    safety: str = typer.Option("standard", "--safety", help="Safety profile name"),
) -> None:
    """DOM XSS, prototype pollution, exposed secrets, and client-side security."""
    _single_module_scan(
        "DOM/Client-Side",
        lambda t, sc: DOMScanner().run(t),
        target, output_dir, report_format, safety,
    )


@app.command("authscan")
def cmd_authscan(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
    safety: str = typer.Option("standard", "--safety", help="Safety profile name"),
) -> None:
    """CSRF, CORS, IDOR, JWT, OAuth, session, default creds, MFA bypass scanner."""
    _single_module_scan(
        "Auth Scan",
        lambda t, sc: AuthScanner(safety_config=sc).run(t),
        target, output_dir, report_format, safety,
    )


@app.command("racescan")
def cmd_racescan(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
    safety: str = typer.Option("standard", "--safety", help="Safety profile name"),
) -> None:
    """Race condition testing — double-spend, rate limit bypass, TOCTOU."""
    _single_module_scan(
        "Race Condition",
        lambda t, sc: RaceScanner().run(t),
        target, output_dir, report_format, safety,
    )


@app.command("smuggle")
def cmd_smuggle(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
    safety: str = typer.Option("standard", "--safety", help="Safety profile name"),
) -> None:
    """HTTP request smuggling — CL.TE, TE.CL, TE.TE, H2 downgrade."""
    _single_module_scan(
        "HTTP Smuggling",
        lambda t, sc: SmuggleScanner().run(t),
        target, output_dir, report_format, safety,
    )


@app.command("advanced")
def cmd_advanced(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
    safety: str = typer.Option("standard", "--safety", help="Safety profile name"),
) -> None:
    """Advanced injections — NoSQL, LDAP, deserialization, CRLF, cache poisoning, CSP."""
    _single_module_scan(
        "Advanced Scanner",
        lambda t, sc: AdvancedScanner(safety_config=sc).run(t),
        target, output_dir, report_format, safety,
    )


@app.command("infrascan")
def cmd_infrascan(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
    safety: str = typer.Option("standard", "--safety", help="Safety profile name"),
) -> None:
    """Infrastructure scanner — actuators, admin panels, config files, debug endpoints, backups."""
    _single_module_scan(
        "Infrastructure Scan",
        lambda t, sc: InfraScanner(safety_config=sc).run(t),
        target, output_dir, report_format, safety,
    )


@app.command("dbscan")
def cmd_dbscan(
    target: str = typer.Option(..., "--target", "-t"),
    ports: str = typer.Option("", "--ports", "-p", help="Database ports to check (default: all common DB ports)"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
    safety: str = typer.Option("standard", "--safety", help="Safety profile name"),
) -> None:
    """Database scanner — exposed DBs, no-auth access, default creds, DB admin panels."""
    _single_module_scan(
        "Database Scan",
        lambda t, sc: DatabaseScanner(safety_config=sc).run(t, ports=ports),
        target, output_dir, report_format, safety,
    )


@app.command("mobilescan")
def cmd_mobilescan(
    app_path: str = typer.Option(..., "--app", "-a", help="Path to .apk (Android) or .ipa (iOS) file"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
    report_format: str = typer.Option("html", "--format", "-f"),
) -> None:
    """Mobile app scanner — static analysis of Android APK or iOS IPA files."""
    from pathlib import Path as P
    print_banner(console)

    if not P(app_path).exists():
        console.print(f"[bold red]File not found:[/bold red] {app_path}")
        raise typer.Exit(1)

    ext = P(app_path).suffix.lower()
    if ext not in (".apk", ".ipa"):
        console.print(f"[bold red]Unsupported file type:[/bold red] {ext} (expected .apk or .ipa)")
        raise typer.Exit(1)

    scan_id = generate_scan_id()
    started_at = utcnow()
    platform = "Android" if ext == ".apk" else "iOS"
    console.print(f"[bold cyan]Mobile Scan ({platform})[/bold cyan] → {app_path}\n")

    all_findings: list[dict] = []
    timings: dict[str, float] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        _run_module(
            f"Mobile ({platform})",
            lambda: MobileScanner().run(app_path),
            prog, all_findings, timings,
        )

    if all_findings:
        all_findings = enrich_all_findings(all_findings)

    aggregate = _build_aggregate(scan_id, app_path, started_at, all_findings)
    _generate_and_display(aggregate, output_dir, report_format, False, False)


# vapt hunt — INTERACTIVE BUG BOUNTY HUNTING MODE

@app.command("hunt")
def cmd_hunt(
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
) -> None:
    """
    Interactive bug bounty hunting mode.

    \b
    Launch this when you find a new bug bounty program. It will:
      1. Ask you for the program details (scope, platform, restrictions)
      2. Build the optimal scanning strategy
      3. Run a complete automated hunt
      4. Generate HackerOne/Bugcrowd-ready reports for every finding

    \b
    Example:
      vapt hunt
    """
    print_banner(console)

    console.print(Panel(
        "[bold]Welcome to Bug Bounty Hunt Mode[/bold]\n\n"
        "I'll ask you about the target program, then run a complete\n"
        "automated hunt with all scanners optimized for bug bounty.\n\n"
        "[dim]Answer the prompts below to configure the hunt.[/dim]",
        title="[bold cyan]VAPT CLI — Bug Bounty Hunter[/bold cyan]",
        border_style="cyan",
    ))

    console.print("\n[bold]Step 1: Bug Bounty Platform[/bold]")
    console.print("  [dim]1. HackerOne  2. Bugcrowd  3. Intigriti  4. Other[/dim]")
    platform_choice = typer.prompt("Platform (1-4)", default="1")
    platform_name = {"1": "HackerOne", "2": "Bugcrowd", "3": "Intigriti", "4": "Other"}.get(
        platform_choice, "HackerOne"
    )

    program_name = typer.prompt("\nProgram name (e.g., 'Meesho')", default="")

    console.print("\n[bold]Step 2: In-Scope Targets[/bold]")
    console.print("  [dim]Enter domains/IPs, one per line. Empty line to finish.[/dim]")
    console.print("  [dim]Example: *.example.com, api.example.com, 192.168.1.0/24[/dim]")
    in_scope: list[str] = []
    while True:
        entry = typer.prompt("  Target", default="")
        if not entry:
            break
        in_scope.append(entry.strip())

    if not in_scope:
        console.print("[bold red]No targets provided. Exiting.[/bold red]")
        raise typer.Exit(1)

    console.print("\n[bold]Step 3: Out-of-Scope (optional)[/bold]")
    console.print("  [dim]Enter domains to EXCLUDE. Empty line to finish.[/dim]")
    out_scope: list[str] = []
    while True:
        entry = typer.prompt("  Exclude", default="")
        if not entry:
            break
        out_scope.append(entry.strip())

    console.print("\n[bold]Step 4: Hunt Configuration[/bold]")

    console.print("\n  [bold]Target types:[/bold]")
    console.print("  [dim]1. Web Only  2. Web + API  3. Web + API + Infra  4. Full (all scanners)  5. Mobile APK/IPA[/dim]")
    hunt_type = typer.prompt("  Hunt type (1-5)", default="4")

    deep_mode = typer.confirm("\n  Enable deep mode? (scan subdomains)", default=True)
    waf_bypass = typer.confirm("  Enable WAF bypass techniques?", default=True)
    validate = typer.confirm("  Validate findings (eliminate false positives)?", default=True)

    console.print("\n  [bold]Stealth level:[/bold]")
    console.print("  [dim]1. Aggressive (fastest)  2. Normal  3. Polite  4. Stealth (slowest)[/dim]")
    stealth_choice = typer.prompt("  Stealth (1-4)", default="2")
    stealth = {"1": "aggressive", "2": "normal", "3": "polite", "4": "stealth"}.get(
        stealth_choice, "normal"
    )

    has_auth = typer.confirm("\n  Do you have authentication credentials?", default=False)
    api_token = None
    auth_method = "none"
    username = None
    password = None
    login_url = None
    cookies_str = None
    if has_auth:
        console.print("  [dim]1. Bearer Token  2. Cookie  3. Form Login  4. Basic Auth[/dim]")
        auth_choice = typer.prompt("  Auth type (1-4)", default="1")
        if auth_choice == "1":
            auth_method = "bearer"
            api_token = typer.prompt("  Bearer token")
        elif auth_choice == "2":
            auth_method = "cookie"
            cookies_str = typer.prompt("  Cookie string (name=val; name2=val2)")
        elif auth_choice == "3":
            auth_method = "form"
            login_url = typer.prompt("  Login URL")
            username = typer.prompt("  Username")
            password = typer.prompt("  Password", hide_input=True)
        elif auth_choice == "4":
            auth_method = "basic"
            username = typer.prompt("  Username")
            password = typer.prompt("  Password", hide_input=True)

    custom_headers_str = ""
    if platform_name == "HackerOne":
        h1_user = typer.prompt(
            "\n  HackerOne username (for X-HackerOne header, optional)", default=""
        )
        if h1_user:
            custom_headers_str = f"X-HackerOne-Research:{h1_user}"
    elif platform_name == "Bugcrowd":
        bc_user = typer.prompt(
            "\n  Bugcrowd username (for X-Bugcrowd header, optional)", default=""
        )
        if bc_user:
            custom_headers_str = f"X-Bugcrowd-Research:{bc_user}"

    scope_in_str = ",".join(in_scope)
    scope_out_str = ",".join(out_scope) if out_scope else None

    hunt_labels = {
        "1": "Web Only",
        "2": "Web + API",
        "3": "Web + API + Infrastructure",
        "4": "Full Hunt (All Scanners)",
        "5": "Mobile APK/IPA",
    }

    console.print(Panel(
        f"[bold]Platform:[/bold]   {platform_name}\n"
        f"[bold]Program:[/bold]    {program_name or 'N/A'}\n"
        f"[bold]Targets:[/bold]    {', '.join(in_scope)}\n"
        f"[bold]Excluded:[/bold]   {', '.join(out_scope) or 'None'}\n"
        f"[bold]Hunt Type:[/bold]  {hunt_labels.get(hunt_type, 'Full')}\n"
        f"[bold]Deep Mode:[/bold]  {'Yes' if deep_mode else 'No'}\n"
        f"[bold]WAF Bypass:[/bold] {'Yes' if waf_bypass else 'No'}\n"
        f"[bold]Validate:[/bold]   {'Yes' if validate else 'No'}\n"
        f"[bold]Stealth:[/bold]    {stealth}\n"
        f"[bold]Auth:[/bold]       {auth_method}",
        title="[bold yellow]Hunt Configuration[/bold yellow]",
        border_style="yellow",
    ))

    if not typer.confirm("\n  Start the hunt?", default=True):
        console.print("[dim]Hunt cancelled.[/dim]")
        raise typer.Exit()

    if hunt_type == "5":
        app_path = typer.prompt("  Path to .apk or .ipa file")
        from pathlib import Path as P
        if not P(app_path).exists():
            console.print(f"[bold red]File not found:[/bold red] {app_path}")
            raise typer.Exit(1)

        scan_id = generate_scan_id()
        started_at = utcnow()
        all_findings: list[dict] = []
        timings: dict[str, float] = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as prog:
            _run_module(
                "Mobile Analysis",
                lambda: MobileScanner().run(app_path),
                prog, all_findings, timings,
            )

        if all_findings:
            all_findings = enrich_all_findings(all_findings)

        aggregate = _build_aggregate(scan_id, app_path, started_at, all_findings)
        _generate_and_display(aggregate, output_dir, "html", executive=True, notify=False)

        try:
            bounty_gen = BountyReportGenerator(output_dir=output_dir)
            bounty_gen.generate_full_report(aggregate, output_format="field")
            bounty_gen.generate_full_report(aggregate, output_format="md")
            if aggregate.get("findings"):
                bounty_gen.generate_per_finding_reports(aggregate)
            console.print("[bold green]All reports generated.[/bold green]")
        except Exception as exc:
            console.print(f"[yellow]⚠ Report warning: {exc}[/yellow]")
        return

    modules_for_type = {
        "1": "recon,ssl,web,dom,fuzz,jsscan,cve,plugins",
        "2": "recon,ssl,web,dom,auth,api,fuzz,jsscan,cve,plugins",
        "3": "recon,port,ssl,web,dom,auth,api,fuzz,jsscan,cloud,cve,infra,db,plugins",
        "4": None,  # All modules
    }
    modules_str = modules_for_type.get(hunt_type)

    console.print(f"\n[bold cyan]Starting hunt across {len(in_scope)} target(s)…[/bold cyan]\n")

    for target_idx, target in enumerate(in_scope, 1):
        console.print(f"\n{'='*60}")
        console.print(f"[bold cyan]Target {target_idx}/{len(in_scope)}: {target}[/bold cyan]")
        console.print(f"{'='*60}\n")

        # Build the scan command args
        scan_kwargs = {
            "target": target,
            "ports": "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5900,6379,8080,8443,9200,27017",
            "output_dir": output_dir,
            "report_format": "html",
            "api_token": api_token,
            "deep": deep_mode,
            "max_subdomains": 10,
            "auth_method": auth_method,
            "login_url": login_url,
            "username": username,
            "password": password,
            "cookies": cookies_str,
            "stealth": stealth,
            "waf_bypass": waf_bypass,
            "validate_findings": validate,
            "cloud": hunt_type in ("3", "4"),
            "plugins_dir": None,
            "executive": True,
            "notify": False,
            "scope_in": scope_in_str,
            "scope_out": scope_out_str,
            "scope_file": None,
            "min_severity": "low",
            "fast": False,
            "show_all": False,
            "modules": modules_str,
            "exclude_categories": None,
            "custom_headers": custom_headers_str or None,
            "safety": "standard",
        }

        try:
            cmd_scan(**scan_kwargs)
        except SystemExit:
            pass
        except Exception as exc:
            console.print(f"[bold red]Error scanning {target}: {exc}[/bold red]")
            continue

    console.print(Panel(
        f"[bold green]Hunt complete![/bold green]\n\n"
        f"Targets scanned: {len(in_scope)}\n"
        f"Reports in: {output_dir}\n\n"
        f"[dim]Review the FIELD: format (.txt) files for HackerOne submission.[/dim]\n"
        f"[dim]Review individual .md files for per-finding reports.[/dim]",
        title=f"[bold cyan]{platform_name} Bug Bounty Hunt — Complete[/bold cyan]",
        border_style="green",
    ))


# vapt elite — GOLD ELITE EDITION HUNTING

@app.command("elite")
def cmd_elite(
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
) -> None:
    """
    Gold Elite Edition — strategic bug bounty hunting.

    \b
    Unlike 'hunt' which runs all scanners broadly, 'elite' uses a
    strategic 8-phase pipeline designed to find NOVEL bugs:

    \b
      Phase 1: Deep JS Reconnaissance — map entire attack surface
      Phase 2: Endpoint Intelligence — classify by business value
      Phase 3: Authenticated Testing — IDOR, privilege escalation
      Phase 4: Business Logic — race conditions, amount manipulation
      Phase 5: OOB Testing — blind SSRF/XSS/XXE confirmation
      Phase 6: Targeted Scanning — focused on sensitive endpoints only
      Phase 7: Elite Intelligence — novelty scoring, duplicate filtering
      Phase 8: Report Generation — submission-ready with intelligence

    \b
    Every finding is scored for novelty and duplicate risk.
    Only NOVEL findings are reported. Common duplicates are suppressed.

    \b
    Example:
      vapt elite
    """
    print_banner(console)

    console.print(Panel(
        "[bold]Welcome to the Gold Elite Edition[/bold]\n\n"
        "This is NOT your average scanner. This finds bugs that\n"
        "other hunters miss, and filters out duplicates before\n"
        "you waste time submitting them.\n\n"
        "[dim]8-phase strategic pipeline with novelty scoring.[/dim]",
        title="[bold yellow]VAPT CLI — Gold Elite Edition[/bold yellow]",
        border_style="yellow",
    ))

    console.print("\n[bold]Step 1: Bug Bounty Platform[/bold]")
    console.print("  [dim]1. HackerOne  2. Bugcrowd  3. Intigriti  4. Other[/dim]")
    platform_choice = typer.prompt("Platform (1-4)", default="1")
    platform_name = {"1": "HackerOne", "2": "Bugcrowd", "3": "Intigriti", "4": "Other"}.get(
        platform_choice, "HackerOne"
    )

    program_name = typer.prompt("\nProgram name (e.g., 'Syfe')", default="")

    console.print("\n[bold]Step 2: Target[/bold]")
    console.print("  [dim]Enter the primary target URL (e.g., https://api.example.com)[/dim]")
    target = typer.prompt("  Target URL")

    if not target:
        console.print("[bold red]No target provided. Exiting.[/bold red]")
        raise typer.Exit(1)

    console.print("\n[bold]Step 3: Additional In-Scope Targets (optional)[/bold]")
    console.print("  [dim]Enter additional domains. Empty line to finish.[/dim]")
    additional_scope: list[str] = []
    while True:
        entry = typer.prompt("  Additional target", default="")
        if not entry:
            break
        additional_scope.append(entry.strip())

    scope_in = [target] + additional_scope

    console.print("\n[bold]Step 4: Out-of-Scope (optional)[/bold]")
    console.print("  [dim]Enter domains to EXCLUDE. Empty line to finish.[/dim]")
    scope_out: list[str] = []
    while True:
        entry = typer.prompt("  Exclude", default="")
        if not entry:
            break
        scope_out.append(entry.strip())

    console.print("\n[bold]Step 5: Authentication (HIGHLY RECOMMENDED)[/bold]")
    console.print("  [dim]Elite hunting works best with authenticated sessions.[/dim]")
    console.print("  [dim]Create 2 test accounts for IDOR testing.[/dim]")

    has_auth = typer.confirm("  Do you have test account credentials?", default=True)
    login_url = None
    email_a = password_a = email_b = password_b = None
    cookies_a = cookies_b = None
    auth_method = "none"

    if has_auth:
        console.print("\n  [dim]1. Form Login (email/password)  2. Cookie  3. Bearer Token[/dim]")
        auth_choice = typer.prompt("  Auth type (1-3)", default="1")

        if auth_choice == "1":
            auth_method = "form"
            login_url = typer.prompt("  Login URL (e.g., https://api.example.com/auth/login)")
            console.print("\n  [bold]Account A (primary):[/bold]")
            email_a = typer.prompt("    Email")
            password_a = typer.prompt("    Password", hide_input=True)
            console.print("\n  [bold]Account B (for IDOR testing, optional):[/bold]")
            email_b = typer.prompt("    Email (empty to skip)", default="")
            if email_b:
                password_b = typer.prompt("    Password", hide_input=True)
            else:
                email_b = None
        elif auth_choice == "2":
            auth_method = "cookie"
            console.print("\n  [bold]Account A (primary):[/bold]")
            cookies_a = typer.prompt("    Cookie string (name=val; name2=val2)")
            console.print("\n  [bold]Account B (for IDOR testing, optional):[/bold]")
            cookies_b = typer.prompt("    Cookie string (empty to skip)", default="")
            if not cookies_b:
                cookies_b = None
        elif auth_choice == "3":
            auth_method = "bearer"
            console.print("\n  [bold]Account A (primary):[/bold]")
            token_a = typer.prompt("    Bearer token")
            cookies_a = f"__bearer__:{token_a}"  # Encode as special cookie format
            console.print("\n  [bold]Account B (for IDOR testing, optional):[/bold]")
            token_b = typer.prompt("    Bearer token (empty to skip)", default="")
            if token_b:
                cookies_b = f"__bearer__:{token_b}"
            else:
                cookies_b = None

    custom_headers: dict[str, str] = {}
    if platform_name == "HackerOne":
        h1_user = typer.prompt(
            "\n  HackerOne username (for X-HackerOne-Research header)", default=""
        )
        if h1_user:
            custom_headers["X-HackerOne-Research"] = h1_user
    elif platform_name == "Bugcrowd":
        bc_user = typer.prompt(
            "\n  Bugcrowd username (for X-Bugcrowd-Research header)", default=""
        )
        if bc_user:
            custom_headers["X-Bugcrowd-Research"] = bc_user

    extra_header = typer.prompt("\n  Any other custom header? (Header:Value, empty to skip)", default="")
    if extra_header and ":" in extra_header:
        key, val = extra_header.split(":", 1)
        custom_headers[key.strip()] = val.strip()

    auth_desc = auth_method
    if auth_method == "form" and email_a:
        auth_desc = f"Form login ({email_a})"
        if email_b:
            auth_desc += f" + Account B ({email_b})"
    elif auth_method == "cookie":
        auth_desc = "Cookie session"
        if cookies_b:
            auth_desc += " + Account B"
    elif auth_method == "bearer":
        auth_desc = "Bearer token"
        if cookies_b:
            auth_desc += " + Account B"

    console.print(Panel(
        f"[bold]Platform:[/bold]   {platform_name}\n"
        f"[bold]Program:[/bold]    {program_name or 'N/A'}\n"
        f"[bold]Target:[/bold]     {target}\n"
        f"[bold]Scope:[/bold]      {', '.join(scope_in)}\n"
        f"[bold]Excluded:[/bold]   {', '.join(scope_out) or 'None'}\n"
        f"[bold]Auth:[/bold]       {auth_desc}\n"
        f"[bold]Headers:[/bold]    {len(custom_headers)} custom header(s)\n"
        f"[bold]Mode:[/bold]       Gold Elite Edition — 8 Phase Strategic Hunt",
        title="[bold yellow]Elite Hunt Configuration[/bold yellow]",
        border_style="yellow",
    ))

    if not typer.confirm("\n  Launch the elite hunt?", default=True):
        console.print("[dim]Hunt cancelled.[/dim]")
        raise typer.Exit()

    hunt = SmartHuntOrchestrator(
        target=target,
        output_dir=output_dir,
        custom_headers=custom_headers,
    )

    hunt.configure(
        program_name=program_name,
        platform=platform_name,
        scope_in=scope_in,
        scope_out=scope_out,
    )

    # Set up authentication
    import requests as _requests

    if auth_method == "form" and login_url and email_a and password_a:
        hunt.setup_auth(
            login_url=login_url,
            email_a=email_a,
            password_a=password_a,
            email_b=email_b or None,
            password_b=password_b or None,
        )
    elif auth_method == "cookie" and cookies_a:
        session_a = _requests.Session()
        session_a.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        session_a.headers.update(custom_headers)
        session_a.verify = False
        for pair in cookies_a.split(";"):
            if "=" in pair:
                k, v = pair.strip().split("=", 1)
                session_a.cookies.set(k.strip(), v.strip())

        session_b = None
        if cookies_b:
            session_b = _requests.Session()
            session_b.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
            session_b.headers.update(custom_headers)
            session_b.verify = False
            for pair in cookies_b.split(";"):
                if "=" in pair:
                    k, v = pair.strip().split("=", 1)
                    session_b.cookies.set(k.strip(), v.strip())

        hunt.setup_auth(session_a=session_a, session_b=session_b)
    elif auth_method == "bearer" and cookies_a:
        # Decode special bearer format
        token_a = cookies_a.replace("__bearer__:", "")
        session_a = _requests.Session()
        session_a.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        session_a.headers["Authorization"] = f"Bearer {token_a}"
        session_a.headers.update(custom_headers)
        session_a.verify = False

        session_b = None
        if cookies_b:
            token_b = cookies_b.replace("__bearer__:", "")
            session_b = _requests.Session()
            session_b.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
            session_b.headers["Authorization"] = f"Bearer {token_b}"
            session_b.headers.update(custom_headers)
            session_b.verify = False

        hunt.setup_auth(session_a=session_a, session_b=session_b)

    # Execute the elite pipeline
    try:
        results = hunt.execute()
    except KeyboardInterrupt:
        console.print("\n[yellow]Hunt interrupted by user.[/yellow]")
        raise typer.Exit()
    except Exception as exc:
        console.print(f"[bold red]Elite hunt error: {exc}[/bold red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        raise typer.Exit(1)

    # Generate elite reports
    try:
        report_gen = EliteReportGenerator(output_dir=output_dir)
        report_paths = report_gen.generate_elite_reports(
            findings=results.get("findings", []),
            program_name=program_name,
            platform=platform_name,
            target=target,
        )
        console.print(f"\n[bold green]Elite reports generated ({len(report_paths)} files):[/bold green]")
        for p in report_paths:
            console.print(f"  [dim]{p}[/dim]")
    except Exception as exc:
        console.print(f"[yellow]⚠ Report generation warning: {exc}[/yellow]")

    console.print(Panel(
        f"[bold green]Elite hunt complete![/bold green]\n\n"
        f"Target: {target}\n"
        f"Total findings: {results.get('total_findings', 0)}\n"
        f"Duration: {results.get('duration_sec', 0):.1f}s\n"
        f"Reports: {output_dir}/elite_*.md\n\n"
        f"[dim]Only novel findings are reported. Common duplicates are suppressed.[/dim]\n"
        f"[dim]Check elite_master_summary.md for the full analysis.[/dim]",
        title=f"[bold yellow]{platform_name} Elite Hunt — Complete[/bold yellow]",
        border_style="green",
    ))


@app.command("bizscan")
def cmd_bizscan(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
) -> None:
    """Run the business logic vulnerability scanner."""
    print_banner(console)
    console.print(f"[cyan]Running business logic scan on {target}...[/cyan]")
    scanner = BusinessLogicScanner()
    result = scanner.run(target)
    findings = result.get("findings", [])
    console.print(f"[green]Found {len(findings)} business logic issues.[/green]")
    for f in findings:
        sev = f.get("severity", "info")
        console.print(f"  [{_risk_color(sev)}]{sev.upper()}[/] {f.get('title', '')}")


@app.command("deepjs")
def cmd_deepjs(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
) -> None:
    """Deep JavaScript reconnaissance — mine endpoints from JS files."""
    print_banner(console)
    console.print(f"[cyan]Running deep JS recon on {target}...[/cyan]")
    recon = DeepJSRecon()
    result = recon.run(target)
    console.print(f"[green]Analyzed {result.get('js_files_analyzed', 0)} JS files.[/green]")
    console.print(f"  API endpoints: {len(result.get('api_endpoints', []))}")
    console.print(f"  Client routes: {len(result.get('client_routes', []))}")
    console.print(f"  GraphQL ops:   {len(result.get('graphql_operations', []))}")
    console.print(f"  WebSockets:    {len(result.get('websocket_urls', []))}")
    console.print(f"  Internal URLs: {len(result.get('internal_urls', []))}")
    console.print(f"  Source maps:   {len(result.get('source_maps', []))}")
    for f in result.get("findings", []):
        sev = f.get("severity", "info")
        console.print(f"  [{_risk_color(sev)}]{sev.upper()}[/] {f.get('title', '')}")


@app.command("authflow")
def cmd_authflow(
    target: str = typer.Option(..., "--target", "-t"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
) -> None:
    """Test authentication flows for IDOR, privilege escalation, session issues."""
    print_banner(console)
    console.print(f"[cyan]Running auth flow scanner on {target}...[/cyan]")
    scanner = AuthFlowScanner()
    result = scanner.run(target)
    findings = result.get("findings", [])
    console.print(f"[green]Found {len(findings)} auth flow issues.[/green]")
    for f in findings:
        sev = f.get("severity", "info")
        console.print(f"  [{_risk_color(sev)}]{sev.upper()}[/] {f.get('title', '')}")


# vapt report / monitor / update / db

@app.command("report")
def cmd_report(
    report_format: str = typer.Option("html", "--format", "-f", help="pdf|html|json"),
    scan_file: Optional[str] = typer.Option(None, "--scan-file", "-s"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o"),
) -> None:
    """Re-generate a report from a saved scan JSON file."""
    print_banner(console)
    if not scan_file:
        console.print("[yellow]Provide --scan-file <path> to a previous scan JSON.[/yellow]")
        raise typer.Exit(1)

    scan_path = Path(scan_file)
    if not scan_path.exists():
        console.print(f"[red]File not found: {scan_file}[/red]")
        raise typer.Exit(1)

    try:
        aggregate = _json.loads(scan_path.read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[red]Failed to read scan file: {exc}[/red]")
        raise typer.Exit(1)

    generator = ReportGenerator(output_dir=output_dir)
    formats = [f.strip() for f in report_format.split(",")]
    paths = generator.generate(aggregate, formats=formats)
    console.print("[bold green]Report generated:[/bold green]")
    for fmt, path in paths.items():
        console.print(f"  {fmt} → {path}")
        if fmt in ("html",) and path.endswith(".html"):
            try:
                webbrowser.open(f"file://{Path(path).resolve()}")
            except Exception:
                pass


@app.command("monitor")
def cmd_monitor(
    target: str = typer.Option(..., "--target", "-t"),
    interval: int = typer.Option(86400, "--interval", "-i", help="Seconds between scans (default 24h)."),
) -> None:
    """Continuously monitor a target for new vulnerabilities."""
    print_banner(console)
    ok, normalized = validate_target(target)
    if not ok:
        console.print(f"[bold red]Invalid target:[/bold red] {normalized}")
        raise typer.Exit(1)

    console.print(f"[cyan]Monitoring {normalized} every {interval}s. Ctrl+C to stop.[/cyan]")

    from vapt.scanner.monitor import Monitor

    def on_change(alert: dict) -> None:
        console.print(f"\n[bold yellow]⚠ Change detected at {alert['detected_at']}[/bold yellow]")
        for key, val in alert.get("changes", {}).items():
            console.print(f"  {key}: {val}")

    try:
        Monitor(normalized, interval=interval, on_change=on_change).start()
    except KeyboardInterrupt:
        console.print("\n[dim]Monitor stopped.[/dim]")


@app.command("update")
def cmd_update() -> None:
    """Update VAPT CLI, tools, and vulnerability signatures."""
    print_banner(console)
    console.print("[bold cyan]VAPT CLI Updater[/bold cyan]\n")

    steps = [
        ("Python package", [sys.executable, "-m", "pip", "install", "--upgrade", "vapt-cli"]),
        ("Nuclei templates", ["nuclei", "-ut"]),
        ("Subfinder", ["subfinder", "-update"]),
    ]

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as prog:
        for name, cmd in steps:
            task = prog.add_task(f"[cyan]Updating {name}…", total=None)
            try:
                subprocess.run(cmd, capture_output=True, timeout=120, check=False)
            except FileNotFoundError:
                pass
            prog.update(task, description=f"[green]✓ {name}")

        task = prog.add_task("[cyan]Refreshing knowledge base…", total=None)
        try:
            init_db()
            seed()
        except Exception as exc:
            console.print(f"[yellow]KB warning: {exc}[/yellow]")
        prog.update(task, description="[green]✓ Knowledge base refreshed")

    console.print("\n[bold green]✓ Update complete.[/bold green]")


@app.command("db")
def cmd_db(
    action: str = typer.Argument("status", help="status | seed | reset"),
) -> None:
    """Manage the local knowledge base database."""
    if action == "seed":
        seed()
        console.print("[green]Knowledge base seeded.[/green]")
    elif action == "status":
        kb = KnowledgeBase()
        entries = kb.get_all()
        console.print(f"Knowledge base contains [bold]{len(entries)}[/bold] entries.")
    elif action == "reset":
        init_db()
        seed()
        console.print("[green]Database reset and re-seeded.[/green]")
    else:
        console.print(f"[red]Unknown action: {action}[/red]")
        raise typer.Exit(1)


# ── Burp Suite replacement commands ──────────────────────


@app.command("proxy")
def cmd_proxy(
    port: int = typer.Option(8080, "--port", "-p", help="Proxy listen port"),
    host: str = typer.Option("127.0.0.1", "--host", help="Proxy listen address"),
    verbose: bool = typer.Option(False, "--verbose", help="Debug logging"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Export flows to JSON on exit"),
) -> None:
    """Start the intercepting HTTP/HTTPS proxy server."""
    from vapt.proxy.server import CertificateAuthority, ProxyServer
    from vapt.proxy.storage import ProxyStorage

    print_banner()
    storage = ProxyStorage()
    ca = CertificateAuthority()

    console.print(f"\n[bold green]VAPT Proxy starting on {host}:{port}[/bold green]")
    console.print(f"CA certificate: [cyan]{ca.ca_cert_path}[/cyan]")
    console.print("Configure your browser to use this proxy.")
    console.print("Install the CA cert to intercept HTTPS traffic.")
    console.print("Press [bold]Ctrl+C[/bold] to stop.\n")

    proxy = ProxyServer(
        host=host, port=port, storage=storage, ca=ca, verbose=verbose,
    )

    try:
        proxy.start(background=True)
        while proxy.running:
            time.sleep(1)
            flows = storage.get_flow_count()
            console.print(f"\r[dim]Flows captured: {flows}[/dim]", end="")
    except KeyboardInterrupt:
        pass
    finally:
        proxy.stop()
        if output:
            count = storage.export_flows(output)
            console.print(f"\n[green]Exported {count} flows to {output}[/green]")
        console.print(f"\n[bold green]Proxy stopped. Total flows: {storage.get_flow_count()}[/bold green]")


@app.command("tui")
def cmd_tui(
    proxy_port: int = typer.Option(8080, "--port", "-p", help="Proxy port for the TUI"),
) -> None:
    """Launch the interactive security testing console (TUI)."""
    from vapt.tui.app import launch_tui
    launch_tui(proxy_port=proxy_port)


@app.command("crawl")
def cmd_crawl(
    target: str = typer.Option(..., "--target", "-t", help="Target URL to crawl"),
    max_depth: int = typer.Option(3, "--depth", help="Maximum crawl depth"),
    max_pages: int = typer.Option(100, "--max-pages", help="Maximum pages to crawl"),
    headless: bool = typer.Option(True, "--headless/--no-headless", help="Run browser in headless mode"),
    light: bool = typer.Option(False, "--light", help="Use lightweight requests-based crawler (no browser)"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o", help="Output directory"),
) -> None:
    """Crawl a website — discover pages, forms, endpoints, and JS files."""
    from vapt.scanner.crawler import Crawler, CrawlerLight

    print_banner()
    ok, target = validate_target(target)
    if not ok:
        console.print(f"[red]Invalid target: {target}[/red]")
        raise typer.Exit(1)
    console.print(f"\n[bold]Crawling [cyan]{target}[/cyan] (depth={max_depth}, max={max_pages})[/bold]\n")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        task = prog.add_task("Crawling...", total=max_pages)

        def on_progress(current, total, url):
            prog.update(task, completed=current, description=f"[cyan]{url[:60]}[/cyan]")

        if light:
            crawler = CrawlerLight(target, max_depth=max_depth, max_pages=max_pages)
        else:
            crawler = Crawler(target, max_depth=max_depth, max_pages=max_pages, headless=headless)

        result = crawler.run(progress_callback=on_progress)

    table = Table(title="Crawl Results", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Pages crawled", str(result.pages_crawled))
    table.add_row("Unique URLs", str(len(set(result.urls))))
    table.add_row("Forms found", str(len(result.forms)))
    table.add_row("JS files", str(len(result.js_files)))
    table.add_row("API endpoints", str(len(result.endpoints)))
    table.add_row("Technologies", ", ".join(result.technologies) if result.technologies else "-")
    table.add_row("Errors", str(len(result.errors)))
    table.add_row("Time", f"{result.elapsed:.1f}s")
    console.print(table)

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    crawl_file = out_path / f"crawl_{target.replace('https://', '').replace('http://', '').replace('/', '_')}.json"

    import json as json_mod
    crawl_file.write_text(json_mod.dumps({
        "target": result.target,
        "urls": list(set(result.urls)),
        "forms": [{"url": f.url, "action": f.action, "method": f.method, "inputs": f.inputs} for f in result.forms],
        "js_files": result.js_files,
        "endpoints": [{"url": e.url, "method": e.method, "source": e.source} for e in result.endpoints],
        "technologies": result.technologies,
    }, indent=2))
    console.print(f"\n[green]Crawl data saved to {crawl_file}[/green]")


@app.command("intruder")
def cmd_intruder(
    target: str = typer.Option(..., "--target", "-t", help="Target URL with §position§ markers"),
    method: str = typer.Option("GET", "--method", "-m", help="HTTP method"),
    attack: str = typer.Option("sniper", "--attack", "-a", help="Attack type: sniper|battering_ram|pitchfork|cluster_bomb"),
    payload_set: str = typer.Option("sqli", "--payloads", "-P", help="Payload set: sqli|xss|traversal|ssti|nosql|commands|common_passwords|idor"),
    payload_file: Optional[str] = typer.Option(None, "--payload-file", help="Custom payload file (one per line)"),
    threads: int = typer.Option(10, "--threads", help="Concurrent threads"),
    delay: float = typer.Option(0.0, "--delay", help="Delay between requests (seconds)"),
    grep: Optional[str] = typer.Option(None, "--grep", help="Regex pattern to grep in responses"),
    output_dir: str = typer.Option("./vapt-reports", "--output", "-o", help="Output directory"),
) -> None:
    """Fuzzing engine — Burp Intruder replacement with 4 attack modes."""
    from vapt.engine.intruder import BUILTIN_PAYLOADS, Intruder, IntruderConfig, PayloadGenerator

    print_banner()

    if payload_file:
        payloads = [PayloadGenerator.from_file(payload_file)]
    else:
        payloads = [BUILTIN_PAYLOADS.get(payload_set, BUILTIN_PAYLOADS["sqli"])]

    marker = "§"
    positions = []
    i = 0
    while i < len(target):
        start = target.find(marker, i)
        if start == -1:
            break
        end = target.find(marker, start + 1)
        if end == -1:
            break
        positions.append(target[start + 1 : end])
        i = end + 1

    console.print(f"\n[bold]Intruder Attack[/bold]")
    console.print(f"Target: [cyan]{target}[/cyan]")
    console.print(f"Mode: [yellow]{attack}[/yellow] | Positions: {len(positions)} | Payloads: {len(payloads[0])}")

    config = IntruderConfig(
        base_url=target,
        method=method,
        positions=positions,
        payloads=payloads,
        attack_type=attack,
        threads=threads,
        delay=delay,
        grep_patterns=[grep] if grep else [],
    )

    intruder = Intruder(config)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        task = prog.add_task("Fuzzing...", total=None)

        def on_progress(current, total, result):
            status = f"[{'red' if result.interesting else 'dim'}]{result.status_code}[/]"
            prog.update(task, description=f"[{current}/{total}] {status} {result.payload[:40]}")

        results = intruder.run(progress_callback=on_progress)

    summary = intruder.summary()
    interesting = intruder.get_interesting()

    console.print(f"\n[bold green]Complete:[/bold green] {summary['total_requests']} requests, "
                  f"[bold red]{summary['interesting_count']} interesting[/bold red], "
                  f"{summary['error_count']} errors")

    if interesting:
        table = Table(title="Interesting Results", show_header=True)
        table.add_column("#", style="dim")
        table.add_column("Payload", style="cyan")
        table.add_column("Status", style="yellow")
        table.add_column("Length", style="green")
        table.add_column("Notes", style="red")
        for idx, r in enumerate(interesting[:30], 1):
            table.add_row(str(idx), r.payload[:50], str(r.status_code),
                          str(r.content_length), "; ".join(r.notes))
        console.print(table)


@app.command("sequencer")
def cmd_sequencer(
    url: str = typer.Option(..., "--url", "-u", help="URL that generates tokens"),
    extract_from: str = typer.Option("cookie", "--from", help="Where to extract: header|cookie|body"),
    extract_name: str = typer.Option("session", "--name", "-n", help="Header/cookie name to extract"),
    extract_regex: Optional[str] = typer.Option(None, "--regex", help="Regex to extract token (group 1)"),
    sample_size: int = typer.Option(200, "--samples", "-s", help="Number of tokens to collect"),
    delay: float = typer.Option(0.1, "--delay", help="Delay between requests"),
) -> None:
    """Token randomness analyzer — Burp Sequencer replacement."""
    from vapt.engine.sequencer import Sequencer

    print_banner()
    console.print(f"\n[bold]Sequencer: Analyzing token randomness[/bold]")
    console.print(f"URL: [cyan]{url}[/cyan]")
    console.print(f"Extract from: [yellow]{extract_from}[/yellow] → {extract_name}\n")

    seq = Sequencer(
        url, extract_from=extract_from, extract_name=extract_name,
        extract_regex=extract_regex, sample_size=sample_size, delay=delay,
    )

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        task = prog.add_task("Collecting tokens...", total=sample_size)

        def on_progress(current, total):
            prog.update(task, completed=current, description=f"Collecting [{current}/{total}]")

        result = seq.analyze(tokens=seq.collect(progress_callback=on_progress))

    table = Table(title="Sequencer Results", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Samples collected", str(result.sample_size))
    table.add_row("Shannon entropy", f"{result.entropy_per_char:.4f}")
    table.add_row("Max possible entropy", f"{result.max_entropy:.4f}")
    table.add_row("Entropy ratio", f"{result.entropy_ratio:.4f}")
    table.add_row("Chi-squared", f"{result.chi_squared:.2f}")
    table.add_row("Monobit ratio", f"{result.monobit_ratio:.4f}")
    table.add_row("Runs score", f"{result.runs_score:.4f}")

    rating_colors = {"excellent": "green", "good": "green", "fair": "yellow", "poor": "red", "critical": "bold red"}
    color = rating_colors.get(result.rating, "white")
    table.add_row("Overall score", f"[bold]{result.overall_score:.1f}/100[/bold]")
    table.add_row("Rating", f"[{color}]{result.rating.upper()}[/{color}]")
    console.print(table)

    if result.warnings:
        console.print("\n[bold yellow]Warnings:[/bold yellow]")
        for w in result.warnings:
            console.print(f"  [yellow]⚠ {w}[/yellow]")


@app.command("codec")
def cmd_codec(
    data: str = typer.Argument(..., help="Data to encode/decode"),
    operation: str = typer.Option("smart", "--op", "-o", help="Operation: b64e|b64d|urle|urld|hexe|hexd|htmle|htmld|jwtd|hashid|smart|md5|sha256"),
) -> None:
    """Encoder, decoder, and hash identification utility."""
    from vapt.utils.codec import Codec
    import json as json_mod

    ops = {
        "b64e": ("Base64 Encode", lambda d: Codec.encode_base64(d)),
        "b64d": ("Base64 Decode", lambda d: Codec.decode_base64(d)),
        "urle": ("URL Encode", lambda d: Codec.encode_url(d)),
        "urld": ("URL Decode", lambda d: Codec.decode_url(d)),
        "hexe": ("Hex Encode", lambda d: Codec.encode_hex(d)),
        "hexd": ("Hex Decode", lambda d: Codec.decode_hex(d)),
        "htmle": ("HTML Encode", lambda d: Codec.encode_html(d)),
        "htmld": ("HTML Decode", lambda d: Codec.decode_html(d)),
        "jwtd": ("JWT Decode", lambda d: json_mod.dumps(Codec.decode_jwt(d), indent=2)),
        "hashid": ("Hash Identify", lambda d: ", ".join(Codec.identify_hash(d))),
        "smart": ("Smart Decode", lambda d: json_mod.dumps(Codec.smart_decode(d), indent=2, default=str)),
        "md5": ("MD5 Hash", lambda d: Codec.hash_string(d, "md5")),
        "sha256": ("SHA-256 Hash", lambda d: Codec.hash_string(d, "sha256")),
        "all": ("All Encodings", lambda d: json_mod.dumps(Codec.encode_all(d), indent=2)),
    }

    if operation not in ops:
        console.print(f"[red]Unknown operation: {operation}[/red]")
        console.print(f"Available: {', '.join(ops.keys())}")
        raise typer.Exit(1)

    name, func = ops[operation]
    try:
        result = func(data)
        console.print(f"[bold]{name}:[/bold]")
        console.print(result)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")


# Entry point

def entry_point() -> None:
    """Main entry point registered in setup.py."""
    app()


if __name__ == "__main__":
    entry_point()
