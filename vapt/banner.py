
from rich.console import Console
from rich.text import Text

from vapt import __version__

BANNER = r"""
██╗   ██╗ █████╗ ██████╗ ████████╗     ██████╗██╗     ██╗
██║   ██║██╔══██╗██╔══██╗╚══██╔══╝    ██╔════╝██║     ██║
██║   ██║███████║██████╔╝   ██║       ██║     ██║     ██║
╚██╗ ██╔╝██╔══██║██╔═══╝    ██║       ██║     ██║     ██║
 ╚████╔╝ ██║  ██║██║        ██║       ╚██████╗███████╗██║
  ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝        ╚═════╝╚══════╝╚═╝
"""

CAPABILITIES = [
    "Recon & OSINT",
    "Port & Service Scanning",
    "SSL/TLS Deep Analysis",
    "Web App Attacks (SQLi, XSS, SSTI, SSRF, XXE, RCE…)",
    "DOM XSS & Client-Side Security",
    "Prototype Pollution & Exposed Secrets",
    "API Security (BOLA, JWT, GraphQL, Mass Assignment…)",
    "Auth Scanning (CSRF, CORS, IDOR, OAuth, Session, MFA Bypass)",
    "Race Condition Testing (Double-Spend, TOCTOU)",
    "HTTP Request Smuggling (CL.TE, TE.CL, H2 Downgrade)",
    "Directory & File Fuzzing (300+ paths)",
    "Cloud Scanning (S3, Azure, GCP, Firebase)",
    "CVE Detection (NVD)",
    "WAF Detection & Bypass (20+ WAFs)",
    "Authenticated Scanning (Form/Bearer/OAuth2/Cookie)",
    "Stealth Mode & Adaptive Rate Limiting",
    "HIGH Confidence Validation",
    "Parallel Scanning Engine",
    "Plugin System (YAML/Python)",
    "Subdomain Takeover & Deep Scanning",
    "Bug Bounty Report Generator (Markdown + Per-Finding)",
    "Compliance Mapping (OWASP / PCI-DSS / SANS 25)",
    "NoSQL / LDAP / Deserialization Injection",
    "CRLF Injection & Cache Poisoning",
    "CSP & Host Header Analysis",
    "Auto Evidence Capture (Real HTTP Req/Res)",
    "Step-by-Step PoC Generation (CWE/CVSS)",
]


def print_banner(console: Console | None = None) -> None:
    if console is None:
        console = Console()

    logo = Text(BANNER, style="bold cyan")
    console.print(logo)

    info = Text()
    info.append(f"  v{__version__}", style="bold green")
    info.append("  |  ", style="dim")
    info.append("Ultimate Vulnerability Assessment & Penetration Testing", style="bold white")
    info.append("  One command. Every attack vector. HIGH confidence. Full report.\n", style="dim italic")
    info.append("\n  Modules: ", style="bold")
    info.append(" · ".join(CAPABILITIES), style="cyan")
    info.append("\n")
    console.print(info)
