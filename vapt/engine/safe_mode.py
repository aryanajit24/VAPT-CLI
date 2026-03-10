
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SafetyProfile:
    name: str
    description: str

    allow_port_scan: bool = True
    allow_default_creds: bool = False
    allow_race_conditions: bool = False
    allow_http_smuggling: bool = False
    allow_cache_poisoning: bool = False
    allow_deserialization: bool = False
    allow_time_blind_sqli: bool = True
    allow_xxe: bool = False
    allow_ssrf: bool = True
    allow_brute_force: bool = False
    allow_dos_tests: bool = False
    allow_mfa_bypass: bool = False
    allow_cloud_write: bool = False
    allow_cloud_scan: bool = True
    allow_command_exec: bool = False
    allow_file_write: bool = False

    max_requests_per_second: float = 5.0
    max_concurrent_threads: int = 3
    max_payloads_per_param: int = 20
    max_fuzz_paths: int = 100

    excluded_categories: list[str] = field(default_factory=list)


SAFETY_PROFILES: dict[str, SafetyProfile] = {

    "aggressive": SafetyProfile(
        name="Aggressive",
        description="No restrictions — use ONLY on YOUR OWN systems!",
        allow_port_scan=True,
        allow_default_creds=True,
        allow_race_conditions=True,
        allow_http_smuggling=True,
        allow_cache_poisoning=True,
        allow_deserialization=True,
        allow_time_blind_sqli=True,
        allow_xxe=True,
        allow_ssrf=True,
        allow_brute_force=True,
        allow_dos_tests=True,
        allow_mfa_bypass=True,
        allow_cloud_write=True,
        allow_cloud_scan=True,
        allow_command_exec=True,
        allow_file_write=True,
        max_requests_per_second=50.0,
        max_concurrent_threads=20,
        max_payloads_per_param=100,
        max_fuzz_paths=500,
    ),

    "standard": SafetyProfile(
        name="Standard",
        description="Safe for most bug bounty programs. Dangerous attacks disabled.",
        allow_port_scan=True,
        allow_default_creds=False,
        allow_race_conditions=False,
        allow_http_smuggling=False,
        allow_cache_poisoning=False,
        allow_deserialization=False,
        allow_time_blind_sqli=True,
        allow_xxe=False,
        allow_ssrf=True,
        allow_brute_force=False,
        allow_dos_tests=False,
        allow_mfa_bypass=False,
        allow_cloud_write=False,
        allow_cloud_scan=True,
        allow_command_exec=False,
        allow_file_write=False,
        max_requests_per_second=5.0,
        max_concurrent_threads=3,
        max_payloads_per_param=20,
        max_fuzz_paths=100,
        excluded_categories=[
            "dos", "ddos", "brute_force", "social_engineering",
            "physical_access", "rate_limiting",
        ],
    ),

    "meesho": SafetyProfile(
        name="Meesho (HackerOne)",
        description="Tailored for Meesho program rules. Very restrictive.",
        allow_port_scan=False,
        allow_default_creds=False,
        allow_race_conditions=False,
        allow_http_smuggling=False,
        allow_cache_poisoning=False,
        allow_deserialization=False,
        allow_time_blind_sqli=True,
        allow_xxe=False,
        allow_ssrf=True,
        allow_brute_force=False,
        allow_dos_tests=False,
        allow_mfa_bypass=False,
        allow_cloud_write=False,
        allow_cloud_scan=False,
        allow_command_exec=False,
        allow_file_write=False,
        max_requests_per_second=2.0,
        max_concurrent_threads=1,
        max_payloads_per_param=10,
        max_fuzz_paths=50,
        excluded_categories=[
            "dos", "ddos", "brute_force", "rate_limiting",
            "clickjacking", "cache_deception",
            "self_xss", "content_spoofing",
            "security_header", "ssl_tls", "cookie_flag", "hsts",
            "username_enumeration", "email_enumeration",
            "spf", "dkim", "dmarc",
            "directory_listing", "path_disclosure", "stack_trace",
            "banner_disclosure", "service_fingerprint", "robots_txt",
            "missing_cert_pinning", "root_detection", "code_obfuscation",
            "tab_nabbing", "task_hijacking", "weak_password_policy",
            "cors_no_impact", "collection_id_enum", "account_deletion",
            "social_engineering", "physical_access",
        ],
    ),

    "optus": SafetyProfile(
        name="Optus (Bugcrowd)",
        description="Tailored for Optus. Infrastructure testing allowed.",
        allow_port_scan=True,
        allow_default_creds=False,
        allow_race_conditions=False,
        allow_http_smuggling=False,
        allow_cache_poisoning=False,
        allow_deserialization=False,
        allow_time_blind_sqli=True,
        allow_xxe=False,
        allow_ssrf=True,
        allow_brute_force=False,
        allow_dos_tests=False,
        allow_mfa_bypass=False,
        allow_cloud_write=False,
        allow_cloud_scan=True,
        allow_command_exec=False,
        allow_file_write=False,
        max_requests_per_second=3.0,
        max_concurrent_threads=2,
        max_payloads_per_param=15,
        max_fuzz_paths=100,
        excluded_categories=[
            "dos", "ddos", "social_engineering", "physical_access",
        ],
    ),

    "hackerone": SafetyProfile(
        name="HackerOne (General)",
        description="Conservative profile for any HackerOne program.",
        allow_port_scan=False,
        allow_default_creds=False,
        allow_race_conditions=False,
        allow_http_smuggling=False,
        allow_cache_poisoning=False,
        allow_deserialization=False,
        allow_time_blind_sqli=True,
        allow_xxe=False,
        allow_ssrf=True,
        allow_brute_force=False,
        allow_dos_tests=False,
        allow_mfa_bypass=False,
        allow_cloud_write=False,
        allow_cloud_scan=True,
        allow_command_exec=False,
        allow_file_write=False,
        max_requests_per_second=3.0,
        max_concurrent_threads=2,
        max_payloads_per_param=15,
        max_fuzz_paths=80,
        excluded_categories=[
            "dos", "ddos", "brute_force", "rate_limiting",
            "social_engineering", "physical_access",
        ],
    ),

    "bugcrowd": SafetyProfile(
        name="Bugcrowd (General)",
        description="Conservative profile for any Bugcrowd program.",
        allow_port_scan=True,
        allow_default_creds=False,
        allow_race_conditions=False,
        allow_http_smuggling=False,
        allow_cache_poisoning=False,
        allow_deserialization=False,
        allow_time_blind_sqli=True,
        allow_xxe=False,
        allow_ssrf=True,
        allow_brute_force=False,
        allow_dos_tests=False,
        allow_mfa_bypass=False,
        allow_cloud_write=False,
        allow_cloud_scan=True,
        allow_command_exec=False,
        allow_file_write=False,
        max_requests_per_second=3.0,
        max_concurrent_threads=2,
        max_payloads_per_param=15,
        max_fuzz_paths=100,
        excluded_categories=[
            "dos", "ddos", "brute_force",
            "social_engineering", "physical_access",
        ],
    ),
}


def get_safety_profile(name: str) -> SafetyProfile:
    profile = SAFETY_PROFILES.get(name.lower())
    if not profile:
        available = ", ".join(SAFETY_PROFILES.keys())
        raise ValueError(f"Unknown safety profile: '{name}'. Available: {available}")
    return profile


def build_safety_config(profile: SafetyProfile) -> dict:
    return {
        "skip_time_blind_sqli": not profile.allow_time_blind_sqli,
        "skip_xxe": not profile.allow_xxe,
        "skip_command_exec": not profile.allow_command_exec,
        "skip_deserialization": not profile.allow_deserialization,
        "skip_cache_poisoning": not profile.allow_cache_poisoning,
        "skip_mfa_bypass": not profile.allow_mfa_bypass,
        "skip_brute_force": not profile.allow_brute_force,
        "skip_default_creds": not profile.allow_default_creds,
        "skip_file_write": not profile.allow_file_write,
        "skip_ssrf": not profile.allow_ssrf,
        "skip_rate_limit_test": not profile.allow_dos_tests,
        "max_payloads_per_param": profile.max_payloads_per_param,
        "max_fuzz_paths": profile.max_fuzz_paths,
        "max_requests_per_second": profile.max_requests_per_second,
        "max_concurrent_threads": profile.max_concurrent_threads,
    }


def filter_findings_by_safety(
    findings: list[dict],
    profile: SafetyProfile,
) -> tuple[list[dict], int]:
    if not profile.excluded_categories:
        return findings, 0

    blocked = {c.lower().replace("-", "_").replace(" ", "_")
                for c in profile.excluded_categories}
    kept: list[dict] = []
    for f in findings:
        cat = f.get("category", "").lower().replace("-", "_").replace(" ", "_")
        title = f.get("title", "").lower()
        vuln_id = f.get("vuln_id", "").lower()
        is_blocked = any(
            b in cat or b in title or b in vuln_id for b in blocked
        )
        if not is_blocked:
            kept.append(f)
    return kept, len(findings) - len(kept)


def format_safety_summary(profile: SafetyProfile) -> str:
    lines = [
        f"[bold]{profile.description}[/bold]",
        f"Rate limit: {profile.max_requests_per_second} req/s  |  "
        f"Threads: {profile.max_concurrent_threads}  |  "
        f"Payloads/param: {profile.max_payloads_per_param}",
        "",
    ]

    blocked = []
    if not profile.allow_port_scan:
        blocked.append("Port scanning")
    if not profile.allow_default_creds:
        blocked.append("Default credential brute-force")
    if not profile.allow_race_conditions:
        blocked.append("Race condition testing (50+ concurrent)")
    if not profile.allow_http_smuggling:
        blocked.append("HTTP request smuggling (corrupts proxies)")
    if not profile.allow_cache_poisoning:
        blocked.append("Cache poisoning (affects other users)")
    if not profile.allow_deserialization:
        blocked.append("Deserialization payloads (code execution)")
    if not profile.allow_xxe:
        blocked.append("XXE external entities (reads server files)")
    if not profile.allow_brute_force:
        blocked.append("Brute-force login attacks")
    if not profile.allow_dos_tests:
        blocked.append("DoS / DDoS testing")
    if not profile.allow_mfa_bypass:
        blocked.append("MFA bypass attempts")
    if not profile.allow_cloud_write:
        blocked.append("Cloud bucket write tests")
    if not profile.allow_command_exec:
        blocked.append("Command execution payloads")
    if not profile.allow_file_write:
        blocked.append("File write payloads")

    if blocked:
        lines.append("[red]Blocked attacks:[/red]")
        for b in blocked:
            lines.append(f"  [red]✗[/red] {b}")
    else:
        lines.append("[yellow]⚠ ALL attacks enabled — use on YOUR OWN servers only![/yellow]")

    allowed = []
    if profile.allow_time_blind_sqli:
        allowed.append("SQL injection (error + time-blind)")
    if profile.allow_ssrf:
        allowed.append("SSRF detection")
    allowed.extend([
        "XSS (reflected, stored, DOM)",
        "CSRF / CORS detection",
        "IDOR enumeration",
        "JWT analysis",
        "API endpoint discovery",
        "SSL/TLS analysis",
        "Directory fuzzing (limited)",
        "CSP analysis",
        "CRLF injection",
    ])

    lines.append("")
    lines.append("[green]Allowed attacks:[/green]")
    for a in allowed:
        lines.append(f"  [green]✓[/green] {a}")

    return "\n".join(lines)
