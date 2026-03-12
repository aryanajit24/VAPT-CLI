
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_TO_CVSS = {
    ("critical", False): 9.3,
    ("critical", True): 8.7,
    ("high", False): 8.1,
    ("high", True): 7.5,
    ("medium", False): 6.3,
    ("medium", True): 5.8,
    ("low", False): 3.7,
    ("low", True): 3.1,
    ("info", False): 0.0,
    ("info", True): 0.0,
}


class EliteReportGenerator:

    def __init__(self, output_dir: str = "./vapt-reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_elite_reports(
        self,
        findings: list[dict],
        program_name: str = "",
        platform: str = "HackerOne",
        target: str = "",
    ) -> list[str]:
        generated = []

        reportable = [
            f for f in findings
            if f.get("submission_readiness") in ("ready", "needs_work")
        ]

        if not reportable:
            path = self._generate_summary_only(findings, program_name, platform, target)
            return [str(path)]

        for idx, finding in enumerate(reportable, 1):
            md_path = self._generate_markdown_report(finding, idx, program_name, platform, target)
            generated.append(str(md_path))

            fields_path = self._generate_field_report(finding, idx, platform)
            generated.append(str(fields_path))

        summary_path = self._generate_master_summary(reportable, findings, program_name, platform, target)
        generated.append(str(summary_path))

        return generated

    def _generate_markdown_report(
        self,
        finding: dict,
        rank: int,
        program_name: str,
        platform: str,
        target: str,
    ) -> Path:
        title = finding.get("title", "Vulnerability Finding")
        severity = finding.get("severity", "medium").upper()
        cvss = finding.get("cvss", finding.get("cvss_score", 0))
        category = finding.get("category", "")
        url = finding.get("url", target)
        description = finding.get("description", "")
        evidence = finding.get("evidence", {})
        impact = finding.get("impact", "")
        remediation = finding.get("remediation", "")
        steps = finding.get("steps_to_reproduce", [])
        
        novelty = finding.get("novelty_score", 0)
        dup_risk = finding.get("duplicate_risk", 0)
        poc_complete = finding.get("poc_completeness", 0)
        readiness = finding.get("submission_readiness", "unknown")
        recommendation = finding.get("elite_recommendation", "")
        chains = finding.get("chain_potential", [])
        
        cvss_vector = self._build_cvss4_vector(finding)

        lines = [
            f"# {title}",
            "",
            "---",
            "",
            f"**Platform:** {platform}",
            f"**Program:** {program_name}",
            f"**Asset:** `{url}`",
            f"**Severity:** {severity}",
            f"**CVSS 4.0:** {cvss} ({cvss_vector})",
            "",
        ]

        if readiness == "ready":
            status_badge = "READY TO SUBMIT"
            status_color = "green"
        elif readiness == "needs_work":
            status_badge = "NEEDS WORK BEFORE SUBMISSION"
            status_color = "yellow"
        else:
            status_badge = "REVIEW REQUIRED"
            status_color = "orange"

        lines.extend([
            "---",
            "",
            "## Elite Intelligence Assessment",
            "",
            f"| Metric | Score |",
            f"|--------|-------|",
            f"| Submission Readiness | **{status_badge}** |",
            f"| Novelty Score | {novelty:.0%} |",
            f"| Duplicate Risk | {dup_risk:.0%} |",
            f"| PoC Completeness | {poc_complete:.0%} |",
            f"| Priority Rank | #{rank} |",
            "",
        ])

        if recommendation:
            lines.extend([
                "> **Recommendation:** " + recommendation,
                "",
            ])

        if dup_risk > 0.7:
            lines.extend([
                f"> **WARNING:** High duplicate risk ({dup_risk:.0%}). This type of finding is commonly reported.",
                f"> Consider whether this specific instance adds novel value beyond existing reports.",
                "",
            ])

        if poc_complete < 0.6:
            lines.extend([
                f"> **WARNING:** PoC completeness is low ({poc_complete:.0%}).",
                f"> Ensure your proof-of-concept demonstrates real-world exploitability.",
                "",
            ])

        lines.extend([
            "---",
            "",
            "## Summary",
            "",
            description,
            "",
        ])

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
            ])
            if isinstance(evidence, dict):
                if "request" in evidence:
                    lines.extend([
                        "### HTTP Request",
                        "```http",
                        str(evidence["request"])[:2000],
                        "```",
                        "",
                    ])
                if "response" in evidence:
                    lines.extend([
                        "### HTTP Response",
                        "```http",
                        str(evidence["response"])[:2000],
                        "```",
                        "",
                    ])
                if "curl" in evidence:
                    lines.extend([
                        "### cURL Command",
                        "```bash",
                        str(evidence["curl"]),
                        "```",
                        "",
                    ])
                remaining = {k: v for k, v in evidence.items() if k not in ("request", "response", "curl")}
                if remaining:
                    lines.extend([
                        "### Additional Evidence",
                        "```json",
                        json.dumps(remaining, indent=2, default=str)[:2000],
                        "```",
                        "",
                    ])
            else:
                lines.extend([
                    "```",
                    str(evidence)[:3000],
                    "```",
                    "",
                ])

        if chains:
            lines.extend([
                "## Attack Chain Potential",
                "",
                "This finding can be combined with other vulnerabilities for increased impact:",
                "",
            ])
            for chain in chains:
                lines.append(f"- **{chain.get('chain', 'N/A')}**: {chain.get('impact', 'N/A')}")
            lines.append("")

        if impact:
            lines.extend([
                "## Impact",
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

        try:
            from vapt.reporting.bounty_report import VULN_REFERENCES
            refs = VULN_REFERENCES.get(category, {})
            if refs:
                lines.extend([
                    "## References",
                    "",
                    f"- **CWE:** {refs.get('cwe', 'N/A')}",
                    f"- **OWASP:** {refs.get('owasp', 'N/A')}",
                    f"- **Type:** {refs.get('type', 'N/A')}",
                    "",
                ])
        except ImportError:
            pass

        lines.extend([
            "---",
            f"*Generated by VAPT CLI Gold Elite Edition — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*",
        ])

        safe_title = "".join(c if c.isalnum() or c in " -_" else "" for c in title)[:50].strip().replace(" ", "_")
        filename = f"elite_{rank}_{safe_title}.md"
        path = self.output_dir / filename
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _generate_field_report(
        self,
        finding: dict,
        rank: int,
        platform: str,
    ) -> Path:
        title = finding.get("title", "")[:150]
        severity = finding.get("severity", "medium").capitalize()
        cvss = finding.get("cvss", finding.get("cvss_score", 0))
        url = finding.get("url", "")
        category = finding.get("category", "")
        description = finding.get("description", "")
        steps = finding.get("steps_to_reproduce", [])
        impact = finding.get("impact", "")
        evidence = finding.get("evidence", {})
        
        try:
            from vapt.reporting.bounty_report import VULN_REFERENCES
            weakness = VULN_REFERENCES.get(category, {}).get("cwe", "CWE-284")
        except ImportError:
            weakness = "CWE-284"

        cvss_vector = self._build_cvss4_vector(finding)

        steps_text = "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1)) if steps else "See description."

        evidence_text = ""
        if evidence:
            if isinstance(evidence, dict):
                parts = []
                if "curl" in evidence:
                    parts.append(f"### cURL\n```bash\n{evidence['curl']}\n```")
                if "request" in evidence:
                    parts.append(f"### Request\n```http\n{str(evidence['request'])[:1500]}\n```")
                if "response" in evidence:
                    parts.append(f"### Response\n```http\n{str(evidence['response'])[:1500]}\n```")
                evidence_text = "\n\n".join(parts)
            else:
                evidence_text = f"```\n{str(evidence)[:2000]}\n```"

        warnings = []
        if finding.get("duplicate_risk", 0) > 0.7:
            warnings.append(f"WARNING: HIGH DUPLICATE RISK ({finding['duplicate_risk']:.0%}) -- Consider strengthening PoC before submission")
        if finding.get("poc_completeness", 0) < 0.6:
            warnings.append(f"WARNING: LOW POC COMPLETENESS ({finding['poc_completeness']:.0%}) -- Add more evidence/reproduction steps")
        if finding.get("submission_readiness") == "needs_work":
            rec = finding.get("elite_recommendation", "Strengthen PoC and check for duplicates")
            warnings.append(f"WARNING: NEEDS WORK: {rec}")

        warning_block = ""
        if warnings:
            warning_block = "\n--- ELITE INTELLIGENCE WARNINGS ---\n" + "\n".join(warnings) + "\n---\n\n"

        if platform == "HackerOne":
            content = self._h1_format(title, url, weakness, severity, cvss_vector, description, steps_text, evidence_text, impact, warning_block)
        elif platform == "Bugcrowd":
            content = self._bugcrowd_format(title, url, weakness, severity, description, steps_text, evidence_text, impact, warning_block)
        else:
            content = self._h1_format(title, url, weakness, severity, cvss_vector, description, steps_text, evidence_text, impact, warning_block)

        safe_title = "".join(c if c.isalnum() or c in " -_" else "" for c in title)[:50].strip().replace(" ", "_")
        filename = f"elite_{rank}_{safe_title}_fields.txt"
        path = self.output_dir / filename
        path.write_text(content, encoding="utf-8")
        return path

    def _h1_format(
        self, title, url, weakness, severity, cvss_vector,
        description, steps_text, evidence_text, impact, warning_block,
    ) -> str:
        return (
            f"{warning_block}"
            f"FIELD: Title\n"
            f"{title}\n\n"
            f"FIELD: Asset\n"
            f"{url}\n\n"
            f"FIELD: Weakness\n"
            f"{weakness}\n\n"
            f"FIELD: Severity\n"
            f"{severity}\n"
            f"CVSS 4.0: {cvss_vector}\n\n"
            f"FIELD: Description\n"
            f"## Summary\n\n"
            f"{description}\n\n"
            f"## Steps To Reproduce\n\n"
            f"{steps_text}\n\n"
            f"## Supporting Material/References\n\n"
            f"{evidence_text}\n\n"
            f"FIELD: Impact\n"
            f"## Summary\n\n"
            f"{impact}\n"
        )

    def _bugcrowd_format(
        self, title, url, weakness, severity,
        description, steps_text, evidence_text, impact, warning_block,
    ) -> str:
        return (
            f"{warning_block}"
            f"FIELD: Title\n"
            f"{title}\n\n"
            f"FIELD: URL\n"
            f"{url}\n\n"
            f"FIELD: Vulnerability Type\n"
            f"{weakness}\n\n"
            f"FIELD: Priority\n"
            f"{severity}\n\n"
            f"FIELD: Description\n"
            f"## Summary\n\n"
            f"{description}\n\n"
            f"## Steps to Reproduce\n\n"
            f"{steps_text}\n\n"
            f"## Proof of Concept\n\n"
            f"{evidence_text}\n\n"
            f"FIELD: Impact\n\n"
            f"{impact}\n"
        )

    def _generate_master_summary(
        self,
        reportable: list[dict],
        all_findings: list[dict],
        program_name: str,
        platform: str,
        target: str,
    ) -> Path:
        total = len(all_findings)
        ready = sum(1 for f in all_findings if f.get("submission_readiness") == "ready")
        needs_work = sum(1 for f in all_findings if f.get("submission_readiness") == "needs_work")
        skipped = sum(1 for f in all_findings if f.get("submission_readiness") == "skip")

        lines = [
            "# Elite Hunt — Master Summary",
            "",
            f"**Target:** {target}",
            f"**Program:** {program_name}",
            f"**Platform:** {platform}",
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            "---",
            "",
            "## Finding Summary",
            "",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Total Findings | {total} |",
            f"| Ready to Submit | {ready} |",
            f"| Needs Work | {needs_work} |",
            f"| Skipped (high duplicate risk) | {skipped} |",
            "",
            "---",
            "",
        ]

        if reportable:
            lines.extend([
                "## Reportable Findings (Ranked by Priority)",
                "",
                "| # | Readiness | Title | Severity | Novelty | Dup Risk |",
                "|---|-----------|-------|----------|---------|----------|",
            ])
            for i, f in enumerate(reportable, 1):
                readiness = f.get("submission_readiness", "?")
                title = f.get("title", "")[:60]
                severity = f.get("severity", "?").upper()
                novelty = f"{f.get('novelty_score', 0):.0%}"
                dup_risk = f"{f.get('duplicate_risk', 0):.0%}"
                lines.append(f"| {i} | {readiness.upper()} | {title} | {severity} | {novelty} | {dup_risk} |")
            lines.append("")

        skipped_findings = [f for f in all_findings if f.get("submission_readiness") == "skip"]
        if skipped_findings:
            lines.extend([
                "## Skipped Findings (Why They Were Filtered Out)",
                "",
                "| Title | Reason | Dup Risk |",
                "|-------|--------|----------|",
            ])
            for f in skipped_findings[:20]:
                title = f.get("title", "")[:50]
                rec = f.get("elite_recommendation", "High duplicate risk")[:60]
                dup = f"{f.get('duplicate_risk', 0):.0%}"
                lines.append(f"| {title} | {rec} | {dup} |")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## Recommendations",
            "",
            "1. Start with the highest-ranked READY finding",
            "2. For NEEDS WORK findings, follow the recommendation in each report",
            "3. Do NOT submit SKIPPED findings — they are almost certainly duplicates",
            "4. Test findings manually before submission to confirm exploitability",
            "5. Create a working PoC (curl command, HTML file, or video) for each submission",
            "",
            "---",
            f"*Generated by VAPT CLI Gold Elite Edition*",
        ])

        path = self.output_dir / "elite_master_summary.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _generate_summary_only(
        self,
        all_findings: list[dict],
        program_name: str,
        platform: str,
        target: str,
    ) -> Path:
        total = len(all_findings)

        lines = [
            "# Elite Hunt — Summary (No Reportable Findings)",
            "",
            f"**Target:** {target}",
            f"**Program:** {program_name}",
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            "---",
            "",
            f"## Assessment: {total} findings analyzed, none are submission-ready",
            "",
            "This means one of:",
            "1. All findings are common duplicates (headers, info disclosure, etc.)",
            "2. No findings had sufficient PoC quality for submission",
            "3. The target has a strong security posture",
            "",
            "## Next Steps",
            "",
            "1. **Go deeper with authentication** — Create test accounts and scan behind login",
            "2. **Focus on business logic** — Test payment flows, promo codes, referrals",
            "3. **Test for race conditions** — Financial operations, coupon redemption",
            "4. **Look for IDOR** — Access other users' data by manipulating IDs",
            "5. **Try different endpoints** — Check mobile API, internal microservices",
            "",
        ]

        if all_findings:
            lines.extend([
                "## All Findings (Not Recommended for Submission)",
                "",
                "| Title | Duplicate Risk | Why Skipped |",
                "|-------|---------------|-------------|",
            ])
            for f in all_findings[:20]:
                title = f.get("title", "")[:50]
                dup = f"{f.get('duplicate_risk', 0):.0%}"
                rec = f.get("elite_recommendation", "Low novelty")[:60]
                lines.append(f"| {title} | {dup} | {rec} |")
            lines.append("")

        lines.extend([
            "---",
            f"*Generated by VAPT CLI Gold Elite Edition*",
        ])

        path = self.output_dir / "elite_summary_no_findings.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _build_cvss4_vector(self, finding: dict) -> str:
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
        if any(k in category for k in ("ssrf", "rce", "command")):
            sc, si, sa = "H", "H", "H"
        elif any(k in category for k in ("idor", "privilege", "access")):
            sc = "H"

        if any(k in category for k in ("xss", "cors", "csrf")):
            ui = "P"
        if "race" in category:
            ac = "H"

        return f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}/VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}"
