"""
Correlator — connect the dots between findings.

Individual vulnerabilities are dangerous, but *combinations* of them
are often catastrophic.  This module looks for attack chains (e.g. XSS
+ broken auth = session hijacking) and clusters related CVEs together
so the report paints a complete picture.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

# These pairs define multi-step attack scenarios.  If both categories
# appear in the same scan, we flag it as an attack chain with critical
# severity — because an attacker would absolutely chain them.
ATTACK_CHAIN_PAIRS: list[tuple[str, str, str]] = [
    ("injection", "authentication", "Auth bypass via SQL injection chain"),
    ("xss", "authentication", "Session hijacking via XSS + broken auth"),
    ("ssrf", "network", "Internal network pivoting via SSRF"),
    ("api", "injection", "API injection leading to data exfiltration"),
    ("security_misconfiguration", "network", "Exposed service via misconfiguration"),
]


class Correlator:
    """Spot relationships and attack chains across scan findings.

    Feed it a list of findings and it'll tell you which ones work
    together to create something worse than any single issue.
    """

    def correlate(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Analyse a list of findings and return correlation metadata.

        Returns:
          - grouped_by_category: findings bucketed by category
          - attack_chains: detected multi-step attack paths
          - related_cves: CVE clusters
          - correlation_summary: human-readable insight list
        """
        grouped = self._group_by_category(findings)
        chains = self._detect_attack_chains(grouped)
        cve_clusters = self._cluster_cves(findings)
        summary = self._build_summary(chains, cve_clusters, grouped)

        return {
            "grouped_by_category": {k: v for k, v in grouped.items()},
            "attack_chains": chains,
            "related_cves": cve_clusters,
            "correlation_summary": summary,
        }

    @staticmethod
    def _group_by_category(
        findings: list[dict[str, Any]],
    ) -> dict[str, list[dict[str, Any]]]:
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in findings:
            cat = f.get("category", "unknown")
            groups[cat].append(f)
        return dict(groups)

    @staticmethod
    def _detect_attack_chains(
        grouped: dict[str, list[dict[str, Any]]],
    ) -> list[dict[str, Any]]:
        chains = []
        for cat_a, cat_b, description in ATTACK_CHAIN_PAIRS:
            if cat_a in grouped and cat_b in grouped:
                chains.append(
                    {
                        "categories": [cat_a, cat_b],
                        "description": description,
                        "severity": "critical",
                        "findings_a": [f.get("vuln_id") for f in grouped[cat_a]],
                        "findings_b": [f.get("vuln_id") for f in grouped[cat_b]],
                    }
                )
        return chains

    @staticmethod
    def _cluster_cves(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        clusters: dict[str, list[str]] = defaultdict(list)
        for f in findings:
            cve_raw = f.get("cve_ids") or ""
            for cve in cve_raw.split(","):
                cve = cve.strip()
                if cve:
                    clusters[cve].append(f.get("vuln_id", "unknown"))
        return [{"cve_id": cve, "affected_vulns": ids} for cve, ids in clusters.items()]

    @staticmethod
    def _build_summary(
        chains: list[dict[str, Any]],
        cve_clusters: list[dict[str, Any]],
        grouped: dict[str, list[dict[str, Any]]],
    ) -> list[str]:
        lines = []
        lines.append(f"Total categories identified: {len(grouped)}")
        lines.append(f"Attack chains detected: {len(chains)}")
        for chain in chains:
            lines.append(f"  ⚠  {chain['description']}")
        if cve_clusters:
            lines.append(f"CVE clusters found: {len(cve_clusters)}")
            for cl in cve_clusters:
                lines.append(f"  • {cl['cve_id']} → {', '.join(cl['affected_vulns'])}")
        return lines
