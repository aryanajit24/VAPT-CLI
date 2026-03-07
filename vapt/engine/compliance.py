"""Compliance framework mapping engine."""

from __future__ import annotations

from typing import Any

from vapt.database.db import get_session, init_db
from vapt.database.models import ComplianceMapping

FRAMEWORKS = ["NIS2", "ISO27001", "PCI-DSS", "NIST-SP800-53", "OWASP"]


class ComplianceEngine:
    """Map vulnerability findings to compliance framework controls.

    Uses two data sources:
    1. DB-driven mappings (ComplianceMapping table seeded by seed_kb)
    2. Tag-driven mappings (compliance_tags field on each finding)
    Both are merged and deduplicated before returning.
    """

    def __init__(self, db_path=None) -> None:
        init_db(db_path)
        self._db_path = db_path

    def _session(self):
        return get_session(self._db_path)

    def map_findings(
        self, findings: list[dict[str, Any]]
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Map findings to their compliance framework controls.

        Returns a dict keyed by framework name, where each value is a
        list of {control_id, control_title, finding_vuln_id, finding_title}
        for every triggered control.  Duplicates are stripped.
        """
        session = self._session()
        try:
            result: dict[str, list[dict[str, Any]]] = {fw: [] for fw in FRAMEWORKS}

            for finding in findings:
                category = finding.get("category", "")
                compliance_tags = finding.get("compliance_tags", "") or ""

                # DB-driven mappings — the seed_kb module populates these
                db_mappings = (
                    session.query(ComplianceMapping)
                    .filter(ComplianceMapping.vuln_category == category)
                    .all()
                )
                for m in db_mappings:
                    fw = m.framework
                    if fw not in result:
                        result[fw] = []
                    result[fw].append(
                        {
                            "control_id": m.control_id,
                            "control_title": m.control_title,
                            "finding_vuln_id": finding.get("vuln_id"),
                            "finding_title": finding.get("title"),
                        }
                    )

                # Tag-driven mappings — some findings carry inline tags
                # like "OWASP-A03,PCI-DSS-6.3" that map directly
                for tag in compliance_tags.split(","):
                    tag = tag.strip()
                    if not tag:
                        continue
                    for fw in FRAMEWORKS:
                        if tag.startswith(fw):
                            if fw not in result:
                                result[fw] = []
                            result[fw].append(
                                {
                                    "control_id": tag,
                                    "control_title": tag,
                                    "finding_vuln_id": finding.get("vuln_id"),
                                    "finding_title": finding.get("title"),
                                }
                            )

            # Deduplicate — same control can be triggered by multiple findings
            for fw in result:
                seen = set()
                deduped = []
                for item in result[fw]:
                    key = (item["control_id"], item.get("finding_vuln_id"))
                    if key not in seen:
                        seen.add(key)
                        deduped.append(item)
                result[fw] = deduped

            return result
        finally:
            session.close()

    def generate_dashboard(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Build a high-level compliance dashboard for the report.

        Each framework gets a status of 'compliant' or 'non-compliant'
        along with the count and list of triggered controls.
        """
        mapped = self.map_findings(findings)
        dashboard = {}
        for fw, controls in mapped.items():
            triggered = {c["control_id"] for c in controls}
            dashboard[fw] = {
                "triggered_controls": sorted(triggered),
                "control_count": len(triggered),
                "status": "non-compliant" if triggered else "compliant",
            }
        return dashboard
