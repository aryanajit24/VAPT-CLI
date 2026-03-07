"""
Knowledge base engine — your vulnerability encyclopedia.

This module is the bridge between raw scan findings and the curated
vulnerability data stored in the local SQLite database.  When a scanner
flags something suspicious, the KB enriches it with explanations,
remediation steps, CVSS scores, and compliance mappings.

Usage:
    kb = KnowledgeBase()
    enriched = kb.match_findings(raw_findings)
"""

from __future__ import annotations

from typing import Any

from vapt.database.db import get_session, init_db
from vapt.database.models import KnowledgeEntry


class KnowledgeBase:
    """Interface to the local vulnerability knowledge base.

    Think of this as a librarian — you hand it a finding and it pulls
    the right reference card with all the details.
    """

    def __init__(self, db_path=None) -> None:
        init_db(db_path)
        self._db_path = db_path

    def _session(self):
        return get_session(self._db_path)

    def get_all(self) -> list[dict[str, Any]]:
        """Return all knowledge base entries as dicts."""
        session = self._session()
        try:
            entries = session.query(KnowledgeEntry).all()
            return [self._to_dict(e) for e in entries]
        finally:
            session.close()

    def get_by_category(self, category: str) -> list[dict[str, Any]]:
        """Return all entries matching a given category."""
        session = self._session()
        try:
            entries = (
                session.query(KnowledgeEntry)
                .filter(KnowledgeEntry.category == category)
                .all()
            )
            return [self._to_dict(e) for e in entries]
        finally:
            session.close()

    def get_by_id(self, vuln_id: str) -> dict[str, Any] | None:
        """Return a single entry by vuln_id, or None if not found."""
        session = self._session()
        try:
            entry = (
                session.query(KnowledgeEntry)
                .filter(KnowledgeEntry.vuln_id == vuln_id)
                .first()
            )
            return self._to_dict(entry) if entry else None
        finally:
            session.close()

    def get_by_severity(self, severity: str) -> list[dict[str, Any]]:
        """Return all entries with the given severity level."""
        session = self._session()
        try:
            entries = (
                session.query(KnowledgeEntry)
                .filter(KnowledgeEntry.severity == severity.lower())
                .all()
            )
            return [self._to_dict(e) for e in entries]
        finally:
            session.close()

    def search(self, keyword: str) -> list[dict[str, Any]]:
        """Full-text search across title and description."""
        kw = f"%{keyword.lower()}%"
        session = self._session()
        try:
            entries = (
                session.query(KnowledgeEntry)
                .filter(
                    KnowledgeEntry.title.ilike(kw)
                    | KnowledgeEntry.description.ilike(kw)
                )
                .all()
            )
            return [self._to_dict(e) for e in entries]
        finally:
            session.close()

    def match_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Cross-reference scan findings against the knowledge base.

        Each finding dict should include at least 'category' or 'vuln_id'.
        We try vuln_id first (exact match) then fall back to category.
        Fields from the KB are merged in without overwriting anything
        the scanner already set — the scanner always wins on conflicts.
        """
        enriched = []
        for finding in findings:
            vuln_id = finding.get("vuln_id")
            category = finding.get("category", "")
            kb_entry = None

            if vuln_id:
                kb_entry = self.get_by_id(vuln_id)
            if kb_entry is None and category:
                matches = self.get_by_category(category)
                kb_entry = matches[0] if matches else None

            merged = dict(finding)
            if kb_entry:
                for key, val in kb_entry.items():
                    if key not in merged or merged[key] is None:
                        merged[key] = val
            enriched.append(merged)
        return enriched

    @staticmethod
    def _to_dict(entry: KnowledgeEntry) -> dict[str, Any]:
        return {
            "id": entry.id,
            "vuln_id": entry.vuln_id,
            "category": entry.category,
            "title": entry.title,
            "description": entry.description,
            "severity": entry.severity,
            "cvss_score": entry.cvss_score,
            "cvss_vector": entry.cvss_vector,
            "owasp_category": entry.owasp_category,
            "nis2_control": entry.nis2_control,
            "iso27001_control": entry.iso27001_control,
            "how_it_works": entry.how_it_works,
            "impact": entry.impact,
            "remediation": entry.remediation,
            "code_example_fix": entry.code_example_fix,
            "cve_ids": entry.cve_ids,
            "references": entry.references,
            "compliance_tags": entry.compliance_tags,
            "detection_pattern": entry.detection_pattern,
            "false_positive_indicators": entry.false_positive_indicators,
        }
