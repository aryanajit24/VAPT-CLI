"""SQLAlchemy ORM models for the knowledge base."""

from __future__ import annotations

import datetime
from datetime import timezone

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from vapt.database.db import Base


class KnowledgeEntry(Base):
    """A single vulnerability rule in the knowledge base.

    Every field maps directly to the spec's required KB schema (Section 4).
    The seed_kb.py module populates this table with 40+ curated entries.
    """

    __tablename__ = "knowledge_base"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Core identification
    vuln_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)

    # Full description (2-3 paragraphs)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Severity and scoring
    severity: Mapped[str] = mapped_column(String(16), nullable=False)  # critical/high/medium/low/info
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cvss_vector: Mapped[str | None] = mapped_column(Text, nullable=True)  # CVSS v3 vector string

    # OWASP / standards mapping
    owasp_category: Mapped[str | None] = mapped_column(String(128), nullable=True)  # e.g. "A03:2021 - Injection"
    nis2_control: Mapped[str | None] = mapped_column(Text, nullable=True)   # NIS2 article mapping
    iso27001_control: Mapped[str | None] = mapped_column(Text, nullable=True)  # ISO 27001 control

    # Technical detail
    how_it_works: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    code_example_fix: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Legacy / supporting fields
    cve_ids: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[str | None] = mapped_column(Text, nullable=True)
    compliance_tags: Mapped[str | None] = mapped_column(Text, nullable=True)
    detection_pattern: Mapped[str | None] = mapped_column(Text, nullable=True)
    false_positive_indicators: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.now(timezone.utc)
    )


class ScanResult(Base):
    """Persisted result of a single scan run.

    Every time `vapt scan` finishes, the aggregate is saved here so
    users can regenerate reports later without re-scanning.
    """

    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=False)
    finished_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    risk_score: Mapped[float] = mapped_column(Float, nullable=True)
    findings: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class MonitorHistory(Base):
    """Periodic snapshots taken by the continuous monitoring loop.

    Each row captures what the target looked like at a point in time,
    plus a diff of what changed since the previous snapshot.
    """

    __tablename__ = "monitor_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    scanned_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=False)
    snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    changes: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class ComplianceMapping(Base):
    """Mapping between vulnerability categories and compliance framework controls.

    These rows link a vuln category (e.g. "injection") to a specific
    regulatory control (e.g. NIS2 Article 21, PCI-DSS Req 6.3).
    The seed_kb module populates these during first run.
    """

    __tablename__ = "compliance_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    framework: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    control_title: Mapped[str] = mapped_column(String(256), nullable=False)
    vuln_category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
