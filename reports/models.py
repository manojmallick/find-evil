# Find Evil! — Findings data model.
#
# A Finding is the unit of forensic conclusion. The two-tier model is the heart
# of the accuracy story (see ACCURACY_REPORT.md):
#
#   CONFIRMED — directly traceable to an artifact + a tool call_id. The report
#               generator REJECTS any CONFIRMED finding whose call_id is not
#               present in the audit log. This is the 0%-hallucination guarantee.
#   INFERRED  — an analytical conclusion. Always confidence-scored, never
#               presented as direct evidence, but still backed by call_ids.
#
# License: Apache 2.0

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Tier(str, enum.Enum):
    """Confidence tier for a finding."""

    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"


@dataclass
class Finding:
    """A single forensic conclusion.

    Attributes:
        id: Stable finding id (e.g. "F-001").
        tier: CONFIRMED or INFERRED.
        category: Taxonomy bucket (e.g. "lateral_movement", "persistence").
        title: One-line human-readable summary.
        description: Full analyst-facing explanation.
        call_id: The primary audit-log call_id this finding derives from.
            REQUIRED for CONFIRMED findings; optional for INFERRED.
        artifact_path: The evidence path/offset the finding points to.
        timestamp: The event time in the evidence (not analysis time).
        confidence: 0.0–1.0. Meaningful for INFERRED; CONFIRMED is implicitly 1.0.
        supporting_call_ids: Additional call_ids that corroborate the finding.
        mitre: Optional MITRE ATT&CK technique id (e.g. "T1021.002").
    """

    id: str
    tier: Tier
    category: str
    title: str
    description: str = ""
    call_id: str | None = None
    artifact_path: str | None = None
    timestamp: str | None = None
    confidence: float = 1.0
    supporting_call_ids: list[str] = field(default_factory=list)
    mitre: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tier": self.tier.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "call_id": self.call_id,
            "artifact_path": self.artifact_path,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
            "supporting_call_ids": self.supporting_call_ids,
            "mitre": self.mitre,
        }


@dataclass
class Discrepancy:
    """A cross-source contradiction caught by the self-correction loop.

    Example: a process present in the disk prefetch timeline but absent from the
    memory process list. Surfaced explicitly rather than silently resolved.
    """

    id: str
    summary: str
    hypotheses: list[str] = field(default_factory=list)
    resolution: str | None = None
    resolved: bool = False
    supporting_call_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "summary": self.summary,
            "hypotheses": self.hypotheses,
            "resolution": self.resolution,
            "resolved": self.resolved,
            "supporting_call_ids": self.supporting_call_ids,
        }


@dataclass
class AnalysisResult:
    """The complete output of an analysis run."""

    case_id: str
    disk_path: str | None = None
    memory_path: str | None = None
    findings: list[Finding] = field(default_factory=list)
    discrepancies: list[Discrepancy] = field(default_factory=list)
    iterations: int = 0
    started_at: str | None = None
    finished_at: str | None = None

    def confirmed(self) -> list[Finding]:
        return [f for f in self.findings if f.tier is Tier.CONFIRMED]

    def inferred(self) -> list[Finding]:
        return [f for f in self.findings if f.tier is Tier.INFERRED]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "disk_path": self.disk_path,
            "memory_path": self.memory_path,
            "summary": {
                "total_findings": len(self.findings),
                "confirmed": len(self.confirmed()),
                "inferred": len(self.inferred()),
                "discrepancies": len(self.discrepancies),
                "iterations": self.iterations,
            },
            "findings": [f.to_dict() for f in self.findings],
            "discrepancies": [d.to_dict() for d in self.discrepancies],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }
