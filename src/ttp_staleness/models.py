from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]


class AttackTechnique(BaseModel):
    """A single ATT&CK technique or sub-technique with its staleness-relevant metadata."""

    technique_id: str
    name: str
    modified: datetime
    is_subtechnique: bool
    deprecated: bool = False
    tactic_ids: list[str] = Field(default_factory=list)
    stix_id: str


class AttackIndex(BaseModel):
    """Full ATT&CK index keyed by technique_id (e.g. T1059.001) with fetch metadata."""

    techniques: dict[str, AttackTechnique] = Field(default_factory=dict)
    fetched_at: datetime
    attack_version: str | None = None
    source_domain: str = "enterprise-attack"


class Rule(BaseModel):
    id: str
    title: str
    path: Path | None = None
    techniques: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    rule: Rule
    severity: Severity
    reason: str


class Report(BaseModel):
    findings: list[Finding] = Field(default_factory=list)

    def has_severity(self, level: Severity) -> bool:
        return any(f.severity == level for f in self.findings)
