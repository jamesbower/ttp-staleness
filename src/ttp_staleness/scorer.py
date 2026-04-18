from __future__ import annotations

import logging
from datetime import UTC, date, datetime

from .models import (
    AttackIndex,
    Report,
    RuleScore,
    SeverityLevel,
    SigmaRule,
    TechniqueFinding,
)

log = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[SeverityLevel, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _severity(days_stale: int) -> SeverityLevel:
    if days_stale >= 365:
        return "critical"
    if days_stale >= 180:
        return "high"
    if days_stale >= 90:
        return "medium"
    return "low"


def _score_technique(
    technique_id: str,
    rule_effective_date: date | None,
    index: AttackIndex,
) -> TechniqueFinding:
    # Use UTC date to match technique modified timestamps (stored in UTC).
    today = datetime.now(UTC).date()
    tech = index.techniques.get(technique_id)

    if tech is None:
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=None,
            technique_modified=None,
            rule_effective_date=rule_effective_date,
            days_stale=0,
            severity="info",
            kind="unknown_technique",
        )

    if tech.deprecated:
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=tech.name,
            technique_modified=tech.modified,
            rule_effective_date=rule_effective_date,
            days_stale=0,
            severity="high",
            kind="deprecated_technique",
        )

    technique_date = tech.modified.date()

    if rule_effective_date is None:
        days_stale = (today - technique_date).days
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=tech.name,
            technique_modified=tech.modified,
            rule_effective_date=None,
            days_stale=days_stale,
            severity=_severity(days_stale),
            kind="no_rule_date",
        )

    if rule_effective_date >= technique_date:
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=tech.name,
            technique_modified=tech.modified,
            rule_effective_date=rule_effective_date,
            days_stale=0,
            severity="low",
            kind="current",
        )

    # Rule predates the technique's last modification: stale.
    # Staleness = how long ago the rule was last effective (days since rule date).
    days_stale = (today - rule_effective_date).days
    return TechniqueFinding(
        technique_id=technique_id,
        technique_name=tech.name,
        technique_modified=tech.modified,
        rule_effective_date=rule_effective_date,
        days_stale=days_stale,
        severity=_severity(days_stale),
        kind="stale",
    )


def _worst_severity(findings: list[TechniqueFinding]) -> SeverityLevel:
    if not findings:
        return "info"
    return max(findings, key=lambda f: _SEVERITY_ORDER[f.severity]).severity


def score_rule(rule: SigmaRule, index: AttackIndex) -> RuleScore:
    effective_date = rule.modified_date or rule.rule_date

    if not rule.technique_ids:
        return RuleScore(
            rule_id=rule.rule_id,
            title=rule.title,
            source_file=rule.source_file,
            status=rule.status,
            findings=[],
            worst_severity="info",
            worst_days_stale=0,
            has_attack_tags=False,
        )

    findings = [
        _score_technique(tid, effective_date, index) for tid in rule.technique_ids
    ]
    worst = _worst_severity(findings)
    worst_days = max(f.days_stale for f in findings)

    return RuleScore(
        rule_id=rule.rule_id,
        title=rule.title,
        source_file=rule.source_file,
        status=rule.status,
        findings=findings,
        worst_severity=worst,
        worst_days_stale=worst_days,
        has_attack_tags=True,
    )


# score_rules remains the stub — Task 3 replaces it.
def score_rules(rules: list[SigmaRule], index: AttackIndex) -> Report:
    """Score rules against an ATT&CK index.

    Stub: the full implementation lands in Task 3. Kept as-is for this task so
    the CLI/reporter contract stays intact.
    """
    _ = (rules, index)
    return Report(findings=[])
