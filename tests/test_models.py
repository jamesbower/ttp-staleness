from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ttp_staleness.models import (
    AttackIndex,
    AttackTechnique,
    Finding,
    Report,
    Rule,
    Severity,
    SigmaRule,
)


def test_severity_literal_values() -> None:
    for v in ("low", "medium", "high", "critical"):
        s: Severity = v  # type: ignore[assignment]
        assert s == v


def test_empty_report_has_no_severity() -> None:
    r = Report(findings=[])
    assert r.has_severity("critical") is False
    assert r.has_severity("low") is False


def test_report_detects_matching_severity() -> None:
    rule = Rule(id="r1", title="t1", path="/x/r1.yml", techniques=[])
    f = Finding(rule=rule, severity="critical", reason="demo")
    r = Report(findings=[f])
    assert r.has_severity("critical") is True
    assert r.has_severity("high") is False


def test_attack_technique_full_shape() -> None:
    t = AttackTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        modified=datetime(2024, 10, 17, 15, 19, 6, tzinfo=UTC),
        is_subtechnique=True,
        deprecated=False,
        tactic_ids=["execution"],
        stix_id="attack-pattern--00000000-0000-0000-0000-000000001060",
    )
    assert t.technique_id == "T1059.001"
    assert t.is_subtechnique is True
    assert t.deprecated is False
    assert t.tactic_ids == ["execution"]
    assert t.modified.tzinfo is not None


def test_attack_technique_requires_core_fields() -> None:
    with pytest.raises(ValueError):
        AttackTechnique()  # type: ignore[call-arg]


def test_attack_index_shape() -> None:
    idx = AttackIndex(
        techniques={},
        fetched_at=datetime(2026, 4, 17, tzinfo=UTC),
    )
    assert idx.techniques == {}
    assert idx.source_domain == "enterprise-attack"
    assert idx.attack_version is None
    assert idx.fetched_at.tzinfo is not None


def test_rule_requires_id_and_title() -> None:
    with pytest.raises(ValueError):
        Rule()  # type: ignore[call-arg]


def test_sigma_rule_minimal_construction() -> None:
    from pathlib import Path

    r = SigmaRule(
        title="PowerShell Encoded Command",
        source_file=Path("/rules/ps.yml"),
    )
    assert r.title == "PowerShell Encoded Command"
    assert r.source_file == Path("/rules/ps.yml")
    assert r.rule_id is None
    assert r.status is None
    assert r.rule_date is None
    assert r.modified_date is None
    assert r.technique_ids == []
    assert r.raw_tags == []


def test_sigma_rule_full_construction() -> None:
    from datetime import date
    from pathlib import Path

    r = SigmaRule(
        rule_id="10598928-44a9-4730-b79f-69b62fe73666",
        title="PowerShell Encoded Command",
        status="test",
        rule_date=date(2024, 3, 15),
        modified_date=date(2024, 11, 1),
        technique_ids=["T1059.001"],
        source_file=Path("/rules/ps.yml"),
        raw_tags=["attack.execution", "attack.t1059.001"],
    )
    assert r.technique_ids == ["T1059.001"]
    assert r.rule_date is not None
    assert r.rule_date.year == 2024
    assert r.modified_date is not None
    assert r.modified_date.month == 11
    assert "attack.t1059.001" in r.raw_tags
