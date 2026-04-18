from datetime import UTC, datetime

from ttp_staleness.models import AttackIndex, Report
from ttp_staleness.scorer import score_rules


def test_empty_inputs_yield_empty_report() -> None:
    index = AttackIndex(fetched_at=datetime(2026, 1, 1, tzinfo=UTC))
    report = score_rules(rules=[], index=index)
    assert isinstance(report, Report)
    assert report.findings == []
    assert report.has_severity("critical") is False
