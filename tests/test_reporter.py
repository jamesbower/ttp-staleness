from __future__ import annotations

import json

import pytest

from ttp_staleness.reporter import render


def test_json_render_parses_as_json(sample_report) -> None:
    out = render(sample_report, output_format="json", min_severity="low")
    parsed = json.loads(out)
    assert "summary" in parsed
    assert "scores" in parsed


def test_html_render_contains_html_tag(sample_report) -> None:
    out = render(sample_report, output_format="html", min_severity="low")
    assert "<html" in out.lower()


def test_unknown_format_raises(sample_report) -> None:
    with pytest.raises(ValueError):
        render(sample_report, output_format="xml", min_severity="low")


def test_filter_scores_drops_below_threshold(sample_report) -> None:
    from ttp_staleness.reporter import _filter_scores

    filtered = _filter_scores(sample_report, "high")
    severities = {s.worst_severity for s in filtered.scores}
    assert severities <= {"critical", "high"}
    # The original report is not mutated.
    assert len(sample_report.scores) == 5


def test_filter_scores_info_threshold_keeps_all(sample_report) -> None:
    from ttp_staleness.reporter import _filter_scores

    filtered = _filter_scores(sample_report, "info")
    assert len(filtered.scores) == len(sample_report.scores)


def test_filter_scores_raises_on_unknown_level(sample_report) -> None:
    import pytest

    from ttp_staleness.reporter import _filter_scores

    with pytest.raises(KeyError):
        _filter_scores(sample_report, "extreme")


def test_json_filters_by_min_severity(sample_report) -> None:
    output = render(sample_report, output_format="json", min_severity="high")
    data = json.loads(output)
    returned_severities = {s["worst_severity"] for s in data["scores"]}
    assert returned_severities <= {"critical", "high"}
    assert len(data["scores"]) == 2


def test_json_summary_unchanged_by_filter(sample_report) -> None:
    """The filter drops scores; summary counters stay authoritative."""
    output = render(sample_report, output_format="json", min_severity="critical")
    data = json.loads(output)
    # Summary reflects the ORIGINAL counts — not the filtered scores.
    assert data["summary"]["total_rules"] == 5
    assert data["summary"]["critical"] == 1


def test_terminal_render_contains_rule_titles(sample_report) -> None:
    out = render(sample_report, output_format="terminal", min_severity="low")
    assert "Critical Test Rule" in out
    assert "High Test Rule" in out
    assert "Medium Test Rule" in out


def test_terminal_render_contains_summary(sample_report) -> None:
    out = render(sample_report, output_format="terminal", min_severity="low")
    # Summary panel mentions the CRITICAL count and domain.
    assert "CRITICAL" in out
    assert "5" in out  # total_rules
    assert "enterprise-attack" in out


def test_terminal_render_has_no_rich_markup_leaks(sample_report) -> None:
    out = render(sample_report, output_format="terminal", min_severity="low")
    # Style markers must not appear as literal text.
    assert "[critical]" not in out
    assert "[/critical]" not in out
    assert "[high]" not in out


def test_terminal_filters_by_min_severity(sample_report) -> None:
    out = render(sample_report, output_format="terminal", min_severity="high")
    assert "Critical Test Rule" in out
    assert "High Test Rule" in out
    # Below-threshold rules must not appear in the table.
    assert "Medium Test Rule" not in out
    assert "Low Test Rule" not in out
