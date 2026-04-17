import json

import pytest

from ttp_staleness.models import Report
from ttp_staleness.reporter import render


def test_terminal_render_contains_header() -> None:
    out = render(Report(findings=[]), output_format="terminal", min_severity="low")
    assert "ttp-staleness" in out.lower()


def test_json_render_parses_as_json() -> None:
    out = render(Report(findings=[]), output_format="json", min_severity="low")
    parsed = json.loads(out)
    assert "findings" in parsed


def test_html_render_contains_html_tag() -> None:
    out = render(Report(findings=[]), output_format="html", min_severity="low")
    assert "<html" in out.lower()


def test_unknown_format_raises() -> None:
    with pytest.raises(ValueError):
        render(Report(findings=[]), output_format="xml", min_severity="low")
