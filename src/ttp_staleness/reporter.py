from __future__ import annotations

from .models import Report, Severity


def render(report: Report, output_format: str, min_severity: Severity) -> str:
    """Render a Report to the requested format.

    Stub: real implementation will filter by min_severity, colourize terminal
    output, and use Jinja for HTML. For now returns minimal valid output so
    the CLI end-to-end path works.
    """
    _ = min_severity
    if output_format == "terminal":
        return f"ttp-staleness scorecard\n{len(report.findings)} findings\n"
    if output_format == "json":
        return report.model_dump_json(indent=2)
    if output_format == "html":
        return (
            "<!doctype html><html><head><title>ttp-staleness</title></head>"
            f"<body><p>{len(report.findings)} findings</p></body></html>"
        )
    raise ValueError(f"unknown output_format: {output_format!r}")
