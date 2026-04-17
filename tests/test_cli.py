from __future__ import annotations

from click.testing import CliRunner

from ttp_staleness import __version__
from ttp_staleness.cli import main


def test_main_help_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Score your detection rules" in result.output


def test_main_version_prints_package_version() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output
