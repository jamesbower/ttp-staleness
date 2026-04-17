from __future__ import annotations

import click


@click.group()
@click.version_option(package_name="ttp-staleness")
def main() -> None:
    """Score your detection rules for ATT&CK technique staleness."""


if __name__ == "__main__":
    main()
