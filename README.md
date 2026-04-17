# ttp-staleness

Score your Sigma/KQL/EQL detection rules for ATT&CK technique staleness.

## Install

```bash
pip install -e ".[dev]"
```

## Usage

```bash
ttp-staleness --help
ttp-staleness scan path/to/rules --format terminal
ttp-staleness scan path/to/rules --format json -o report.json
```

Env vars use the `TTP_` prefix: `TTP_CACHE_DIR`, `TTP_CACHE_TTL_HOURS`, `TTP_ATTACK_DOMAIN`, `TTP_NO_CACHE`.

## Development

```bash
pytest -q
ruff check src/ tests/
mypy src/
```

## License

MIT
