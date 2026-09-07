# BioDrift

Contextual behavioral verification for Python packages under incomplete observation.

## Quick Start

```bash
pip install -e ".[dev]"
biodrift --help
biodrift init
pytest
```

## Verification suites

- `pytest` — unit + integration tests
- `python scripts/bug_hunt.py` — adversarial scenarios scoreboard
- `python scripts/extreme_tests.py` — extreme-behaviour edge cases
- `python scripts/calibrate_100.py` — 100-scenario calibration hunt

See [docs/calibration-findings.md](docs/calibration-findings.md) for what
the calibration hunt surfaced: three real product bugs it fixed and the
reasoning behind the coverage threshold.
