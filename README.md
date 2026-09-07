# BioDrift

Contextual behavioral verification for Python packages under incomplete observation.

## Web app (Vetting Console)

A single-page dashboard over the real engine. Runs packages in an isolated
subprocess under OS-level `sys.audit` hooks and lets you drive verification
from a browser — browse/edit contracts, run verifications, and view
stress/calibration results.

```bash
make web          # installs deps, starts uvicorn
# open http://127.0.0.1:8000
```

Tabs: **Verify** (pick a fixture package + contract → verdict, coverage,
findings, live event feed), **Contracts** (CRUD), **Runs** (history from
`biodrift.db`), **Stress** (progressive-stress + calibration dashboards).

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
