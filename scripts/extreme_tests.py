"""Extreme tests: verify real packages and synthetic event storms end to end.

Runs real installed packages (pydantic, rich, click, certifi) as workloads,
plus a synthetic 150-module import chain, and checks verdicts against
per-case contracts. Writes a summary to results/extreme.json.

Usage:  python scripts/extreme_tests.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

SITE_PACKAGES = "/opt/anaconda3/lib/python3.13/site-packages"

_CONTRACT_TMPL = """\
package_id: "{pid}"
version_family: "1.x"
environment:
  os: "darwin"
  python_versions: ["3.13"]
  architecture: "*"
phase_rules: []
capability_rules:
  - capability: "module_load"
    allowed_resources: ["*"]
    allowed_destinations: []
    allowed_actions: ["import"]
    blocked: false
    severity: "low"
{file_read_rules}coverage_threshold: 1.0
provenance:
  source_url: "https://example.com/{pid}"
  source_hash: "sha256:local"
  created_by: "extreme-tests"
  verified_by: ["extreme-tests"]
  admitted_by: "extreme-tests"
admission_status: "admitted"
"""

_FILE_READ_TMPL = """  - capability: "file_read"
    allowed_resources: {allowed}
    allowed_destinations: []
    allowed_actions: []
    blocked: false
    severity: "medium"
"""

CASE_IMPORT = 'import {mod}\nprint("{mod} import ok")'


def write_contract(pid: str, file_read_allowed: list[str] | None = None) -> Path:
    path = Path(tempfile.mkdtemp(prefix="biodrift_extreme_cfg_")) / f"{pid}.yaml"
    reads = ""
    if file_read_allowed is not None:
        reads = _FILE_READ_TMPL.format(
            allowed=json.dumps([s for s in file_read_allowed])
        )
    path.write_text(
        _CONTRACT_TMPL.format(pid=pid, file_read_rules=reads)
    )
    return path


def make_storm_chain(count: int) -> Path:
    base = Path(tempfile.mkdtemp(prefix="biodrift_extreme_storm_"))
    for i in range(count - 1):
        (base / f"m{i:04d}.py").write_text(
            f"import m{i + 1:04d} as _next\nVALUE = {i}\n"
        )
    (base / f"m{count - 1:04d}.py").write_text(f"VALUE = {count - 1}\n")
    return base


def verify(package_path: Path, contract_path: Path | None,
           expected: str) -> dict:
    from biodrift.pipeline import run_verification

    start = time.monotonic()
    result = run_verification(
        package_path=package_path,
        contract_path=contract_path,
        output_dir=str(REPO / "results"),
        persist=True,
    )
    duration = time.monotonic() - start
    return {
        "events": result.events_count,
        "coverage": round(result.decision.coverage_ratio, 3),
        "verdict": result.decision.verdict.value,
        "duration_s": round(duration, 2),
        "pass": result.decision.verdict.value == expected,
    }


def run_all() -> list[dict]:
    os.environ["PYTHONPATH"] = SITE_PACKAGES
    results: list[dict] = []

    cases = [
        ("real-pydantic", "import-only, native extension load",
         CASE_IMPORT.format(mod="pydantic"), None, "COMPLIANT"),
        ("real-rich", "import-only, large pure-python tree",
         CASE_IMPORT.format(mod="rich"), None, "COMPLIANT"),
        ("real-click", "import-only",
         CASE_IMPORT.format(mod="click"), None, "COMPLIANT"),
        ("real-certifi-io", "real IO: reads CA bundle (allowed)",
         "import certifi\nprint(certifi.contents()[len(certifi.contents()):])",
         ["*certifi*"], "COMPLIANT"),
        ("real-certifi-strict", "real IO: reads CA bundle (not allowed)",
         "import certifi\nprint(certifi.contents()[len(certifi.contents()):])",
         ["/tmp/*"], "VIOLATION"),
    ]

    for name, note, scenario, file_reads, expected in cases:
        overlay = Path(tempfile.mkdtemp(prefix="biodrift_extreme_wl_"))
        (overlay / "scen.py").write_text(scenario)
        r = verify(overlay, write_contract(name.replace("-", "_"), file_reads),
                   expected)
        r.update(name=name, note=note, expected=expected)
        results.append(r)
        print(
            f"[{'PASS' if r['pass'] else 'FAIL'}] {r['name']:<22} "
            f"{r['verdict']:<12} events={r['events']:<5} "
            f"cov={r['coverage']:.0%}  {r['duration_s']}s  ({note})"
        )

    storm = make_storm_chain(150)
    r = verify(storm, write_contract("storm_chain"), "COMPLIANT")
    r.update(name="storm-150-chain", note="150-module import chain stress",
             expected="COMPLIANT")
    results.append(r)
    print(
        f"[{'PASS' if r['pass'] else 'FAIL'}] {r['name']:<22} "
        f"{r['verdict']:<12} events={r['events']:<5} "
        f"cov={r['coverage']:.0%}  (150-module import chain stress)"
    )

    return results


def main() -> None:
    results = run_all()
    out = REPO / "results"
    out.mkdir(exist_ok=True)
    (out / "extreme.json").write_text(json.dumps(results, indent=2))
    print(f"\n{sum(r['pass'] for r in results)}/{len(results)} passed → "
          f"results/extreme.json")


if __name__ == "__main__":
    main()