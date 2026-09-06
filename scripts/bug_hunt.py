"""Reward-system bug hunt: adversarial scenarios scored against expected verdicts.

Each scenario is a tiny package contract-correctly expected to yield a specific
verdict. A mismatch is a BUG (reward lost); a match is a HIT. Writes
results/scoreboard.json.

Recommended contract usage:
  _BENIGN  governs file_read + file_write + module_load (all /tmp/*)
  _STRICT  governs file_read + module_load only (file_read: /tmp/* only)
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from biodrift.models import Verdict  # noqa: E402
from biodrift.pipeline import run_verification  # noqa: E402

_BENIGN = Path("config/contracts/fixture-benign.yaml")       # file_read/write+module_load /tmp/*
# strict contract: file_read+module_load, file_read:/tmp/* only
_STRICT = Path("config/contracts/fixture-home-reader.yaml")


def _pkg(src: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="biodrift_hunt_"))
    (root / "src").mkdir()
    (root / "pyproject.toml").write_text(
        '[build-system]\nrequires=["setuptools>=61"]\n'
        'build-backend="setuptools.build_meta"\n'
        '[project]\nname = "hunt"\nversion = "1.0.0"\n'
    )
    for name, code in src.items():
        (root / "src" / name).write_text(code)
    return root


SCENARIOS = [
    # id, builder-result, Contract, expected
    # --- benign contract: all three governed caps under /tmp/* ---
    ("write-and-read-tmp", _pkg({"main.py":
        'open("/tmp/a.txt","w").write("x")\nopen("/tmp/a.txt","r").read()\n'}),
     _BENIGN, Verdict.COMPLIANT),
    ("write-wrong-dir", _pkg({"main.py":
        'open("/etc/evil","w").write("x")\n'}),
     _BENIGN, Verdict.VIOLATION),
    # --- strict contract: file_read+module_load; write is UNGOVERNED (not a violation) ---
    ("read-tmp-covered", _pkg({"main.py":
        'open("/tmp/ok.txt","w")\nopen("/tmp/ok.txt","r").read()\n'}),
     _STRICT, Verdict.COMPLIANT),
    ("read-etc-violation", _pkg({"main.py":
        'open("/etc/passwd","r").read()\n'}),
     _STRICT, Verdict.VIOLATION),
    ("read-etc-module-phase", _pkg({"main.py":
        '# import phase\nopen("/etc/passwd","r").read()\n'}),
     _STRICT, Verdict.VIOLATION),
    # --- crash must not be stamped COMPLIANT/VIOLATION ---
    ("boom-main", _pkg({"main.py": "raise RuntimeError('boom')\n"}),
     _STRICT, Verdict.INCONCLUSIVE),
    # --- hidden module not the entry must still be caught ---
    ("hidden-module", _pkg({
        "aaa_pure.py": "pass\n",
        "zzz_cap.py": 'open("/etc/passwd","r").read()\n',
    }), _STRICT, Verdict.VIOLATION),
    # --- init-only package side effect ---
    ("init-only", _pkg({"__init__.py":
        'open("/etc/passwd","r").read()\n'}),
     _STRICT, Verdict.VIOLATION),
    # --- double action, one is a violation ---
    ("mixed-write-read", _pkg({"main.py":
        'open("/tmp/a.txt","w")\nopen("/etc/passwd","r").read()\n'}),
     _STRICT, Verdict.VIOLATION),
    # --- allowed write under strict? file_write ungoverned -> not a violation,
    #     but insufficient governed-capability coverage -> INCONCLUSIVE (RQ2) ---
    ("write-tmp-ungoverned-lowcov", _pkg({"main.py":
        'open("/tmp/a.txt","w").write("x")\n'}),
     _STRICT, Verdict.INCONCLUSIVE),
]


def run(sc) -> dict:
    pid, root, contract, expected = sc[0], sc[1], sc[2], sc[3]
    t0 = time.monotonic()
    try:
        r = run_verification(package_path=root, contract_path=contract,
                             output_dir=str(REPO / "results"), persist=False)
        verdict, events, cov, reason = (r.decision.verdict, r.events_count,
                                        r.decision.coverage_ratio, r.decision.reason)
    except Exception as e:
        verdict, events, cov, reason = (None, 0, 0.0,
                                        f"EXCEPTION: {type(e).__name__}: {e}")
    ok = verdict == expected
    return {
        "id": pid, "expected": expected.value if expected else None,
        "got": verdict.value if verdict else "ERROR", "events": events,
        "coverage": round(cov, 2), "reason": reason,
        "duration_s": round(time.monotonic() - t0, 2), "pass": ok,
    }


def main() -> None:
    results = [run(s) for s in SCENARIOS]
    hits = sum(r["pass"] for r in results)
    bugs = [r for r in results if not r["pass"]]

    print("=== REWARD-SYSTEM BUG HUNT ===")
    print(f"Scenarios: {len(results)}   Hits: {hits}   Bugs: {len(bugs)}\n")
    for r in results:
        mark = "HIT " if r["pass"] else "BUG "
        print(f"[{mark}] {r['id']:<26} expected={r['expected']:<12} "
              f"got={r['got']:<12} ev={r['events']}")
        if not r["pass"]:
            print(f"        reason: {r['reason'][:140]}")

    (REPO / "results").mkdir(exist_ok=True)
    (REPO / "results" / "scoreboard.json").write_text(
        json.dumps(results, indent=2))
    print(f"\nScore: {hits}/{len(results)}   → results/scoreboard.json")


if __name__ == "__main__":
    main()