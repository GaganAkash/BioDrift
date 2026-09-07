"""Progressive stress test: scale dataset size and watch behavior degrade.

Scales two independent axes and records pass rate, wall time, and peak
memory at each step:

  N_events  : number of behavioural events in a single workload
  N_caps    : number of governed capabilities per contract

At each (N_caps, N_events) step we run a clean (COMPLIANT) workload and a
poisoned (VIOLATION) workload through the decision engine and assert the
verdict is unchanged as the dataset grows — i.e. correctness must survive
scaling, not just complete. Also reports timing and RSS so a hidden
O(n^2) or leak becomes visible.

Because the engine is linear in events, the expectation is flat correctness
and linear time; the point of the test is to *prove* that and catch any
regression (e.g. an accidentally-quadratic allowlist, or a coverage count
that degrades with size).

Usage:  python scripts/progressive_stress.py
"""

from __future__ import annotations

import json
import resource
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from biodrift.decision.engine import decide  # noqa: E402
from biodrift.models import Capability, Event, Phase, _uuid  # noqa: E402

_CAPS = [c for c in Capability]


def _event(cap: Capability, i: int) -> Event:
    return Event(
        run_id=_uuid(),
        package_id="stress-pkg",
        component_id="stress",
        phase=Phase.EXECUTION,
        capability=cap,
        action="op",
        resource=f"/allowed/res-{cap.value}-{i % 7}.txt",
        observer="python_audit",
    )


def _rules(n_caps: int) -> dict:
    """Contract allowing the first n capabilities on the '*allowed*' path."""
    return {
        "capability_rules": [
            {
                "capability": cap.value,
                "allowed_resources": ["/allowed/*"],
                "allowed_destinations": [],
                "allowed_actions": [],
                "blocked": False,
            }
            for cap in _CAPS[:n_caps]
        ]
    }


def peak_rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def _build_pool(n_caps: int, n_events: int) -> list[Event]:
    """Build an event pool for a contract, reusing engine-level scaling.

    Event construction (pydantic + UUID) is the dominant cost at this scale,
    so build each pool once and slice it per event-count step. The decision
    engine itself is what the stress test measures.
    """
    return [_event(_CAPS[i % n_caps], i) for i in range(n_events)]


def run_step(n_caps: int, n_events: int, pool: list[Event]) -> dict:
    rules = _rules(n_caps)
    events = pool[:n_events]
    before = peak_rss_mb()
    start = time.monotonic()

    clean = decide(events, rules, coverage_ratio=1.0, attribution_confidence=0.9)
    clean_t = time.monotonic() - start

    poisoned = list(events)
    poisoned.append(
        Event(
            run_id=_uuid(), package_id="x", component_id="x",
            phase=Phase.EXECUTION,
            capability=_CAPS[0], action="op", resource="/etc/shadow",
            observer="python_audit",
        )
    )
    start = time.monotonic()
    bad = decide(poisoned, rules, coverage_ratio=1.0, attribution_confidence=0.9)
    bad_t = time.monotonic() - start

    return {
        "n_caps": n_caps,
        "n_events": n_events,
        "clean_ok": clean.verdict.value == "COMPLIANT",
        "poison_ok": bad.verdict.value == "VIOLATION",
        "clean_s": round(clean_t, 4),
        "poison_s": round(bad_t, 4),
        "rss_mb": round(peak_rss_mb() - before, 1),
    }


def main() -> None:
    cap_steps = [1, 4, 9, len(_CAPS)]
    event_steps = [1_000, 10_000, 100_000, 500_000]

    results: list[dict] = []
    print(f"{'caps':>4} {'events':>9} {'clean':>5} {'poison':>7} "
          f"{'t_clean':>8} {'t_poison':>8} {'dRSS':>7}")
    for n_caps in cap_steps:
        pool = _build_pool(n_caps, max(event_steps))
        for n_events in event_steps:
            r = run_step(n_caps, n_events, pool)
            results.append(r)
            ok = (r["clean_ok"] and r["poison_ok"])
            print(f"{r['n_caps']:>4} {r['n_events']:>9} "
                  f"{'OK' if r['clean_ok'] else 'BAD':>5} "
                  f"{'OK' if r['poison_ok'] else 'BAD':>7} "
                  f"{r['clean_s']:>8} {r['poison_s']:>8} {r['rss_mb']:>7} "
                  f"{'   <-- FAIL' if not ok else ''}")

    out = REPO / "results"
    out.mkdir(exist_ok=True)
    (out / "progressive_stress.json").write_text(json.dumps(results, indent=2))
    fails = [r for r in results if not (r["clean_ok"] and r["poison_ok"])]
    print(f"\n{len(results) - len(fails)}/{len(results)} steps held verdicts "
          f"under stress")
    if fails:
        print("FAILURES:")
        for f in fails:
            print(f"  caps={f['n_caps']} events={f['n_events']} "
                  f"clean={f['clean_ok']} poison={f['poison_ok']}")


if __name__ == "__main__":
    main()
