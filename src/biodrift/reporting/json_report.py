"""JSON report generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from biodrift.models import Finding, RunMeta, Verdict


def generate_json_report(
    run_meta: RunMeta,
    findings: list[Finding],
    events_count: int,
    coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a structured JSON report for a verification run."""
    verdict_counts = {v.value: 0 for v in Verdict}
    for f in findings:
        verdict_counts[f.verdict.value] += 1

    return {
        "run_id": run_meta.run_id,
        "package_id": run_meta.package_id,
        "package_digest": run_meta.package_digest,
        "candidate_version": run_meta.candidate_version,
        "timestamp": run_meta.timestamp.isoformat(),
        "final_verdict": run_meta.final_verdict.value if run_meta.final_verdict else None,
        "summary": {
            "total_events": events_count,
            "total_findings": len(findings),
            "verdict_counts": verdict_counts,
        },
        "coverage": coverage or {},
        "findings": [f.model_dump(mode="json") for f in findings],
    }


def save_report(report: dict[str, Any], path: Path | str) -> Path:
    """Save report to a JSON file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return path
