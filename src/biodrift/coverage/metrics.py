"""Coverage metrics computation."""

from __future__ import annotations

from pydantic import BaseModel

from biodrift.coverage.security_paths import SecurityPath


class CoverageMetrics(BaseModel):
    total_paths: int = 0
    covered_paths: int = 0
    coverage_ratio: float = 0.0
    weighted_coverage: float = 0.0
    critical_uncovered: int = 0


def compute_coverage(paths: list[SecurityPath]) -> CoverageMetrics:
    """Compute security-relevance coverage metrics."""
    if not paths:
        return CoverageMetrics()

    total = len(paths)
    covered = sum(1 for p in paths if p.covered)
    total_weight = sum(p.weight for p in paths)
    covered_weight = sum(p.weight for p in paths if p.covered)
    critical_uncovered = sum(
        1 for p in paths if not p.covered and p.criticality == "critical"
    )

    return CoverageMetrics(
        total_paths=total,
        covered_paths=covered,
        coverage_ratio=covered / total if total else 0.0,
        weighted_coverage=covered_weight / total_weight if total_weight else 0.0,
        critical_uncovered=critical_uncovered,
    )
