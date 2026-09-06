"""Verification closure planner (RX2 scaffold)."""

from __future__ import annotations

from pydantic import BaseModel


class ObservationCandidate(BaseModel):
    observer: str
    capability: str
    expected_information_gain: float = 0.0
    estimated_cost: float = 1.0
    priority: float = 0.0


def plan_next_observation(
    current_coverage: dict[str, float],
    cost_budget: float = 10.0,
    candidates: list[ObservationCandidate] | None = None,
) -> ObservationCandidate | None:
    """Choose next observation to maximize information gain per cost.

    ponytail: greedy gain/cost ratio. Replace with adaptive sequential
    testing when measurement shows diminishing returns.
    """
    if not candidates:
        return None

    for c in candidates:
        c.priority = c.expected_information_gain / max(c.estimated_cost, 0.01)

    candidates.sort(key=lambda c: c.priority, reverse=True)

    for c in candidates:
        if c.estimated_cost <= cost_budget:
            return c

    return None
