"""Contract evolution tracking."""

from __future__ import annotations

from biodrift.models.contracts import Contract

_METADATA_FIELDS = {"contract_id", "created_at", "provenance"}


def detect_drift(
    baseline: Contract, current: Contract, threshold: float = 0.1
) -> dict[str, bool]:
    """Compare two contract versions and flag significant drift.

    Metadata fields (contract_id, created_at, provenance admission events)
    are excluded — they are regenerated on every load and are not semantic.

    ponytail: simple field-level comparison. Replace with capability-level
    semantic diff when false positives accumulate.
    """
    baseline_data = baseline.model_dump()
    current_data = current.model_dump()

    drifted: dict[str, bool] = {}
    for key, value in baseline_data.items():
        if key in _METADATA_FIELDS:
            continue
        if value != current_data.get(key):
            drifted[key] = True

    return drifted
