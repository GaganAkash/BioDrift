"""Contract integrity: reference-poisoning resistance (RX1 scaffold)."""

from __future__ import annotations

from biodrift.models.contracts import Contract


def quarantine_unexplained_changes(
    old_contract: Contract, new_contract: Contract
) -> list[str]:
    """Detect unexplained changes between contract versions.

    Returns list of changed fields that lack explicit admission evidence.
    ponytail: naive field diff, replace with semantic diff if false positives grow.
    """
    changes: list[str] = []
    old_data = old_contract.model_dump()
    new_data = new_contract.model_dump()

    for key in old_data:
        if old_data[key] != new_data.get(key) and key not in ("admission_status", "created_at"):
            changes.append(key)

    return changes


def require_admission_evidence(contract: Contract) -> bool:
    """Check that contract has admission evidence (provenance + admission_event).

    ponytail: stub that always passes when provenance exists. Real implementation
    would verify cryptographic signatures or human approval records.
    """
    return bool(contract.provenance.admission_event)
