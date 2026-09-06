"""Contract manager: load, validate, and record provenance of behavioral contracts."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from biodrift.models import AdmissionStatus, _uuid
from biodrift.models.contracts import Contract


def load_contract(path: Path | str) -> Contract:
    """Load a contract from a YAML or JSON file."""
    path = Path(path)
    with open(path) as f:
        data = yaml.safe_load(f) if path.suffix in (".yaml", ".yml") else json.load(f)

    if "provenance" not in data:
        data["provenance"] = {}
    data["provenance"]["admission_event"] = str(_uuid())

    return Contract(**data)


def save_contract(contract: Contract, path: Path | str) -> None:
    """Save a contract to a YAML file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = contract.model_dump(mode="json")
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False)


def admit_contract(contract: Contract, admitted_by: str = "system") -> Contract:
    """Mark a contract as admitted with provenance."""
    contract.admission_status = AdmissionStatus.ADMIITTED
    contract.provenance.admitted_by = admitted_by
    contract.provenance.admission_event = str(_uuid())
    return contract


def quarantine_contract(contract: Contract, reason: str = "") -> Contract:
    """Mark a contract as quarantined (potential poisoning)."""
    contract.admission_status = AdmissionStatus.QUARANTINED
    return contract
