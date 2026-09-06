"""Behavioral contract models for trusted reference specifications."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from biodrift.models import AdmissionStatus, Capability, Phase, _utcnow, _uuid


class CapabilityRule(BaseModel):
    capability: Capability
    allowed_resources: list[str] = Field(default_factory=list)
    allowed_destinations: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    blocked: bool = False
    severity: str = "medium"


class PhaseRule(BaseModel):
    phase: Phase
    allowed_capabilities: list[Capability] = Field(default_factory=list)
    capability_rules: list[CapabilityRule] = Field(default_factory=list)
    coverage_required: bool = True


class Environment(BaseModel):
    os: str = "linux"
    python_versions: list[str] = Field(default_factory=lambda: ["3.10", "3.11", "3.12"])
    architecture: str = "x86_64"
    constraints: dict[str, Any] = Field(default_factory=dict)


class Provenance(BaseModel):
    source_url: str = ""
    source_hash: str = ""
    created_by: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    admitted_by: str = ""
    verified_by: list[str] = Field(default_factory=list)
    admission_event: str | None = None


class Contract(BaseModel):
    contract_id: str = Field(default_factory=_uuid)
    package_id: str
    version_family: str
    environment: Environment = Field(default_factory=Environment)
    phase_rules: list[PhaseRule] = Field(default_factory=list)
    capability_rules: list[CapabilityRule] = Field(default_factory=list)
    resource_rules: list[str] = Field(default_factory=list)
    destination_rules: list[str] = Field(default_factory=list)
    attribution_requirements: dict[str, Any] = Field(default_factory=dict)
    coverage_threshold: float = Field(ge=0.0, le=1.0, default=0.8)
    provenance: Provenance = Field(default_factory=Provenance)
    admission_status: AdmissionStatus = Field(default=AdmissionStatus.PENDING)
    created_at: datetime = Field(default_factory=_utcnow)
