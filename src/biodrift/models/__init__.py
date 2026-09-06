"""Core data models for BioDrift events, contracts, and findings."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --- Enums ---


class Phase(str, enum.Enum):
    INTAKE = "intake"
    STATIC = "static"
    IMPORT = "import"
    EXECUTION = "execution"
    CLEANUP = "cleanup"


class Capability(str, enum.Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    NETWORK_CONNECT = "network_connect"
    NETWORK_LISTEN = "network_listen"
    PROCESS_SPAWN = "process_spawn"
    PROCESS_EXEC = "process_exec"
    MODULE_LOAD = "module_load"
    ENV_ACCESS = "env_access"
    SUBPROCESS_SHELL = "subprocess_shell"
    CODE_EXEC = "code_exec"
    SETUID = "setuid"
    CAPABILITY_RAW = "capability_raw"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(str, enum.Enum):
    COMPLIANT = "COMPLIANT"
    VIOLATION = "VIOLATION"
    INCONCLUSIVE = "INCONCLUSIVE"


class AdmissionStatus(str, enum.Enum):
    PENDING = "pending"
    ADMIITTED = "admitted"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"


# --- Canonical Event ---


class Event(BaseModel):
    run_id: str = Field(default_factory=_uuid)
    package_id: str
    component_id: str
    phase: Phase
    capability: Capability
    action: str
    resource: str = ""
    destination: str = ""
    dependency_lineage: list[str] = Field(default_factory=list)
    process_id: int | None = None
    parent_process_id: int | None = None
    native_object: str | None = None
    timestamp: datetime = Field(default_factory=_utcnow)
    observer: str
    evidence_id: str = Field(default_factory=_uuid)
    context: dict[str, Any] = Field(default_factory=dict)


# --- Finding ---


class Finding(BaseModel):
    finding_id: str = Field(default_factory=_uuid)
    run_id: str
    event_id: str
    package_id: str
    component_id: str
    capability: Capability
    verdict: Verdict
    reason: str = ""
    evidence: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    attribution_confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    timestamp: datetime = Field(default_factory=_utcnow)


# --- Run Metadata ---


class RunMeta(BaseModel):
    run_id: str = Field(default_factory=_uuid)
    package_id: str
    package_digest: str
    candidate_version: str
    environment: dict[str, Any] = Field(default_factory=dict)
    observer_config: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_utcnow)
    completed: bool = False
    final_verdict: Verdict | None = None
