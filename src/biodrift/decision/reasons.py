"""Decision reason codes."""

from __future__ import annotations

from pydantic import BaseModel


class ReasonCode(BaseModel):
    code: str
    description: str
    severity: str = "info"


REASON_CODES: dict[str, ReasonCode] = {
    "INSUFFICIENT_COVERAGE": ReasonCode(
        code="INSUFFICIENT_COVERAGE",
        description="Security-relevance coverage below configured threshold",
        severity="warning",
    ),
    "LOW_ATTRIBUTION_CONFIDENCE": ReasonCode(
        code="LOW_ATTRIBUTION_CONFIDENCE",
        description="Attribution confidence below minimum threshold",
        severity="warning",
    ),
    "CONFLICTING_OBSERVERS": ReasonCode(
        code="CONFLICTING_OBSERVERS",
        description="Multiple observers report conflicting evidence",
        severity="warning",
    ),
    "CAPABILITY_VIOLATION": ReasonCode(
        code="CAPABILITY_VIOLATION",
        description="Observed capability violates contract rule",
        severity="error",
    ),
    "RESOURCE_VIOLATION": ReasonCode(
        code="RESOURCE_VIOLATION",
        description="Observed resource access violates contract rule",
        severity="error",
    ),
    "DESTINATION_VIOLATION": ReasonCode(
        code="DESTINATION_VIOLATION",
        description="Observed network destination violates contract rule",
        severity="error",
    ),
}


def get_reason(code: str) -> ReasonCode:
    return REASON_CODES.get(code, ReasonCode(code=code, description="Unknown reason"))
