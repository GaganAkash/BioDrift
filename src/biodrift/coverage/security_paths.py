"""Security-relevance coverage assessment."""

from __future__ import annotations

from pydantic import BaseModel, Field

from biodrift.models import Capability, Event


class SecurityPath(BaseModel):
    path_id: str
    description: str
    capability: Capability
    weight: float = 1.0
    criticality: str = "medium"
    covered: bool = False
    events: list[str] = Field(default_factory=list)


def enumerate_security_paths(events: list[Event], config: dict | None = None) -> list[SecurityPath]:
    """Enumerate security-relevant paths from observed events.

    ponytail: one path per unique capability+resource pair. Real implementation
    would use static analysis to pre-define expected security paths.
    """
    seen: dict[str, SecurityPath] = {}
    default_weights = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
    weights = (config or {}).get("weights", default_weights)

    for event in events:
        key = f"{event.capability.value}:{event.resource}"
        if key not in seen:
            seen[key] = SecurityPath(
                path_id=key,
                description=f"{event.capability.value} on {event.resource}",
                capability=event.capability,
                weight=weights.get("medium", 0.5),
            )
        seen[key].covered = True
        seen[key].events.append(event.evidence_id)

    return list(seen.values())
