"""Responsibility attribution: estimate which component is responsible for events."""

from __future__ import annotations

from biodrift.models import Event


def attribute_event(
    event: Event,
    package_components: list[str],
    known_lineage: dict[str, list[str]] | None = None,
) -> tuple[str, float]:
    """Attribute an event to a specific component with confidence score.

    Returns (component_id, confidence).

    ponytail: deterministic attribution based on module path prefix matching.
    Real implementation would use call-chain analysis and native object mapping.
    """
    if not package_components:
        return event.component_id, 0.3

    resource = event.resource.lower()
    for component in package_components:
        if component.lower() in resource:
            return component, 0.9

    if event.process_id and event.parent_process_id:
        return "subprocess", 0.5

    return event.component_id, 0.7
