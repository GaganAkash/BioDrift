"""Event normalization: raw telemetry → canonical BioDrift events."""

from __future__ import annotations

from typing import Any

from biodrift.models import Event


def normalize_events(raw_events: list[dict[str, Any]], observer: str) -> list[Event]:
    """Convert raw observer output to canonical Event objects.

    ponytail: thin adapter, real normalization would apply
    observer-specific field mapping and deduplication.
    """
    events = []
    for raw in raw_events:
        events.append(
            Event(
                run_id=raw.get("run_id", ""),
                package_id=raw.get("package_id", ""),
                component_id=raw.get("component_id", observer),
                phase=raw.get("phase", "execution"),
                capability=raw.get("capability", "capability_raw"),
                action=raw.get("action", ""),
                resource=raw.get("resource", ""),
                destination=raw.get("destination", ""),
                dependency_lineage=raw.get("dependency_lineage", []),
                process_id=raw.get("process_id"),
                parent_process_id=raw.get("parent_process_id"),
                native_object=raw.get("native_object"),
                observer=observer,
                context=raw.get("context", {}),
            )
        )
    return events
