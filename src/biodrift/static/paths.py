"""Security path discovery from static analysis."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SecurityPathEntry:
    file: str
    line: int
    capability: str
    function: str
    criticality: str = "medium"


def discover_security_paths(
    capabilities: list[dict],
) -> list[SecurityPathEntry]:
    """Convert raw capability analysis results to SecurityPathEntry objects."""
    paths: list[SecurityPathEntry] = []
    high_risk = ("file_write", "network_connect", "process_spawn")
    for cap in capabilities:
        criticality = "high" if cap.get("capability") in high_risk else "medium"
        paths.append(
            SecurityPathEntry(
                file=cap.get("file", ""),
                line=cap.get("line", 0),
                capability=cap.get("capability", ""),
                function=cap.get("function", ""),
                criticality=criticality,
            )
        )
    return paths
