"""Subprocess/process lineage observer."""

from __future__ import annotations

from typing import Any

from biodrift.models import Capability, Event, Phase
from biodrift.observers.base import Observer


class ProcessObserver(Observer):
    name = "process"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._events: list[Event] = []
        self._run_id: str = ""
        self._package_id: str = ""

    def start(self, run_id: str, package_id: str) -> None:
        self._run_id = run_id
        self._package_id = package_id
        self._events.clear()

    def stop(self) -> None:
        pass

    def get_events(self) -> list[Event]:
        return list(self._events)

    def record_spawn(
        self,
        pid: int,
        ppid: int,
        cmdline: str = "",
        exe: str = "",
        package_id: str = "",
    ) -> Event:
        """Record a subprocess spawn event (called externally by the workload engine)."""
        event = Event(
            run_id=self._run_id,
            package_id=package_id or self._package_id,
            component_id="process",
            phase=Phase.EXECUTION,
            capability=Capability.PROCESS_SPAWN,
            action="spawn",
            resource=exe or cmdline,
            process_id=pid,
            parent_process_id=ppid,
            observer=self.name,
            context={"cmdline": cmdline, "exe": exe},
        )
        self._events.append(event)
        return event
