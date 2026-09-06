"""ptrace-based native observer (Linux only)."""

from __future__ import annotations

import platform
from typing import Any

from biodrift.models import Event
from biodrift.observers.base import Observer

_LINUX = platform.system() == "Linux"


class PtraceObserver(Observer):
    name = "ptrace"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._events: list[Event] = []

    def start(self, run_id: str, package_id: str) -> None:
        if not _LINUX:
            return  # platform-gated: non-Linux is a silent no-op
        # ponytail: ptrace capture is Linux-only and untested on this host.
        # Add syscall interception via tracerpid when validated on a Linux CI.
        pass

    def stop(self) -> None:
        pass

    def get_events(self) -> list[Event]:
        return list(self._events)
