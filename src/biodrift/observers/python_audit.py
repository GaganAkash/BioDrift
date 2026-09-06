"""Python sys.audit hook observer."""

from __future__ import annotations

import sys
from typing import Any

from biodrift.models import Capability, Event, Phase
from biodrift.observers.base import Observer

_AUDIT_EVENT_MAP: dict[str, tuple[Phase, Capability, str]] = {
    "open": (Phase.EXECUTION, Capability.FILE_READ, "open"),
    "io:open": (Phase.EXECUTION, Capability.FILE_READ, "io.open"),
    "io:close": (Phase.EXECUTION, Capability.FILE_READ, "io.close"),
    "subprocess.Popen": (Phase.EXECUTION, Capability.PROCESS_SPAWN, "popen"),
    "subprocess.Popen:exec": (Phase.EXECUTION, Capability.PROCESS_EXEC, "exec"),
    "os.system": (Phase.EXECUTION, Capability.SUBPROCESS_SHELL, "system"),
    "socket.connect": (Phase.EXECUTION, Capability.NETWORK_CONNECT, "connect"),
    "socket.bind": (Phase.EXECUTION, Capability.NETWORK_LISTEN, "bind"),
    "import": (Phase.IMPORT, Capability.MODULE_LOAD, "import"),
    "builtins.__import__": (Phase.IMPORT, Capability.MODULE_LOAD, "__import__"),
    "compile": (Phase.EXECUTION, Capability.CODE_EXEC, "compile"),
    "exec": (Phase.EXECUTION, Capability.CODE_EXEC, "exec"),
    "eval": (Phase.EXECUTION, Capability.CODE_EXEC, "eval"),
}


class PythonAuditObserver(Observer):
    name = "python_audit"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._events: list[Event] = []
        self._run_id: str = ""
        self._package_id: str = ""
        self._active = False
        self._hook_installed = False

    def _hook(self, event: str, args: tuple[Any, ...]) -> None:
        if not self._active:
            return

        mapped = _AUDIT_EVENT_MAP.get(event)
        if not mapped:
            return

        phase, capability, action = mapped
        resource = ""
        destination = ""
        context: dict[str, Any] = {"raw_event": event}

        if event in ("open", "io:open") and args:
            resource = str(args[0]) if args else ""
        elif event in ("socket.connect", "socket.bind") and args:
            destination = str(args[0]) if args else ""
        else:
            if args:
                resource = str(args[0])

        self._events.append(
            Event(
                run_id=self._run_id,
                package_id=self._package_id,
                component_id="python",
                phase=phase,
                capability=capability,
                action=action,
                resource=resource,
                destination=destination,
                observer=self.name,
                context=context,
            )
        )

    def start(self, run_id: str, package_id: str) -> None:
        self._run_id = run_id
        self._package_id = package_id
        self._events.clear()
        self._active = True
        if not self._hook_installed:
            sys.addaudithook(self._hook)
            self._hook_installed = True

    def stop(self) -> None:
        self._active = False

    def get_events(self) -> list[Event]:
        return list(self._events)
