"""eBPF kernel observer (Linux only, interface scaffold).

ponytail: interface stub. Real implementation requires a Linux kernel with
BPF support; kept as a no-op scaffold so the observer registry is stable.
Add kprobe/uprobe syscall capture when validated on a Linux CI.
"""

from __future__ import annotations

from biodrift.models import Event
from biodrift.observers.base import Observer


class EbpfObserver(Observer):
    name = "ebpf"

    def start(self, run_id: str, package_id: str) -> None:
        pass

    def stop(self) -> None:
        pass

    def get_events(self) -> list[Event]:
        return []
