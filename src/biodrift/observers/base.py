"""Observer base class and plugin interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from biodrift.models import Event


class Observer(ABC):
    """Base class for all BioDrift observers.

    Each observer captures events from a specific layer
    (Python audit, process, ptrace, eBPF) and normalizes
    them into canonical Event objects.
    """

    name: str = "base"

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @abstractmethod
    def start(self, run_id: str, package_id: str) -> None:
        """Begin observing."""

    @abstractmethod
    def stop(self) -> None:
        """Stop observing and flush remaining events."""

    @abstractmethod
    def get_events(self) -> list[Event]:
        """Return collected canonical events."""

    def __enter__(self) -> Observer:
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()
