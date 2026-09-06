"""Subprocess bootstrap: install audit hook and record events to a log file.

This module runs inside the isolated workload subprocess. It installs a
sys.audit hook before importing the candidate package, serializes each
canonical event to JSON lines, and flushes on completion.

The audit hook receives an "import" event natively (CPython emits it for
every import), so no __import__ wrapping is needed.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

_ACTIVE = False
_WRITING = False

# ponytail: on macOS only "subprocess.Popen" fires (no "Popen:exec"), so we
# map Popen -> process_exec to keep process execution observable everywhere.
_AUDIT_MAP = {
    "open": ("execution", "file_read", "open"),
    "io:open": ("execution", "file_read", "io.open"),
    "io:close": ("execution", "file_read", "io.close"),
    "subprocess.Popen": ("execution", "process_exec", "popen"),
    "subprocess.Popen:exec": ("execution", "process_exec", "exec"),
    "os.system": ("execution", "subprocess_shell", "system"),
    "socket.connect": ("execution", "network_connect", "connect"),
    "socket.bind": ("execution", "network_listen", "bind"),
    "import": ("import", "module_load", "import"),
}

_IGNORED_SUFFIXES = ()
_NOISE_MARKERS = ("__pycache__",)


def _import_roots() -> list[str]:
    """All PYTHONPATH entries that are real directories (candidate import roots)."""
    roots: list[str] = []
    for entry in os.environ.get("PYTHONPATH", "").split(os.pathsep):
        if entry and os.path.isdir(entry):
            roots.append(entry)
    return roots


def _within_import_root(resource: str) -> bool:
    res = os.path.realpath(resource)
    for root in _import_roots():
        try:
            if os.path.commonpath([res, os.path.realpath(root)]) == os.path.realpath(root):
                return True
        except ValueError:
            continue
    return False


def _classify_open(resource: str) -> str | None:
    """Classify an open() as module_load, noise, or a normal resource access.

    A resource under a PYTHONPATH root that is a Python artifact (.py/.pyc/
    .so/.dylib/.dll) is treated as module_load. Bytecode cache loads later
    skip the .py source open, so .pyc must also count as import evidence or
    coverage becomes nondeterministic across cached/uncached runs.
    """
    if resource.endswith((".py", ".pyc", ".pyo", ".so", ".dylib", ".dll")) and (
        _within_import_root(resource)
    ):
        return "module_load"
    if any(marker in resource for marker in _NOISE_MARKERS):
        return "noise"
    return None


def _emit(
    phase: str,
    capability: str,
    action: str,
    resource: str,
    destination: str,
    context: dict[str, Any] | None = None,
) -> None:
    global _WRITING
    if _WRITING:
        return
    log_path = os.environ.get("BIODRIFT_EVENT_LOG")
    if not log_path:
        return
    record = {
        "run_id": os.environ.get("BIODRIFT_RUN_ID", ""),
        "package_id": os.environ.get("BIODRIFT_PACKAGE_ID", ""),
        "component_id": "python",
        "phase": phase,
        "capability": capability,
        "action": action,
        "resource": resource,
        "destination": destination,
        "observer": "python_audit",
        "context": context or {},
    }
    _WRITING = True
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(record, default=str) + "\n")
    finally:
        _WRITING = False


def _hook(event: str, args: tuple[Any, ...]) -> None:
    if not _ACTIVE:
        return
    mapped = _AUDIT_MAP.get(event)
    if not mapped:
        return
    phase, capability, action = mapped
    if args and isinstance(args[0], int):
        return  # fd-reopen noise, not a path-based access
    resource = str(args[0]) if args else ""
    if event in ("open", "io:open") and args:
        load = _classify_open(resource)
        if load == "module_load":
            _emit("import", "module_load", "import", str(resource), "")
            return
        if load == "noise":
            return
        if len(args) >= 2:
            mode = str(args[1])
            if any(c in mode for c in ("w", "a", "x", "+")):
                capability = "file_write"
    if event == "import" and args:
        _emit("import", "module_load", "import", str(args[0]), "")
    destination = ""
    if event in ("socket.connect", "socket.bind") and args:
        # args[0] is the socket object (repr garbage), args[1] is the
        # (host, port) address tuple. Use the address so allowlist matching
        # on network destinations can actually succeed.
        addr = args[1] if len(args) > 1 else args[0]
        destination = str(addr)
        resource = str(addr) if len(args) > 1 else str(args[0])
    _emit(
        phase,
        capability,
        action,
        resource,
        destination,
        {"raw_event": event},
    )


def run(entries: list[str]) -> None:
    """Install audit hooks and import each entry module.

    Entries are module names, or `.py` file paths (for root __init__.py
    packages that have no importable top-level name). A failed import is
    tallied, and the subprocess exits non-zero so the caller can flag the
    workload as partially run.
    """
    global _ACTIVE
    _ACTIVE = os.environ.get("BIODRIFT_AUDIT") == "1"

    # Force source-based, deterministic loads. A stale __pycache__ causes the
    # module to load from .pyc with no .py open() audit event, making
    # module_load evidence (and coverage) vary run-to-run. Purge caches in the
    # import roots so every run re-reads source identically.
    try:
        sys.dont_write_bytecode = True
        for root in _import_roots():
            cache = os.path.join(root, "__pycache__")
            if os.path.isdir(cache):
                import shutil
                shutil.rmtree(cache, ignore_errors=True)
    except Exception:
        pass

    sys.addaudithook(_hook)

    import importlib
    import importlib.util

    failures = 0
    for entry in entries:
        try:
            if entry.endswith(".py") and os.path.exists(entry):
                name = f"__biodrift_{Path(entry).stem}__"
                spec = importlib.util.spec_from_file_location(name, entry)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules[name] = mod
                    spec.loader.exec_module(mod)
            else:
                importlib.import_module(entry)
        except Exception:
            failures += 1

    if failures:
        sys.exit(1)


if __name__ == "__main__":
    run(sys.argv[1:])