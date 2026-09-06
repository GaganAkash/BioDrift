"""Workload engine: run candidate package scenarios under observation."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from biodrift.models import Event


class WorkloadResult:
    def __init__(
        self,
        events: list[Event],
        exit_code: int,
        duration_s: float,
        stdout: str = "",
        stderr: str = "",
    ):
        self.events = events
        self.exit_code = exit_code
        self.duration_s = duration_s
        self.stdout = stdout
        self.stderr = stderr


def run_workload(
    package_dir: Path,
    run_id: str,
    package_id: str,
    scenario: str = "default",
    entry_module: str | None = None,
    timeout_s: float = 30.0,
    enable_audit: bool = True,
    enable_process: bool = True,
) -> WorkloadResult:
    """Execute the candidate package in an isolated subprocess and capture events.

    ponytail: run target module via subprocess with PYTHONPATH isolation.
    Add per-scenario argument generation when fixture set grows.
    """
    events: list[Event] = []
    import time

    start = time.monotonic()
    tempdir = tempfile.mkdtemp(prefix="biodrift_wl_")
    log_path = Path(tempdir) / "audit.log"

    audit_flag = "1" if enable_audit else "0"
    proc_flag = "1" if enable_process else "0"
    env = dict(os.environ)
    env["BIODRIFT_RUN_ID"] = run_id
    env["BIODRIFT_PACKAGE_ID"] = package_id
    env["BIODRIFT_AUDIT"] = audit_flag
    env["BIODRIFT_PROCESS"] = proc_flag
    env["BIODRIFT_EVENT_LOG"] = str(log_path)
    env["PYTHONPATH"] = str(package_dir) + os.pathsep + env.get("PYTHONPATH", "")

    entry, sysroot = _find_entry_module(package_dir, entry_module)
    env["PYTHONPATH"] = str(sysroot) + os.pathsep + env.get("PYTHONPATH", "")

    modules = _all_importable_modules(sysroot, entry)
    cmd = [sys.executable, "-m", "biodrift._bootstrap", *modules]

    try:
        proc = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        exit_code = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        exit_code = -1
        stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout or "")
        stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr or "")

    duration = time.monotonic() - start

    if log_path.exists():
        events = _load_events_from_log(log_path, run_id, package_id)

    return WorkloadResult(
        events=events,
        exit_code=exit_code,
        duration_s=duration,
        stdout=stdout,
        stderr=stderr,
    )


def _find_entry_module(package_dir: Path, entry_module: str | None = None) -> tuple[str, Path]:
    """Find the primary importable module and its sys.path root.

    For a ``<root>/src/<pkg>.py`` layout the import root is ``<root>/src``.
    Returns (module_name, import_root).

    ponytail: prefers conventional entry-point names (main/app/cli/run),
    falls back to the first non-underscore module. __main__.py is not
    handled (needs runpy, not import_module).
    """
    if entry_module:
        parts = entry_module.split(".")
        for base in (package_dir, package_dir / "src"):
            if (base / f"{parts[0]}.py").exists() or (base / parts[0]).exists():
                return entry_module, base
        return entry_module, package_dir

    base = package_dir / "src" if (package_dir / "src").exists() else package_dir
    py_files = sorted(
        f for f in base.rglob("*.py") if f.name != "__init__.py"
    )
    if not py_files:
        init = base / "__init__.py"
        if init.exists():
            return str(init), base
        return "main", base

    def rel_module(f: Path) -> str:
        rel = f.relative_to(base)
        parts = list(rel.parts[:-1]) + [rel.stem]
        return ".".join(parts)

    for name in ("main", "app", "cli", "run"):
        for f in py_files:
            if f.stem == name:
                return rel_module(f), base

    for f in py_files:
        if not f.stem.startswith("_"):
            return rel_module(f), base

    return rel_module(py_files[0]), base


def _all_importable_modules(sysroot: Path, entry: str) -> list[str]:
    """Every importable module under sysroot, entry first.

    Sweeping all modules (not just the guessed entry) removes the
    false-negative class where the picked entry misses hidden behavior.
    Package dirs (via __init__.py) are included so package-level side
    effects are exercised even with no child modules.

    ponytail: top-level modules only; module sweep, no scenario parameters.
    """
    modules: list[str] = []
    for p in sorted(sysroot.rglob("*.py")):
        rel = p.relative_to(sysroot)
        if p.name == "__init__.py":
            parent = str(rel.parent).replace("/", ".")
            if parent == ".":
                modules.append(str(p))  # root package init: load by path
            else:
                modules.append(parent)
            continue
        modules.append(rel.with_suffix("").as_posix().replace("/", "."))
    modules = [m.lstrip(".") for m in modules if m and m != "."]
    if entry in modules:
        modules.remove(entry)
    return [entry] + modules


def _load_events_from_log(log_path: Path, run_id: str, package_id: str) -> list[Event]:
    """Load events recorded by the in-subprocess audit hook."""
    import json

    events: list[Event] = []
    for line in log_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        data.setdefault("run_id", run_id)
        data.setdefault("package_id", package_id)
        data.setdefault("observer", "python_audit")
        try:
            events.append(Event(**data))
        except Exception:
            continue  # ponytail: skip malformed log lines; add warnings when validation is wired
    return events