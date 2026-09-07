"""Workload engine: run candidate package scenarios under observation."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
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
    on_event: Callable[[dict], None] | None = None,
) -> WorkloadResult:
    """Execute the candidate package in an isolated subprocess and capture events.

    ``on_event`` (when given) is a callback invoked for each normalized
    event record as it is written to the audit log *during* the run, so a
    streaming consumer (e.g. a web UI) can show live telemetry. If omitted,
    events are returned only after the subprocess exits.

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

    proc: subprocess.Popen | None = None
    try:
        proc = subprocess.Popen(
            cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        exit_code, stdout, stderr = _pump(proc, log_path, run_id, package_id, on_event, timeout_s)
    except subprocess.TimeoutExpired as e:
        exit_code = -1
        stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout or "")
        stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr or "")
        if proc is not None:
            proc.kill()

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


def _pump(
    proc: subprocess.Popen,
    log_path: Path,
    run_id: str,
    package_id: str,
    on_event: Callable[[dict], None] | None,
    timeout_s: float,
) -> tuple[int, str, str]:
    """Run the subprocess, streaming audit-log lines to ``on_event`` as they appear.

    Because the child appends to ``log_path`` incrementally, we poll the log
    and deliver each new line via the callback before the process finishes.
    Output is captured text-only (no TTY), so lines are drained to avoid
    a deadlocked pipe if the child writes a lot.

    ponytail: poll-inotify pattern — assumes single-writer append log; a
    blocking tail (queues.Queue + inotify) is overkill for our sizes.
    """
    import time as _t

    chunks_out: list[str] = []
    chunks_err: list[str] = []
    seen = 0
    deadline = _t.monotonic() + timeout_s

    while proc.poll() is None:
        if _t.monotonic() > deadline:
            raise subprocess.TimeoutExpired(proc.args, timeout_s)
        _drain(proc, chunks_out, chunks_err)
        _stream_new_lines(log_path, run_id, package_id, on_event, seen)
        seen = _count_lines(log_path)
        _t.sleep(0.01)

    _drain(proc, chunks_out, chunks_err)
    _stream_new_lines(log_path, run_id, package_id, on_event, seen)
    proc.wait()

    return (
        proc.returncode or 0,
        "".join(chunks_out),
        "".join(chunks_err),
    )


def _drain(proc, chunks_out: list[str], chunks_err: list[str]) -> None:
    try:
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            chunks_out.append(line)
    except Exception:
        pass
    try:
        while True:
            line = proc.stderr.readline()
            if not line:
                break
            chunks_err.append(line)
    except Exception:
        pass


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    n = 0
    with open(path) as f:
        for _ in f:
            n += 1
    return n


def _stream_new_lines(
    log_path: Path,
    run_id: str,
    package_id: str,
    on_event: Callable[[dict], None] | None,
    start_line: int,
) -> None:
    if on_event is None or not log_path.exists():
        return
    import json as _json

    with open(log_path) as f:
        for idx, line in enumerate(f):
            if idx < start_line:
                continue
            line = line.strip()
            if not line:
                continue
            try:
                data = _json.loads(line)
            except Exception:
                continue
            data.setdefault("run_id", run_id)
            data.setdefault("package_id", package_id)
            data.setdefault("observer", "python_audit")
            on_event(data)


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