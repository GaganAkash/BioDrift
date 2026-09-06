"""Integration tests for hardening behaviors (subprocess workloads)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from biodrift.models import Verdict
from biodrift.pipeline import run_verification

_CONTRACT = Path("config/contracts/fixture-home-reader.yaml")


def _make_pkg(modules: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="biodrift_test_"))
    (root / "src").mkdir()
    (root / "pyproject.toml").write_text(
        '[build-system]\nrequires=["setuptools>=61"]\n'
        'build-backend="setuptools.build_meta"\n'
        '[project]\nname = "test-hardening"\nversion = "1.0.0"\n'
    )
    for name, code in modules.items():
        (root / "src" / name).write_text(code)
    return root


class TestEntrySweep:
    def test_hidden_module_caught(self):
        # Wrong-entry guess (aaa_pure sorts first) must not miss zzz_main.
        root = _make_pkg({
            "aaa_pure.py": 'import os\nprint("pure")\n',
            "zzz_main.py": (
                'import os\n'
                'open(os.path.expanduser("~/.ssh/known_hosts") '
                'if os.path.exists(os.path.expanduser("~/.ssh/known_hosts")) '
                'else "/etc/passwd").read()\n'
            ),
        })
        result = run_verification(package_path=root, contract_path=_CONTRACT,
                                  persist=False)
        assert result.decision.verdict == Verdict.VIOLATION

    def test_only_init_package_caught(self):
        # src/__init__.py side effect must be exercised.
        root = _make_pkg({
            "__init__.py": (
                'import os\n'
                'open(os.path.expanduser("~/.ssh/known_hosts") '
                'if os.path.exists(os.path.expanduser("~/.ssh/known_hosts")) '
                'else "/etc/passwd").read()\n'
            ),
        })
        result = run_verification(package_path=root, contract_path=_CONTRACT,
                                  persist=False)
        assert result.decision.verdict == Verdict.VIOLATION


class TestDeterminism:
    def test_result_identical_across_pycache_runs(self):
        """A stale __pycache__ must not change observable events/coverage."""
        import json
        import os
        import subprocess
        import sys
        import tempfile

        root = _make_pkg({"main.py": 'open("/tmp/det.txt","w")\n'
                                     'open("/tmp/det.txt","r").read()\n'})
        src = str(root / "src")

        def run_once() -> list[str]:
            tmp = Path(tempfile.mkdtemp()) / "audit.log"
            env = {**os.environ, "BIODRIFT_RUN_ID": "r", "BIODRIFT_PACKAGE_ID": "p",
                   "BIODRIFT_AUDIT": "1", "BIODRIFT_EVENT_LOG": str(tmp),
                   "PYTHONPATH": src}
            rc = subprocess.run(
                [sys.executable, "-m", "biodrift._bootstrap", "main"],
                env=env, capture_output=True).returncode
            assert rc == 0
            events = [json.loads(ln) for ln in tmp.read_text().splitlines()
                      if ln.strip()]
            return sorted(e["capability"] for e in events)

        clean = run_once()

        # Force a cached state (compile the module), then run again.
        import contextlib
        import importlib
        sys.path.insert(0, src)
        with contextlib.suppress(Exception):
            importlib.import_module("main")

        cached = run_once()
        assert clean == cached, f"pycache changed events: {clean} vs {cached}"


class TestCrashSurfacing:
    def test_crashing_workload_is_inconclusive(self):
        root = _make_pkg({"main.py": 'raise RuntimeError("boom")\n'})
        result = run_verification(package_path=root, contract_path=_CONTRACT,
                                  persist=False)
        assert result.decision.verdict == Verdict.INCONCLUSIVE
        assert "exit code" in result.decision.reason.lower()


class TestInputErrors:
    def test_missing_package_is_clean_error(self):
        from biodrift.pipeline import VerificationError

        with pytest.raises(VerificationError):
            run_verification(package_path="/tmp/does-not-exist-anywhere",
                             contract_path=_CONTRACT, persist=False)

    def test_corrupt_contract_is_clean_error(self):
        from biodrift.pipeline import VerificationError

        bad = Path(tempfile.mkdtemp()) / "bad.yaml"
        bad.write_text("!no [ valid")
        with pytest.raises(VerificationError):
            run_verification(package_path="fixtures/benign/agent",
                             contract_path=bad, persist=False)