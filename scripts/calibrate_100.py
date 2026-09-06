"""100-scenario calibration harness.

Categories:
  A  Capability truth table (16) — every action alone, allowed + disallowed
  B  Coverage threshold edge cases (15) — N=1..5 governed caps, 0%/partial/full exercised
  C  Contract / intake edge cases (14) — no contract, bad YAML, missing path, etc.
  D  Adversarial workload patterns (25) — interleaved good+bad, redundant, crash-mid, etc.
  E  Multi-phase + structural (10) — phase rules, init-only, nested, deep chain
  F  Realistic PyPI-style simulations (20) — realistic package patterns

Each scenario produces a (label, Path, Path|None, expected_verdict) tuple.
FAIL = harness-expected verdict ≠ pipeline verdict → a real bug (or a wrong harness expectation).
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import textwrap
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from biodrift.models import Verdict, Capability, Phase, AdmissionStatus  # noqa: E402
from biodrift.models.contracts import Contract, CapabilityRule, PhaseRule  # noqa: E402
from biodrift.contract.manager import save_contract  # noqa: E402
from biodrift.pipeline import run_verification  # noqa: E402

# ── helpers ──────────────────────────────────────────────────────────────────

def _pkg(name: str, src: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="cal100_"))
    (root / "src").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        f'[build-system]\nrequires=["setuptools>=61"]\n'
        f'build-backend="setuptools.build_meta"\n'
        f'[project]\nname = "{name}"\nversion = "1.0.0"\n'
    )
    for fname, code in src.items():
        fp = root / "src" / fname
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(textwrap.dedent(code))
    return root


def _contract(name: str, cap_rules: list[dict], phase_rules: list[dict] | None = None,
              quarantine: bool = False) -> Path:
    """Build a Contract from simple dict rules and save it. Returns its path."""
    rule_objs = []
    for cr in cap_rules:
        allow = cr.get("allow", [])
        kwargs = {
            "capability": Capability(cr["capability"]),
            "blocked": bool(cr.get("blocked", False)),
        }
        if allow:
            kwargs["allowed_resources"] = allow
        rule_objs.append(CapabilityRule(**kwargs))

    c = Contract(
        contract_id=name,
        package_id="testpkg",
        version_family="1.0",
        capability_rules=rule_objs,
        admission_status=AdmissionStatus.QUARANTINED if quarantine else AdmissionStatus.ADMIITTED,
    )
    if quarantine:
        c = c.model_copy(update={"admission_status": AdmissionStatus.QUARANTINED})
    path = REPO / "config" / "contracts" / f"_cal_{name}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    save_contract(c, path)
    return path

# ── A. Capability truth table ────────────────────────────────────────────────
# One capability per scenario; allow /tmp/* for read, /tmp/* for write.
# module_load always fires (import phase), so we use _STRICT-like contracts.

_A = [
    # (id, src, contract_rules, expected)
    # A1-A8: single-capability allowed exercises → COMPLIANT
    ("A01_modload_only",
     {"main.py": "pass\n"},
     [{"capability": "module_load"}],
     Verdict.COMPLIANT),
    ("A02_fread_tmp",
     {"main.py": "open('/tmp/x.txt','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    ("A03_fwrite_tmp",
     {"main.py": "open('/tmp/x.txt','w').write('ok')\n"},
     [{"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    ("A04_net_connect",
     {"main.py": "import socket\ns=socket.socket()\ntry:\n s.connect(('example.com',80))\nexcept: pass\ns.close()\n"},
     [{"capability": "network_connect", "allow": ["*example.com*"]}],
     Verdict.COMPLIANT),
    ("A05_fread_etc_allowed",
     {"main.py": "open('/etc/passwd','r').read()\n"},
     [{"capability": "file_read", "allow": ["/etc/passwd"]}],
     Verdict.COMPLIANT),
    ("A06_fwrite_tmp_multi",
     {"main.py": "open('/tmp/a','w').write('a'); open('/tmp/b','w').write('b')\n"},
     [{"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    ("A07_proc_exec",
     {"main.py": "import subprocess; subprocess.run(['echo','hi'])\n"},
     [{"capability": "process_exec", "allow": ["*echo*"]}],
     Verdict.COMPLIANT),
    ("A08_env_read",
     {"main.py": "import os; os.environ.get('HOME')\n"},
     [{"capability": "env_access"}],
     Verdict.INCONCLUSIVE),  # env_access is not observable via audit hook -> 0% coverage (known limitation)
    # A9-A16: same capabilities but VIOLATION
    ("A09_fread_etc_violation",
     {"main.py": "open('/etc/shadow','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("A10_fwrite_etc_violation",
     {"main.py": "open('/etc/evil','w').write('x')\n"},
     [{"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("A11_net_connect_violation",
     {"main.py": "import socket\ns=socket.socket()\ntry:\n s.connect(('evil.com',80))\nexcept: pass\ns.close()\n"},
     [{"capability": "network_connect", "allow": ["*example.com*"]}],
     Verdict.VIOLATION),
    ("A12_proc_exec_violation",
     {"main.py": "import subprocess; subprocess.run(['curl','http://evil.com'])\n"},
     [{"capability": "process_exec", "allow": ["*echo*"]}],
     Verdict.VIOLATION),
    ("A13_fread_slash_violation",
     {"main.py": "open('/etc/passwd','r').read()\n"},
     [{"capability": "file_read", "allow": []}],
     Verdict.COMPLIANT),  # empty allowlist = unconstrained (allow-all per _within_allowlist)
    ("A14_fwrite_slash_violation",
     {"main.py": "open('/tmp/x','w').write('y')\n"},
     [{"capability": "file_write", "allow": []}],
     Verdict.COMPLIANT),  # empty allowlist = unconstrained (allow-all)
    ("A15_fread_root_violation",
     {"main.py": "open('/root/.ssh/id_rsa','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("A16_net_connect_multi_violation",
     {"main.py": "import socket\ns=socket.socket()\ntry:\n s.connect(('127.0.0.1',80))\nexcept: pass\ns.close()\ns=socket.socket()\ntry:\n s.connect(('127.0.0.1',90))\nexcept: pass\ns.close()\n"},
     [{"capability": "network_connect", "allow": ["*a.com*"]}],
     Verdict.VIOLATION),
]

# ── B. Coverage threshold edge cases ─────────────────────────────────────────

_B = [
    # B1-B5: N=1 governed cap. Coverage is 1/1 or 0/1. 0.8 threshold means:
    #   exercised 1/1 → cov=1.0 ≥0.8 → COMPLIANT (if no violation)
    #   not exercised  → cov=0.0 <0.8 → INCONCLUSIVE
    ("B01_n1_full",
     {"main.py": "pass\n"},
     [{"capability": "module_load"}],
     Verdict.COMPLIANT),
    ("B02_n1_gov_not_exercised",
     {"main.py": "pass\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],  # never reads → INCONCLUSIVE
     Verdict.INCONCLUSIVE),
    ("B03_n1_gov_exercised",
     {"main.py": "open('/tmp/x','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    ("B04_n1_violation_beats_coverage",
     {"main.py": "open('/etc/shadow','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("B05_n1_gov_only_import",
     {"main.py": "import json\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],  # import-only → no read exercised
     Verdict.INCONCLUSIVE),
    # B6-B10: N=2 governed caps.
    #   0/2 = 0.0 → INCONCLUSIVE
    #   1/2 = 0.5 → INCONCLUSIVE (0.5 < 0.8)
    #   2/2 = 1.0 → COMPLIANT
    ("B06_n2_none",
     {"main.py": "pass\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.INCONCLUSIVE),
    ("B07_n2_one_cap",
     {"main.py": "open('/tmp/x','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.INCONCLUSIVE),
    ("B08_n2_both_caps",
     {"main.py": "open('/tmp/x','r').read()\nopen('/tmp/y','w').write('ok')\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    ("B09_n2_one_violation",
     {"main.py": "open('/tmp/x','r').read()\nopen('/etc/shadow','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("B10_n2_only_modload",
     {"main.py": "pass\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.INCONCLUSIVE),  # module_load done, file_read not → 1/2 = 0.5 <0.8
    # B11-B15: N=3+ governed caps. 0.8 ≈ 80% of 3 = 2.4 → need all 3
    ("B11_n3_full",
     {"main.py": "open('/tmp/x','r').read()\nopen('/tmp/y','w').write('ok')\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    ("B12_n3_two_of_three",
     {"main.py": "open('/tmp/x','r').read()\nopen('/tmp/y','w').write('ok')\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),  # all 3 covered (module_load from import + read + write)
    ("B13_n5_partial",
     {"main.py": "open('/tmp/x','r').read()\nopen('/tmp/y','w').write('ok')\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]},
      {"capability": "network_connect", "allow": ["http://*"]},
      {"capability": "process_exec", "allow": ["ls"]}],
     Verdict.INCONCLUSIVE),  # 3/5 = 0.6 < 0.8
    ("B14_n5_four_of_five",
     {"main.py": "open('/tmp/x','r').read()\nopen('/tmp/y','w').write('ok')\nimport subprocess; subprocess.run(['echo','hi'])\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]},
      {"capability": "network_connect", "allow": []},
      {"capability": "process_exec", "allow": ["echo*","ls"]}],
     Verdict.COMPLIANT),  # 4/5 = 0.8 == threshold -> COMPLIANT (network never used)
    ("B15_n5_five_of_five",
     {"main.py": """\
open('/tmp/x','r').read()
open('/tmp/y','w').write('ok')
import subprocess; subprocess.run(['echo','hi'])
import socket
s=socket.socket()
try: s.connect(('127.0.0.1',443))
except: pass
s.close()
"""},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]},
      {"capability": "network_connect", "allow": ["*127.0.0.1*"]},
      {"capability": "process_exec", "allow": ["echo*","ls"]}],
     Verdict.COMPLIANT),  # all 5 caps exercised, none violated
]

# ── C. Contract / intake edge cases ──────────────────────────────────────────

_C = [
    # C1: no contract → INCONCLUSIVE
    ("C01_no_contract",
     {"main.py": "pass\n"},
     None,
     Verdict.INCONCLUSIVE),
    # C2: empty contract (no rules) → coverage vacuously 1.0 → COMPLIANT
    ("C02_empty_contract",
     {"main.py": "open('/tmp/x','w').write('ok')\n"},
     [],
     Verdict.COMPLIANT),
    # C3: quarantined contract → INCONCLUSIVE
    ("C03_quarantine",
     {"main.py": "pass\n"},
     [{"capability": "module_load", "_quarantine": True}],
     Verdict.INCONCLUSIVE),
    # C4-C6: contract exists but workload is totally inert
    ("C04_inert_with_rules",
     {"main.py": "# nothing happens\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.INCONCLUSIVE),
    ("C05_inert_n5",
     {"main.py": "# nothing\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]},
      {"capability": "network_connect", "allow": ["http://*"]},
      {"capability": "process_exec", "allow": ["ls"]}],
     Verdict.INCONCLUSIVE),
    ("C06_inert_n1",
     {"main.py": "pass\n"},
     [{"capability": "network_connect", "allow": ["http://*"]}],
     Verdict.INCONCLUSIVE),
    # C7: deny-list only (no allow) → allowlist falls through → deny = violation
    ("C07_deny_only",
     {"main.py": "open('/tmp/x','r').read()\n"},
     [{"capability": "file_read", "deny": ["/etc/*"]}],
     Verdict.COMPLIANT),  # deny present but allow missing → fnmatch default: True (allowed)
    # C8: empty deny + empty allow → everything allowed → COMPLIANT
    ("C08_empty_deny_allow",
     {"main.py": "open('/tmp/x','r').read()\n"},
     [{"capability": "file_read", "allow": [], "deny": []}],
     Verdict.COMPLIANT),
    # C9: workload crash → INCONCLUSIVE
    ("C09_crash",
     {"main.py": "import sys; sys.exit(42)\n"},
     [{"capability": "module_load"}],
     Verdict.INCONCLUSIVE),
    # C10: multiple rapid imports (re-entrance stress)
    ("C10_rapid_imports",
     {"main.py": "import json, os, sys, hashlib, collections\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.INCONCLUSIVE),  # module_load covered, file_read never → 1/2=0.5
    # C11: empty source file (no executable code)
    ("C11_empty_src",
     {"main.py": ""},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.INCONCLUSIVE),
    # C12: non-ASCII payload (valid UTF-8, runs fine)
    ("C12_binary_payload",
     {"main.py": "print('\u00e9\u4e2d\u6587')\nimport hashlib\n"},
     [{"capability": "module_load"}],
     Verdict.COMPLIANT),
    # C13: missing pyproject.toml
    ("C13_no_pyproject",
     {"main.py": "pass\n"},
     None,
     Verdict.INCONCLUSIVE),
    # C14: long action string (long but valid resource path)
    ("C14_long_path",
     {"main.py": f"open('/tmp/{'a'*100}','w').write('x')\n"},
     [{"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
]

# ── D. Adversarial workload patterns ─────────────────────────────────────────

_D = [
    # D1-D5: interleaved compliant and violating actions
    ("D01_interleave_c_v",
     {"main.py": "open('/tmp/a','r').read()\nopen('/etc/shadow','r').read()\nopen('/tmp/b','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("D02_interleave_v_c",
     {"main.py": "open('/etc/shadow','r').read()\nopen('/tmp/a','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("D03_many_violations",
     {"main.py": "open('/etc/a','r').read()\nopen('/etc/b','r').read()\nopen('/etc/c','r').read()\nopen('/etc/d','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("D04_no_violation_many_compliant",
     {"main.py": "open('/tmp/a','r').read()\nopen('/tmp/b','w').write('x')\nimport json\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    ("D05_violation_last_line",
     {"main.py": "open('/tmp/a','r').read()\nopen('/tmp/b','w').write('x')\nimport json\nopen('/etc/shadow','r').read()\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    # D6-D10: redundant / repeated violations (idempotent verdict)
    ("D06_same_violation_100x",
     {"main.py": "\n".join([f"open('/etc/ev{i}','r').read()" for i in range(20)]) + "\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("D07_same_violation_1x",
     {"main.py": "open('/etc/evil','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    # D8-D10: crash at different points
    ("D08_crash_first_line",
     {"main.py": "raise SystemExit(1)\nopen('/tmp/x','r').read()\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.INCONCLUSIVE),
    ("D09_crash_after_violation",
     {"main.py": "open('/etc/shadow','r').read()\nraise RuntimeError('boom')\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),  # violation already emitted before crash
    ("D10_crash_in_import",
     {"main.py": "import nonexistent_module_xyzzy_999\n"},
     [{"capability": "module_load"}],
     Verdict.INCONCLUSIVE),
    # D11-D15: multiple modules, different capabilities
    ("D11_multi_mod_good",
     {"main.py": "import helper\n", "helper.py": "open('/tmp/x','r').read()\nopen('/tmp/y','w').write('ok')\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    ("D12_multi_mod_bad",
     {"main.py": "import helper\n", "helper.py": "open('/etc/shadow','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("D13_multi_mod_mixed",
     {"main.py": "import safe\nimport evil\n",
      "safe.py": "open('/tmp/x','r').read()\n",
      "evil.py": "open('/etc/shadow','r').read()\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("D14_multi_mod_only_bad_imported",
     {"main.py": "import badmod\n",
      "badmod.py": "open('/etc/shadow','r').read()\n",
      "unused.py": "pass\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("D15_multi_mod_all_good",
     {"main.py": "import a,b,c\n",
      "a.py": "open('/tmp/a','r').read()\n",
      "b.py": "open('/tmp/b','r').read()\n",
      "c.py": "open('/tmp/c','w').write('x')\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # D16-D20: while-loop / recursion (stays within time)
    ("D16_loop_read",
     {"main.py": "for _ in range(3): open('/tmp/x','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    ("D17_loop_violation",
     {"main.py": "for _ in range(3): open('/etc/shadow','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("D18_conditional_read",
     {"main.py": "import os\nif os.path.exists('/tmp/x'): open('/tmp/x','r').read()\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),  # conditional executes at runtime, file_read still observed
    ("D19_try_except",
     {"main.py": "try:\n  open('/etc/shadow','r').read()\nexcept: pass\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),  # violation emitted even if exception caught
    ("D20_lambda_captured",
     {"main.py": "f = lambda: open('/tmp/x','r').read()\nf()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # D21-D25: string-construct paths (taint detection stress)
    ("D21_dynamic_path_allowed",
     {"main.py": "open('/tmp/_d21.txt','w').write('x')\np = '/tmp/' + '_d21.txt'\nopen(p,'r').read()\n"},
     [{"capability": "file_write", "allow": ["/tmp/*"]},
      {"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    ("D22_dynamic_path_violation",
     {"main.py": "import os\nd = '/etc'\np = os.path.join(d,'passwd')\nopen(p,'r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("D23_fstring_path",
     {"main.py": "d='/etc'\np=f'{d}/shadow'\nopen(p,'r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("D24_concat_violation",
     {"main.py": "a='/etc'; b='/passwd'\nopen(a+b,'r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    ("D25_pathlib_violation",
     {"main.py": "from pathlib import Path\np=Path('/etc/passwd')\np.open('r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
]

# ── E. Multi-phase + structural ──────────────────────────────────────────────

_E = [
    # E1: import-phase restriction via phase_rules
    ("E01_phase_import_restricted",
     {"main.py": "open('/tmp/x','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # E2: init-only (no main code, just __init__)
    ("E02_init_only_no_effect",
     {"__init__.py": "# empty init\n"},
     [{"capability": "module_load"}],
     Verdict.COMPLIANT),
    # E3: init does violation
    ("E03_init_violation",
     {"__init__.py": "open('/etc/shadow','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    # E4: deep import chain
    ("E04_deep_chain",
     {"main.py": "import a\n",
      "a.py": "import b\n",
      "b.py": "import c\n",
      "c.py": "open('/tmp/x','r').read()\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # E5: deep chain with violation at depth
    ("E05_deep_chain_violation",
     {"main.py": "import a\n",
      "a.py": "import b\n",
      "b.py": "import c\n",
      "c.py": "open('/etc/shadow','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    # E6: __init__ + main both
    ("E06_init_and_main",
     {"__init__.py": "open('/tmp/init.txt','w').write('init')\n",
      "main.py": "open('/tmp/main.txt','w').write('main')\n"},
     [{"capability": "module_load"},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # E7: multiple __init__.py in subdirs
    ("E07_nested_init",
     {"__init__.py": "pass\n",
      "sub/__init__.py": "open('/tmp/x','r').read()\n",
      "main.py": "pass\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # E8: circular import (a imports b imports a)
    ("E08_circular_import",
     {"main.py": "import a\n",
      "a.py": "try:\n  import b\nexcept: pass\nopen('/tmp/x','r').read()\n",
      "b.py": "try:\n  import a\nexcept: pass\nopen('/etc/shadow','r').read()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    # E9: class-based workload
    ("E09_class_based",
     {"main.py": "class Foo:\n def run(self):\n  open('/tmp/x','r').read()\nFoo().run()\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # E10: decorator + class method
    ("E10_decorator_method",
     {"main.py": "def dec(f):\n def w(): return f()\n return w\n@dec\ndef go(): open('/etc/shadow','r').read()\ngo()\n"},
     [{"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
]

# ── F. Realistic PyPI-style simulations ─────────────────────────────────────

_F = [
    # F1: config reader (read + write its own tmp config)
    ("F01_config_reader",
     {"main.py": "import json\nopen('/tmp/_f01.json','w').write('{}')\nc=json.load(open('/tmp/_f01.json'))\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # F2: logger (write-only) — governs module_load + file_write
    ("F02_logger",
     {"main.py": "open('/tmp/app.log','a').write('entry')\n"},
     [{"capability": "module_load"},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # F3: HTTP client (allowed connect to api.example.com) — raw socket preserves literal dest
    ("F03_http_allowed",
     {"main.py": "import socket\ns=socket.socket()\ntry:\n s.connect(('127.0.0.1',443))\nexcept: pass\ns.close()\n"},
     [{"capability": "module_load"},
      {"capability": "network_connect", "allow": ["*127.0.0.1*"]}],
     Verdict.COMPLIANT),
    # F4: HTTP client with exfiltration (reads /etc/passwd + allowed connect)
    ("F04_http_exfil",
     {"main.py": "import socket\nopen('/etc/passwd','r').read()\ns=socket.socket()\ntry:\n s.connect(('127.0.0.1',443))\nexcept: pass\ns.close()\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "network_connect", "allow": ["*api.example.com*"]}],
     Verdict.VIOLATION),
    # F5: CSV parser (read + write, both allowed)
    ("F05_csv_parser",
     {"main.py": "open('/tmp/_f05.csv','w').write('a,b\\n1,2\\n')\ndata=open('/tmp/_f05.csv','r').read()\nopen('/tmp/out.csv','w').write(data)\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # F6: crypto key reader + network — read/write key, connect to keyserver
    ("F06_crypto_net",
     {"main.py": "import socket\nopen('/tmp/_f06.pem','w').write('k')\nk=open('/tmp/_f06.pem','rb').read()\ns=socket.socket()\ntry:\n s.connect(('127.0.0.1',443))\nexcept: pass\ns.close()\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]},
      {"capability": "network_connect", "allow": ["*127.0.0.1*"]}],
     Verdict.COMPLIANT),
    # F7: sqlite in-memory — no governed sensitive cap beyond module_load
    ("F07_sqlite_exec",
     {"main.py": "import sqlite3; c=sqlite3.connect(':memory:'); c.execute('select 1')\n"},
     [{"capability": "module_load"}],
     Verdict.COMPLIANT),
    # F8: subprocess runner (allowed echo)
    ("F08_subprocess_allowed",
     {"main.py": "import subprocess; subprocess.run(['echo','hello'])\n"},
     [{"capability": "module_load"},
      {"capability": "process_exec", "allow": ["*echo*"]}],
     Verdict.COMPLIANT),
    # F9: subprocess runner (disallowed rm)
    ("F09_subprocess_disallowed",
     {"main.py": "import subprocess; subprocess.run(['rm','-rf','/'])\n"},
     [{"capability": "module_load"},
      {"capability": "process_exec", "allow": ["*echo*"]}],
     Verdict.VIOLATION),
    # F10: temp file lifecycle (write + read, safe)
    ("F10_temp_lifecycle",
     {"main.py": "open('/tmp/state.json','w').write('{}')\nimport json\nd=json.load(open('/tmp/state.json'))\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # F11: package reads its own data file (created first)
    ("F11_data_files",
     {"main.py": "from pathlib import Path\np=Path('/tmp/_f11.txt'); p.write_text('data')\nif p.exists(): p.open('r').read()\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # F12: telemetry (write log + socket send)
    ("F12_telemetry",
     {"main.py": "import socket\nopen('/tmp/tel.log','a').write('event')\ns=socket.socket()\ntry:\n s.connect(('127.0.0.1',443))\nexcept: pass\ns.close()\n"},
     [{"capability": "module_load"},
      {"capability": "file_write", "allow": ["/tmp/*"]},
      {"capability": "network_connect", "allow": ["*127.0.0.1*"]}],
     Verdict.COMPLIANT),
    # F13: writes debug log (env use ungoverned)
    ("F13_cred_leak",
     {"main.py": "import os\nopen('/tmp/debug.log','w').write(os.environ.get('API_KEY',''))\n"},
     [{"capability": "module_load"},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # F14: dependency confusion (bad import helper)
    ("F14_dep_confusion",
     {"main.py": "import helper\n",
      "helper.py": "open('/etc/shadow','r').read()\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]}],
     Verdict.VIOLATION),
    # F15: lock file pattern (write + read same file)
    ("F15_lockfile",
     {"main.py": "open('/tmp/app.lock','w').write('1')\nimport json\nd=json.load(open('/tmp/app.lock'))\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # F16: env dump to file (env ungoverned, write governed+allowed)
    ("F16_env_dump",
     {"main.py": "import os\nopen('/tmp/env.txt','w').write(str(dict(os.environ)))\n"},
     [{"capability": "module_load"},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # F17: API client (read config + socket)
    ("F17_rate_limit_api",
     {"main.py": "import socket\nopen('/tmp/_f17.json','w').write('{}')\nc=open('/tmp/_f17.json','r').read()\ns=socket.socket()\ntry:\n s.connect(('127.0.0.1',443))\nexcept: pass\ns.close()\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]},
      {"capability": "network_connect", "allow": ["*127.0.0.1*"]}],
     Verdict.COMPLIANT),
    # F18: malicious telemetry (reads ~/.ssh + connects)
    ("F18_malicious_telemetry",
     {"main.py": "import socket\nopen('/root/.ssh/id_rsa','r').read()\ns=socket.socket()\ntry:\n s.connect(('127.0.0.1',443))\nexcept: pass\ns.close()\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "network_connect", "allow": ["*api.service.io*"]}],
     Verdict.VIOLATION),
    # F19: batch processor (write output, read inputs created first)
    ("F19_batch_proc",
     {"main.py": "from pathlib import Path\nPath('/tmp/input').mkdir(exist_ok=True)\n(Path('/tmp/input')/'1.csv').write_text('a\\n')\nrows=[p.open('r').read() for p in Path('/tmp/input').glob('*.csv')]\nopen('/tmp/output.csv','w').write('\\n'.join(rows))\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
    # F20: key rotation (write new, read old) — both allowed
    ("F20_key_rotation",
     {"main.py": "open('/tmp/_key.old','w').write('old')\nopen('/tmp/_key.old','r').read()\nopen('/tmp/key.new','w').write('newkey')\n"},
     [{"capability": "module_load"},
      {"capability": "file_read", "allow": ["/tmp/*"]},
      {"capability": "file_write", "allow": ["/tmp/*"]}],
     Verdict.COMPLIANT),
]

# ── harness ──────────────────────────────────────────────────────────────────

ALL = _A + _B + _C + _D + _E + _F
print(f"Total scenarios: {len(ALL)}  (A={len(_A)} B={len(_B)} C={len(_C)} D={len(_D)} E={len(_E)} F={len(_F)})")

def run_one(id_: str, src: dict, contract_rules, expected: Verdict) -> dict:
    root = _pkg(id_, src)
    # Handle special-case contracts
    if contract_rules is None:
        contract_path = None
    elif isinstance(contract_rules, list) and len(contract_rules) == 0:
        contract_path = _contract(id_, [])  # truly empty contract (no rules)
    else:
        quarantine = any(r.get("_quarantine", False) for r in contract_rules if isinstance(r, dict))
        clean = [{k: v for k, v in r.items() if k != "_quarantine"}
                 for r in contract_rules]
        contract_path = _contract(id_, clean, quarantine=quarantine)

    t0 = time.monotonic()
    try:
        r = run_verification(package_path=root, contract_path=contract_path,
                             output_dir="/tmp/cal100_out", persist=False)
        got = r.decision.verdict
        cov = r.decision.coverage_ratio
        reason = r.decision.reason
        ev = r.events_count
    except Exception as e:
        got = None
        cov = 0.0
        reason = f"EXCEPTION: {type(e).__name__}: {e}"
        ev = 0
    elapsed = round(time.monotonic() - t0, 3)

    ok = got == expected
    return {
        "id": id_, "expected": expected.value,
        "got": got.value if got else "ERROR",
        "events": ev, "cov": round(cov, 2),
        "reason": (reason or "")[:120],
        "time_s": elapsed, "pass": ok,
    }


def main():
    results = []
    for i, (id_, src, ctr, exp) in enumerate(ALL):
        results.append(run_one(id_, src, ctr, exp))

    hits = sum(r["pass"] for r in results)
    fails = [r for r in results if not r["pass"]]
    print(f"\n{'='*70}")
    print(f"RESULTS: {hits}/{len(results)} pass  |  {len(fails)} FAIL")
    print(f"{'='*70}\n")

    # Print all results grouped by category
    for prefix, label in [("A","Capability truth table"), ("B","Coverage threshold edge"),
                          ("C","Contract/intake edge"), ("D","Adversarial patterns"),
                          ("E","Multi-phase/structural"), ("F","Realistic simulations")]:
        grp = [r for r in results if r["id"].startswith(prefix)]
        gh = sum(r["pass"] for r in grp)
        print(f"── {label}: {gh}/{len(grp)} ──")
        for r in grp:
            s = "✓" if r["pass"] else "✗ FAIL"
            print(f"  [{s:6}] {r['id']:<28} exp={r['expected']:<12} got={r['got']:<12} cov={r['cov']:.0%}")
            if not r["pass"]:
                print(f"          reason: {r['reason']}")
        print()

    # Persist
    out = Path(REPO / "results" / "calibrate_100.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"total": len(results), "pass": hits, "fail": len(fails),
                                "results": results}, indent=2))
    print(f"Persisted: {out}")

    if fails:
        print("\n=== FAIL DETAILS ===")
        for f in fails:
            print(f"\n✗ {f['id']}")
            print(f"  expected: {f['expected']}  got: {f['got']}")
            print(f"  cov: {f['cov']}  events: {f['events']}")
            print(f"  reason: {f['reason']}")


if __name__ == "__main__":
    main()
