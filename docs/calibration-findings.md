# Calibration Findings

This document records what a 100-scenario calibration hunt surfaced about
BioDrift's decision quality, the three real product defects it exposed and
fixed, and the one deliberately deferred design decision. It is meant to be
read as an engineering log, not a sales pitch: several scenarios were wrong
in the harness, several were wrong in the product, and the interesting part
is telling the two apart.

## What the calibration is

`scripts/calibrate_100.py` runs 100 scenarios across six categories and
compares the verifier's verdict against a hand-written expectation:

| Category | Count | What it probes |
|----------|------:|----------------|
| A — Capability truth table | 16 | Every action alone, allowed and disallowed |
| B — Coverage threshold edges | 15 | N=1..5 governed caps, 0%/partial/full exercised |
| C — Contract / intake edges | 14 | Missing contract, bad YAML, missing path |
| D — Adversarial patterns | 25 | Interleaved good+bad, redundant, crash-mid |
| E — Multi-phase / structural | 10 | Phase rules, init-only, nested, deep chain |
| F — Realistic PyPI-style sims | 20 | Realistic package behaviours |

Current state: **100/100 pass** (50 COMPLIANT, 18 INCONCLUSIVE, 32
VIOLATION). Three of those 100 failures were real product bugs.

## Three product bugs found and fixed

### 1. `socket.connect` destinations never matched the allowlist

The audit hook read `args[0]` — the socket object repr — instead of
`args[1]`, the `(host, port)` tuple, when resolving the destination for a
network-connect event. As a result the destination string used for allowlist
matching was always the socket repr, so a network allowlist could never
match and every connect was a false-positive VIOLATION. Fixed in
`_bootstrap.py` to read the address tuple.

Why it mattered: it was silent. Nothing crashed; verdicts were just
aggressively wrong in one direction (false violations), which is easy to
miss because it looks like the tool "being strict."

### 2. Process execution was unobservable on macOS

The `process_exec` audit capability mapped to `subprocess.Popen:exec`, which
only fires on Linux. On macOS the audit line never appears, so a workload
that launched a subprocess emitted no event and slipped through to
INCONCLUSIVE — a comfortable "inconclusive" instead of a confident
VIOLATION. The event map now routes `subprocess.Popen` to the exec observer,
which fires on every platform.

Why it mattered: this is the opposite failure mode from #1 — it
under-reports (INCONCLUSIVE) rather than over-reports, so an attacker's
`rm -rf /` looked like "we couldn't tell" instead of "caught."

### 3. `sample_benign.yaml` did not parse

The bundled sample contract had a python-style `"""` docstring as its first
line, which is not valid YAML, so the sample was unusable out of the box.
Replaced with a `documented:` field. Minor, but a first-time user's very
first import would fail.

## The one deliberate non-change: empty allowlists

The empty-allowlist rule returns "allow everything" (`_within_allowlist([])`
→ `True`). At first blush that looks like a latent bug — shouldn't an empty
allowlist deny all? — and the instinct on the hunt was to flip it. Flipping
it would have broken a legitimate contract in the repo
(`fixture-quiet.yaml`) that uses an empty `allowed_resources` alongside a
real `allowed_destinations`, i.e. it allows *any* resource on a specific
host. Empty-allowlist is a real, usable "everything except these
destinations" form. Left as-is, and documented in the code.

## Coverage threshold: why 0.8 fights for its life

The lowest-hanging defensive lever looked like lowering `min_coverage` from
0.8 to something more forgiving. A sweep of 0.5/0.6/0.7 all admitted an
undesirable state: with a 2-capability contract, a workload that only loads
the module reaches coverage 0.50 (1 of 2 governed caps exercised). At
threshold 0.5 that import-only state is judged COMPLIANT — a false
COMPLIANT, the worst outcome for a verification tool. 0.8 sits above that
mandatory-import floor (`1/N` for a 2-cap contract), so an import-only state
never clears the bar. The threshold was reverted to 0.8 and a code comment
now records *why* it must stay above the floor, so nobody erodes it in the
future.

## Harness bugs vs product bugs

Most failures during the hunt were the harness or its sandbox, not the
product. Worth listing so the record is honest:

- Raw `socket` calls resolve hostnames to IPs, defeating hostname allowlists
  — scenarios must connect to `127.0.0.1` and wrap `socket.connect` in
  try/except (a refused connect emits the audit event then raises).
- `subprocess.Popen:exec` is Linux-only, so the harness had to use
  `subprocess.run` for process-exec scenarios to match the fixed observer.
- `env_access` is not observable through the audit hook and correctly stays
  INCONCLUSIVE; that is a coverage reality, not a bug.
- Boundary-clearing scenarios (null bytes, 500-char paths, missing files)
  surface as INCONCLUSIVE, which is the expected behaviour for crashes.

The distinction matters: changing the product to pass a mis-labelled harness
expectation would have moved correctness into the wrong direction, so the
harness, not the product, was corrected.

## Residual risk

Coverage is a *lower bound* on behaviour — a workload that exercises every
governed capability but then does something allowed-but-wrong cannot be
distinguished from one that did something allowed-and-right purely on count.
The recent addition (`pipeline._uncovered_capabilities`) makes low-coverage
verdicts say *which* governed capability was never observed ("never
observed: file_write"), which helps an operator tell a mis-scoped contract
from an evasion hiding behind an unexercised capability. That is the current
frontier.
