"""End-to-end verification pipeline orchestration."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from biodrift.config import BioDriftConfig, load_config
from biodrift.contract.manager import load_contract
from biodrift.decision.engine import Decision, decide
from biodrift.intake.artifact import Artifact, resolve_package
from biodrift.models import RunMeta, Verdict
from biodrift.reporting.json_report import generate_json_report, save_report
from biodrift.storage.db import init_db
from biodrift.storage.repositories import (
    ContractRepository,
    EventRepository,
    FindingRepository,
    RunRepository,
)
from biodrift.workload import run_workload


class VerificationError(Exception):
    """User-facing verification error (bad input, not a system fault)."""


class PipelineResult:
    def __init__(
        self,
        decision: Decision,
        run_meta: RunMeta,
        events_count: int,
        report_path: Path | None = None,
    ):
        self.decision = decision
        self.run_meta = run_meta
        self.events_count = events_count
        self.report_path = report_path


def run_verification(
    package_path: str | Path,
    contract_path: str | Path | None = None,
    config: BioDriftConfig | None = None,
    output_dir: str | Path = "results",
    db_path: str | None = None,
    scenario: str = "default",
    entry_module: str | None = None,
    persist: bool = True,
    live: Callable[[dict], None] | None = None,
) -> PipelineResult:
    """Run the full BioDrift verification pipeline on a candidate package."""
    cfg = config or load_config()
    start = time.monotonic()

    try:
        artifact = resolve_package(package_path)
        contract = _load_contract(contract_path, artifact)
    except FileNotFoundError as e:
        raise VerificationError(str(e)) from e
    except Exception as e:  # yaml/toml parse errors
        raise VerificationError(f"Invalid contract or package metadata: {e}") from e

    from biodrift.static.analyzer import analyze_package  # noqa: F401

    pkg_path = (
        artifact.path
        if artifact.path.is_dir()
        else Path(artifact.isolated_dir or artifact.path)
    )

    workload = run_workload(
        package_dir=pkg_path,
        run_id=artifact.artifact_id,
        package_id=artifact.package_name,
        scenario=scenario,
        entry_module=entry_module,
        enable_audit=True,
        enable_process=True,
        on_event=live,
    )

    all_events = workload.events
    run_meta = _build_run_meta(artifact, cfg, len(all_events))

    if contract is None:
        decision = Decision(
            verdict=Verdict.INCONCLUSIVE,
            reason="No governing contract; cannot verify without a trusted reference",
            coverage_ratio=0.0,
            attribution_confidence=_compute_attribution(all_events, pkg_path),
            evidence_count=len(all_events),
        )
    elif contract.admission_status.value == "quarantined":
        decision = Decision(
            verdict=Verdict.INCONCLUSIVE,
            reason="Contract quarantined: package-shipped contract is "
            "untrusted (self-certification / reference poisoning)",
            coverage_ratio=_compute_coverage_ratio(all_events, contract),
            attribution_confidence=_compute_attribution(all_events, pkg_path),
            evidence_count=len(all_events),
        )
    else:
        decision = decide(
            events=all_events,
            contract_rules=_contract_to_rules(contract),
            coverage_ratio=_compute_coverage_ratio(all_events, contract),
            attribution_confidence=_compute_attribution(all_events, pkg_path),
            min_coverage=cfg.decision.min_coverage,
            min_attribution_confidence=cfg.decision.min_attribution_confidence,
            coverage_missing=_uncovered_capabilities(all_events, contract),
        )
    run_meta.final_verdict = decision.verdict

    if workload.exit_code != 0 and decision.verdict != Verdict.VIOLATION:
        decision = Decision(
            verdict=Verdict.INCONCLUSIVE,
            reason=f"Candidate workload failed (exit code {workload.exit_code}); "
            f"observed behavior may be incomplete",
            findings=decision.findings,
            coverage_ratio=decision.coverage_ratio,
            attribution_confidence=decision.attribution_confidence,
            evidence_count=len(all_events),
        )
        run_meta.final_verdict = decision.verdict

    report_path = None
    if persist:
        report_obj = generate_json_report(
            run_meta,
            decision.findings,
            len(all_events),
            coverage={"coverage_ratio": _compute_coverage_ratio(all_events, contract)},
        )
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        report_path = save_report(report_obj, out / f"{run_meta.run_id}.json")

        from biodrift.reporting.html_report import generate_html_report

        generate_html_report(report_obj, out / f"{run_meta.run_id}.html")

        db = init_db(db_path or cfg.storage.db_path)
        with db() as session:
            RunRepository(session).create(run_meta)
            EventRepository(session).create_all(all_events)
            for f in decision.findings:
                FindingRepository(session).create(f)
            if contract is not None:
                ContractRepository(session).create(contract)

    elapsed = time.monotonic() - start
    run_meta.environment["verification_duration_s"] = f"{elapsed:.3f}"

    return PipelineResult(
        decision=decision,
        run_meta=run_meta,
        events_count=len(all_events),
        report_path=report_path,
    )


def _load_contract(contract_path: str | Path | None, artifact: Artifact):
    if contract_path:
        contract = load_contract(contract_path)
        pkg_root = (
            artifact.path
            if artifact.path.is_dir()
            else Path(artifact.isolated_dir or artifact.path)
        )
        if pkg_root.resolve() in Path(contract_path).resolve().parents:
            from biodrift.contract.manager import quarantine_contract

            return quarantine_contract(
                contract,
                reason="Contract shipped by candidate package itself; "
                "untrusted self-certification (reference poisoning)",
            )
        return contract

    candidates = list(Path("config/contracts").glob(f"{artifact.package_name}*.yaml"))
    if candidates:
        return load_contract(candidates[0])
    return None


def _build_run_meta(artifact: Artifact, cfg: BioDriftConfig, events_count: int) -> RunMeta:
    return RunMeta(
        run_id=artifact.artifact_id,
        package_id=artifact.package_name,
        package_digest=artifact.digest or "unresolved",
        candidate_version=artifact.version,
        environment={
            "python": artifact.environment.python_version,
            "os": artifact.environment.os_name,
            "arch": artifact.environment.architecture,
            "events_count": events_count,
        },
        observer_config={
            k: {"enabled": v.enabled} for k, v in cfg.observers.items()
        },
    )


def _compute_coverage_ratio(events, contract) -> float:
    """Coverage = fraction of contract-governed capabilities actually observed.

    Coverage is measured against the contract's governed capability space,
    never against observed events alone, so an absence of sensitive behavior
    cannot score as complete coverage (RQ2).
    """
    if contract is None:
        return 1.0 if events else 0.0

    expected = {
        rule.capability.value
        for rule in contract.capability_rules
        if not rule.blocked
    }
    for phase_rule in contract.phase_rules:
        for cr in phase_rule.capability_rules:
            if not cr.blocked:
                expected.add(cr.capability.value)

    if not expected:
        return 1.0 if events else 0.0

    observed = {evt.capability.value for evt in events}
    covered = expected & observed
    return len(covered) / len(expected)


def _uncovered_capabilities(events, contract) -> list[str]:
    """Governed-but-unobserved capabilities, in a stable order.

    Lets the INCONCLUSIVE reason say *which* governed capability a workload
    never exercised, so an operator can tell a mis-scoped contract from an
    evasion that hides behind an unexercised capability.
    """
    if contract is None:
        return []
    expected = {
        rule.capability.value
        for rule in contract.capability_rules
        if not rule.blocked
    }
    for phase_rule in contract.phase_rules:
        for cr in phase_rule.capability_rules:
            if not cr.blocked:
                expected.add(cr.capability.value)
    observed = {evt.capability.value for evt in events}
    return sorted(expected - observed)


def _compute_attribution(events, package_dir=None) -> float:
    """Average attribution confidence across events.

    Uses responsibility.attribute_event when package_dir is available,
    falls back to heuristic otherwise.
    """
    if not events:
        return 0.0
    if package_dir is None:
        return min(0.9, 0.5 + 0.1 * min(len(events), 5))

    from biodrift.attribution.lineage import build_import_lineage
    from biodrift.attribution.responsibility import attribute_event

    components = _extract_components(package_dir)
    lineage = build_import_lineage(package_dir)
    known: dict[str, list[str]] = {}
    for node in lineage:
        known.setdefault(node.source_path, []).append(node.name)

    scores = []
    for evt in events:
        _, conf = attribute_event(evt, components, known)
        scores.append(conf)
    return sum(scores) / len(scores)


def _extract_components(package_dir: Path) -> list[str]:
    """Extract component names (module names) from the package source."""
    components: list[str] = []
    src = package_dir / "src" if (package_dir / "src").exists() else package_dir
    for py_file in src.rglob("*.py"):
        rel = py_file.relative_to(src)
        name = str(rel.with_suffix("")).replace("/", ".").replace("\\", ".")
        if name.endswith(".__init__"):
            name = name[:-9]
        components.append(name)
    return components


def _contract_to_rules(contract) -> dict[str, Any]:
    """Convert a Contract to the flat rule dict the decision engine consumes."""
    if contract is None:
        return {"capability_rules": []}

    rules: dict[str, Any] = {"capability_rules": []}
    capability_rules: dict[str, dict[str, Any]] = {}

    for rule in contract.capability_rules:
        capability_rules[rule.capability.value] = {
            "capability": rule.capability.value,
            "allowed_resources": list(rule.allowed_resources),
            "allowed_destinations": list(rule.allowed_destinations),
            "blocked": rule.blocked,
        }

    for phase_rule in contract.phase_rules:
        for cr in phase_rule.capability_rules:
            capability_rules[cr.capability.value] = {
                "capability": cr.capability.value,
                "allowed_resources": list(cr.allowed_resources),
                "allowed_destinations": list(cr.allowed_destinations),
                "blocked": cr.blocked,
            }

    rules["capability_rules"] = list(capability_rules.values())
    return rules