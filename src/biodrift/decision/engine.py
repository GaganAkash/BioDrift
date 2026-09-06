"""Three-state decision engine: COMPLIANT / VIOLATION / INCONCLUSIVE."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from biodrift.models import Event, Finding, Severity, Verdict


class Decision(BaseModel):
    verdict: Verdict
    reason: str = ""
    findings: list[Finding] = []
    coverage_ratio: float = 0.0
    attribution_confidence: float = 0.0
    evidence_count: int = 0


def decide(
    events: list[Event],
    contract_rules: dict[str, Any],
    coverage_ratio: float,
    attribution_confidence: float,
    min_coverage: float = 0.8,
    min_attribution_confidence: float = 0.6,
    conflict_count: int = 0,
    coverage_missing: list[str] | None = None,
) -> Decision:
    """Emit COMPLIANT, VIOLATION, or INCONCLUSIVE with evidence.

    Rules:
    - VIOLATION: positive violation evidence with sufficient attribution/context
    - COMPLIANT: no conflicting behavior + coverage >= threshold + sufficient attribution
    - INCONCLUSIVE: insufficient evidence, conflicting, or attribution unresolved
    """
    findings: list[Finding] = []
    violation_events = _find_violations(events, contract_rules)

    for evt in violation_events:
        findings.append(
            Finding(
                run_id=evt.run_id,
                event_id=evt.evidence_id,
                package_id=evt.package_id,
                component_id=evt.component_id,
                capability=evt.capability,
                verdict=Verdict.VIOLATION,
                reason=f"Observed {evt.capability.value} on {evt.resource} conflicts with contract",
                evidence=[evt.evidence_id],
                severity=Severity.HIGH,
                attribution_confidence=attribution_confidence,
            )
        )

    if findings:
        return Decision(
            verdict=Verdict.VIOLATION,
            reason=f"{len(findings)} violation(s) found",
            findings=findings,
            coverage_ratio=coverage_ratio,
            attribution_confidence=attribution_confidence,
            evidence_count=len(events),
        )

    if coverage_ratio < min_coverage:
        missing = coverage_missing or []
        detail = f"; never observed: {', '.join(missing)}" if missing else ""
        return Decision(
            verdict=Verdict.INCONCLUSIVE,
            reason=(
                f"Insufficient coverage: {coverage_ratio:.2%} < "
                f"{min_coverage:.2%}{detail}"
            ),
            findings=[],
            coverage_ratio=coverage_ratio,
            attribution_confidence=attribution_confidence,
            evidence_count=len(events),
        )

    if attribution_confidence < min_attribution_confidence:
        reason = (
            f"Low attribution confidence: {attribution_confidence:.2f} "
            f"< {min_attribution_confidence}"
        )
        return Decision(
            verdict=Verdict.INCONCLUSIVE,
            reason=reason,
            findings=[],
            coverage_ratio=coverage_ratio,
            attribution_confidence=attribution_confidence,
            evidence_count=len(events),
        )

    if conflict_count > 0:
        return Decision(
            verdict=Verdict.INCONCLUSIVE,
            reason=f"{conflict_count} observer conflict(s)",
            findings=[],
            coverage_ratio=coverage_ratio,
            attribution_confidence=attribution_confidence,
            evidence_count=len(events),
        )

    return Decision(
        verdict=Verdict.COMPLIANT,
        reason="No violations; coverage and attribution sufficient",
        findings=[],
        coverage_ratio=coverage_ratio,
        attribution_confidence=attribution_confidence,
        evidence_count=len(events),
    )


def _find_violations(events: list[Event], rules: dict[str, Any]) -> list[Event]:
    """Identify events that violate contract capability rules.

    Each rule lists allowed_resources / allowed_destinations (fnmatch
    patterns). An event whose capability has a rule is a violation when the
    target falls outside the allowlist. Capabilities with no rule are
    unconstrained.

    ponytail: fnmatch allowlist only; add regex/IP-range matching when
    fixture set demands it.
    """
    blocked_capabilities = set(rules.get("blocked_capabilities", []))
    rule_by_capability = {
        r["capability"]: r for r in rules.get("capability_rules", [])
    }

    violations = []
    for evt in events:
        cap = evt.capability.value
        if cap in blocked_capabilities:
            violations.append(evt)
            continue

        rule = rule_by_capability.get(cap)
        if not rule or rule.get("blocked"):
            continue

        if not _within_allowlist(evt.resource, rule.get("allowed_resources", [])):
            violations.append(evt)
            continue

        if evt.destination and not _within_allowlist(
            evt.destination, rule.get("allowed_destinations", [])
        ):
            violations.append(evt)

    return violations


def _within_allowlist(target: str, patterns: list[str]) -> bool:
    import fnmatch

    if not patterns:
        return True
    if not target:
        return False
    return any(fnmatch.fnmatch(target, pat) for pat in patterns)
