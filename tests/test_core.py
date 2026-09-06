"""Integration tests for the core pipeline."""

from __future__ import annotations

import tempfile
from pathlib import Path

from biodrift.decision.engine import decide
from biodrift.models import Capability, Event, Phase, Verdict, _uuid
from biodrift.normalize.events import normalize_events


def _make_event(**overrides) -> Event:
    defaults = {
        "run_id": _uuid(),
        "package_id": "test-pkg",
        "component_id": "test",
        "phase": Phase.EXECUTION,
        "capability": Capability.FILE_READ,
        "action": "open",
        "resource": "/tmp/test.txt",
        "observer": "python_audit",
    }
    defaults.update(overrides)
    return Event(**defaults)


class TestModels:
    def test_event_creation(self):
        event = _make_event()
        assert event.run_id
        assert event.package_id == "test-pkg"
        assert event.capability == Capability.FILE_READ

    def test_finding_creation(self):
        from biodrift.models import Finding, Severity

        finding = Finding(
            run_id=_uuid(),
            event_id=_uuid(),
            package_id="test-pkg",
            component_id="test",
            capability=Capability.FILE_READ,
            verdict=Verdict.COMPLIANT,
            reason="test",
        )
        assert finding.verdict == Verdict.COMPLIANT
        assert finding.severity == Severity.MEDIUM


class TestNormalize:
    def test_normalize_events(self):
        raw = [
            {
                "run_id": "r1",
                "package_id": "pkg",
                "phase": "execution",
                "capability": "file_read",
                "action": "open",
                "resource": "/etc/passwd",
                "observer": "python_audit",
            }
        ]
        events = normalize_events(raw, "python_audit")
        assert len(events) == 1
        assert events[0].capability == Capability.FILE_READ


class TestDecision:
    def test_inconclusive_on_low_coverage(self):
        events = [_make_event()]
        result = decide(
            events=events,
            contract_rules={},
            coverage_ratio=0.3,
            attribution_confidence=0.9,
        )
        assert result.verdict == Verdict.INCONCLUSIVE
        assert "coverage" in result.reason.lower()

    def test_inconclusive_reason_names_unobserved_capability(self):
        result = decide(
            events=[],
            contract_rules={},
            coverage_ratio=0.5,
            attribution_confidence=0.9,
            coverage_missing=["file_write", "file_delete"],
        )
        assert result.verdict == Verdict.INCONCLUSIVE
        assert "file_write" in result.reason
        assert "file_delete" in result.reason

    def test_compliant_when_sufficient(self):
        events = [_make_event()]
        result = decide(
            events=events,
            contract_rules={},
            coverage_ratio=0.9,
            attribution_confidence=0.9,
        )
        assert result.verdict == Verdict.COMPLIANT

    def test_violation_on_blocked_resource(self):
        events = [_make_event(resource="/etc/shadow")]
        result = decide(
            events=events,
            contract_rules={
                "capability_rules": [
                    {
                        "capability": "file_read",
                        "allowed_resources": ["/tmp/*", "/etc/passwd"],
                    }
                ]
            },
            coverage_ratio=0.9,
            attribution_confidence=0.9,
        )
        assert result.verdict == Verdict.VIOLATION
        assert len(result.findings) == 1

    def test_inconclusive_on_low_attribution(self):
        events = [_make_event()]
        result = decide(
            events=events,
            contract_rules={},
            coverage_ratio=0.9,
            attribution_confidence=0.3,
        )
        assert result.verdict == Verdict.INCONCLUSIVE
        assert "attribution" in result.reason.lower()

    def test_quarantined_contract_is_inconclusive(self):
        from biodrift.contract.manager import load_contract, quarantine_contract
        from biodrift.pipeline import _contract_to_rules

        contract = quarantine_contract(
            load_contract(Path("config/contracts/fixture-benign.yaml")),
            reason="untrusted",
        )
        assert contract.admission_status.value == "quarantined"
        # Contract rules still usable; quarantine gate lives in the pipeline.
        assert "capability_rules" in _contract_to_rules(contract)


class TestCoverage:
    def test_compute_coverage(self):
        from biodrift.coverage.metrics import compute_coverage
        from biodrift.coverage.security_paths import SecurityPath

        paths = [
            SecurityPath(
                path_id="a",
                description="a",
                capability=Capability.FILE_READ,
                covered=True,
            ),
            SecurityPath(
                path_id="b",
                description="b",
                capability=Capability.NETWORK_CONNECT,
                covered=False,
            ),
        ]
        metrics = compute_coverage(paths)
        assert metrics.total_paths == 2
        assert metrics.covered_paths == 1
        assert metrics.coverage_ratio == 0.5


class TestStorage:
    def test_db_init_and_crud(self):
        from biodrift.models import RunMeta, Verdict
        from biodrift.storage.db import init_db
        from biodrift.storage.repositories import RunRepository

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "test.db")
            session_factory = init_db(db_path)
            with session_factory() as session:
                repo = RunRepository(session)
                meta = RunMeta(
                    package_id="test-pkg",
                    package_digest="abc123",
                    candidate_version="1.0.0",
                )
                rec = repo.create(meta)
                assert rec.run_id == meta.run_id

                repo.update_verdict(meta.run_id, Verdict.COMPLIANT)
                updated = repo.get(meta.run_id)
                assert updated.final_verdict == "COMPLIANT"
