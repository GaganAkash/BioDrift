"""Repository pattern over SQLite storage."""

from __future__ import annotations

import json

from sqlalchemy import func
from sqlalchemy.orm import Session

from biodrift.models import Event, Finding, RunMeta, Verdict
from biodrift.models.contracts import Contract
from biodrift.storage.db import ContractRecord, EventRecord, FindingRecord, RunRecord


class RunRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, meta: RunMeta) -> RunRecord:
        rec = RunRecord(
            run_id=meta.run_id,
            package_id=meta.package_id,
            package_digest=meta.package_digest,
            candidate_version=meta.candidate_version,
            environment_json=json.dumps(meta.environment),
            observer_config_json=json.dumps(meta.observer_config),
            timestamp=meta.timestamp,
            completed=int(meta.completed),
            final_verdict=meta.final_verdict.value if meta.final_verdict else None,
        )
        self.session.add(rec)
        self.session.commit()
        return rec

    def get(self, run_id: str) -> RunRecord | None:
        return self.session.get(RunRecord, run_id)

    def update_verdict(self, run_id: str, verdict: Verdict) -> None:
        rec = self.get(run_id)
        if rec:
            rec.final_verdict = verdict.value
            rec.completed = 1
            self.session.commit()

    def list_runs(self, package_id: str | None = None) -> list[RunRecord]:
        q = self.session.query(RunRecord)
        if package_id:
            q = q.filter(RunRecord.package_id == package_id)
        return q.order_by(RunRecord.timestamp.desc()).all()

    def count_all(self) -> int:
        return self.session.query(func.count(RunRecord.run_id)).scalar() or 0

    def verdict_counts(self) -> dict[str, int]:
        rows = (
            self.session.query(RunRecord.final_verdict, func.count())
            .group_by(RunRecord.final_verdict)
            .all()
        )
        return {verdict or "UNKNOWN": count for verdict, count in rows}


class EventRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, event: Event) -> EventRecord:
        rec = EventRecord(
            evidence_id=event.evidence_id,
            run_id=event.run_id,
            package_id=event.package_id,
            component_id=event.component_id,
            phase=event.phase.value,
            capability=event.capability.value,
            action=event.action,
            resource=event.resource,
            destination=event.destination,
            dependency_lineage_json=json.dumps(event.dependency_lineage),
            process_id=event.process_id,
            parent_process_id=event.parent_process_id,
            native_object=event.native_object,
            timestamp=event.timestamp,
            observer=event.observer,
            context_json=json.dumps(event.context),
        )
        self.session.add(rec)
        self.session.commit()
        return rec

    def create_all(self, events: list[Event]) -> None:
        recs = [
            EventRecord(
                evidence_id=e.evidence_id,
                run_id=e.run_id,
                package_id=e.package_id,
                component_id=e.component_id,
                phase=e.phase.value,
                capability=e.capability.value,
                action=e.action,
                resource=e.resource,
                destination=e.destination,
                dependency_lineage_json=json.dumps(e.dependency_lineage),
                process_id=e.process_id,
                parent_process_id=e.parent_process_id,
                native_object=e.native_object,
                timestamp=e.timestamp,
                observer=e.observer,
                context_json=json.dumps(e.context),
            )
            for e in events
        ]
        self.session.add_all(recs)
        self.session.commit()

    def get_by_run(self, run_id: str) -> list[EventRecord]:
        return (
            self.session.query(EventRecord)
            .filter(EventRecord.run_id == run_id)
            .order_by(EventRecord.timestamp)
            .all()
        )

    def count_by_run(self, run_id: str) -> int:
        return self.session.query(EventRecord).filter(EventRecord.run_id == run_id).count()

    def count_all(self) -> int:
        return self.session.query(func.count(EventRecord.evidence_id)).scalar() or 0

    def recent(self, limit: int = 500) -> list[EventRecord]:
        return (
            self.session.query(EventRecord)
            .order_by(EventRecord.timestamp.desc())
            .limit(limit)
            .all()
        )


class FindingRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, finding: Finding) -> FindingRecord:
        rec = FindingRecord(
            finding_id=finding.finding_id,
            run_id=finding.run_id,
            event_id=finding.event_id,
            package_id=finding.package_id,
            component_id=finding.component_id,
            capability=finding.capability.value,
            verdict=finding.verdict.value,
            reason=finding.reason,
            evidence_json=json.dumps(finding.evidence),
            severity=finding.severity.value,
            attribution_confidence=finding.attribution_confidence,
            timestamp=finding.timestamp,
        )
        self.session.add(rec)
        self.session.commit()
        return rec

    def get_by_run(self, run_id: str) -> list[FindingRecord]:
        return (
            self.session.query(FindingRecord)
            .filter(FindingRecord.run_id == run_id)
            .order_by(FindingRecord.timestamp)
            .all()
        )

    def count_by_verdict(self, run_id: str, verdict: str) -> int:
        return (
            self.session.query(FindingRecord)
            .filter(FindingRecord.run_id == run_id, FindingRecord.verdict == verdict)
            .count()
        )

    def count_all(self) -> int:
        return self.session.query(func.count(FindingRecord.finding_id)).scalar() or 0

    def incidents(self, limit: int = 200) -> list[FindingRecord]:
        return (
            self.session.query(FindingRecord)
            .filter(FindingRecord.verdict == "VIOLATION")
            .order_by(FindingRecord.timestamp.desc())
            .limit(limit)
            .all()
        )


class ContractRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, contract: Contract) -> ContractRecord:
        rec = ContractRecord(
            contract_id=contract.contract_id,
            package_id=contract.package_id,
            version_family=contract.version_family,
            contract_json=contract.model_dump_json(),
            admission_status=contract.admission_status.value,
            created_at=contract.created_at,
        )
        self.session.add(rec)
        self.session.commit()
        return rec

    def get(self, contract_id: str) -> ContractRecord | None:
        return self.session.get(ContractRecord, contract_id)

    def get_by_package(self, package_id: str) -> list[ContractRecord]:
        return (
            self.session.query(ContractRecord)
            .filter(ContractRecord.package_id == package_id)
            .order_by(ContractRecord.created_at.desc())
            .all()
        )
