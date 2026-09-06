"""SQLite storage layer for BioDrift runs, events, and findings."""

from __future__ import annotations

from sqlalchemy import (
    Column,
    DateTime,
    Engine,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


class RunRecord(Base):
    __tablename__ = "runs"

    run_id = Column(String(36), primary_key=True)
    package_id = Column(String(255), nullable=False, index=True)
    package_digest = Column(String(128), nullable=False)
    candidate_version = Column(String(64), nullable=False)
    environment_json = Column(Text, default="{}")
    observer_config_json = Column(Text, default="{}")
    timestamp = Column(DateTime, nullable=False)
    completed = Column(Integer, default=0)
    final_verdict = Column(String(16), nullable=True)


class EventRecord(Base):
    __tablename__ = "events"

    evidence_id = Column(String(36), primary_key=True)
    run_id = Column(String(36), nullable=False, index=True)
    package_id = Column(String(255), nullable=False)
    component_id = Column(String(255), nullable=False)
    phase = Column(String(32), nullable=False)
    capability = Column(String(32), nullable=False)
    action = Column(String(255), nullable=False)
    resource = Column(Text, default="")
    destination = Column(Text, default="")
    dependency_lineage_json = Column(Text, default="[]")
    process_id = Column(Integer, nullable=True)
    parent_process_id = Column(Integer, nullable=True)
    native_object = Column(String(255), nullable=True)
    timestamp = Column(DateTime, nullable=False)
    observer = Column(String(64), nullable=False)
    context_json = Column(Text, default="{}")


class FindingRecord(Base):
    __tablename__ = "findings"

    finding_id = Column(String(36), primary_key=True)
    run_id = Column(String(36), nullable=False, index=True)
    event_id = Column(String(36), nullable=False)
    package_id = Column(String(255), nullable=False)
    component_id = Column(String(255), nullable=False)
    capability = Column(String(32), nullable=False)
    verdict = Column(String(16), nullable=False)
    reason = Column(Text, default="")
    evidence_json = Column(Text, default="[]")
    severity = Column(String(16), nullable=False)
    attribution_confidence = Column(Float, nullable=False)
    timestamp = Column(DateTime, nullable=False)


class ContractRecord(Base):
    __tablename__ = "contracts"

    contract_id = Column(String(36), primary_key=True)
    package_id = Column(String(255), nullable=False, index=True)
    version_family = Column(String(128), nullable=False)
    contract_json = Column(Text, nullable=False)
    admission_status = Column(String(16), nullable=False)
    created_at = Column(DateTime, nullable=False)


def get_engine(db_path: str = "results/biodrift.db") -> Engine:
    return create_engine(f"sqlite:///{db_path}")


def init_db(db_path: str = "results/biodrift.db") -> sessionmaker[Session]:
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)
