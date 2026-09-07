"""BioDrift Vetting Console — thin FastAPI layer over the real engine.

The verification work is done by the existing pipeline
(biodrift.pipeline.run_verification), which runs the candidate package in an
isolated subprocess under sys.audit OS-level hooks. This app only glues that
to a browser: contracts, runs, and the stress dashboards.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from biodrift.contract.manager import load_contract, save_contract  # noqa: E402
from biodrift.pipeline import run_verification  # noqa: E402
from biodrift.storage.db import init_db  # noqa: E402
from biodrift.storage.repositories import (  # noqa: E402
    EventRepository,
    FindingRepository,
    RunRepository,
)

CONTRACTS_DIR = REPO / "config" / "contracts"
FIXTURES_DIR = REPO / "fixtures"
DB_PATH = str(REPO / "results" / "biodrift.db")

app = FastAPI(title="BioDrift Vetting Console")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "contracts": len(list(CONTRACTS_DIR.glob("*.yaml")))}


class ContractIn(BaseModel):
    name: str
    yaml: str


@app.get("/api/contracts")
def list_contracts() -> list[dict]:
    out = []
    for p in sorted(CONTRACTS_DIR.glob("*.yaml")):
        try:
            c = load_contract(p)
            out.append({
                "name": p.stem,
                "package_id": c.package_id,
                "admission_status": c.admission_status.value,
                "n_rules": len(c.capability_rules),
                "lines": len(p.read_text().splitlines()),
            })
        except Exception as e:
            out.append({"name": p.stem, "error": str(e)[:120]})
    return out


@app.get("/api/contracts/{name}")
def get_contract(name: str) -> dict:
    p = CONTRACTS_DIR / f"{name}.yaml"
    if not p.exists():
        raise HTTPException(404, f"no contract named {name}")
    return {"name": name, "yaml": p.read_text()}


@app.post("/api/contracts")
def create_contract(c: ContractIn) -> dict:
    if not c.name or ".." in c.name or "/" in c.name:
        raise HTTPException(400, "invalid contract name")
    p = CONTRACTS_DIR / f"{c.name}.yaml"
    try:
        save_contract(load_contract_from_yaml(c.yaml), p)
    except Exception as e:
        raise HTTPException(400, f"contract does not parse: {e}") from None
    return {"ok": True, "name": c.name}


def load_contract_from_yaml(text: str):
    import yaml

    from biodrift.models.contracts import Contract

    return Contract(**yaml.safe_load(text))


@app.delete("/api/contracts/{name}")
def delete_contract(name: str) -> dict:
    p = CONTRACTS_DIR / f"{name}.yaml"
    if not p.exists():
        raise HTTPException(404, f"no contract named {name}")
    p.unlink()
    return {"ok": True}


@app.get("/api/packages")
def list_packages() -> list[dict]:
    out = []
    for group in sorted(f for f in FIXTURES_DIR.iterdir() if f.is_dir()):
        for sub in sorted(g for g in group.iterdir() if g.is_dir()):
            if (sub / "src").exists() or list(sub.glob("*.py")):
                out.append({
                    "name": f"{group.name}/{sub.name}",
                    "path": str(sub),
                })
    return out


class VerifyIn(BaseModel):
    package: str
    contract: str


@app.post("/api/verify")
def verify(v: VerifyIn) -> dict:
    pkg = Path(v.package)
    contract = CONTRACTS_DIR / f"{v.contract}.yaml"
    if not pkg.exists():
        raise HTTPException(400, f"package path does not exist: {pkg}")
    if not contract.exists():
        raise HTTPException(400, f"no contract named {v.contract}")

    start = time.monotonic()
    try:
        result = run_verification(
            package_path=pkg,
            contract_path=contract,
            output_dir=str(REPO / "results"),
            persist=True,
            db_path=DB_PATH,
        )
    except Exception as e:
        raise HTTPException(422, f"verification failed: {e}") from None

    run_id = result.run_meta.run_id
    db = init_db(DB_PATH)
    with db() as session:
        events = EventRepository(session).get_by_run(run_id)
        findings = FindingRepository(session).get_by_run(run_id)
        events = [
            {
                "capability": e.capability,
                "action": e.action,
                "resource": e.resource,
                "destination": e.destination,
                "phase": e.phase,
            }
            for e in events
        ]
        findings = [
            {
                "verdict": f.verdict,
                "capability": f.capability,
                "reason": f.reason,
                "severity": f.severity,
            }
            for f in findings
        ]

    return {
        "run_id": run_id,
        "package": v.package,
        "contract": v.contract,
        "verdict": result.decision.verdict.value,
        "reason": result.decision.reason,
        "coverage": round(result.decision.coverage_ratio, 3),
        "attribution": round(result.decision.attribution_confidence, 3),
        "events_count": len(events),
        "findings_count": len(findings),
        "duration_s": round(time.monotonic() - start, 2),
        "events": events,
        "findings": findings,
    }


@app.get("/api/runs")
def list_runs() -> list[dict]:
    db = init_db(DB_PATH)
    with db() as session:
        runs = RunRepository(session).list_runs()
        return [
            {
                "run_id": r.run_id,
                "package_id": r.package_id,
                "candidate_version": r.candidate_version,
                "final_verdict": r.final_verdict,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            }
            for r in runs[-50:]
        ][::-1]


@app.get("/api/stress")
def stress() -> dict:
    out = {}
    for name in ("progressive_stress.json", "calibrate_100.json"):
        p = REPO / "results" / name
        if p.exists():
            out[name] = json.loads(p.read_text())
    return out