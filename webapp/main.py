"""BioDrift Vetting Console — thin FastAPI layer over the real engine.

The verification work is done by the existing pipeline
(biodrift.pipeline.run_verification), which runs the candidate package in an
isolated subprocess under sys.audit OS-level hooks. This app only glues that
to a browser: contracts, runs, and the stress dashboards.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
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

# Optional bearer token gate. When set, every /api call must present
# `Authorization: Bearer <token>`. Read-only GETs can be allowed without it
# via ALLOW_ANON_GET. Disabled (empty) by default so the demo runs open.
API_TOKEN = os.environ.get("BIODRIFT_API_TOKEN", "")
ALLOW_ANON_GET = os.environ.get("BIODRIFT_ALLOW_ANON_GET", "1") == "1"

_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]+$")

app = FastAPI(title="BioDrift Vetting Console")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


def _check_auth(request: Request, method: str) -> None:
    if not API_TOKEN:
        return
    if method == "GET" and ALLOW_ANON_GET:
        return
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {API_TOKEN}":
        raise HTTPException(401, "missing or invalid API token")


def _safe_name(name: str) -> str:
    if not _NAME_RE.match(name or ""):
        raise HTTPException(400, f"invalid contract name: {name!r}")
    return name


def _contract_path(name: str) -> Path:
    return CONTRACTS_DIR / f"{_safe_name(name)}.yaml"


def _resolve_package(pkg: str) -> Path:
    """Resolve a package path, confining it to the fixtures catalog."""
    path = Path(pkg).resolve()
    root = FIXTURES_DIR.resolve()
    try:
        path.relative_to(root)
    except ValueError:
        raise HTTPException(400, "package path must live under fixtures/") from None
    if not path.is_dir():
        raise HTTPException(400, f"package path is not a directory: {pkg}")
    return path


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
def get_contract(name: str, request: Request) -> dict:
    _check_auth(request, "GET")
    p = _contract_path(name)
    if not p.exists():
        raise HTTPException(404, f"no contract named {name}")
    return {"name": name, "yaml": p.read_text()}


@app.post("/api/contracts")
def create_contract(c: ContractIn, request: Request) -> dict:
    _check_auth(request, "POST")
    p = _contract_path(c.name)
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
def delete_contract(name: str, request: Request) -> dict:
    _check_auth(request, "DELETE")
    p = _contract_path(name)
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
def verify(v: VerifyIn, request: Request) -> dict:
    _check_auth(request, "POST")
    pkg = _resolve_package(v.package)
    contract = _contract_path(v.contract)
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


class VerifyStreamIn(BaseModel):
    package: str
    contract: str


@app.post("/api/verify/stream")
async def verify_stream(v: VerifyStreamIn, request: Request) -> StreamingResponse:
    """Live-verify: SSE stream of audit events as the workload runs.

    Emits an ``event`` SSE line per observed audit event (real-time from the
    isolated subprocess's sys.audit hook), then a final ``done`` line with
    the verdict, coverage, and findings. The blocking pipeline runs in a
    thread executor while events are marshalled onto an asyncio queue.
    """
    _check_auth(request, "POST")
    pkg = _resolve_package(v.package)
    contract = _contract_path(v.contract)
    if not contract.exists():
        raise HTTPException(400, f"no contract named {v.contract}")

    queue: asyncio.Queue = asyncio.Queue()

    def emit(rec: dict) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            loop.call_soon_threadsafe(queue.put_nowait, ("event", rec))
        else:
            queue.put_nowait(("event", rec))

    def run_blocking() -> dict:
        start = time.monotonic()
        result = run_verification(
            package_path=pkg,
            contract_path=contract,
            output_dir=str(REPO / "results"),
            persist=True,
            db_path=DB_PATH,
            live=emit,
        )
        return {
            "dur": round(time.monotonic() - start, 2),
            "verdict": result.decision.verdict.value,
            "reason": result.decision.reason,
            "coverage": round(result.decision.coverage_ratio, 3),
            "attribution": round(result.decision.attribution_confidence, 3),
            "events": result.events_count,
        }

    loop = asyncio.get_running_loop()
    fut = loop.run_in_executor(None, run_blocking)

    async def gen():
        done = False
        while not done:
            try:
                kind, payload = await asyncio.wait_for(queue.get(), timeout=0.2)
            except asyncio.TimeoutError:
                if fut.done():
                    done = True
                    break
                continue
            if kind == "event":
                yield f"event: audit\ndata: {json.dumps(payload)}\n\n"
        try:
            summary = await fut
        except Exception as exc:
            yield f"event: done\ndata: {json.dumps({'error': str(exc)})}\n\n"
            return
        yield f"event: done\ndata: {json.dumps(summary)}\n\n"

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/runs")
def list_runs(request: Request) -> list[dict]:
    _check_auth(request, "GET")
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
def stress(request: Request) -> dict:
    _check_auth(request, "GET")
    out = {}
    for name in ("progressive_stress.json", "calibrate_100.json"):
        p = REPO / "results" / name
        if p.exists():
            out[name] = json.loads(p.read_text())
    return out