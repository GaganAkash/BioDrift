"""BioDrift Vetting Console — thin FastAPI layer over the real engine.

The verification work is done by the existing pipeline
(biodrift.pipeline.run_verification), which runs the candidate package in an
isolated subprocess under sys.audit OS-level hooks. This app only glues that
to a browser: contracts, runs, stress dashboards, reports, and user admin.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import platform
import re
import sys
import time
from collections import defaultdict
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

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
from webapp.users import UserStore  # noqa: E402

CONTRACTS_DIR = REPO / "config" / "contracts"
FIXTURES_DIR = REPO / "fixtures"
DB_PATH = str(REPO / "results" / "biodrift.db")

# Optional bearer token gate. When set, every /api call must present
# `Authorization: Bearer <token>`. Read-only GETs can be allowed without it
# via ALLOW_ANON_GET. Disabled (empty) by default so the demo runs open.
API_TOKEN = os.environ.get("BIODRIFT_API_TOKEN", "")
ALLOW_ANON_GET = os.environ.get("BIODRIFT_ALLOW_ANON_GET", "1") == "1"

SESSION_SECRET = os.environ.get("BIODRIFT_SESSION_SECRET", "biodrift-demo-secret")

_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]+$")

app = FastAPI(title="BioDrift Vetting Console")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

# Session users + roles live in config/users.json (see webapp/users.py).
users = UserStore()

# Landing page and auth pages are public; the console itself is behind login.
_PUBLIC_PATHS = {"/", "/login", "/register", "/logout"}


@app.middleware("http")
async def require_session(request: Request, call_next):
    """Gate the console and its APIs behind the login page (session cookie)."""
    path = request.url.path
    if (
        path.startswith("/static")
        or path in _PUBLIC_PATHS
        or request.session.get("authed")
    ):
        return await call_next(request)
    return RedirectResponse("/login", status_code=303)


# Added last so it runs outermost: session is populated before our gate sees it.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=False,
)


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


def _require_admin(request: Request) -> None:
    if request.session.get("role") != "admin":
        raise HTTPException(403, "admin role required")


def _contract_path(name: str) -> Path:
    return CONTRACTS_DIR / f"{_safe_name(name)}.yaml"


# --- Device-aware contract library -------------------------------------------
# A contract lives on a device if its declared environment matches the host
# (os/architecture, "*" = any). Contracts with no environment block are
# universal. Engine calibration scenarios (_cal_*) are not device contracts.
HOST_OS = platform.system().lower()
HOST_ARCH = platform.machine().lower()
HOST_ARCH = {"aarch64": "arm64", "amd64": "x86_64"}.get(HOST_ARCH, HOST_ARCH)
AUTO_DIR = REPO / "results" / "_auto_contracts"


def _contract_raw(text: str) -> dict:
    import yaml

    try:
        return yaml.safe_load(text) or {}
    except Exception:
        return {}


def _matches_host(raw: dict) -> bool:
    env = raw.get("environment")
    if not env:
        return True
    os_ = str(env.get("os", "*")).lower()
    arch = str(env.get("architecture", "*")).lower()
    return os_ in (HOST_OS, "*") and arch in (HOST_ARCH, "*")


def _authored_contract_paths() -> list[Path]:
    return [p for p in CONTRACTS_DIR.glob("*.yaml") if not p.stem.startswith("_")]


def _baseline_name(pkg: str) -> str:
    return "auto_" + pkg.replace("/", "_")


def _baseline_yaml(pkg: str) -> str:
    return (
        f'package_id: "{pkg}"\n'
        f'version_family: "0.0.0-auto"\n'
        f"environment:\n  os: \"{HOST_OS}\"\n  architecture: \"{HOST_ARCH}\"\n"
        "capability_rules: []\n"
        "coverage_threshold: 0.0\n"
    )


def _baseline_contracts() -> list[dict]:
    """One permissive baseline contract for every package found on this device
    that has no authored contract matching it yet."""
    authored_ids = {
        _contract_raw(p.read_text()).get("package_id")
        for p in _authored_contract_paths()
    }
    return [
        {
            "name": _baseline_name(pkg["name"]),
            "package_id": pkg["name"],
            "path": pkg["path"],
            "admission_status": "pending",
            "n_rules": 0,
            "lines": 0,
            "baseline": True,
        }
        for pkg in list_packages()
        if pkg["name"] not in authored_ids
    ]


def _authored_contract_entries() -> list[dict]:
    out = []
    for p in _authored_contract_paths():
        raw = _contract_raw(p.read_text())
        if not _matches_host(raw):
            continue
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


def device_contracts() -> list[dict]:
    return _authored_contract_entries() + _baseline_contracts()


def _resolve_contract_path(name: str, package: str = "") -> Path:
    p = _contract_path(name)
    if p.exists():
        return p
    baselines = _baseline_contracts()
    match = next((b for b in baselines if b["name"] == name), None)
    if match:
        f = AUTO_DIR.joinpath(f"{name}.yaml")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(_baseline_yaml(match["package_id"]))
        return f
    raise HTTPException(400, f"no contract named {name}")


def _resolve_contract_yaml(name: str) -> str:
    p = _contract_path(name)
    if p.exists():
        return p.read_text()
    for b in _baseline_contracts():
        if b["name"] == name:
            return _baseline_yaml(b["package_id"])
    raise HTTPException(404, f"no contract named {name}")


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
def landing() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "landing.html")


@app.get("/console")
def index() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/login")
def login_page() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "login.html")


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    u = users.authenticate(username, password)
    if u:
        request.session["authed"] = True
        request.session["user"] = u["username"]
        request.session["role"] = u["role"]
        return RedirectResponse("/console", status_code=303)
    return RedirectResponse("/login?error=1", status_code=303)


@app.get("/register")
def register_page() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "register.html")


@app.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...),
             email: str = Form("")):
    try:
        users.register(username, password, email)
    except ValueError as e:
        return RedirectResponse(f"/register?error={quote(str(e))}", status_code=303)
    request.session["authed"] = True
    request.session["user"] = username
    request.session["role"] = "researcher"
    return RedirectResponse("/console", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "contracts": len(device_contracts())}


def _run_to_dict(r) -> dict:
    return {
        "run_id": r.run_id,
        "package_id": r.package_id,
        "candidate_version": r.candidate_version,
        "final_verdict": r.final_verdict,
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
    }


@app.get("/api/me")
def me(request: Request) -> dict:
    return {
        "username": request.session.get("user"),
        "role": request.session.get("role", "viewer"),
    }


@app.get("/api/overview")
def overview(request: Request) -> dict:
    _check_auth(request, "GET")
    db = init_db(DB_PATH)
    with db() as session:
        runs = RunRepository(session)
        verdicts = runs.verdict_counts()
        recent = [_run_to_dict(r) for r in runs.list_runs()[:5]]
        runs_total = runs.count_all()
        events_total = EventRepository(session).count_all()
        findings_total = FindingRepository(session).count_all()

    stress = {}
    for name in ("progressive_stress.json", "calibrate_100.json"):
        p = REPO / "results" / name
        if p.exists():
            stress[name] = json.loads(p.read_text())
    prog = stress.get("progressive_stress.json") or []
    cal = stress.get("calibrate_100.json") or {}
    cal_rows = cal.get("results", []) if isinstance(cal.get("results"), list) else []
    engine_rows = [r for r in prog if not r.get("kind")]

    return {
        "runs_total": runs_total,
        "verdicts": verdicts,
        "events_total": events_total,
        "findings_total": findings_total,
        "contracts": len(device_contracts()),
        "packages": len(list_packages()),
        "recent": recent,
        "stress": {
            "engine_steps": len(engine_rows),
            "e2e_runs": len([r for r in prog if r.get("kind")]),
            "all_ok": bool(engine_rows)
            and all(r.get("clean_ok") and r.get("poison_ok") for r in engine_rows),
        },
        "calibrate": {"total": cal.get("total", 0), "pass": cal.get("pass", 0)},
        "calibrate_rows": cal_rows[:5],
    }


class UserIn(BaseModel):
    username: str
    password: str
    role: str = "researcher"
    email: str = ""


@app.get("/api/users")
def list_users(request: Request) -> list[dict]:
    _require_admin(request)
    return users.list()


@app.post("/api/users")
def create_user(u: UserIn, request: Request) -> dict:
    _require_admin(request)
    try:
        users.upsert(u.username, u.password, u.role, u.email)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    return {"ok": True, "username": u.username, "role": u.role}


@app.delete("/api/users/{username}")
def delete_user(username: str, request: Request) -> dict:
    _require_admin(request)
    if username == request.session.get("user"):
        raise HTTPException(400, "cannot delete the account you are signed in as")
    try:
        users.delete(username)
    except KeyError:
        raise HTTPException(404, f"no user named {username}") from None
    return {"ok": True}


def _csv_response(rows: list[dict], filename: str) -> Response:
    buf = io.StringIO()
    fieldnames = list(rows[0].keys()) if rows else []
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/reports/incidents", response_model=None)
def incidents(request: Request, format: str = "json") -> Response | list[dict]:
    _check_auth(request, "GET")
    db = init_db(DB_PATH)
    with db() as session:
        rows = [
            {
                "run_id": f.run_id,
                "package_id": f.package_id,
                "capability": f.capability,
                "reason": f.reason,
                "severity": f.severity,
                "timestamp": f.timestamp.isoformat() if f.timestamp else None,
            }
            for f in FindingRepository(session).incidents()
        ]
    if format == "csv":
        return _csv_response(rows, "biodrift_incidents.csv")
    if format != "json":
        raise HTTPException(400, "format must be json or csv")
    return rows


@app.get("/api/reports/audit", response_model=None)
def audit_log(request: Request, format: str = "json", limit: int = 500) -> Response | list[dict]:
    _check_auth(request, "GET")
    limit = max(1, min(limit, 10_000))
    db = init_db(DB_PATH)
    with db() as session:
        rows = [
            {
                "run_id": e.run_id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "phase": e.phase,
                "capability": e.capability,
                "action": e.action,
                "resource": e.resource,
                "destination": e.destination,
                "process_id": e.process_id,
            }
            for e in EventRepository(session).recent(limit)
        ]
    if format == "csv":
        return _csv_response(rows, "biodrift_audit.csv")
    if format != "json":
        raise HTTPException(400, "format must be json or csv")
    return rows


@app.get("/api/reports/analytics")
def analytics(request: Request) -> dict:
    _check_auth(request, "GET")
    db = init_db(DB_PATH)
    with db() as session:
        runs = [_run_to_dict(r) for r in RunRepository(session).list_runs()[:500]]
        events_total = EventRepository(session).count_all()
        findings_total = FindingRepository(session).count_all()

    counts: dict[str, int] = defaultdict(int)
    days: dict[str, int] = defaultdict(int)
    for r in runs:
        key = r["final_verdict"] or "UNKNOWN"
        counts[key] += 1
        if r["timestamp"]:
            days[r["timestamp"][:10]] += 1

    verdicts_over_time = [
        {"day": (date.today() - timedelta(days=13 - i)).isoformat(),
         "count": days.get((date.today() - timedelta(days=13 - i)).isoformat(), 0)}
        for i in range(14)
    ]

    return {
        "runs_total": len(runs),
        "events_total": events_total,
        "findings_total": findings_total,
        "verdicts": dict(counts),
        "verdicts_over_time": verdicts_over_time,
        "avg_events_per_run": round(events_total / len(runs), 1) if runs else None,
    }


class ContractIn(BaseModel):
    name: str
    yaml: str


@app.get("/api/contracts")
def list_contracts() -> list[dict]:
    return device_contracts()


@app.get("/api/contracts/{name}")
def get_contract(name: str, request: Request) -> dict:
    _check_auth(request, "GET")
    return {"name": name, "yaml": _resolve_contract_yaml(name)}


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
    contract = _resolve_contract_path(v.contract, v.package)

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
    contract = _resolve_contract_path(v.contract, v.package)

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
            for r in runs[:50]
        ]


@app.get("/api/stress")
def stress(request: Request) -> dict:
    _check_auth(request, "GET")
    out = {}
    for name in ("progressive_stress.json", "calibrate_100.json"):
        p = REPO / "results" / name
        if p.exists():
            out[name] = json.loads(p.read_text())
    return out