"""FastAPI layer: REST API + static dashboard."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .engine import Engine

BASE = Path(__file__).resolve().parent.parent
ROOT = Path(os.environ.get("RANSOMSHIELD_ROOT", BASE / "demo"))
SIM = BASE / "simulator" / "simulate.py"
STATIC = Path(__file__).resolve().parent / "static"

engine = Engine(ROOT)
_sim_proc: subprocess.Popen | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    engine.start()
    yield
    engine.stop()


app = FastAPI(title="RansomShield", version="1.0", lifespan=lifespan)


class Config(BaseModel):
    auto_recover: bool


def _sim_running() -> bool:
    return _sim_proc is not None and _sim_proc.poll() is None


@app.get("/api/status")
def status():
    _sim_running()                       # reap finished simulator (avoids zombies)
    return {**engine.status(), "simulator_running": _sim_running()}


@app.get("/api/files")
def files():
    return engine.files_view()


@app.get("/api/events")
def events(limit: int = 60):
    return list(engine.events)[-max(1, min(limit, 300)):][::-1]


@app.get("/api/alerts")
def alerts():
    return engine.alerts[::-1]


@app.get("/api/report")
def report():
    return Response(engine.report_text(), media_type="text/plain",
                    headers={"Content-Disposition": 'attachment; filename="incident_report.txt"'})


@app.post("/api/config")
def config(cfg: Config):
    engine.auto_recover = cfg.auto_recover
    return {"auto_recover": engine.auto_recover}


@app.post("/api/snapshot")
def snapshot():
    try:
        return engine.snapshot("manual")
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))


@app.post("/api/recover")
def recover():
    try:
        return engine.recover()
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))


@app.post("/api/resume")
def resume():
    engine.resume()
    return {"state": engine.state}


# ---- demo helpers (only ever touch the isolated demo folder) ---------------
@app.post("/api/demo/normal-edit")
def demo_normal_edit():
    if engine.state in ("THREAT", "CONTAINED"):
        raise HTTPException(409, "Threat active - recover or reset first.")
    target = engine.layout.protected / "project.py"
    with open(target, "a") as f:
        f.write(f"# edited by user at {time.strftime('%H:%M:%S')}\n")
    return {"edited": "project.py"}


@app.post("/api/demo/bulk-copy")
def demo_bulk_copy():
    """Simulates a user pasting a folder: 8 text files + 4 photos (random bytes = like real JPEGs)."""
    if engine.state in ("THREAT", "CONTAINED"):
        raise HTTPException(409, "Threat active - recover or reset first.")
    tag = time.strftime("%H%M%S")
    prot = engine.layout.protected
    for i in range(8):
        (prot / f"copied_{tag}_{i}.txt").write_text(f"normal document {i}\n" * 200)
    for i in range(4):
        (prot / f"photo_{tag}_{i}.jpg").write_bytes(b"\xff\xd8\xff\xe0" + os.urandom(4096))
    return {"copied": 12}


@app.post("/api/demo/attack")
def demo_attack():
    global _sim_proc
    if engine.state in ("THREAT", "CONTAINED"):
        raise HTTPException(409, "Threat active - recover or reset first.")
    if _sim_running():
        raise HTTPException(409, "Simulator already running.")
    _sim_proc = subprocess.Popen(
        [sys.executable, str(SIM), "--target", str(engine.layout.protected), "--delay", "0.7"])
    return {"started": True}


@app.post("/api/demo/reset")
def demo_reset():
    global _sim_proc
    if _sim_running():
        _sim_proc.terminate()
    engine.reset_demo()
    return {"state": engine.state}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
