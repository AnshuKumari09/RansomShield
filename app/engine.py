"""
RansomShield engine: monitoring -> behaviour scoring -> canary detection
-> containment -> snapshot recovery.

Everything operates only inside one isolated demo folder (see Layout).
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import signal
import sqlite3
import threading
import time
from collections import Counter, deque
from contextlib import contextmanager
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# ----------------------------------------------------------------- tuning
WINDOW_SECONDS = 6.0          # sliding window for behaviour scoring
SCORE_THRESHOLD = 10          # score at which a threat is declared
PTS = {"file": 1, "entropy": 3, "ext": 3, "delete": 1, "canary": 10}
HIGH_ENTROPY = 7.0            # bits/byte; encrypted/random data is ~7.9+
ENTROPY_JUMP = 1.5            # required rise vs. the snapshot baseline
MIN_ENTROPY_BYTES = 1024      # tiny files give noisy entropy
BENIGN_EXT = {".swp", ".tmp", ".bak", ".part", ".crdownload"}
AUTOSNAP_QUIET = 3.0          # quiet seconds before a benign edit is re-snapshotted
MUTE_TAIL = 1.5               # ignore our own chmod/restore echoes (seconds)
KEEP_SNAPSHOTS = 5
MARKER = ".ransomshield_demo"
COMPRESSED_EXT = {".jpg", ".jpeg", ".png", ".gif", ".zip", ".gz", ".7z", ".rar",
                  ".mp3", ".mp4", ".mkv", ".pdf", ".docx", ".xlsx", ".pptx"}
SUSPICIOUS_KINDS = ("entropy", "ext", "canary")


# ----------------------------------------------------------------- helpers
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def file_entropy(path: Path, limit: int = 65536) -> float | None:
    try:
        with open(path, "rb") as f:
            return shannon_entropy(f.read(limit))
    except OSError:
        return None


# ----------------------------------------------------------------- layout
class Layout:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.protected = self.root / "Protected"
        self.backup = self.root / "Backup"
        self.canary = self.root / "Canary"
        self.logs = self.root / "Logs"
        self.quarantine = self.root / "Quarantine"

    def ensure(self):
        for d in (self.protected, self.backup, self.canary, self.logs, self.quarantine):
            d.mkdir(parents=True, exist_ok=True)
        (self.root / MARKER).write_text("RansomShield isolated demo folder. Safe to delete.\n")


def _demo_files() -> dict[str, bytes]:
    code = "".join(f"def step_{i}(x):\n    return x * {i} + {i % 7}\n\n" for i in range(110))
    notes = "".join(f"Meeting note {i}: discuss milestone {i} and assign owners.\n" for i in range(50))
    report = b"%PDF-1.4\n" + "".join(
        f"Research report section {i}: methods, results and discussion of experiment {i}.\n" for i in range(60)
    ).encode()
    image = b"\xff\xd8\xff\xe0" + bytes((i // 16) % 64 for i in range(6000))
    csv = "id,name,score\n" + "".join(f"{i},student_{i},{(i * 37) % 100}\n" for i in range(200))
    return {
        "project.py": code.encode(),
        "report.pdf": report,
        "notes.txt": notes.encode(),
        "image.jpg": image,
        "data.csv": csv.encode(),
    }


def _canary_files() -> dict[str, bytes]:
    filler = "".join(f"Decoy record {i}: do not modify. RansomShield canary.\n" for i in range(40))
    return {
        "Q4_Financials.xlsx": ("CANARY Q4 financials\n" + filler).encode(),
        "passwords_backup.txt": ("CANARY passwords backup\n" + filler).encode(),
        "tax_records_2025.docx": ("CANARY tax records\n" + filler).encode(),
    }


def seed_demo(layout: Layout):
    """Write the sample files students/judges will see."""
    for name, data in _demo_files().items():
        (layout.protected / name).write_bytes(data)


# ----------------------------------------------------------------- watchdog
class _Handler(FileSystemEventHandler):
    def __init__(self, engine: "Engine"):
        self.engine = engine

    def on_any_event(self, event):
        if event.is_directory or event.event_type in ("opened", "closed", "closed_no_write"):
            return
        self.engine.handle(event.event_type, event.src_path, getattr(event, "dest_path", None) or None)


# ----------------------------------------------------------------- engine
class Engine:
    def __init__(self, root):
        self.layout = Layout(root)
        self._lock = threading.RLock()
        self.state = "SAFE"                 # SAFE | THREAT | CONTAINED | RECOVERED
        self.auto_recover = False
        self.locked = False
        self._mute_depth = 0
        self._mute_until = 0.0
        self._window: dict[tuple[str, str], tuple[float, int]] = {}
        self.events: deque = deque(maxlen=300)
        self.alerts: list[dict] = []
        self.history: deque = deque(maxlen=160)
        self._baseline: dict[str, dict] = {}
        self.canaries: dict[str, str] = {}
        self._fcache: dict[str, tuple] = {}
        self._observer = None
        self._ticker = None
        self._stop = threading.Event()
        self._db: sqlite3.Connection | None = None
        self._eid = 0
        self._dirty = False                 # benign changes since last snapshot
        self._last_event = 0.0

    # ------------------------------------------------------------ lifecycle
    def start(self):
        L = self.layout
        L.ensure()
        self._db = sqlite3.connect(L.logs / "ransomshield.db", check_same_thread=False)
        self._db.executescript(
            "CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL, kind TEXT, path TEXT, detail TEXT, score INTEGER);"
            "CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts REAL, body TEXT);"
        )
        if not any(p.is_file() for p in L.protected.iterdir()):
            seed_demo(L)
        self._ensure_canaries()
        snap = self._latest_snapshot_dir()
        if snap:
            self._baseline = json.loads((snap / "manifest.json").read_text())["files"]
        else:
            self.snapshot("startup")
        self._stop.clear()
        self._observer = Observer()
        self._observer.schedule(_Handler(self), str(L.protected), recursive=True)
        self._observer.start()
        self._ticker = threading.Thread(target=self._tick, daemon=True)
        self._ticker.start()

    def stop(self):
        self._stop.set()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)
        if self._ticker:
            self._ticker.join(timeout=2)
        if self._db:
            self._db.close()
            self._db = None

    def _tick(self):
        while not self._stop.wait(0.5):
            with self._lock:
                now = time.time()
                self._prune(now)
                self.history.append((now, self._score()))
                if (self._dirty and self.state in ("SAFE", "RECOVERED") and not self._window
                        and now - self._last_event > AUTOSNAP_QUIET and self._autosnap_ok()):
                    self._dirty = False
                    try:
                        self.snapshot("auto")
                    except (RuntimeError, OSError):
                        pass

    def _autosnap_ok(self) -> bool:
        """Only trust the current folder state if nothing looks suspicious."""
        for f in self.files_view():
            if f["canary"]:
                if f["status"] != "ok":
                    return False
                continue
            if f["status"] in ("modified", "unknown") and self._entropy_flag(f["name"], f["name"]):
                return False
        return True

    @contextmanager
    def _quiet(self):
        """Suppress events caused by RansomShield itself (chmod, restore)."""
        with self._lock:
            self._mute_depth += 1
        try:
            yield
        finally:
            with self._lock:
                self._mute_depth -= 1
                self._mute_until = time.time() + MUTE_TAIL

    # ------------------------------------------------------------ canaries
    def _ensure_canaries(self):
        L = self.layout
        self.canaries = {}
        for name, data in _canary_files().items():
            live, pristine = L.protected / name, L.canary / name
            if not pristine.exists():
                pristine.write_bytes(data)
            if not live.exists():
                shutil.copy2(pristine, live)
            self.canaries[name] = sha256_file(pristine)
        (L.canary / "manifest.json").write_text(json.dumps(self.canaries, indent=2))

    def _canary_changed(self, rel: str) -> bool:
        try:
            return sha256_file(self.layout.protected / rel) != self.canaries[rel]
        except OSError:
            return True

    # ------------------------------------------------------------ detection
    def _rel(self, p) -> str | None:
        if not p:
            return None
        try:
            return Path(p).resolve().relative_to(self.layout.protected).as_posix()
        except (ValueError, OSError):
            return None

    def _add(self, kind: str, rel: str, now: float):
        self._window.setdefault((kind, rel), (now, PTS[kind]))

    def _prune(self, now: float):
        for k in [k for k, (t, _) in self._window.items() if now - t > WINDOW_SECONDS]:
            del self._window[k]

    def _suspicious(self) -> dict:
        """Window entries that look malicious (not plain edits); falls back to everything."""
        sus = {k: v for k, v in self._window.items() if k[0] in ("entropy", "ext", "canary")}
        return sus or dict(self._window)

    def _score(self) -> int:
        return sum(p for _, p in self._window.values())

    def _has_suspicious_signal(self) -> bool:
        return any(k[0] in SUSPICIOUS_KINDS for k in self._window)
    def _entropy_flag(self, rel_now: str, rel_base: str) -> float | None:
        p = self.layout.protected / rel_now
        try:
            if p.stat().st_size < MIN_ENTROPY_BYTES:
                return None
        except OSError:
            return None
        h = file_entropy(p)
        if h is None:
            return None
        base = self._baseline.get(rel_base, {}).get("entropy")
        if base is None and p.suffix.lower() in COMPRESSED_EXT:
            return None                      # naya compressed file: high entropy normal hai
        if h >= HIGH_ENTROPY and (base is None or h - base >= ENTROPY_JUMP):
            return h
        return None

    def _ext_changed(self, rel: str, drel: str) -> bool:
        a, b = Path(rel).suffix.lower(), Path(drel).suffix.lower()
        if a in BENIGN_EXT or b in BENIGN_EXT:
            return False
        if drel in self._baseline and rel not in self._baseline:   # temp-file-then-rename save
            return False
        return a != b

    def handle(self, kind: str, src: str, dest: str | None = None):
        if self._mute_depth > 0 or time.time() < self._mute_until:
            return
        rel, drel = self._rel(src), self._rel(dest)
        if kind == "moved":
            if drel is None:
                kind = "deleted"
            elif rel is None:
                kind, rel = "created", drel
        if rel is None:
            return
        if Path(drel or rel).name.startswith("."):
            return

        with self._lock:
            if self.state == "RECOVERED":
                self.state = "SAFE"
            now = time.time()
            self._prune(now)
            notes: list[str] = []
            canary = None

            if kind in ("modified", "created"):
                if rel in self.canaries:
                    if kind == "created" or self._canary_changed(rel):
                        canary = rel
                else:
                    self._add("file", rel, now)
                    h = self._entropy_flag(rel, rel)
                    if h:
                        self._add("entropy", rel, now)
                        notes.append(f"entropy {h:.2f}")
            elif kind == "deleted":
                if rel in self.canaries:
                    canary = rel
                else:
                    self._add("delete", rel, now)
            elif kind == "moved":
                if rel in self.canaries or drel in self.canaries:
                    canary = rel if rel in self.canaries else drel
                else:
                    self._add("file", rel, now)
                    if self._ext_changed(rel, drel):
                        self._add("ext", rel, now)
                        notes.append(f"{Path(rel).suffix or 'none'} -> {Path(drel).suffix}")
                    h = self._entropy_flag(drel, rel)
                    if h:
                        self._add("entropy", rel, now)
                        notes.append(f"entropy {h:.2f}")
            if canary:
                self._add("canary", canary, now)
                notes.append("CANARY TOUCHED")

            score = self._score()
            self._dirty, self._last_event = True, now
            self._record(kind, drel and f"{rel} -> {drel}" or rel, "; ".join(notes), score)
            if self.state == "SAFE" and (canary or (score >= SCORE_THRESHOLD and self._has_suspicious_signal())):
                self._raise_alert(score, canary, now)

    def _record(self, kind: str, path: str, detail: str, score: int):
        self._eid += 1
        ev = {"id": self._eid, "ts": time.time(), "kind": kind, "path": path, "detail": detail, "score": score}
        self.events.append(ev)
        self._db_run("INSERT INTO events(ts,kind,path,detail,score) VALUES(?,?,?,?,?)",
                     (ev["ts"], kind, path, detail, score))

    def _db_run(self, sql: str, args: tuple = ()):
        if self._db:
            try:
                self._db.execute(sql, args)
                self._db.commit()
            except sqlite3.Error:
                pass

    def _raise_alert(self, score: int, canary: str | None, now: float):
        k = Counter(kind for kind, _ in self._window)
        reasons = []
        if canary:
            reasons.append(f"Canary file touched: {canary}")
        if k["file"]:
            reasons.append(f"{k['file']} file(s) changed within {WINDOW_SECONDS:.0f}s")
        if k["entropy"]:
            reasons.append(f"{k['entropy']} file(s) rewritten with encrypted-looking (high-entropy) data")
        if k["ext"]:
            reasons.append(f"{k['ext']} file(s) renamed to a new extension")
        sus = self._suspicious()
        first = min(t for t, _ in sus.values())
        alert = {
            "id": len(self.alerts) + 1, "ts": now, "score": score, "reasons": reasons,
            "files": sorted({r for _, r in sus}), "actions": [], "status": "detected",
            "metrics": {"detection_seconds": round(now - first, 2), "files_total": len(self._baseline),
                        "files_affected": len({r for _, r in sus})},
        }
        self.state = "THREAT"
        self.alerts.append(alert)
        self._db_run("INSERT INTO alerts(ts,body) VALUES(?,?)", (now, json.dumps(alert)))
        threading.Thread(target=self._contain, args=(alert,), daemon=True).start()

    # ------------------------------------------------------------ containment
    def _kill_simulator(self) -> int | None:
        pf = self.layout.logs / "sim.pid"
        try:
            pid = int(pf.read_text().strip())
        except (OSError, ValueError):
            return None
        if pid == os.getpid():
            return None
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pid = None
        try:
            pf.unlink()
        except OSError:
            pass
        return pid

    def _set_lock(self, lock: bool):
        with self._quiet():
            for p in sorted(self.layout.protected.rglob("*")):
                try:
                    if p.is_dir():
                        os.chmod(p, 0o555 if lock else 0o755)
                    else:
                        os.chmod(p, 0o444 if lock else 0o644)
                except OSError:
                    pass
            try:
                os.chmod(self.layout.protected, 0o555 if lock else 0o755)
            except OSError:
                pass
            self.locked = lock

    def _contain(self, alert: dict):
        t0 = time.time()
        pid = self._kill_simulator()
        alert["actions"].append(
            f"Stopped suspicious process (PID {pid})" if pid else "No registered suspicious process found to stop")
        self._set_lock(True)
        alert["actions"].append("Protected folder locked read-only")
        alert["actions"].append(f"Containment finished in {time.time() - t0:.2f}s")
        with self._lock:
            alert["files"] = sorted(set(alert["files"]) | {r for _, r in self._suspicious()})
            alert["metrics"]["files_affected"] = len(alert["files"])
            alert["metrics"]["containment_seconds"] = round(time.time() - alert["ts"], 2)
            self.state = "CONTAINED"
            alert["status"] = "contained"
        if self.auto_recover:
            try:
                self.recover()
            except Exception as exc:  # noqa: BLE001 - surfaced in alert
                alert["actions"].append(f"Auto-recovery failed: {exc}")

    # ------------------------------------------------------------ snapshots
    def _snapshots(self) -> list[Path]:
        return sorted(d for d in self.layout.backup.glob("snap_*") if (d / "manifest.json").exists())

    def _latest_snapshot_dir(self) -> Path | None:
        s = self._snapshots()
        return s[-1] if s else None

    def snapshot(self, label: str = "manual") -> dict:
        if self.state in ("THREAT", "CONTAINED"):
            raise RuntimeError("Refusing to snapshot while a threat is active.")
        L = self.layout
        sid = f"snap_{int(time.time() * 1000)}"
        files_dir = L.backup / sid / "files"
        files: dict[str, dict] = {}
        for p in sorted(L.protected.rglob("*")):
            if not p.is_file() or p.name.startswith("."):
                continue
            rel = p.relative_to(L.protected).as_posix()
            dst = files_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p, dst)
            files[rel] = {"sha256": sha256_file(dst), "size": dst.stat().st_size, "entropy": file_entropy(dst)}
        manifest = {"id": sid, "label": label, "ts": time.time(), "files": files}
        (L.backup / sid / "manifest.json").write_text(json.dumps(manifest, indent=2))
        self._baseline = files
        for old in self._snapshots()[:-KEEP_SNAPSHOTS]:
            shutil.rmtree(old, ignore_errors=True)
        return {"id": sid, "label": label, "files": len(files)}

    def recover(self) -> dict:
        snap = self._latest_snapshot_dir()
        if not snap:
            raise RuntimeError("No snapshot available.")
        t0 = time.time()
        L = self.layout
        manifest = json.loads((snap / "manifest.json").read_text())["files"]
        restored, quarantined = [], []
        with self._quiet():
            self._set_lock(False)
            qdir = L.quarantine / time.strftime("%Y%m%d-%H%M%S")
            for p in sorted(L.protected.rglob("*")):
                if p.is_file() and not p.name.startswith("."):
                    rel = p.relative_to(L.protected).as_posix()
                    if rel not in manifest:                      # e.g. *.locked files
                        qdir.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(p), str(qdir / p.name))
                        quarantined.append(rel)
            for rel, meta in manifest.items():
                dst, src = L.protected / rel, snap / "files" / rel
                if not dst.exists() or sha256_file(dst) != meta["sha256"]:
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(src, dst)
                    restored.append(rel)
            verified = all(
                (L.protected / rel).exists() and sha256_file(L.protected / rel) == m["sha256"]
                for rel, m in manifest.items())
        with self._lock:
            self._window.clear()
            self._dirty = False
            self.state = "RECOVERED"
            report = {"snapshot": snap.name, "restored": restored, "quarantined": quarantined, "verified": verified}
            if self.alerts:
                a = self.alerts[-1]
                a["status"] = "recovered"
                a["metrics"]["recovery_seconds"] = round(time.time() - t0, 2)
                a["actions"].append(f"Restored {len(restored)} file(s) from snapshot; "
                                    f"quarantined {len(quarantined)} suspicious file(s); "
                                    f"integrity check {'PASSED' if verified else 'FAILED'}")
        return report

    def resume(self):
        """Unlock and return to normal monitoring without restoring."""
        self._set_lock(False)
        with self._lock:
            self._window.clear()
            self.state = "SAFE"

    def reset_demo(self):
        L = self.layout
        self._kill_simulator()
        with self._quiet():
            self._set_lock(False)
            for d in (L.protected, L.backup, L.canary):
                for child in d.iterdir():
                    shutil.rmtree(child, ignore_errors=True) if child.is_dir() else child.unlink()
            seed_demo(L)
            self._ensure_canaries()
            with self._lock:
                self.state = "SAFE"
                self._window.clear()
                self.events.clear()
                self.alerts.clear()
                self.history.clear()
            self.snapshot("reset")

    def report_text(self) -> str:
        if not self.alerts:
            return "RansomShield incident report\n\nNo incidents recorded yet.\n"
        a, m = self.alerts[-1], self.alerts[-1].get("metrics", {})
        fmt = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))
        lines = [
            "RansomShield incident report", "=" * 28,
            f"Incident #{a['id']} detected at {fmt(a['ts'])}",
            f"Final status: {a['status']}    Threat score: {a['score']} (alert at {SCORE_THRESHOLD})", "",
            "Why it fired:", *[f"  - {r}" for r in a["reasons"]], "",
            "Actions taken:", *[f"  - {x}" for x in a["actions"]], "",
            "Metrics:",
            f"  - Detection time (first suspicious change -> alert): {m.get('detection_seconds', 'n/a')} s",
            f"  - Containment time (alert -> contained): {m.get('containment_seconds', 'n/a')} s",
            f"  - Recovery time: {m.get('recovery_seconds', 'n/a')} s",
            f"  - Files affected before containment: {m.get('files_affected', 'n/a')} of {m.get('files_total', 'n/a')}", "",
            "Files involved:", *[f"  - {f}" for f in a["files"]], "",
            "Recent file activity:",
            *[f"  {fmt(e['ts'])}  {e['kind']:<9} {e['path']} {e['detail']}" for e in list(self.events)[-20:]], "",
            "Note: prototype on an isolated demo folder; not a production antivirus.",
        ]
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------ views
    def files_view(self) -> list[dict]:
        L, base, out, seen = self.layout, self._baseline, [], set()
        for p in sorted(L.protected.rglob("*")):
            try:
                if not p.is_file() or p.name.startswith("."):
                    continue
                rel = p.relative_to(L.protected).as_posix()
                st = p.stat()
                key = (st.st_mtime_ns, st.st_size)
                c = self._fcache.get(rel)
                if not c or c[0] != key:
                    c = (key, sha256_file(p), file_entropy(p))
                    self._fcache[rel] = c
            except OSError:
                continue
            seen.add(rel)
            if rel in base:
                status = "ok" if c[1] == base[rel]["sha256"] else "modified"
            else:
                status = "unknown"
            out.append({"name": rel, "size": st.st_size, "entropy": round(c[2] or 0, 2),
                        "status": status, "canary": rel in self.canaries})
        for rel in base:
            if rel not in seen:
                out.append({"name": rel, "size": base[rel]["size"], "entropy": 0, "status": "missing",
                            "canary": rel in self.canaries})
        return out

    def status(self) -> dict:
        with self._lock:
            now = time.time()
            self._prune(now)
            kinds = Counter(k for k, _ in self._window)
            snap = self._latest_snapshot_dir()
            snap_info = None
            if snap:
                m = json.loads((snap / "manifest.json").read_text())
                snap_info = {"id": m["id"], "label": m["label"], "ts": m["ts"], "files": len(m["files"])}
            return {
                "state": self.state, "score": self._score(), "threshold": SCORE_THRESHOLD,
                "window_seconds": WINDOW_SECONDS, "window": dict(kinds), "locked": self.locked,
                "auto_recover": self.auto_recover, "snapshot": snap_info,
                "history": [(round(t, 2), s) for t, s in self.history], "now": now,
            }
