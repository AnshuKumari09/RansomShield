import hashlib
import subprocess
import sys
import time
from pathlib import Path

import pytest

from app.engine import Engine, shannon_entropy, sha256_file

SIM = Path(__file__).resolve().parent.parent / "simulator" / "simulate.py"


def wait_for(cond, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return False


@pytest.fixture()
def eng(tmp_path):
    e = Engine(tmp_path / "demo")
    e.start()
    time.sleep(0.5)
    yield e
    try:
        e._set_lock(False)
    finally:
        e.stop()


def snapshot_hashes(e):
    return {p.name: sha256_file(p) for p in e.layout.protected.iterdir() if p.is_file()}


def test_entropy_text_vs_random():
    import os
    assert shannon_entropy(b"hello world " * 200) < 4
    assert shannon_entropy(os.urandom(8192)) > 7.9


def test_normal_edit_stays_safe(eng):
    with open(eng.layout.protected / "project.py", "a") as f:
        f.write("# a normal edit\n")
    time.sleep(1.5)
    assert eng.state == "SAFE"
    assert eng.status()["score"] < eng.status()["threshold"]


def test_legit_edit_survives_later_recovery(eng):
    with open(eng.layout.protected / "project.py", "a") as f:
        f.write("# important new work\n")
    assert wait_for(lambda: eng.status()["snapshot"]["label"] == "auto", timeout=15)
    edited = sha256_file(eng.layout.protected / "project.py")
    subprocess.Popen([sys.executable, str(SIM), "--target", str(eng.layout.protected), "--delay", "0.3"])
    assert wait_for(lambda: eng.state == "CONTAINED")
    assert eng.recover()["verified"]
    assert sha256_file(eng.layout.protected / "project.py") == edited


def test_attack_detected_contained_recovered(eng):
    before = snapshot_hashes(eng)
    proc = subprocess.Popen([sys.executable, str(SIM), "--target", str(eng.layout.protected), "--delay", "0.3"])
    assert wait_for(lambda: eng.state == "CONTAINED"), f"state={eng.state}"
    assert eng.locked
    assert eng.alerts and eng.alerts[0]["reasons"]
    proc.wait(timeout=5)
    assert proc.returncode != 0               # killed by containment
    report = eng.recover()
    assert report["verified"]
    assert eng.state == "RECOVERED"
    assert snapshot_hashes(eng) == before
    assert not any(p.suffix == ".locked" for p in eng.layout.protected.iterdir())


def test_canary_alone_triggers(eng):
    with open(eng.layout.protected / "passwords_backup.txt", "a") as f:
        f.write("tampered\n")
    assert wait_for(lambda: eng.state in ("THREAT", "CONTAINED"))
    assert any("Canary" in r for r in eng.alerts[0]["reasons"])


def test_simulator_refuses_non_demo_target(tmp_path):
    d = tmp_path / "somewhere" / "Protected"
    d.mkdir(parents=True)
    (d / "a.txt").write_text("keep me")
    r = subprocess.run([sys.executable, str(SIM), "--target", str(d)], capture_output=True)
    assert r.returncode == 2
    assert (d / "a.txt").read_text() == "keep me"


def test_bulk_copy_text_no_false_alarm(eng):
    for i in range(15):
        (eng.layout.protected / f"copy_{i}.txt").write_text(f"normal file {i}\n" * 200)
    time.sleep(2)
    assert eng.state == "SAFE"


def test_bulk_copy_compressed_no_false_alarm(eng):
    import os
    for i in range(12):
        (eng.layout.protected / f"photo_{i}.jpg").write_bytes(os.urandom(4096))
    time.sleep(2)
    assert eng.state == "SAFE"