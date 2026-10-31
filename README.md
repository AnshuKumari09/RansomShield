# RansomShield

Behavior-based ransomware detection, automatic containment and file recovery.
Hackathon prototype. Works on one isolated demo folder with a harmless simulator.

## Run (2 minutes)

```bash
pip install -r requirements.txt
python run.py
# open http://127.0.0.1:8000
```

The first start creates `demo/` (Protected, Backup, Canary, Logs, Quarantine) with sample files,
three decoy "canary" files and a first safe snapshot.

## Live demo script (3 scenarios)

1. **Normal activity**: click **1. Edit a file normally**. Score rises by 1, status stays **SAFE**.
   Wait ~7 s: the edit is auto-snapshotted (header shows "Last safe snapshot").
2. **Attack**: click **2. Launch simulated attack**. Within ~1.5 s the band turns red,
   **THREAT DETECTED**, score crosses the threshold, and the alert panel lists why
   (files changed fast, high-entropy rewrites, extension changes, canary touched).
3. **Response**: it flips to **THREAT CONTAINED**: simulator process killed, folder locked read-only.
   Click **3. Recover files** (or tick *Recover automatically*): files restored from the snapshot,
   suspicious `*.locked` files moved to `demo/Quarantine/`, SHA-256 integrity check passes,
   status **FILES RECOVERED**.

**Reset demo** puts everything back for the next judge.

## How detection works

| Signal | Points | Idea |
|---|---|---|
| Distinct file changed in 6 s window | 1 each | Mass modification |
| File rewritten to high entropy (>=7.0 bits/byte and +1.5 vs snapshot) | 3 each | Encrypted data looks random |
| File renamed to a different extension | 3 each | `.locked`-style renames |
| Canary file modified / renamed / deleted | 10 | Instant alert, nothing legit touches decoys |

Score >= 10 (or any canary touch) raises an alert and starts containment.
Normal edits score ~1, so no false alarm.

## Architecture / team mapping

- `app/engine.py`: watchdog monitor, scoring, canaries (Member 1); containment, snapshots, recovery (Member 2)
- `app/main.py` + SQLite log (`demo/Logs/ransomshield.db`) + API, `tests/` (Member 4)
- `app/static/index.html`: dashboard (Member 3). Plain HTML/JS to avoid an npm build during a hackathon;
  it only needs the JSON API, so porting to React + Recharts is straightforward if you want it.
- `simulator/simulate.py`: harmless behaviour simulator, refuses to run outside the demo folder.

API: `GET /api/status|files|events|alerts`, `POST /api/snapshot|recover|resume|config`,
`POST /api/demo/normal-edit|attack|reset`.

Tests: `pytest -q` (the attack test takes a few seconds, the auto-snapshot test ~7 s).

## Be honest with judges (limits)

- Prototype on one folder, not a production antivirus; no guarantee against real ransomware.
- Similar tools exist; the contribution is the integrated detect -> contain -> recover workflow.
- Process attribution is simplified: the simulator registers its PID in `Logs/sim.pid` and that is the
  process RansomShield stops. Real attribution needs OS-level hooks (ETW / eBPF / minifilter) - say so as future work.
- Locking uses file permissions. Running as root/admin bypasses permissions (the process kill still applies);
  on Windows only the read-only file attribute is applied.
- Recovery restores the *last safe snapshot*; edits made after it are lost. Benign edits are re-snapshotted
  automatically after ~7 s of quiet, and never while anything looks suspicious.
# RansomShield
