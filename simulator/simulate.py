#!/usr/bin/env python3
"""
HARMLESS ransomware-BEHAVIOUR simulator for the RansomShield demo.

It only imitates what detectors look for: many files rewritten quickly with
random (high-entropy) bytes, then renamed with a new extension.

Hard guard rails (this is a demo fixture, not a tool):
  * refuses to run unless --target is a folder named "Protected" whose parent
    holds the .ransomshield_demo marker created by RansomShield
  * top-level files only, no recursion, no symlinks, capped file count
  * no encryption keys, no ransom note, no network, no persistence
  * the original data lives in RansomShield's Backup/ snapshots
"""
import argparse
import os
import sys
import time
from pathlib import Path

MARKER = ".ransomshield_demo"
COMPRESSED_EXT = {".jpg", ".jpeg", ".png", ".gif", ".zip", ".gz", ".7z", ".rar",
                  ".mp3", ".mp4", ".mkv", ".pdf", ".docx", ".xlsx", ".pptx"}
SUSPICIOUS_KINDS = ("entropy", "ext", "canary")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="demo/Protected folder")
    ap.add_argument("--delay", type=float, default=0.5, help="seconds between files")
    ap.add_argument("--max-files", type=int, default=25)
    args = ap.parse_args()

    target = Path(args.target).resolve()
    root = target.parent
    if target.name != "Protected" or not (root / MARKER).exists():
        print("REFUSING: target is not a RansomShield demo 'Protected' folder.", file=sys.stderr)
        return 2

    logs = root / "Logs"
    logs.mkdir(exist_ok=True)
    pidfile = logs / "sim.pid"
    pidfile.write_text(str(os.getpid()))

    try:
        files = sorted(
            (p for p in target.iterdir()
             if p.is_file() and not p.is_symlink() and not p.name.startswith(".") and p.suffix != ".locked"),
            key=lambda p: p.name.lower(),
        )[: args.max_files]
        for p in files:
            try:
                size = p.stat().st_size
                with open(p, "r+b") as f:
                    f.write(os.urandom(size))
                p.rename(p.with_name(p.name + ".locked"))
                print(f"[sim] 'encrypted' {p.name}", flush=True)
            except PermissionError:
                print("[sim] write blocked - folder is locked. Stopping.", flush=True)
                break
            time.sleep(args.delay)
    finally:
        try:
            pidfile.unlink()
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
