#!/usr/bin/env python3
"""
Live progress bar for autopilot.py. Run it in a second terminal:

    python3 progress.py            # refresh every 5 seconds until Ctrl+C
    python3 progress.py --once     # print once and exit
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE_FILE = ROOT / ".autopilot" / "state.json"
RUN_LOG = ROOT / "autopilot_run.log"

STEP_RE = re.compile(r"^\[(\d\d:\d\d:\d\d)\] ==> \((\d+)/(\d+)\) (\S+) (.+)$")
TOTAL_RE = re.compile(r"(\d+) processes in guide, (\d+) to run")
FIX_RE = re.compile(r"fix attempt (\d+)/(\d+)")


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"done": [], "history": [], "total_cost_usd": 0.0}


def parse_log() -> dict:
    info = {"total": None, "step": None, "fix": None, "stopped": False, "finished": False}
    try:
        lines = RUN_LOG.read_text(encoding="utf-8").splitlines()
    except OSError:
        return info
    for line in lines:
        if m := TOTAL_RE.search(line):
            info["total"] = int(m.group(2))
        elif m := STEP_RE.match(line):
            info["step"] = {"started": m.group(1), "i": int(m.group(2)), "n": int(m.group(3)),
                            "id": m.group(4), "title": m.group(5)}
            info["fix"] = None
        elif m := FIX_RE.search(line):
            info["fix"] = (int(m.group(1)), int(m.group(2)))
        elif "STOPPED at" in line:
            info["stopped"] = True
        elif "All selected processes completed" in line:
            info["finished"] = True
    return info


def fmt_minutes(mins: float) -> str:
    h, m = divmod(int(round(mins)), 60)
    return f"{h}h {m:02d}m" if h else f"{m}m"


def render() -> str:
    state = load_state()
    info = parse_log()
    step = info["step"]
    total = (step["n"] if step else info["total"]) or 0
    # Steps finished in this run = the current step's index minus one (or all, when finished).
    finished = total if info["finished"] else (step["i"] - 1 if step else 0)

    width = max(20, min(50, shutil.get_terminal_size((80, 20)).columns - 30))
    frac = finished / total if total else 0.0
    filled = int(frac * width)
    bar = "█" * filled + "░" * (width - filled)

    out = [f"PhishLens autopilot  [{bar}] {finished}/{total}  {frac * 100:5.1f}%"]

    if info["finished"]:
        out.append("Status:   all steps completed ✅")
    elif info["stopped"]:
        out.append(f"Status:   STOPPED at {step['id'] if step else '?'} ❌  (see autopilot_run.log)")
    elif step:
        now = datetime.now()
        started = datetime.combine(now.date(), datetime.strptime(step["started"], "%H:%M:%S").time())
        elapsed = (now - started).total_seconds() / 60
        if elapsed < 0:
            elapsed += 24 * 60
        fix = f"  · fix attempt {info['fix'][0]}/{info['fix'][1]}" if info["fix"] else ""
        out.append(f"Now:      {step['id']} {step['title']}  ({fmt_minutes(elapsed)} so far{fix})")
    else:
        out.append("Status:   waiting for autopilot to start…")

    history = [h for h in state.get("history", []) if h.get("ok")]
    if history:
        avg = sum(h["minutes"] for h in history) / len(history)
        remaining = max(total - finished, 0)
        last = history[-1]
        out.append(f"Last:     {last['id']} done in {fmt_minutes(last['minutes'])}"
                   f"{' after ' + str(last['fix_attempts']) + ' fix(es)' if last['fix_attempts'] else ''}")
        out.append(f"Average:  {fmt_minutes(avg)} per step  ·  ETA ~{fmt_minutes(avg * remaining)}")
    cost = state.get("total_cost_usd") or 0.0
    if cost:
        out.append(f"Cost:     ${cost:.2f} reported")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description="Progress bar for autopilot.py")
    ap.add_argument("--once", action="store_true", help="print once and exit")
    ap.add_argument("--interval", type=float, default=5.0, help="refresh interval in seconds")
    args = ap.parse_args()

    if args.once:
        print(render())
        return
    try:
        while True:
            sys.stdout.write("\033[H\033[J" + render() + "\n\n(Ctrl+C to exit)\n")
            sys.stdout.flush()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
