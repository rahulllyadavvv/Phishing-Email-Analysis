#!/usr/bin/env python3
"""
PhishLens autopilot: runs every process in docs/PROMPTS.md through Claude Code
(headless mode), verifies with pytest + ruff, asks Claude to fix failures,
commits each finished process, and can resume after any stop.

Usage (from the project root):
    python autopilot.py                 # run everything that is not done yet
    python autopilot.py --dry-run       # list processes without running
    python autopilot.py --from P3.1     # start at a specific process
    python autopilot.py --only P6.4     # run one process
    python autopilot.py --include-optional   # also run Phase 16
    python autopilot.py --reset P5.2    # mark a process as not done

Requirements: Claude Code CLI installed and logged in (`claude` on PATH), git, Python 3.10+.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path.cwd()
PROMPTS_FILE = ROOT / "docs" / "PROMPTS.md"
STATE_DIR = ROOT / ".autopilot"
STATE_FILE = STATE_DIR / "state.json"
LOG_DIR = STATE_DIR / "logs"

CLAUDE_TIMEOUT_SEC = 60 * 60          # max time for one Claude Code run
CHECK_TIMEOUT_SEC = 20 * 60           # max time for pytest / ruff
MAX_OUTPUT_FOR_FIX = 6000             # chars of failing output sent back to Claude
OPTIONAL_PHASES = {"16"}

BUILD_RULES = """
You are running in UNATTENDED AUTOPILOT MODE. No human will answer questions.

Rules for this run:
1. Do ONLY the process given below. Do not start other processes, even if you see them in docs/PROMPTS.md.
2. Never ask questions or wait for confirmation. When something is ambiguous, choose the simplest reasonable option that fits CLAUDE.md and record it in docs/DECISIONS.md under the heading of this process.
3. If the process is marked [PLAN FIRST], first write your plan to docs/plans/<process id>.md, then implement it.
4. Use the project virtual environment in .venv (create it with `python -m venv .venv` if it does not exist) and install dependencies there. Never use sudo or install system packages.
5. If a system library is missing (for example libmagic, zbar, yara, WeasyPrint libraries), keep the code, mark only the affected tests with pytest.mark.skipif and a clear reason, and add the missing library to docs/SETUP_NOTES.md.
6. NEVER use real API keys, real malware or real network access in tests. Mock all HTTP and DNS. Do not create or edit .env; only edit .env.example.
7. Before finishing, run `pytest -q` and `ruff check .` (fix with `ruff check . --fix` where possible) and make sure both pass.
8. Do not run git commit; the autopilot commits for you.
9. End your final message with a short summary: files changed, tests added, and anything recorded in DECISIONS.md or SETUP_NOTES.md.
""".strip()

PROCESS_RE = re.compile(
    r"^### (?P<id>P\d+\.\d+) (?P<title>.+?)\s*$\n+```\n(?P<prompt>.*?)\n```\s*\n+\*\*Done when:\*\*\s*(?P<done>.+?)\s*$",
    re.MULTILINE | re.DOTALL,
)


# ---------- helpers ----------

def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def parse_processes() -> list[dict]:
    if not PROMPTS_FILE.exists():
        sys.exit(f"Cannot find {PROMPTS_FILE}. Put the prompt guide at docs/PROMPTS.md.")
    text = PROMPTS_FILE.read_text(encoding="utf-8")
    procs = []
    for m in PROCESS_RE.finditer(text):
        title = m["title"]
        plan_first = "[PLAN FIRST]" in title
        procs.append({
            "id": m["id"],
            "phase": m["id"][1:].split(".")[0],
            "title": title.replace("[PLAN FIRST]", "").strip(),
            "plan_first": plan_first,
            "prompt": m["prompt"].strip(),
            "done_when": m["done"].strip(),
        })
    if not procs:
        sys.exit("No processes found in docs/PROMPTS.md. Check the file format.")
    return procs


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {"done": [], "history": [], "total_cost_usd": 0.0}


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def venv_python() -> str:
    for candidate in (ROOT / ".venv" / "bin" / "python", ROOT / ".venv" / "Scripts" / "python.exe"):
        if candidate.exists():
            return str(candidate)
    return sys.executable


def run(cmd: list[str], timeout: int) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"Command timed out after {timeout}s: {' '.join(cmd)}"


def ensure_prereqs() -> None:
    if not shutil.which("claude"):
        sys.exit("Claude Code CLI ('claude') not found on PATH. Install it and log in first.")
    if not shutil.which("git"):
        sys.exit("git not found on PATH.")
    if not (ROOT / ".git").exists():
        log("No git repo found, running git init")
        run(["git", "init"], 60)
    gi = ROOT / ".gitignore"
    existing = gi.read_text(encoding="utf-8") if gi.exists() else ""
    if ".autopilot/" not in existing:
        with gi.open("a", encoding="utf-8") as f:
            f.write("\n.autopilot/\n.env\n")


def call_claude(prompt: str, args, log_name: str) -> dict:
    cmd = ["claude", "-p", prompt, "--output-format", "json",
           "--permission-mode", args.permission_mode]
    if args.permission_mode != "bypassPermissions":
        cmd += ["--allowedTools", args.allowed_tools]
    else:
        cmd = ["claude", "-p", prompt, "--output-format", "json", "--dangerously-skip-permissions"]
    code, out = run(cmd, CLAUDE_TIMEOUT_SEC)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / f"{log_name}.log").write_text(out, encoding="utf-8")
    result = {"exit_code": code, "is_error": code != 0, "result": out[-2000:], "cost": 0.0}
    try:
        data = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
        result["is_error"] = bool(data.get("is_error", code != 0))
        result["result"] = str(data.get("result", ""))[-2000:]
        result["cost"] = float(data.get("total_cost_usd") or 0.0)
    except (json.JSONDecodeError, IndexError, ValueError):
        pass
    return result


def verify() -> tuple[bool, str]:
    py = venv_python()
    t_code, t_out = run([py, "-m", "pytest", "-q", "-x", "--no-header"], CHECK_TIMEOUT_SEC)
    tests_ok = t_code in (0, 5)          # 5 = no tests collected (early phases)
    r_code, r_out = run([py, "-m", "ruff", "check", "."], CHECK_TIMEOUT_SEC)
    lint_ok = r_code == 0
    report = f"--- pytest (exit {t_code}) ---\n{t_out[-MAX_OUTPUT_FOR_FIX:]}\n" \
             f"--- ruff (exit {r_code}) ---\n{r_out[-2000:]}"
    return tests_ok and lint_ok, report


def build_prompt(proc: dict) -> str:
    flag = " [PLAN FIRST]" if proc["plan_first"] else ""
    return (f"{BUILD_RULES}\n\n"
            f"=== PROCESS {proc['id']}: {proc['title']}{flag} ===\n\n"
            f"{proc['prompt']}\n\n"
            f"DONE WHEN: {proc['done_when']}\n"
            f"Check the DONE WHEN condition yourself before finishing.")


def build_fix_prompt(proc: dict, report: str, attempt: int) -> str:
    return (f"{BUILD_RULES}\n\n"
            f"=== FIX ATTEMPT {attempt} FOR PROCESS {proc['id']}: {proc['title']} ===\n"
            f"The process was implemented but verification failed. Fix the problems below "
            f"without changing behavior required by earlier processes. Stay within the scope of {proc['id']}.\n\n"
            f"DONE WHEN: {proc['done_when']}\n\n"
            f"Verification output:\n{report}")


def commit(proc: dict) -> None:
    run(["git", "add", "-A"], 120)
    code, out = run(["git", "commit", "-m", f"{proc['id']}: {proc['title']}", "--no-verify"], 120)
    if code != 0 and "nothing to commit" not in out:
        log(f"git commit warning: {out.strip()[:300]}")


# ---------- main loop ----------

def main() -> None:
    ap = argparse.ArgumentParser(description="PhishLens Claude Code autopilot")
    ap.add_argument("--from", dest="start", help="start at this process id, e.g. P3.1")
    ap.add_argument("--to", dest="end", help="stop after this process id")
    ap.add_argument("--only", help="run a single process id")
    ap.add_argument("--include-optional", action="store_true", help="also run Phase 16")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--reset", help="mark a process as not done and exit")
    ap.add_argument("--max-fix-attempts", type=int, default=3)
    ap.add_argument("--permission-mode", default="acceptEdits",
                    choices=["acceptEdits", "auto", "bypassPermissions"],
                    help="bypassPermissions only inside a disposable container/VM")
    ap.add_argument("--allowed-tools", default="Read,Edit,Write,Glob,Grep,Bash",
                    help="tools Claude may use without asking")
    args = ap.parse_args()

    procs = parse_processes()
    state = load_state()

    if args.reset:
        state["done"] = [p for p in state["done"] if p != args.reset]
        save_state(state)
        log(f"{args.reset} marked as not done.")
        return

    ids = [p["id"] for p in procs]
    for opt in (args.start, args.end, args.only):
        if opt and opt not in ids:
            sys.exit(f"Unknown process id {opt}. Valid: {', '.join(ids)}")

    selected, active = [], args.start is None
    for p in procs:
        if args.only:
            if p["id"] == args.only:
                selected.append(p)
            continue
        if p["id"] == args.start:
            active = True
        if active and (args.include_optional or p["phase"] not in OPTIONAL_PHASES):
            selected.append(p)
        if p["id"] == args.end:
            break

    todo = [p for p in selected if p["id"] not in state["done"] or args.only]
    log(f"{len(procs)} processes in guide, {len(todo)} to run.")
    if args.dry_run:
        for p in todo:
            print(f"  {p['id']:6} {'[PLAN FIRST] ' if p['plan_first'] else ''}{p['title']}")
        return

    ensure_prereqs()

    for i, proc in enumerate(todo, 1):
        log(f"==> ({i}/{len(todo)}) {proc['id']} {proc['title']}")
        started = time.time()
        res = call_claude(build_prompt(proc), args, proc["id"])
        state["total_cost_usd"] += res["cost"]
        if res["is_error"]:
            log(f"Claude Code reported an error for {proc['id']}: {res['result'][-500:]}")

        ok, report = verify()
        attempt = 0
        while not ok and attempt < args.max_fix_attempts:
            attempt += 1
            log(f"Verification failed, fix attempt {attempt}/{args.max_fix_attempts}")
            res = call_claude(build_fix_prompt(proc, report, attempt), args, f"{proc['id']}_fix{attempt}")
            state["total_cost_usd"] += res["cost"]
            ok, report = verify()

        state["history"].append({"id": proc["id"], "ok": ok, "fix_attempts": attempt,
                                 "minutes": round((time.time() - started) / 60, 1)})
        if not ok:
            (LOG_DIR / f"{proc['id']}_verify.log").write_text(report, encoding="utf-8")
            save_state(state)
            log(f"STOPPED at {proc['id']}: tests/lint still failing after {attempt} fix attempts.")
            log(f"See .autopilot/logs/{proc['id']}_verify.log. Resume with: python autopilot.py --from {proc['id']}")
            sys.exit(1)

        commit(proc)
        state["done"].append(proc["id"])
        save_state(state)
        log(f"Done {proc['id']} in {state['history'][-1]['minutes']} min "
            f"(reported cost so far ${state['total_cost_usd']:.2f})")

    log("All selected processes completed.")
    log("Manual step left: copy .env.example to .env and add your API keys, then run `docker compose up`.")
    if (ROOT / "docs" / "SETUP_NOTES.md").exists():
        log("Also read docs/SETUP_NOTES.md for any system libraries to install.")


if __name__ == "__main__":
    main()
