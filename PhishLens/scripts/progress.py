"""Print a progress bar for the PhishLens build plan.

Steps come from the plan in docs/PhishLens_Claude_Code_Prompts.md ("### P2.1 ..." headings under
"# Phase 2: ..." headings). A step counts as done when a git commit subject starts with its
number (e.g. "P2.1: DNS helper"). Optional phases are shown but left out of the overall total.

Usage: python scripts/progress.py [--width N]
"""

from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLAN = ROOT / "docs" / "PhishLens_Claude_Code_Prompts.md"

PHASE_RE = re.compile(r"^# Phase (\d+)(\s*\(optional\))?:\s*(.+?)\s*$", re.IGNORECASE)
STEP_RE = re.compile(r"^### P(\d+\.\d+)\s+(.+?)\s*$")
COMMIT_RE = re.compile(r"^P(\d+\.\d+):")


@dataclass
class Phase:
    number: int
    title: str
    optional: bool = False
    steps: list[tuple[str, str]] = field(default_factory=list)


def parse_plan(text: str) -> list[Phase]:
    """Return the phases and their (step id, step title) pairs from the plan markdown."""
    phases: list[Phase] = []
    for line in text.splitlines():
        if m := PHASE_RE.match(line):
            phases.append(Phase(int(m.group(1)), m.group(3), optional=bool(m.group(2))))
        elif (m := STEP_RE.match(line)) and phases:
            title = m.group(2).replace("[PLAN FIRST]", "").strip()
            phases[-1].steps.append((m.group(1), title))
    return phases


def done_steps(subjects: list[str]) -> set[str]:
    """Return the step ids ("P1.2" -> "1.2") found at the start of commit subjects."""
    return {m.group(1) for s in subjects if (m := COMMIT_RE.match(s))}


def git_subjects(root: Path = ROOT) -> list[str]:
    out = subprocess.run(
        ["git", "log", "--format=%s"], cwd=root, capture_output=True, text=True, check=True
    )
    return out.stdout.splitlines()


def bar(done: int, total: int, width: int) -> str:
    filled = round(width * done / total) if total else 0
    return "█" * filled + "░" * (width - filled)


def render(phases: list[Phase], done: set[str], width: int = 20) -> str:
    required = [s for p in phases if not p.optional for s, _ in p.steps]
    total_done = sum(s in done for s in required)
    pct = round(100 * total_done / len(required)) if required else 0
    lines = [
        f"Overall  [{bar(total_done, len(required), width + 14)}]  "
        f"{total_done}/{len(required)}  {pct}%",
        "",
    ]
    next_step = next(
        ((s, t) for p in phases for s, t in p.steps if s not in done), None
    )
    name_width = max((len(p.title) for p in phases), default=0)
    name_width = min(name_width, 32)
    for p in phases:
        n = sum(s in done for s, _ in p.steps)
        title = p.title if len(p.title) <= name_width else p.title[: name_width - 1] + "…"
        label = f"P{p.number:<2} {title:<{name_width}}"
        status = ""
        if p.steps and n == len(p.steps):
            status = "✅"
        elif next_step and any(s == next_step[0] for s, _ in p.steps):
            status = f"→ next: P{next_step[0]} {next_step[1]}"
        if p.optional:
            status = f"{status} (optional)".strip()
        counts = f"{n}/{len(p.steps)}"
        lines.append(f"{label} [{bar(n, len(p.steps), width)}]  {counts:<5} {status}".rstrip())
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--width", type=int, default=20, help="width of the per-phase bars")
    args = parser.parse_args()
    phases = parse_plan(PLAN.read_text(encoding="utf-8"))
    print(render(phases, done_steps(git_subjects()), args.width))


if __name__ == "__main__":
    main()
