import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent


def _load_script() -> ModuleType:
    path = ROOT / "scripts" / "progress.py"
    spec = importlib.util.spec_from_file_location("progress", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look up their module in sys.modules
    spec.loader.exec_module(module)
    return module


pg = _load_script()

PLAN = """\
# Phase 0: Project setup

### P0.1 Project scaffold
### P0.2 Shared data models

# Phase 1: Input and parsing

### P1.1 Email loader
### P1.2 Header parsing [PLAN FIRST]

# Phase 2 (optional): Mailbox automation

### P2.1 Mailbox ingestion
"""


def test_parse_plan() -> None:
    phases = pg.parse_plan(PLAN)
    assert [(p.number, p.title, p.optional) for p in phases] == [
        (0, "Project setup", False),
        (1, "Input and parsing", False),
        (2, "Mailbox automation", True),
    ]
    assert phases[1].steps == [("1.1", "Email loader"), ("1.2", "Header parsing")]


def test_done_steps_reads_commit_prefixes() -> None:
    subjects = ["P1.1: Email loader", "P0.2: Models", "first commit", "Fix P1.2 typo"]
    assert pg.done_steps(subjects) == {"1.1", "0.2"}


def test_render_counts_and_next_step() -> None:
    out = pg.render(pg.parse_plan(PLAN), {"0.1", "0.2", "1.1"}, width=10)
    lines = out.splitlines()
    # Optional phase is excluded from the overall total.
    assert "3/4  75%" in lines[0]
    assert "2/2" in lines[2] and "✅" in lines[2]
    assert "1/2" in lines[3] and "next: P1.2 Header parsing" in lines[3]
    assert "0/1" in lines[4] and "(optional)" in lines[4]


def test_bar() -> None:
    assert pg.bar(1, 2, 10) == "█" * 5 + "░" * 5
    assert pg.bar(0, 0, 4) == "░░░░"


def test_real_plan_parses() -> None:
    phases = pg.parse_plan((ROOT / "docs" / "PhishLens_Claude_Code_Prompts.md").read_text())
    assert phases[0].steps[0][0] == "0.1"
    assert sum(len(p.steps) for p in phases if not p.optional) > 0
