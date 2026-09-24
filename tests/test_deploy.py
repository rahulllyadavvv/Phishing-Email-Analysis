"""Checks on the Docker setup (static: nothing is built or started here)."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
SERVICES = COMPOSE["services"]


def _volumes(service: str) -> list[str]:
    return [v.split(":")[0] for v in SERVICES[service].get("volumes", [])]


def test_services_and_ports() -> None:
    assert set(SERVICES) == {"redis", "api", "worker", "ui"}
    assert "8000:8000" in SERVICES["api"]["ports"] and "8501:8501" in SERVICES["ui"]["ports"]
    assert SERVICES["ui"]["environment"]["PHISHLENS_API_URL"] == "http://api:8000"


def test_ui_has_no_access_to_quarantine() -> None:
    assert "quarantine" in _volumes("api") and "quarantine" in _volumes("worker")
    assert "data" in _volumes("api") and "data" in _volumes("worker")
    assert _volumes("ui") == []


def test_health_checks_and_env_file() -> None:
    assert "healthcheck" in SERVICES["api"] and "healthcheck" in SERVICES["redis"]
    for name in ("api", "worker", "ui"):
        assert SERVICES[name]["env_file"] == [{"path": ".env", "required": False}]
        assert SERVICES[name]["depends_on"]


def test_image_runs_as_non_root_and_keeps_secrets_out() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert dockerfile.startswith("# PhishLens") and "FROM python:3.11-slim" in dockerfile
    assert "\nUSER phishlens\n" in dockerfile
    for package in ("libmagic1", "libzbar0", "libpango-1.0-0", "libcairo2", "yara"):
        assert package in dockerfile
    ignored = (ROOT / ".dockerignore").read_text().split()
    assert {".env", ".git", "samples", "quarantine", "reports", "*.sqlite"} <= set(ignored)


def test_makefile_targets() -> None:
    makefile = (ROOT / "Makefile").read_text()
    for target in ("up:", "down:", "test:", "lint:", "fixtures:"):
        assert f"\n{target}" in f"\n{makefile}"


def test_ci_workflow() -> None:
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    assert set(ci[True]) == {"push", "pull_request"}  # YAML 1.1 reads the key "on" as True
    steps = ci["jobs"]["test"]["steps"]
    commands = " ".join(step.get("run", "") for step in steps)
    assert "ruff check ." in commands and "pytest" in commands and "libzbar0" in commands
    python = next(s for s in steps if s.get("uses", "").startswith("actions/setup-python"))
    assert python["with"]["python-version"] == "3.11" and python["with"]["cache"] == "pip"
    build = [s for s in ci["jobs"]["docker"]["steps"] if "build-push-action" in s.get("uses", "")]
    assert build and build[0]["with"]["push"] is False
