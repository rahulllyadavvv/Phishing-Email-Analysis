"""Download the MITRE ATT&CK Enterprise dataset used for technique names and tactics.

Fetches ``enterprise-attack.json`` from the official MITRE CTI repository on GitHub into
``data/mitre/`` (about 45 MB; gitignored). Without it, PhishLens falls back to the short
technique table in ``data/mitre_rules.yaml``.

Usage: python scripts/update_attack_data.py [--url URL] [--out data/mitre/enterprise-attack.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_OUT = ROOT / "data" / "mitre" / "enterprise-attack.json"


def download(url: str, out: Path, timeout: float = 120.0) -> int:
    """Download to a temporary file, check it is an ATT&CK bundle, then replace ``out``.
    Returns the number of attack-pattern objects."""
    out.parent.mkdir(parents=True, exist_ok=True)
    partial = out.with_suffix(".part")
    with httpx.stream("GET", url, timeout=timeout, follow_redirects=True) as response:
        response.raise_for_status()
        with partial.open("wb") as handle:
            for chunk in response.iter_bytes():
                handle.write(chunk)
    data = json.loads(partial.read_text(encoding="utf-8"))
    if data.get("type") != "bundle":
        partial.unlink(missing_ok=True)
        raise ValueError("downloaded file is not a STIX bundle")
    patterns = sum(1 for o in data.get("objects", []) if o.get("type") == "attack-pattern")
    partial.replace(out)
    return patterns


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download MITRE ATT&CK Enterprise data")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    try:
        count = download(args.url, args.out)
    except (httpx.HTTPError, ValueError, OSError) as exc:
        print(f"Download failed: {exc}", file=sys.stderr)
        return 1
    print(f"Saved {args.out} ({count} techniques)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
