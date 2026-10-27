"""Static analysis of executables, shortcuts and images, and YARA scanning (attachment helpers).

Nothing is run: pefile reads PE headers, LnkParse3 reads shortcut structures, Pillow/pyzbar decode
image pixels, and YARA scans bytes.

- PE: machine, subsystem, DLL or not, whether a signature is present (security directory, not
  validated), compile time (flagged when before 2000 or in the future), suspicious imports,
  section entropy and packer section names.
- LNK: target (relative path / local base path), arguments, working dir and icon; commands
  that run script hosts, LOLBins or remote paths are flagged.
- Images: QR codes (``qr.decode_qr``).
- YARA: every ``*.yar``/``*.yara`` file in ``YARA_RULES_DIR`` (default ``data/yara``), compiled
  once. Rule ``meta: severity`` sets the finding severity (default high).
"""

from __future__ import annotations

import io
import re
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any

import LnkParse3
import pefile
import yara

from phishlens.analyzers.office import OfficeReport as ContentReport
from phishlens.analyzers.qr import decode_qr, qr_available
from phishlens.config import get_settings
from phishlens.data_loader import DATA_DIR, executable_indicators
from phishlens.ioc.defang import defang_url

__all__ = [
    "analyze_image",
    "analyze_lnk",
    "analyze_pe",
    "clear_yara_cache",
    "defang_text",
    "yara_rules",
    "yara_scan",
]

YARA_TIMEOUT_SECONDS = 10
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>]+", re.IGNORECASE)
_EPOCH_2000 = datetime(2000, 1, 1, tzinfo=UTC)


def defang_text(text: str) -> str:
    """Defang every URL inside free text (command lines, arguments)."""
    return _URL_RE.sub(lambda m: defang_url(m.group(0)), text)


# --- PE ------------------------------------------------------------------------------------------


def analyze_pe(data: bytes) -> ContentReport:
    report = ContentReport()
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except Exception as exc:
        report.info["valid_pe"] = False
        report.errors.append(f"pe: not a valid PE ({type(exc).__name__})")
        return report
    try:
        indicators = executable_indicators()
        timestamp = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=UTC)
        unusual_time = timestamp < _EPOCH_2000 or timestamp > datetime.now(UTC)
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        wanted = {name.lower() for name in indicators.suspicious_imports}
        imports: list[str] = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                name = (imp.name or b"").decode("latin-1", "replace")
                base = name[:-1] if name[-1:] in ("A", "W") else name
                if base.lower() in wanted and base not in imports:
                    imports.append(base)
        sections = [
            {
                "name": s.Name.rstrip(b"\0").decode("latin-1", "replace"),
                "entropy": round(s.get_entropy(), 2),
                "size": s.SizeOfRawData,
            }
            for s in pe.sections
        ]
        packer_names = {n.lower() for n in indicators.packer_sections}
        packer_sections = [s["name"] for s in sections if s["name"].lower() in packer_names]
        high_entropy = [
            s["name"] for s in sections
            if s["entropy"] >= indicators.entropy_threshold and s["size"] > 0
        ]
        info = {
            "valid_pe": True,
            "machine": hex(pe.FILE_HEADER.Machine),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "dll": pe.is_dll(),
            "signature_present": security.Size > 0,
            "compile_time": timestamp.isoformat(),
            "unusual_compile_time": unusual_time,
            "suspicious_imports": imports,
            "sections": sections,
        }
    finally:
        pe.close()
    report.info.update(info)
    report.flags.append(
        (
            "pe_executable_attachment",
            {
                "dll": info["dll"],
                "signature_present": info["signature_present"],
                "compile_time": info["compile_time"],
                "unusual_compile_time": unusual_time,
                "suspicious_imports": imports,
            },
        )
    )
    if packer_sections or high_entropy:
        report.flags.append(
            (
                "pe_packed",
                {"packer_sections": packer_sections, "high_entropy_sections": high_entropy},
            )
        )
    return report


# --- LNK -----------------------------------------------------------------------------------------


def analyze_lnk(data: bytes) -> ContentReport:
    report = ContentReport()
    try:
        parsed = LnkParse3.lnk_file(io.BytesIO(data)).get_json()
    except Exception as exc:
        report.errors.append(f"lnk: {type(exc).__name__}: {exc}")
        return report
    strings = parsed.get("data") or {}
    link_info = parsed.get("link_info") or {}
    target = (
        link_info.get("local_base_path")
        or link_info.get("common_path_suffix")
        or strings.get("relative_path")
        or ""
    )
    arguments = strings.get("command_line_arguments") or ""
    info = {
        "target": str(target),
        "arguments": str(arguments),
        "working_directory": strings.get("working_directory"),
        "icon_location": strings.get("icon_location"),
    }
    report.info.update({k: defang_text(v) if isinstance(v, str) else v for k, v in info.items()})
    command = f"{target} {arguments}".lower()
    hits = [c for c in executable_indicators().lnk_commands if c in command]
    if hits:
        report.flags.append(
            (
                "lnk_suspicious_command",
                {
                    "target": defang_text(str(target)),
                    "arguments": defang_text(str(arguments)),
                    "indicators": hits,
                },
            )
        )
    for match in _URL_RE.finditer(f"{target} {arguments}"):
        report.add_url(match.group(0).rstrip(".,;)"))
    return report


# --- Images --------------------------------------------------------------------------------------


def analyze_image(data: bytes) -> ContentReport:
    report = ContentReport()
    if not qr_available():
        report.info["qr_decoding"] = "unavailable (zbar not installed)"
        return report
    texts = decode_qr(data)
    report.info["qr_codes"] = len(texts)
    urls = [t for t in texts if _URL_RE.fullmatch(t.strip())]
    for url in urls:
        if url not in report.qr_urls:
            report.qr_urls.append(url)
    if texts:
        report.flags.append(
            (
                "qr_code_url",
                {
                    "urls": [defang_url(u) for u in urls],
                    "other_texts": [defang_text(t) for t in texts if t not in urls],
                },
            )
        )
    return report


# --- YARA ----------------------------------------------------------------------------------------


def _rules_dir() -> Path:
    configured = get_settings().yara_rules_dir
    return Path(configured) if configured else DATA_DIR / "yara"


@cache
def _compile(directory: str) -> tuple[Any, tuple[str, ...]]:
    """Compile every rule file in ``directory``; files that fail are skipped and reported."""
    folder = Path(directory)
    files = sorted(
        p for p in folder.glob("*") if p.suffix.lower() in (".yar", ".yara") and p.is_file()
    ) if folder.is_dir() else []
    good: dict[str, str] = {}
    errors: list[str] = []
    externals = {"filename": "", "filepath": "", "extension": "", "filetype": ""}
    for path in files:
        try:
            yara.compile(filepath=str(path), externals=externals)
        except yara.Error as exc:
            errors.append(f"yara: {path.name}: {exc}")
            continue
        good[path.stem] = str(path)
    rules = yara.compile(filepaths=good, externals=externals) if good else None
    return rules, tuple(errors)


def yara_rules() -> tuple[Any, tuple[str, ...]]:
    """(compiled rules or None, compile errors) for the configured rules folder."""
    return _compile(str(_rules_dir()))


def clear_yara_cache() -> None:
    _compile.cache_clear()


def yara_scan(data: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    """Match the rules against ``data``. Returns (matches, errors)."""
    rules, errors = yara_rules()
    if rules is None or not data:
        return [], list(errors)
    try:
        matches = rules.match(data=data, timeout=YARA_TIMEOUT_SECONDS)
    except yara.Error as exc:
        return [], [*errors, f"yara: {exc}"]
    found = []
    for match in matches:
        meta = dict(match.meta)
        found.append(
            {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "description": meta.get("description"),
                "severity": str(meta.get("severity", "high")).lower(),
            }
        )
    return found, list(errors)
