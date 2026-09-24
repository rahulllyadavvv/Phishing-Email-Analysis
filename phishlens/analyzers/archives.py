"""In-memory archive unpacking with zip-bomb limits (helper for the attachment analyzer).

Supported: zip (including ZipCrypto and AES passwords, via pyzipper), 7z (py7zr), tar (plain,
gz, bz2, xz), single-file gzip, and ISO 9660 disk images (pycdlib). Nothing is ever written to
disk or executed: members are decompressed into memory, in chunks, and every chunk is checked
against the limits of one shared ``Budget``:

- ``max_depth``: archives nested deeper than this are not opened;
- ``max_files``: total number of extracted files;
- ``max_total_bytes``: total decompressed size;
- ``file_timeout``: seconds allowed to decompress one member.

Crossing a limit stops that archive (files extracted so far are kept) and records a ``limit``
event, which the analyzer reports as ``archive_limit_exceeded`` (possible zip bomb).

Password-protected members are tried with the candidate passwords in order; events record
which password opened an archive (and whether it came from the email body) or that none did.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import py7zr
import pycdlib
import pyzipper
from py7zr.io import Py7zIO, WriterFactory

from phishlens.analyzers.filetype import category_of_mime, detect_type
from phishlens.models import Attachment
from phishlens.parser.attachments import make_attachment

__all__ = [
    "ARCHIVE_TYPES",
    "Budget",
    "LimitExceeded",
    "PasswordCandidate",
    "UnpackResult",
    "unpack",
]

CHUNK = 64 * 1024

ARCHIVE_TYPES = frozenset(
    {
        "application/zip",
        "application/x-7z-compressed",
        "application/x-tar",
        "application/gzip",
        "application/x-gzip",
        "application/x-bzip2",
        "application/x-xz",
        "application/x-iso9660-image",
    }
)


class LimitExceeded(Exception):
    """A decompression limit was crossed. ``limit`` names it (files, size, depth, timeout)."""

    def __init__(self, limit: str, detail: str) -> None:
        super().__init__(detail)
        self.limit = limit


class WrongPassword(Exception):
    """None of the candidate passwords opened an encrypted member."""


@dataclass(frozen=True)
class PasswordCandidate:
    password: str
    source: str  # "body" or "default"


@dataclass
class Budget:
    """Limits shared by every archive of one email (or one standalone file)."""

    max_depth: int
    max_files: int
    max_total_bytes: int
    file_timeout: float
    files: int = 0
    total_bytes: int = 0
    clock: Callable[[], float] = time.monotonic

    def start_file(self) -> float:
        if self.files >= self.max_files:
            raise LimitExceeded("files", f"more than {self.max_files} files")
        return self.clock() + self.file_timeout

    def add_bytes(self, count: int, deadline: float) -> None:
        self.total_bytes += count
        if self.total_bytes > self.max_total_bytes:
            raise LimitExceeded(
                "size", f"more than {self.max_total_bytes // (1024 * 1024)} MB decompressed"
            )
        if self.clock() > deadline:
            raise LimitExceeded("timeout", f"a member took more than {self.file_timeout:g}s")


@dataclass
class UnpackResult:
    """Files extracted from one top-level attachment (any depth), plus what happened."""

    files: list[Attachment] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)


class _Capped(io.RawIOBase):
    """A writable buffer that charges every write to the budget."""

    def __init__(self, budget: Budget, deadline: float) -> None:
        self.buffer = io.BytesIO()
        self.budget = budget
        self.deadline = deadline

    def writable(self) -> bool:
        return True

    def write(self, data: Any) -> int:
        chunk = bytes(data)
        self.budget.add_bytes(len(chunk), self.deadline)
        return self.buffer.write(chunk)


def _read_capped(stream: Any, budget: Budget) -> bytes:
    """Read a decompressing stream to the end, chunk by chunk, within the budget."""
    deadline = budget.start_file()
    out = _Capped(budget, deadline)
    while chunk := stream.read(CHUNK):
        out.write(chunk)
    return out.buffer.getvalue()


# --- Formats: each yields (member name, bytes) and raises WrongPassword / LimitExceeded ---------


def _zip_members(
    data: bytes, passwords: list[PasswordCandidate], budget: Budget, opened: list
) -> Iterator[tuple[str, bytes]]:
    with pyzipper.AESZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if not info.flag_bits & 0x1:
                with archive.open(info) as stream:
                    yield info.filename, _read_capped(stream, budget)
                continue
            for candidate in ([opened[0]] if opened else []) + passwords:
                try:
                    with archive.open(info, pwd=candidate.password.encode()) as stream:
                        content = _read_capped(stream, budget)
                except (RuntimeError, pyzipper.BadZipFile, ValueError):
                    continue  # wrong password (ZipCrypto may also fail its CRC check)
                if not opened:
                    opened.append(candidate)
                yield info.filename, content
                break
            else:
                raise WrongPassword(info.filename)


class _SevenZipFactory(WriterFactory):
    def __init__(self, budget: Budget) -> None:
        self.budget = budget
        self.products: dict[str, _SevenZipOut] = {}

    def create(self, filename: str) -> Py7zIO:
        product = _SevenZipOut(self.budget, self.budget.start_file())
        self.products[filename] = product
        return product


class _SevenZipOut(Py7zIO):
    def __init__(self, budget: Budget, deadline: float) -> None:
        self.capped = _Capped(budget, deadline)

    def write(self, s: bytes | bytearray) -> int:
        return self.capped.write(s)

    def read(self, size: int | None = None) -> bytes:
        return b""

    def seek(self, offset: int, whence: int = 0) -> int:
        return 0

    def flush(self) -> None:
        return None

    def size(self) -> int:
        return len(self.capped.buffer.getvalue())


def _7z_members(
    data: bytes, passwords: list[PasswordCandidate], budget: Budget, opened: list
) -> Iterator[tuple[str, bytes]]:
    with py7zr.SevenZipFile(io.BytesIO(data)) as probe:
        encrypted = probe.needs_password()
    candidates: list[PasswordCandidate | None] = list(passwords) if encrypted else [None]
    for candidate in candidates:
        try:
            with py7zr.SevenZipFile(
                io.BytesIO(data), password=candidate.password if candidate else None
            ) as archive:
                entries = [e for e in archive.list() if not e.is_directory]
                declared = sum(int(e.uncompressed or 0) for e in entries)
                if budget.total_bytes + declared > budget.max_total_bytes:
                    raise LimitExceeded("size", f"declares {declared} bytes uncompressed")
                factory = _SevenZipFactory(budget)
                archive.extractall(factory=factory)
        except LimitExceeded:
            raise
        except Exception:
            if candidate is None:
                raise
            continue  # wrong password: py7zr raises various decoding errors
        if candidate is not None:
            opened.append(candidate)
        for name, product in factory.products.items():
            yield name, product.capped.buffer.getvalue()
        return
    raise WrongPassword("7z archive")


def _tar_members(data: bytes, budget: Budget) -> Iterator[tuple[str, bytes]]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            if not member.isfile():
                continue  # links, devices and directories are never followed
            stream = archive.extractfile(member)
            if stream is not None:
                yield member.name, _read_capped(stream, budget)


def _gzip_member(data: bytes, name: str, budget: Budget) -> Iterator[tuple[str, bytes]]:
    inner = name[:-3] if name.lower().endswith(".gz") else (name + ".out")
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        yield inner, _read_capped(stream, budget)


def _iso_members(data: bytes, budget: Budget) -> Iterator[tuple[str, bytes]]:
    iso = pycdlib.PyCdlib()
    iso.open_fp(io.BytesIO(data))
    try:
        key = "joliet_path" if iso.has_joliet() else "iso_path"
        for dirname, _dirs, files in iso.walk(**{key: "/"}):
            for filename in files:
                path = dirname.rstrip("/") + "/" + filename
                length = iso.get_record(**{key: path}).get_data_length()
                if budget.total_bytes + length > budget.max_total_bytes:
                    raise LimitExceeded("size", f"{path} declares {length} bytes")
                out = _Capped(budget, budget.start_file())
                iso.get_file_from_iso_fp(out, **{key: path})
                yield path.lstrip("/").split(";")[0], out.buffer.getvalue()
    finally:
        iso.close()


def _members(
    attachment: Attachment,
    mime: str,
    passwords: list[PasswordCandidate],
    budget: Budget,
    opened: list,
) -> Iterator[tuple[str, bytes]]:
    data = attachment.data
    if mime == "application/zip":
        return _zip_members(data, passwords, budget, opened)
    if mime == "application/x-7z-compressed":
        return _7z_members(data, passwords, budget, opened)
    if mime == "application/x-iso9660-image":
        return _iso_members(data, budget)
    if mime == "application/x-tar":
        return _tar_members(data, budget)
    try:  # gz / bz2 / xz: a compressed tar, or a single compressed file
        tarfile.open(fileobj=io.BytesIO(data), mode="r:*").close()
        return _tar_members(data, budget)
    except tarfile.TarError:
        if mime in ("application/gzip", "application/x-gzip"):
            return _gzip_member(data, attachment.filename, budget)
        raise


def _unpack_into(
    attachment: Attachment,
    passwords: list[PasswordCandidate],
    budget: Budget,
    result: UnpackResult,
) -> None:
    mime = attachment.detected_type or detect_type(attachment.data)
    if mime not in ARCHIVE_TYPES:
        return
    name = attachment.filename
    if attachment.depth >= budget.max_depth:
        result.events.append(
            {"archive": name, "event": "limit", "limit": "depth",
             "detail": f"nested deeper than {budget.max_depth} levels"}
        )
        return
    opened: list[PasswordCandidate] = []
    children: list[Attachment] = []
    try:
        for member_name, content in _members(attachment, mime, passwords, budget, opened):
            budget.files += 1
            child = make_attachment(
                member_name, content, parent=name, depth=attachment.depth + 1
            ).model_copy(update={"detected_type": detect_type(content)})
            children.append(child)
    except LimitExceeded as exc:
        result.events.append(
            {"archive": name, "event": "limit", "limit": exc.limit, "detail": str(exc)}
        )
    except WrongPassword:
        result.events.append(
            {"archive": name, "event": "encrypted_unopened", "tried": len(passwords)}
        )
    except Exception as exc:  # corrupt or unsupported archive: keep what we have
        result.events.append(
            {"archive": name, "event": "error", "detail": f"{type(exc).__name__}: {exc}"}
        )
    if opened:
        result.events.append(
            {"archive": name, "event": "encrypted_opened",
             "password": opened[0].password, "source": opened[0].source}
        )
    for child in children:
        result.files.append(child)
        if category_of_mime(child.detected_type) == "archive" or (
            child.detected_type == "application/x-iso9660-image"
        ):
            _unpack_into(child, passwords, budget, result)


def unpack(
    attachment: Attachment, passwords: list[PasswordCandidate], budget: Budget
) -> UnpackResult:
    """Recursively unpack ``attachment`` if it is an archive. Never raises.

    Extracted files get ``parent`` (the containing archive's name), ``depth`` and hashes.
    Synchronous and CPU-bound: call it with ``asyncio.to_thread``.
    """
    result = UnpackResult()
    try:
        _unpack_into(attachment, passwords, budget, result)
    except Exception as exc:
        result.events.append(
            {"archive": attachment.filename, "event": "error",
             "detail": f"{type(exc).__name__}: {exc}"}
        )
    return result
