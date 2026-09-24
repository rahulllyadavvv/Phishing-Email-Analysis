"""Tests for phishlens.analyzers.archives. All archives are built in memory from harmless
bytes; nothing touches the disk."""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile

import py7zr
import pycdlib
import pyzipper

from phishlens.analyzers.archives import Budget, PasswordCandidate, unpack
from phishlens.analyzers.filetype import detect_type
from phishlens.parser.attachments import make_attachment

MB = 1024 * 1024


def _budget(**kw) -> Budget:
    defaults = dict(max_depth=3, max_files=100, max_total_bytes=200 * MB, file_timeout=10.0)
    return Budget(**{**defaults, **kw})


def _att(name: str, data: bytes, depth: int = 0):
    return make_attachment(name, data, depth=depth).model_copy(
        update={"detected_type": detect_type(data)}
    )


def _zip(entries: dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buf.getvalue()


def _events(result, kind: str) -> list[dict]:
    return [e for e in result.events if e["event"] == kind]


def test_zip_members_are_extracted_and_hashed() -> None:
    result = unpack(_att("a.zip", _zip({"x.txt": b"hello", "dir/y.bin": b"MZ..."})), [], _budget())
    files = {f.filename: f for f in result.files}
    assert set(files) == {"x.txt", "dir/y.bin"}
    assert files["x.txt"].parent == "a.zip" and files["x.txt"].depth == 1
    assert files["x.txt"].sha256 == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )
    assert files["dir/y.bin"].detected_type == "application/x-dosexec"
    assert result.events == []


def test_non_archive_is_left_alone() -> None:
    result = unpack(_att("a.txt", b"plain"), [], _budget())
    assert result.files == [] and result.events == []


def test_nested_archives_and_depth_limit() -> None:
    level3 = _zip({"deep.txt": b"deep"})
    level2 = _zip({"l3.zip": level3})
    level1 = _zip({"l2.zip": level2})
    result = unpack(_att("l1.zip", level1), [], _budget(max_depth=2))
    names = [(f.filename, f.parent, f.depth) for f in result.files]
    assert names == [("l2.zip", "l1.zip", 1), ("l3.zip", "l2.zip", 2)]
    [limit] = _events(result, "limit")
    assert (limit["archive"], limit["limit"]) == ("l3.zip", "depth")


def test_file_count_limit_keeps_what_was_extracted() -> None:
    data = _zip({f"f{i}.txt": b"x" for i in range(10)})
    result = unpack(_att("many.zip", data), [], _budget(max_files=4))
    assert len(result.files) == 4
    assert _events(result, "limit")[0]["limit"] == "files"


def test_zip_bomb_size_limit() -> None:
    bomb = _zip({"zeros.bin": b"\0" * (5 * MB)})
    assert len(bomb) < 20_000  # tiny on the wire
    result = unpack(_att("bomb.zip", bomb), [], _budget(max_total_bytes=1 * MB))
    assert result.files == []
    assert _events(result, "limit")[0]["limit"] == "size"


def test_timeout_limit() -> None:
    ticks = iter(range(0, 1000, 5))  # every clock read jumps 5 s
    budget = _budget(file_timeout=4.0)
    budget.clock = lambda: next(ticks)
    result = unpack(_att("slow.zip", _zip({"a.bin": b"a" * (300 * 1024)})), [], budget)
    assert _events(result, "limit")[0]["limit"] == "timeout"


def test_zipcrypto_and_aes_passwords() -> None:
    aes = io.BytesIO()
    with pyzipper.AESZipFile(aes, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as archive:
        archive.setpassword(b"s3cret")
        archive.writestr("a.txt", b"inside")
    candidates = [PasswordCandidate("wrong", "body"), PasswordCandidate("s3cret", "body")]
    result = unpack(_att("aes.zip", aes.getvalue()), candidates, _budget())
    assert [f.data for f in result.files] == [b"inside"]
    [opened] = _events(result, "encrypted_opened")
    assert (opened["password"], opened["source"]) == ("s3cret", "body")

    failed = unpack(_att("aes.zip", aes.getvalue()), candidates[:1], _budget())
    assert failed.files == []
    assert _events(failed, "encrypted_unopened") == [
        {"archive": "aes.zip", "event": "encrypted_unopened", "tried": 1}
    ]


def test_7z_plain_and_encrypted() -> None:
    plain, secret = io.BytesIO(), io.BytesIO()
    with py7zr.SevenZipFile(plain, "w") as archive:
        archive.writestr(b"seven", "s.txt")
    with py7zr.SevenZipFile(secret, "w", password="pw7") as archive:
        archive.writestr(b"hidden", "h.txt")
    assert [f.data for f in unpack(_att("p.7z", plain.getvalue()), [], _budget()).files] == [
        b"seven"
    ]
    result = unpack(
        _att("s.7z", secret.getvalue()),
        [PasswordCandidate("nope", "body"), PasswordCandidate("pw7", "default")],
        _budget(),
    )
    assert [(f.filename, f.data) for f in result.files] == [("h.txt", b"hidden")]
    assert _events(result, "encrypted_opened")[0]["source"] == "default"
    locked = unpack(_att("s.7z", secret.getvalue()), [], _budget())
    assert _events(locked, "encrypted_unopened")


def test_7z_declared_size_limit() -> None:
    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w") as archive:
        archive.writestr(b"\0" * (3 * MB), "big.bin")
    result = unpack(_att("big.7z", buf.getvalue()), [], _budget(max_total_bytes=MB))
    assert _events(result, "limit")[0]["limit"] == "size"


def test_tar_gz_and_single_gzip() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        info = tarfile.TarInfo("docs/t.txt")
        info.size = 3
        archive.addfile(info, io.BytesIO(b"tar"))
        link = tarfile.TarInfo("evil-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive.addfile(link)
    result = unpack(_att("t.tar.gz", buf.getvalue()), [], _budget())
    assert [(f.filename, f.data) for f in result.files] == [("docs/t.txt", b"tar")]

    single = unpack(_att("report.txt.gz", gzip.compress(b"gz body")), [], _budget())
    assert [(f.filename, f.data) for f in single.files] == [("report.txt", b"gz body")]


def test_iso_image() -> None:
    iso = pycdlib.PyCdlib()
    iso.new(joliet=3)
    payload = b"MZ fake exe"
    iso.add_fp(io.BytesIO(payload), len(payload), "/INVOICE.EXE;1", joliet_path="/invoice.exe")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    result = unpack(_att("invoice.iso", out.getvalue()), [], _budget())
    [file] = result.files
    assert (file.filename, file.data, file.parent) == ("invoice.exe", payload, "invoice.iso")
    assert file.detected_type == "application/x-dosexec"


def test_corrupt_archive_is_an_error_event() -> None:
    result = unpack(_att("broken.zip", b"PK\x03\x04" + b"garbage" * 10), [], _budget())
    assert result.files == []
    assert _events(result, "error")


def test_budget_is_shared_across_archives() -> None:
    budget = _budget(max_files=3)
    first = unpack(_att("a.zip", _zip({"1": b"1", "2": b"2"})), [], budget)
    second = unpack(_att("b.zip", _zip({"3": b"3", "4": b"4"})), [], budget)
    assert len(first.files) + len(second.files) == 3
    assert _events(second, "limit")
