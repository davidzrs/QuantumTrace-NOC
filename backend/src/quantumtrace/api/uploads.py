"""Safe materialisation of uploaded files (incl. zip and gzip) into a temp directory.

Two budgets apply. `max_upload` caps the bytes received, which on Vercel is what the platform
limits. `max_unpacked` caps what lands on disk once `.zip` archives and `.gz` files are
expanded, so a small compressed upload can't unpack into gigabytes. Zip entries under folders
the engine never reads (`.git`, `node_modules`, virtualenvs) aren't unpacked or counted, so a
zipped repository fits the same budget as the folder the browser would have sent.
"""

from __future__ import annotations

import gzip
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Protocol

from fastapi import HTTPException, UploadFile, status

from quantumtrace.core.engine import IGNORED_DIRS

CHUNK = 1024 * 1024


class _Readable(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


def _too_large(what: str, max_bytes: int, advice: str) -> HTTPException:
    limit = max_bytes // (1024 * 1024)
    return HTTPException(
        status.HTTP_413_CONTENT_TOO_LARGE, f"{what} is over the {limit} MB limit. {advice}"
    )


def _safe_name(name: str) -> PurePosixPath:
    parts = [
        p for p in PurePosixPath(name.replace("\\", "/")).parts if p not in ("", ".", "..", "/")
    ]
    if not parts:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid file name: {name!r}")
    return PurePosixPath(*parts)


def display_name(name: str) -> str:
    """The name the user picked: clients may gzip files in transit and append `.gz`."""
    return name.removesuffix(".gz")


class _Budget:
    def __init__(self, max_upload: int, max_unpacked: int) -> None:
        self.max_upload, self.max_unpacked = max_upload, max_unpacked
        self.received = self.unpacked = 0

    def receive(self, n: int) -> None:
        self.received += n
        if self.received > self.max_upload:
            raise _too_large("Upload", self.max_upload, "Scan fewer files at once.")

    def unpack(self, n: int) -> None:
        self.unpacked += n
        if self.unpacked > self.max_unpacked:
            raise _too_large(
                "Unpacked upload", self.max_unpacked, "Scan a smaller folder or capture."
            )


def _copy(src: _Readable, dest: Path, count: Callable[[int], None]) -> None:
    with dest.open("wb") as out:
        while chunk := src.read(CHUNK):
            count(len(chunk))  # raises before an oversized chunk is written
            out.write(chunk)


async def materialise(
    files: list[UploadFile], dest: Path, *, max_upload: int, max_unpacked: int
) -> None:
    budget = _Budget(max_upload, max_unpacked)
    for upload in files:
        name = _safe_name(upload.filename or "upload.bin")
        received = dest / name
        received.parent.mkdir(parents=True, exist_ok=True)
        _copy(upload.file, received, budget.receive)

        target = received
        if received.suffix == ".gz" and _is_gzip(received):
            target = received.with_suffix("")  # auth.py.gz -> auth.py
            try:
                with gzip.open(received, "rb") as gz:
                    _copy(gz, target, budget.unpack)
            except (OSError, EOFError) as exc:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST, f"{name} is not a valid gzip file."
                ) from exc
            received.unlink()
        else:
            budget.unpack(received.stat().st_size)

        if zipfile.is_zipfile(target):
            _extract(target, target.with_suffix(""), budget)
            target.unlink()


def _is_gzip(path: Path) -> bool:
    with path.open("rb") as fh:
        return fh.read(2) == b"\x1f\x8b"


def _extract(
    archive: Path,
    dest: Path,
    budget: _Budget,
    *,
    keep: Callable[[PurePosixPath, int], bool] | None = None,
    strip_top: bool = False,
) -> tuple[int, int]:
    """Unpack `archive` into `dest`. `keep(path, size)` filters entries; `strip_top` drops a
    single top-level folder whatever its name. Returns (files unpacked, files in the archive)."""
    kept = 0
    with zipfile.ZipFile(archive) as zf:
        entries = [(i, _safe_name(i.filename)) for i in zf.infolist() if not i.is_dir()]
        # repo.zip usually holds repo/...: unpack to repo/app.py, not repo/repo/app.py
        tops = {name.parts[0] for _, name in entries if len(name.parts) > 1}
        nested = len(tops) == 1 and all(len(n.parts) > 1 for _, n in entries)
        strip = 1 if nested and (strip_top or tops == {dest.name}) else 0
        for info, full in entries:
            name = PurePosixPath(*full.parts[strip:])
            if IGNORED_DIRS.intersection(name.parts[:-1]):
                continue
            if keep is not None and not keep(name, info.file_size):
                continue
            out = dest / name
            if not out.resolve().is_relative_to(dest.resolve()):
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unsafe path in archive")
            out.parent.mkdir(parents=True, exist_ok=True)
            # count the bytes actually written: the size in the zip header can lie
            with zf.open(info) as src:
                _copy(src, out, budget.unpack)
            kept += 1
    return kept, len(entries)
