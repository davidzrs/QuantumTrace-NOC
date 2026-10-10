"""Safe materialisation of uploaded files (incl. zip archives) into a temp directory."""

from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath

from fastapi import HTTPException, UploadFile, status


def _too_large(what: str, max_bytes: int) -> HTTPException:
    limit = max_bytes // (1024 * 1024)
    return HTTPException(
        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        f"{what} is over the {limit} MB limit. Scan fewer files at once.",
    )


def _safe_name(name: str) -> PurePosixPath:
    parts = [
        p for p in PurePosixPath(name.replace("\\", "/")).parts if p not in ("", ".", "..", "/")
    ]
    if not parts:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid file name: {name!r}")
    return PurePosixPath(*parts)


async def materialise(files: list[UploadFile], dest: Path, max_bytes: int) -> None:
    total = 0
    for upload in files:
        data = await upload.read()
        total += len(data)
        if total > max_bytes:
            raise _too_large("Upload", max_bytes)
        target = dest / _safe_name(upload.filename or "upload.bin")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        if zipfile.is_zipfile(target):
            total = _extract(target, target.with_suffix(""), total, max_bytes)
            target.unlink()


def _extract(archive: Path, dest: Path, total: int, max_bytes: int) -> int:
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            total += info.file_size
            if total > max_bytes:
                raise _too_large("Unpacked archive", max_bytes)
            out = dest / _safe_name(info.filename)
            if not out.resolve().is_relative_to(dest.resolve()):
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unsafe path in archive")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(zf.read(info))
    return total
