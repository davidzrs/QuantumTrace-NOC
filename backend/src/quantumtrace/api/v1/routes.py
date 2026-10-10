from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import Field

from quantumtrace import __version__
from quantumtrace.api.deps import get_repository, require_api_key
from quantumtrace.api.settings import Settings, get_settings
from quantumtrace.api.uploads import materialise
from quantumtrace.cbom.cyclonedx import to_cyclonedx
from quantumtrace.core.classifier import Rule, default_classifier
from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import Model, ScanResult, ScanSummary
from quantumtrace.store.repository import ScanRepository

public = APIRouter(tags=["meta"])
router = APIRouter(dependencies=[Depends(require_api_key)])

Repo = Annotated[ScanRepository, Depends(get_repository)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


class Health(Model):
    status: str
    version: str
    max_upload_mb: int = Field(description="Largest total upload a scan accepts")
    persistent: bool = Field(description="Whether scan history survives an API restart")


class Sample(Model):
    name: str
    files: int


class SampleScanRequest(Model):
    sample: str


@public.get("/health", operation_id="health")
def health(settings: SettingsDep, repo: Repo) -> Health:
    return Health(
        status="ok",
        version=__version__,
        max_upload_mb=settings.max_upload_mb,
        persistent=repo.persistent,
    )


@router.get("/rules", tags=["rules"], operation_id="listRules")
def list_rules() -> list[Rule]:
    return default_classifier().rules


@router.get("/samples", tags=["scans"], operation_id="listSamples")
def list_samples(settings: SettingsDep) -> list[Sample]:
    root = settings.samples_dir
    if not root.is_dir():
        return []
    return [
        Sample(name=d.name, files=sum(1 for f in d.rglob("*") if f.is_file()))
        for d in sorted(root.iterdir())
        if d.is_dir()
    ]


@router.post("/scans/sample", tags=["scans"], operation_id="scanSample")
def scan_sample(body: SampleScanRequest, settings: SettingsDep, repo: Repo) -> ScanResult:
    names = {s.name for s in list_samples(settings)}
    if body.sample not in names and body.sample != "all":
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown sample {body.sample!r}")
    root = settings.samples_dir
    target = root if body.sample == "all" else root / body.sample
    result = run_scan([target], display_targets=[f"samples/{body.sample}"])
    _relativise(result, root, "samples/")
    repo.save(result)
    return result


@router.post("/scans", tags=["scans"], operation_id="scanUpload")
async def scan_upload(
    files: Annotated[list[UploadFile], File(description="Files or .zip archives to scan")],
    settings: SettingsDep,
    repo: Repo,
) -> ScanResult:
    with tempfile.TemporaryDirectory(prefix="qt-") as tmp:
        dest = Path(tmp)
        await materialise(files, dest, settings.max_upload_mb * 1024 * 1024)
        result = run_scan([dest], display_targets=upload_targets(files))
        _relativise(result, dest, "")
    repo.save(result)
    return result


def upload_targets(files: list[UploadFile]) -> list[str]:
    """What the user picked: loose files by name, a folder upload once as `folder/`."""
    targets: dict[str, None] = {}
    for f in files:
        top, sep, _ = (f.filename or "upload").replace("\\", "/").lstrip("/").partition("/")
        targets[top + sep] = None
    return list(targets)


def _relativise(result: ScanResult, root: Path, prefix: str) -> None:
    """Never leak server filesystem paths: rewrite evidence relative to the scanned root."""
    base = f"{root}/"

    def fix(value: str) -> str:
        return prefix + value.removeprefix(base) if value.startswith(base) else value

    for f in result.findings:
        for ev in f.asset.all_evidence:
            ev.location = fix(ev.location)
            ev.context = {k: fix(v) for k, v in ev.context.items()}


MAX_HISTORY = 50


@router.get("/scans", tags=["scans"], operation_id="listScans")
def list_scans(
    repo: Repo,
    ids: Annotated[
        list[str],
        Query(
            max_length=MAX_HISTORY,
            description="Scan ids to summarise. There is deliberately no way to list every scan: "
            "each client keeps the ids of the scans it ran.",
        ),
    ],
) -> list[ScanSummary]:
    return repo.summaries(ids)


@router.get("/scans/{scan_id}", tags=["scans"], operation_id="getScan")
def get_scan(scan_id: str, repo: Repo) -> ScanResult:
    result = repo.get(scan_id)
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return result


@router.delete(
    "/scans/{scan_id}",
    tags=["scans"],
    operation_id="deleteScan",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_scan(scan_id: str, repo: Repo) -> None:
    """Whoever holds a scan's id can read it, so they can also delete it. Idempotent."""
    repo.delete(scan_id)


@router.get("/scans/{scan_id}/cbom", tags=["scans"], operation_id="getScanCbom")
def get_scan_cbom(scan_id: str, repo: Repo) -> dict[str, Any]:
    return to_cyclonedx(get_scan(scan_id, repo))
