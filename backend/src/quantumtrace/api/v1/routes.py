from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import Field

from quantumtrace import __version__
from quantumtrace.api.deps import get_repository, require_api_key
from quantumtrace.api.settings import Settings, get_settings
from quantumtrace.api.uploads import display_name, materialise
from quantumtrace.cbom.cyclonedx import to_cyclonedx
from quantumtrace.core.classifier import Rule, default_classifier
from quantumtrace.core.engine import run_probe, run_scan
from quantumtrace.core.models import Model, ScanResult, ScanSummary
from quantumtrace.scanners.network.probe import ProbeError, ProbeRefused
from quantumtrace.store.repository import ScanRepository

public = APIRouter(tags=["meta"])
router = APIRouter(dependencies=[Depends(require_api_key)])

Repo = Annotated[ScanRepository, Depends(get_repository)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


class Health(Model):
    status: str
    version: str
    max_upload_mb: int = Field(description="Largest request a scan accepts, after compression")
    max_unpacked_mb: int = Field(
        description="Largest total a scan accepts once .zip and .gz uploads are unpacked. "
        "Clients that see this field may gzip each file and append .gz to its name."
    )
    persistent: bool = Field(description="Whether scan history survives an API restart")


class Sample(Model):
    name: str
    files: int


class SampleScanRequest(Model):
    sample: str


class TlsProbeRequest(Model):
    host: str = Field(max_length=253, description="Host name or IP, e.g. example.com")
    port: int = Field(default=443, ge=1, le=65535)


@public.get("/health", operation_id="health")
def health(settings: SettingsDep, repo: Repo) -> Health:
    return Health(
        status="ok",
        version=__version__,
        max_upload_mb=settings.max_upload_mb,
        max_unpacked_mb=settings.max_unpacked_mb,
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
        await materialise(
            files,
            dest,
            max_upload=settings.max_upload_mb * 1024 * 1024,
            max_unpacked=settings.max_unpacked_mb * 1024 * 1024,
        )
        result = run_scan([dest], display_targets=upload_targets(files))
        _relativise(result, dest, "")
    repo.save(result)
    return result


def upload_targets(files: list[UploadFile]) -> list[str]:
    """What the user picked: loose files by name, a folder upload once as `folder/`."""
    targets: dict[str, None] = {}
    for f in files:
        name = display_name(f.filename or "upload")
        top, sep, _ = name.replace("\\", "/").lstrip("/").partition("/")
        targets[top + sep] = None
    return list(targets)


@router.post("/probes/tls", tags=["scans"], operation_id="probeTls")
def probe_tls(body: TlsProbeRequest, settings: SettingsDep, repo: Repo) -> ScanResult:
    """Handshake with a live host and classify what it negotiates: TLS version, key exchange
    (classical or hybrid ML-KEM), cipher, what it still permits over TLS 1.2, and the leaf
    certificate key. Public addresses only, unless the API runs with QT_PROBE_PRIVATE."""
    try:
        result = run_probe(body.host, body.port, allow_private=settings.probe_private)
    except ProbeRefused as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except ProbeError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    repo.save(result)
    return result


def _relativise(result: ScanResult, root: Path, prefix: str) -> None:
    """Never leak server filesystem paths: rewrite evidence relative to the scanned root, with
    forward slashes whatever the server's path separator is."""
    base = f"{root}{os.sep}"

    def fix(value: str) -> str:
        if not value.startswith(base):
            return value
        return prefix + value.removeprefix(base).replace(os.sep, "/")

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
