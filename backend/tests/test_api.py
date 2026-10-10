from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from quantumtrace.api.app import create_app
from quantumtrace.api.settings import Settings, get_settings


def make_client(samples: Path, api_key: str | None = None) -> TestClient:
    settings = Settings(samples_dir=samples, api_key=api_key)
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app)


@pytest.fixture
def client(samples: Path) -> TestClient:
    return make_client(samples)


def test_health(client: TestClient) -> None:
    assert client.get("/api/v1/health").json()["status"] == "ok"


def test_samples_listed(client: TestClient) -> None:
    names = {s["name"] for s in client.get("/api/v1/samples").json()}
    assert {"cloud-posture", "sample-repos", "network-capture"} <= names


def test_scan_sample_then_fetch_and_export(client: TestClient) -> None:
    res = client.post("/api/v1/scans/sample", json={"sample": "cloud-posture"})
    assert res.status_code == 200
    scan = res.json()
    assert scan["score"]["counts"]["critical"] > 0

    assert client.get(f"/api/v1/scans/{scan['id']}").json()["id"] == scan["id"]
    assert client.get("/api/v1/scans").json()[0]["id"] == scan["id"]
    files = {f["asset"]["evidence"]["context"].get("file") for f in scan["findings"]}
    assert all(p.startswith("samples/cloud-posture/") for p in files), files
    cbom = client.get(f"/api/v1/scans/{scan['id']}/cbom").json()
    assert cbom["specVersion"] == "1.6"


def test_unknown_sample_404(client: TestClient) -> None:
    assert client.post("/api/v1/scans/sample", json={"sample": "../etc"}).status_code == 404


def test_upload_zip(client: TestClient, samples: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        kms = samples / "cloud-posture/kms_key_inventory.json"
        zf.write(kms, "cloud/kms_key_inventory.json")
    res = client.post(
        "/api/v1/scans", files=[("files", ("posture.zip", buf.getvalue(), "application/zip"))]
    )
    assert res.status_code == 200, res.text
    locations = {f["asset"]["evidence"]["context"].get("file") for f in res.json()["findings"]}
    assert locations == {"posture/cloud/kms_key_inventory.json"}


def test_zip_slip_rejected_safely(client: TestClient) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.json", '{"Keys": []}')
    res = client.post("/api/v1/scans", files=[("files", ("x.zip", buf.getvalue()))])
    assert res.status_code == 200  # path components are stripped, file lands inside temp dir


def test_api_key_enforced_when_configured(samples: Path) -> None:
    client = make_client(samples, api_key="s3cret")
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/rules").status_code == 401
    assert client.get("/api/v1/rules", headers={"X-API-Key": "s3cret"}).status_code == 200
