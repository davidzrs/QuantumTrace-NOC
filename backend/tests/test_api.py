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
    body = client.get("/api/v1/health").json()
    assert body["status"] == "ok"
    assert (body["max_upload_mb"], body["max_unpacked_mb"]) == (200, 500)
    assert body["persistent"] is False


def test_upload_over_limit_413(samples: Path) -> None:
    settings = Settings(samples_dir=samples, max_upload_mb=1)
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    res = TestClient(app).post(
        "/api/v1/scans", files=[("files", ("big.bin", b"x" * (1024 * 1024 + 1), "text/plain"))]
    )
    assert res.status_code == 413
    assert "1 MB limit" in res.json()["detail"]


def _client_with(samples: Path, max_upload_mb: int = 200, max_unpacked_mb: int = 500) -> TestClient:
    settings = Settings(
        samples_dir=samples, max_upload_mb=max_upload_mb, max_unpacked_mb=max_unpacked_mb
    )
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app)


def test_gzipped_upload_is_unpacked(samples: Path) -> None:
    import gzip

    src = samples / "network-capture" / "network.pcap"
    client = _client_with(samples)
    res = client.post(
        "/api/v1/scans",
        files=[("files", ("captures/network.pcap.gz", gzip.compress(src.read_bytes())))],
    )
    assert res.status_code == 200
    body = res.json()
    assert body["targets"] == ["captures/"]
    assert "network-pcap" in body["scanners"]
    locations = {f["asset"]["evidence"]["context"].get("file") for f in body["findings"]}
    assert locations == {"captures/network.pcap"}


def test_compressed_size_counts_against_upload_limit(samples: Path) -> None:
    import gzip

    # 3 MB of text gzips to a few KB: under a 1 MB upload limit, within 5 MB unpacked
    client = _client_with(samples, max_upload_mb=1, max_unpacked_mb=5)
    big = gzip.compress(b"import hashlib\n" * 200_000)
    res = client.post("/api/v1/scans", files=[("files", ("app.py.gz", big))])
    assert res.status_code == 200
    assert res.json()["targets"] == ["app.py"]


def test_unpacked_limit_stops_gzip_and_zip_bombs(samples: Path) -> None:
    import gzip

    client = _client_with(samples, max_upload_mb=1, max_unpacked_mb=1)
    bomb = gzip.compress(b"\0" * (2 * 1024 * 1024))
    res = client.post("/api/v1/scans", files=[("files", ("a.py.gz", bomb))])
    assert res.status_code == 413
    assert "Unpacked upload is over the 1 MB limit" in res.json()["detail"]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.py", b"\0" * (2 * 1024 * 1024))
    res = client.post("/api/v1/scans", files=[("files", ("x.zip", buf.getvalue()))])
    assert res.status_code == 413


def test_zip_skips_dependency_folders(samples: Path) -> None:
    # a zipped repo whose node_modules alone is over the unpacked limit still scans
    client = _client_with(samples, max_unpacked_mb=1)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("repo/app.py", "import hashlib\nhashlib.md5(b'x')\n")
        zf.writestr("repo/node_modules/big/index.py", b"#" * (2 * 1024 * 1024))
        zf.writestr("repo/.git/objects/blob", b"\0" * (2 * 1024 * 1024))
    res = client.post("/api/v1/scans", files=[("files", ("repo.zip", buf.getvalue()))])
    assert res.status_code == 200
    files = {f["asset"]["evidence"]["location"] for f in res.json()["findings"]}
    assert files == {"repo/app.py"}  # not repo/repo/app.py


def test_folder_and_zip_in_one_scan(samples: Path) -> None:
    import gzip

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.write(samples / "network-capture" / "network.pcap", "network.pcap")
    code = b"import hashlib\nhashlib.sha1(b'x')\n"
    res = _client_with(samples).post(
        "/api/v1/scans",
        files=[
            ("files", ("repo/src/app.py.gz", gzip.compress(code))),
            ("files", ("captures.zip", buf.getvalue())),
        ],
    )
    assert res.status_code == 200
    body = res.json()
    assert body["targets"] == ["repo/", "captures.zip"]
    assert {"source-code", "network-pcap"} <= set(body["scanners"])


def test_bad_gzip_is_400(samples: Path) -> None:
    res = _client_with(samples).post(
        "/api/v1/scans", files=[("files", ("a.py.gz", b"\x1f\x8bnot really gzip"))]
    )
    assert res.status_code == 400
    assert "not a valid gzip file" in res.json()["detail"]


def test_redis_used_when_configured(samples: Path) -> None:
    from quantumtrace.api.app import make_repository
    from quantumtrace.store.repository import RedisScanRepository

    settings = Settings(samples_dir=samples, redis_url="https://x.upstash.io", redis_token="t")
    assert isinstance(make_repository(settings), RedisScanRepository)


def test_samples_listed(client: TestClient) -> None:
    names = {s["name"] for s in client.get("/api/v1/samples").json()}
    assert {"cloud-posture", "sample-repos", "network-capture"} <= names


def test_scan_sample_then_fetch_and_export(client: TestClient) -> None:
    res = client.post("/api/v1/scans/sample", json={"sample": "cloud-posture"})
    assert res.status_code == 200
    scan = res.json()
    assert scan["score"]["counts"]["critical"] > 0

    assert client.get(f"/api/v1/scans/{scan['id']}").json()["id"] == scan["id"]
    history = client.get("/api/v1/scans", params={"ids": [scan["id"], "missing"]}).json()
    assert [h["id"] for h in history] == [scan["id"]]
    files = {f["asset"]["evidence"]["context"].get("file") for f in scan["findings"]}
    assert all(p.startswith("samples/cloud-posture/") for p in files), files
    cbom = client.get(f"/api/v1/scans/{scan['id']}/cbom").json()
    assert cbom["specVersion"] == "1.6"


def test_scans_cannot_be_listed_without_ids(client: TestClient) -> None:
    client.post("/api/v1/scans/sample", json={"sample": "cloud-posture"})
    assert client.get("/api/v1/scans").status_code == 422


def test_delete_scan(client: TestClient) -> None:
    scan = client.post("/api/v1/scans/sample", json={"sample": "cloud-posture"}).json()
    assert client.delete(f"/api/v1/scans/{scan['id']}").status_code == 204
    assert client.get(f"/api/v1/scans/{scan['id']}").status_code == 404
    assert client.get("/api/v1/scans", params={"ids": [scan["id"]]}).json() == []
    assert client.delete(f"/api/v1/scans/{scan['id']}").status_code == 204  # idempotent


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


def test_upload_folder_keeps_paths(client: TestClient, samples: Path) -> None:
    # A browser folder upload names each file by its path inside the chosen folder.
    repo = samples / "sample-repos"
    paths = ["python/legacy_accounts.py", "java/SessionCipher.java", "go/go.mod"]
    res = client.post(
        "/api/v1/scans",
        files=[("files", (f"sample-repos/{p}", (repo / p).read_bytes())) for p in paths],
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["targets"] == ["sample-repos/"]
    locations = {f["asset"]["evidence"]["location"] for f in body["findings"]}
    assert locations == {
        "sample-repos/python/legacy_accounts.py",
        "sample-repos/java/SessionCipher.java",
    }


def test_upload_targets_list_loose_files_and_folders(client: TestClient, samples: Path) -> None:
    kms = (samples / "cloud-posture/kms_key_inventory.json").read_bytes()
    res = client.post(
        "/api/v1/scans",
        files=[
            ("files", ("kms.json", kms)),
            ("files", ("app/a/kms.json", kms)),
            ("files", ("app/b/kms.json", kms)),
        ],
    )
    assert res.json()["targets"] == ["kms.json", "app/"]


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


def test_probe_refuses_private_hosts(client: TestClient) -> None:
    res = client.post("/api/v1/probes/tls", json={"host": "127.0.0.1"})
    assert res.status_code == 400
    assert "private" in res.json()["detail"]


def test_probe_rejects_bad_port(client: TestClient) -> None:
    res = client.post("/api/v1/probes/tls", json={"host": "example.com", "port": 70000})
    assert res.status_code == 422


def test_probe_needs_api_key_when_configured(samples: Path) -> None:
    client = make_client(samples, api_key="s3cret")
    assert client.post("/api/v1/probes/tls", json={"host": "example.com"}).status_code == 401


def test_probe_saves_scan(samples: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from quantumtrace.api.v1 import routes
    from quantumtrace.core.models import RiskScore, ScanResult, TierCounts

    seen: dict[str, object] = {}

    def fake_probe(host: str, port: int, *, allow_private: bool) -> ScanResult:
        seen.update(host=host, port=port, allow_private=allow_private)
        score = RiskScore(value=0, grade="A", counts=TierCounts())
        return ScanResult(
            targets=[f"{host}:{port}"], scanners=["tls-probe"], findings=[], score=score
        )

    monkeypatch.setattr(routes, "run_probe", fake_probe)
    client = make_client(samples)
    res = client.post("/api/v1/probes/tls", json={"host": "example.com"})
    assert res.status_code == 200
    assert seen == {"host": "example.com", "port": 443, "allow_private": False}
    assert client.get(f"/api/v1/scans/{res.json()['id']}").status_code == 200
