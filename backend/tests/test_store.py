from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import ScanResult
from quantumtrace.store.repository import InMemoryScanRepository, RedisScanRepository


class FakeUpstash:
    """Just enough of the Upstash REST /pipeline endpoint for the commands the store sends."""

    def __init__(self) -> None:
        self.strings: dict[str, str] = {}

    def run(self, cmd: str, *args: str) -> Any:
        match cmd:
            case "SET":
                self.strings[args[0]] = args[1]
                return "OK"
            case "GET":
                return self.strings.get(args[0])
            case "MGET":
                return [self.strings.get(k) for k in args]
            case "DEL":
                return sum(self.strings.pop(k, None) is not None for k in args)
        raise AssertionError(cmd)

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/pipeline"
        assert request.headers["Authorization"] == "Bearer t0ken"
        commands = json.loads(request.content)
        return httpx.Response(200, json=[{"result": self.run(*c)} for c in commands])


@pytest.fixture
def scan(samples: Path) -> ScanResult:
    return run_scan([samples / "cloud-posture"])


def test_redis_store_round_trip(scan: ScanResult) -> None:
    fake = FakeUpstash()
    repo = RedisScanRepository(
        "https://example.upstash.io", "t0ken", transport=httpx.MockTransport(fake.handler)
    )
    assert repo.get(scan.id) is None
    assert repo.summaries([scan.id]) == []
    assert repo.summaries([]) == []

    repo.save(scan)
    other = scan.model_copy(update={"id": "other"})
    repo.save(other)
    assert repo.get(scan.id) == scan
    [summary] = repo.summaries([scan.id, "expired"])
    assert (summary.id, summary.findings) == (scan.id, len(scan.findings))
    assert [s.id for s in repo.summaries(["other", scan.id])] == ["other", scan.id]

    repo.delete(scan.id)
    assert repo.get(scan.id) is None
    assert [s.id for s in repo.summaries([scan.id, "other"])] == ["other"]


def test_redis_errors_surface(scan: ScanResult) -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json=[{"error": "WRONGPASS"}]))
    repo = RedisScanRepository("https://example.upstash.io", "t0ken", transport=transport)
    with pytest.raises(RuntimeError, match="WRONGPASS"):
        repo.get(scan.id)


def test_memory_store_summarises_only_asked_ids(scan: ScanResult) -> None:
    repo = InMemoryScanRepository()
    repo.save(scan)
    repo.save(scan.model_copy(update={"id": "someone-else"}))
    assert [s.id for s in repo.summaries([scan.id, "missing"])] == [scan.id]
    assert repo.persistent is False
