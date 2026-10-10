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
        self.lists: dict[str, list[str]] = {}

    def run(self, cmd: str, *args: str) -> Any:
        lst = self.lists.setdefault(args[0], []) if cmd.startswith("L") else []
        match cmd:
            case "SET":
                self.strings[args[0]] = args[1]
                return "OK"
            case "GET":
                return self.strings.get(args[0])
            case "MGET":
                return [self.strings.get(k) for k in args]
            case "LREM":
                lst[:] = [x for x in lst if x != args[2]]
                return 0
            case "LPUSH":
                lst.insert(0, args[1])
                return len(lst)
            case "LTRIM":
                lst[:] = lst[int(args[1]) : int(args[2]) + 1]
                return "OK"
            case "LRANGE":
                return lst[int(args[1]) : int(args[2]) + 1]
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
        "https://example.upstash.io",
        "t0ken",
        max_items=2,
        transport=httpx.MockTransport(fake.handler),
    )
    assert repo.get(scan.id) is None
    assert repo.list() == []

    repo.save(scan)
    assert repo.get(scan.id) == scan
    [summary] = repo.list()
    assert (summary.id, summary.findings) == (scan.id, len(scan.findings))

    newer = [scan.model_copy(update={"id": f"n{i}"}) for i in range(2)]
    for r in newer:
        repo.save(r)
    assert [s.id for s in repo.list()] == ["n1", "n0"]  # capped at max_items, newest first


def test_redis_errors_surface(scan: ScanResult) -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json=[{"error": "WRONGPASS"}]))
    repo = RedisScanRepository("https://example.upstash.io", "t0ken", transport=transport)
    with pytest.raises(RuntimeError, match="WRONGPASS"):
        repo.get(scan.id)


def test_memory_store_lists_summaries(scan: ScanResult) -> None:
    repo = InMemoryScanRepository()
    repo.save(scan)
    assert [s.id for s in repo.list()] == [scan.id]
    assert repo.persistent is False
