"""Persistence boundary. The API depends on ScanRepository only.

- InMemoryScanRepository: one process (local dev, Docker). Lost on restart.
- RedisScanRepository: Upstash Redis over its REST API, for serverless hosts such as Vercel,
  where consecutive requests can land on different instances.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Protocol

import httpx

from quantumtrace.core.models import ScanResult, ScanSummary


class ScanRepository(Protocol):
    @property
    def persistent(self) -> bool: ...
    def save(self, result: ScanResult) -> None: ...
    def get(self, scan_id: str) -> ScanResult | None: ...
    def list(self, limit: int = 50) -> list[ScanSummary]: ...


class InMemoryScanRepository:
    """Bounded LRU store. Results are lost on restart."""

    persistent = False

    def __init__(self, max_items: int = 200) -> None:
        self._items: OrderedDict[str, ScanResult] = OrderedDict()
        self._max = max_items

    def save(self, result: ScanResult) -> None:
        self._items[result.id] = result
        self._items.move_to_end(result.id)
        while len(self._items) > self._max:
            self._items.popitem(last=False)

    def get(self, scan_id: str) -> ScanResult | None:
        return self._items.get(scan_id)

    def list(self, limit: int = 50) -> list[ScanSummary]:
        return [ScanSummary.of(r) for r in reversed(self._items.values())][:limit]


class RedisScanRepository:
    """Scans as JSON with a TTL, plus a capped list of ids and per-scan summaries for history."""

    persistent = True
    INDEX = "qt:scans"

    def __init__(
        self,
        url: str,
        token: str,
        *,
        ttl_seconds: int = 7 * 24 * 3600,
        max_items: int = 200,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._http = httpx.Client(
            base_url=url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
            transport=transport,
        )
        self._ttl = ttl_seconds
        self._max = max_items

    def _pipeline(self, *commands: list[Any]) -> list[Any]:
        res = self._http.post("/pipeline", json=list(commands))
        res.raise_for_status()
        replies: list[dict[str, Any]] = res.json()
        if errors := [r["error"] for r in replies if "error" in r]:
            raise RuntimeError(f"Redis error: {errors[0]}")
        return [r["result"] for r in replies]

    def save(self, result: ScanResult) -> None:
        ttl = str(self._ttl)
        self._pipeline(
            ["SET", f"qt:scan:{result.id}", result.model_dump_json(), "EX", ttl],
            ["SET", f"qt:summary:{result.id}", ScanSummary.of(result).model_dump_json(), "EX", ttl],
            ["LREM", self.INDEX, "0", result.id],
            ["LPUSH", self.INDEX, result.id],
            ["LTRIM", self.INDEX, "0", str(self._max - 1)],
        )

    def get(self, scan_id: str) -> ScanResult | None:
        [raw] = self._pipeline(["GET", f"qt:scan:{scan_id}"])
        return ScanResult.model_validate_json(raw) if raw else None

    def list(self, limit: int = 50) -> list[ScanSummary]:
        [ids] = self._pipeline(["LRANGE", self.INDEX, "0", str(max(limit, 1) - 1)])
        if not ids:
            return []
        [raws] = self._pipeline(["MGET", *(f"qt:summary:{i}" for i in ids)])
        # Expired scans leave their id in the index until LTRIM pushes it out.
        return [ScanSummary.model_validate_json(r) for r in raws if r]
