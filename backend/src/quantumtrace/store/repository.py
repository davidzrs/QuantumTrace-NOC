"""Persistence boundary. The API depends on ScanRepository only.

There is no "all scans" listing: history lives in each browser, which asks for the summaries of
the scan ids it ran. A scan is reachable only by its unguessable id.

- InMemoryScanRepository: one process (local dev, Docker). Lost on restart.
- RedisScanRepository: Upstash Redis over its REST API, for serverless hosts such as Vercel,
  where consecutive requests can land on different instances.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Sequence
from typing import Any, Protocol

import httpx

from quantumtrace.core.models import ScanResult, ScanSummary


class ScanRepository(Protocol):
    @property
    def persistent(self) -> bool: ...
    def save(self, result: ScanResult) -> None: ...
    def get(self, scan_id: str) -> ScanResult | None: ...
    def delete(self, scan_id: str) -> None: ...
    def summaries(self, ids: Sequence[str]) -> list[ScanSummary]:
        """Summaries for the given ids that still exist, in the order asked."""
        ...


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

    def delete(self, scan_id: str) -> None:
        self._items.pop(scan_id, None)

    def summaries(self, ids: Sequence[str]) -> list[ScanSummary]:
        return [ScanSummary.of(r) for i in ids if (r := self._items.get(i))]


class RedisScanRepository:
    """Each scan as JSON plus a small summary for history, both expiring after the TTL."""

    persistent = True

    def __init__(
        self,
        url: str,
        token: str,
        *,
        ttl_seconds: int = 30 * 24 * 3600,  # long enough to reopen reports saved to an account
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._http = httpx.Client(
            base_url=url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
            transport=transport,
        )
        self._ttl = ttl_seconds

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
        )

    def get(self, scan_id: str) -> ScanResult | None:
        [raw] = self._pipeline(["GET", f"qt:scan:{scan_id}"])
        return ScanResult.model_validate_json(raw) if raw else None

    def delete(self, scan_id: str) -> None:
        self._pipeline(["DEL", f"qt:scan:{scan_id}", f"qt:summary:{scan_id}"])

    def summaries(self, ids: Sequence[str]) -> list[ScanSummary]:
        if not ids:
            return []
        [raws] = self._pipeline(["MGET", *(f"qt:summary:{i}" for i in ids)])
        return [ScanSummary.model_validate_json(r) for r in raws if r]
