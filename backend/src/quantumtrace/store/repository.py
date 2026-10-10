"""Persistence boundary. Swap the in-memory store for SQLite/Postgres without touching the API."""

from __future__ import annotations

from collections import OrderedDict
from typing import Protocol

from quantumtrace.core.models import ScanResult


class ScanRepository(Protocol):
    def save(self, result: ScanResult) -> None: ...
    def get(self, scan_id: str) -> ScanResult | None: ...
    def list(self, limit: int = 50) -> list[ScanResult]: ...


class InMemoryScanRepository:
    """Bounded LRU store. Results are lost on restart (fine for demo / Fly auto-stop)."""

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

    def list(self, limit: int = 50) -> list[ScanResult]:
        return list(reversed(self._items.values()))[:limit]
