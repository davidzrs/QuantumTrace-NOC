"""Scanner protocol. Every ingestion vector (cloud, code, network, ...) implements this."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable

from quantumtrace.core.models import CryptoAsset, ScanNote, SourceType
from quantumtrace.scanners.runtime.model import RuntimeTrace


@runtime_checkable
class Scanner(Protocol):
    name: str
    source_type: SourceType

    def accepts(self, path: Path) -> bool:
        """Cheap check (extension / sniffing) whether this scanner handles the file."""
        ...

    def scan(self, paths: Sequence[Path]) -> Iterable[CryptoAsset | ScanNote | RuntimeTrace]:
        """Scan all accepted files together (lets scanners correlate across files).

        Yield a ScanNote for anything the input could not prove (encrypted certificates,
        unresolved references, ...) so the report states its own blind spots. A RuntimeTrace
        is evidence about other scanners' findings: the engine lays it over them."""
        ...


class ScannerRegistry:
    def __init__(self) -> None:
        self._scanners: dict[str, Scanner] = {}

    def register(self, scanner: Scanner) -> None:
        self._scanners[scanner.name] = scanner

    def get(self, name: str) -> Scanner:
        return self._scanners[name]

    def all(self) -> list[Scanner]:
        return list(self._scanners.values())


registry = ScannerRegistry()
