"""Source-code scanner for Python, Java and Go.

Regex-driven, per-language rule sets (python_lang / java_lang / go_lang) that map API usage
to classifier aliases, resolve same-file constants for key sizes and modes, and flag misuse
(ECB, hard-coded keys, non-CSPRNG randomness, hand-rolled primitives). Every asset carries
file + line + snippet evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from quantumtrace.core.models import CryptoAsset, ScanNote, SourceType
from quantumtrace.scanners.code import go_lang, java_lang, python_lang
from quantumtrace.scanners.code.common import SourceFile

LANGUAGES: dict[str, tuple[str, Callable[[SourceFile], None]]] = {
    ".py": ("python", python_lang.scan),
    ".java": ("java", java_lang.scan),
    ".go": ("go", go_lang.scan),
}
EXTENSIONS = set(LANGUAGES)
MAX_FILE_BYTES = 2 * 1024 * 1024


class SourceCodeScanner:
    name = "source-code"
    source_type = SourceType.CODE

    def accepts(self, path: Path) -> bool:
        return path.suffix.lower() in EXTENSIONS

    def scan(self, paths: Sequence[Path]) -> Iterable[CryptoAsset | ScanNote]:
        for path in paths:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            language, handler = LANGUAGES[path.suffix.lower()]
            src = SourceFile.load(path, language)
            handler(src)
            yield from src.assets
