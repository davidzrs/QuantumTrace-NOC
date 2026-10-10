"""Scan orchestration: expand targets -> dispatch files to scanners -> classify -> score.

This is the single entry point used by every adapter (API, CLI, future extensions).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

from quantumtrace.core.classifier import Classifier, default_classifier
from quantumtrace.core.models import CryptoAsset, Finding, ScanNote, ScanResult
from quantumtrace.core.scoring import score, score_by_source
from quantumtrace.scanners import Scanner, registry
from quantumtrace.scanners.network import probe

IGNORED_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".idea", ".vscode"}


def iter_files(targets: Iterable[Path]) -> Iterable[Path]:
    for target in targets:
        if target.is_file():
            yield target
        elif target.is_dir():
            for p in sorted(target.rglob("*")):
                if p.is_file() and not IGNORED_DIRS.intersection(p.parts):
                    yield p


def run_scan(
    targets: Sequence[Path],
    *,
    scanners: Sequence[Scanner] | None = None,
    classifier: Classifier | None = None,
    display_targets: Sequence[str] | None = None,
) -> ScanResult:
    scanners = list(scanners) if scanners is not None else registry.all()
    classifier = classifier or default_classifier()
    files = list(iter_files(targets))

    findings: list[Finding] = []
    notes: list[ScanNote] = []
    used: list[str] = []
    errors: list[str] = []
    for scanner in scanners:
        accepted = [f for f in files if scanner.accepts(f)]
        if not accepted:
            continue
        used.append(scanner.name)
        try:
            for item in scanner.scan(accepted):
                if isinstance(item, CryptoAsset):
                    findings.append(classifier.classify(item))
                elif item not in notes:
                    notes.append(item)
        except Exception as exc:  # one broken input must not kill the whole scan
            errors.append(f"{scanner.name}: {exc}")

    return ScanResult(
        targets=list(display_targets) if display_targets else [str(t) for t in targets],
        scanners=used,
        findings=findings,
        score=score(findings),
        score_by_source=score_by_source(findings),
        limitations=notes,
        errors=errors,
    )


def run_probe(
    host: str, port: int = 443, *, allow_private: bool = False, classifier: Classifier | None = None
) -> ScanResult:
    """Probe a live TLS endpoint. Raises `ProbeError` (message safe to show) when the host is
    not allowed or doesn't complete a handshake."""
    classifier = classifier or default_classifier()
    target = probe.resolve_public(host, port, allow_private=allow_private)
    findings: list[Finding] = []
    notes: list[ScanNote] = []
    for item in probe.probe(target):
        if isinstance(item, CryptoAsset):
            findings.append(classifier.classify(item))
        elif item not in notes:
            notes.append(item)
    return ScanResult(
        targets=[f"{target.host}:{target.port}"],
        scanners=[probe.SCANNER],
        findings=findings,
        score=score(findings),
        score_by_source=score_by_source(findings),
        limitations=notes,
    )
