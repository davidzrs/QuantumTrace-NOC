from __future__ import annotations

from pathlib import Path

import pytest

from quantumtrace.core.models import Finding, ScanResult

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


@pytest.fixture(scope="session")
def samples() -> Path:
    assert SAMPLES.is_dir(), f"samples/ not found at {SAMPLES}"
    return SAMPLES


def summarise(result: ScanResult) -> set[tuple[str, str, str]]:
    """(tier, algorithm name, usage) triples: the shape golden tests assert against."""
    return {_triple(f) for f in result.findings}


def _triple(f: Finding) -> tuple[str, str, str]:
    return (f.classification.tier.value, f.classification.name, f.asset.usage or "")
