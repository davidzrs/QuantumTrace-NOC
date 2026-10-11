from __future__ import annotations

from pathlib import Path

import pytest

from quantumtrace.core.models import Finding, ScanResult

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
PERSONAL_SAMPLES = Path(__file__).resolve().parents[2] / "personal-samples"
SAMPLE_SOURCES = Path(__file__).resolve().parent / "sample_sources"  # what built the binaries


@pytest.fixture(scope="session")
def samples() -> Path:
    assert SAMPLES.is_dir(), f"samples/ not found at {SAMPLES}"
    return SAMPLES


@pytest.fixture(scope="session")
def personal_samples() -> Path:
    """Our own inputs for the file types the organisers' samples don't cover
    (personal-samples/README.md at the repository root)."""
    assert PERSONAL_SAMPLES.is_dir(), f"personal-samples/ not found at {PERSONAL_SAMPLES}"
    return PERSONAL_SAMPLES


def summarise(result: ScanResult) -> set[tuple[str, str, str]]:
    """(tier, algorithm name, usage) triples: the shape golden tests assert against."""
    return {_triple(f) for f in result.findings}


def _triple(f: Finding) -> tuple[str, str, str]:
    return (f.classification.tier.value, f.classification.name, f.asset.usage or "")
