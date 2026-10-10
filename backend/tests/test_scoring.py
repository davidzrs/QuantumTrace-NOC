"""Per-source scores: what a report filtered to one source shows as its risk score."""

from __future__ import annotations

from pathlib import Path

import pytest

from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import ScanResult, SourceType
from quantumtrace.core.scoring import score


@pytest.fixture(scope="module")
def result(samples: Path) -> ScanResult:
    return run_scan([samples / "cloud-posture", samples / "sample-repos"])


def test_only_sources_in_the_scan_are_scored(result: ScanResult) -> None:
    assert set(result.score_by_source) == {SourceType.CLOUD, SourceType.CODE}


def test_each_source_scores_its_own_findings(result: ScanResult) -> None:
    for source, source_score in result.score_by_source.items():
        subset = [f for f in result.findings if f.asset.evidence.source_type is source]
        assert source_score == score(subset)
        assert 0 < source_score.value < 100


def test_source_counts_add_up_to_the_whole_scan(result: ScanResult) -> None:
    for tier in ("critical", "medium", "safe", "unknown"):
        per_source = sum(getattr(s.counts, tier) for s in result.score_by_source.values())
        assert per_source == getattr(result.score.counts, tier)


def test_empty_scan_has_no_source_scores(tmp_path: Path) -> None:
    assert run_scan([tmp_path]).score_by_source == {}
