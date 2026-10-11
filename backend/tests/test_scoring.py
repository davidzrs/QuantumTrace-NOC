"""Scores: per-source scores, and the weights (classically broken > Shor key exchange and
encryption > Shor authentication)."""

from __future__ import annotations

from pathlib import Path

import pytest

from quantumtrace.core.classifier import default_classifier
from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import (
    CryptoAsset,
    Evidence,
    Exposure,
    RiskScore,
    ScanResult,
    SourceType,
    grade_for,
)
from quantumtrace.core.scoring import finding_weight, score


@pytest.fixture(scope="module")
def result(samples: Path) -> ScanResult:
    return run_scan([samples / "cloud-posture", samples / "sample-repos"])


def test_only_sources_in_the_scan_are_scored(result: ScanResult) -> None:
    assert set(result.score_by_source) == {SourceType.CLOUD, SourceType.CODE}


def test_each_source_scores_its_own_findings(result: ScanResult) -> None:
    for source, source_score in result.score_by_source.items():
        subset = [f for f in result.findings if f.asset.evidence.source_type is source]
        assert source_score == score(subset)
        assert 0 < source_score.value < 10


def test_source_counts_add_up_to_the_whole_scan(result: ScanResult) -> None:
    for tier in ("critical", "medium", "safe", "unknown"):
        per_source = sum(getattr(s.counts, tier) for s in result.score_by_source.values())
        assert per_source == getattr(result.score.counts, tier)


def test_empty_scan_has_no_source_scores(tmp_path: Path) -> None:
    assert run_scan([tmp_path]).score_by_source == {}


def weight(algorithm: str, usage: str, flags: list[str] | None = None) -> float:
    ev = Evidence(source_type=SourceType.CLOUD, location="arn:x")
    asset = CryptoAsset(
        observed=algorithm, algorithm=algorithm, usage=usage, flags=flags or [],
        exposure=Exposure.INTERNAL, evidence=ev,
    )  # fmt: skip
    return finding_weight(default_classifier().classify(asset))


def test_harvest_now_decrypt_later_outweighs_signatures() -> None:
    assert weight("RSA_2048", "ENCRYPT_DECRYPT") > weight("RSA_2048", "SIGN_VERIFY")
    assert weight("ECDHE", "tls-key-exchange") > weight("ECDSA", "tls-authentication")
    assert weight("RSA", "ssh-host-key") < weight("RSA", "tls-key-exchange")


def test_misuse_outweighs_grover() -> None:
    assert weight("AES-128", "encryption", ["ecb-mode"]) > weight("AES-128", "encryption")
    assert weight("AES-128", "encryption", ["ecb-mode"]) == weight("SHA-1", "hash")
    assert weight("AES-128", "encryption", ["ecb-mode"]) == weight("RSA", "tls-key-exchange")


def test_kms_encryption_key_ranks_above_signing_keys(samples: Path) -> None:
    result = run_scan([samples / "cloud-posture"])
    rsa = [f for f in result.findings if f.classification.rule_id == "rsa" and f.asset.usage]
    enc = [finding_weight(f) for f in rsa if f.asset.usage == "ENCRYPT_DECRYPT"]
    sig = [finding_weight(f) for f in rsa if f.asset.usage == "SIGN_VERIFY"]
    assert enc and sig and min(enc) > max(sig)


def test_score_is_out_of_ten_to_one_decimal(result: ScanResult) -> None:
    for s in [result.score, *result.score_by_source.values()]:
        assert 0 <= s.value <= 10
        assert s.value == round(s.value, 1)
        assert s.grade == grade_for(s.value)


@pytest.mark.parametrize(
    ("stored", "grade", "read"),
    [
        (40.1, "C", 4.0),  # an old 0-100 score
        (5.0, "A", 0.5),  # old and under 10, but an A: 5.0 out of 10 would be a C
        (5.6, "C", 5.6),  # already 0-10
        (1.5, "A", 1.5),  # both scales say A: left alone
    ],
)
def test_reports_stored_on_the_old_scale_read_out_of_ten(
    stored: float, grade: str, read: float
) -> None:
    old = RiskScore.model_validate_json(
        f'{{"value": {stored}, "grade": "{grade}", "counts": {{}}}}'
    )
    assert old.value == read
