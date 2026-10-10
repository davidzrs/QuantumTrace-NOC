"""Quantum Risk Score: 0 (quantum-ready) .. 100 (everything Shor-exposed on the internet).

Deliberately simple and explainable for the demo; tune the weights here only.
"""

from __future__ import annotations

from collections.abc import Sequence

from quantumtrace.core.models import Exposure, Finding, RiskScore, RiskTier, TierCounts

TIER_WEIGHT: dict[RiskTier, float] = {
    RiskTier.CRITICAL: 10.0,
    RiskTier.MEDIUM: 4.0,
    RiskTier.UNKNOWN: 2.0,
    RiskTier.SAFE: 0.0,
}
BROKEN_WEIGHT = TIER_WEIGHT[RiskTier.CRITICAL]
EXPOSURE_MULTIPLIER: dict[Exposure, float] = {
    Exposure.INTERNET: 1.5,  # Harvest-Now-Decrypt-Later: traffic is trivially capturable
    Exposure.INTERNAL: 1.0,
    Exposure.UNKNOWN: 1.0,
}
MAX_PER_FINDING = BROKEN_WEIGHT * EXPOSURE_MULTIPLIER[Exposure.INTERNET]

GRADES = ((20.0, "A"), (40.0, "B"), (60.0, "C"), (80.0, "D"))


def finding_weight(finding: Finding) -> float:
    c = finding.classification
    base = BROKEN_WEIGHT if c.classically_broken else TIER_WEIGHT[c.tier]
    return base * EXPOSURE_MULTIPLIER[finding.asset.exposure]


def score(findings: Sequence[Finding]) -> RiskScore:
    counts = TierCounts()
    for f in findings:
        setattr(
            counts, f.classification.tier.value, getattr(counts, f.classification.tier.value) + 1
        )
    if not findings:
        return RiskScore(value=0.0, grade="A", counts=counts)
    value = round(100 * sum(map(finding_weight, findings)) / (len(findings) * MAX_PER_FINDING), 1)
    grade = next((g for limit, g in GRADES if value < limit), "F")
    return RiskScore(value=value, grade=grade, counts=counts)
