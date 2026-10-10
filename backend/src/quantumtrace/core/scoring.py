"""Quantum Risk Score: 0 (quantum-ready) .. 100 (everything Shor-exposed on the internet).

Deliberately simple and explainable for the demo; tune the weights here only.
"""

from __future__ import annotations

from collections.abc import Sequence

from quantumtrace.core.models import (
    Exposure,
    Finding,
    QuantumThreat,
    RiskScore,
    RiskTier,
    SourceType,
    TierCounts,
)

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
# Harvest-Now-Decrypt-Later hits confidentiality: a key exchange or ciphertext recorded today is
# decrypted once a quantum computer exists. Forging a signature needs that computer at the time
# of the attack, so Shor-exposed authentication weighs less. Unlisted usages keep full weight.
AUTHENTICATION_USAGES = {
    "signature", "sign_verify", "certificate-key", "certificate-signature",
    "tls-authentication", "ssh-host-key",
}  # fmt: skip
AUTHENTICATION_MULTIPLIER = 0.7
MAX_PER_FINDING = BROKEN_WEIGHT * EXPOSURE_MULTIPLIER[Exposure.INTERNET]

GRADES = ((20.0, "A"), (40.0, "B"), (60.0, "C"), (80.0, "D"))


def finding_weight(finding: Finding) -> float:
    c, a = finding.classification, finding.asset
    if c.classically_broken:
        base = BROKEN_WEIGHT
    elif c.threat is QuantumThreat.SHOR and (a.usage or "").lower() in AUTHENTICATION_USAGES:
        base = TIER_WEIGHT[c.tier] * AUTHENTICATION_MULTIPLIER
    else:
        base = TIER_WEIGHT[c.tier]
    return base * EXPOSURE_MULTIPLIER[a.exposure]


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


def score_by_source(findings: Sequence[Finding]) -> dict[SourceType, RiskScore]:
    """The score of each source's findings alone, so a report filtered to one source shows
    that source's exposure rather than the whole scan's."""
    return {
        source: score(subset)
        for source in SourceType
        if (subset := [f for f in findings if f.asset.evidence.source_type is source])
    }
