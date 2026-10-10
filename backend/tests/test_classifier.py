from __future__ import annotations

import pytest

from quantumtrace.core.classifier import Classifier, Rule, default_classifier, load_rules
from quantumtrace.core.models import QuantumThreat, RiskTier


@pytest.mark.parametrize(
    ("algorithm", "key_size", "rule_id", "tier"),
    [
        # Shor-vulnerable -> critical
        ("RSA", 2048, "rsa", RiskTier.CRITICAL),
        ("RSA", 1024, "rsa-1024", RiskTier.CRITICAL),
        ("RSA_4096", None, "rsa", RiskTier.CRITICAL),
        ("ECDSA", 256, "ecdsa", RiskTier.CRITICAL),
        ("EC_prime256v1", None, "ecdsa", RiskTier.CRITICAL),
        ("SHA1withRSA", None, "rsa", RiskTier.CRITICAL),
        ("Ed25519", None, "eddsa", RiskTier.CRITICAL),
        ("ECDHE", None, "ecdh", RiskTier.CRITICAL),
        ("DSA", None, "dsa", RiskTier.CRITICAL),
        ("DH", 2048, "dh", RiskTier.CRITICAL),
        ("DH", 1024, "dh-1024", RiskTier.CRITICAL),  # SSH diffie-hellman-group1-sha1
        ("DHE", 1024, "dh-1024", RiskTier.CRITICAL),  # TLS DHE, size from ServerKeyExchange
        ("DH", 512, "dh-1024", RiskTier.CRITICAL),
        # Grover-weakened -> medium
        ("AES", 128, "aes-128", RiskTier.MEDIUM),
        ("AES-128-GCM", None, "aes-128", RiskTier.MEDIUM),
        ("DESede", None, "3des", RiskTier.MEDIUM),
        ("SHA-1", None, "sha1", RiskTier.MEDIUM),
        ("MD5", None, "md5", RiskTier.MEDIUM),
        # Quantum-resilient -> safe
        ("AES", 256, "aes-256", RiskTier.SAFE),
        ("SYMMETRIC_DEFAULT", None, "aes-256", RiskTier.SAFE),
        ("SHA-384", None, "sha384", RiskTier.SAFE),
        ("ML-KEM-768", None, "ml-kem", RiskTier.SAFE),
        ("ML_DSA_65", None, "ml-dsa", RiskTier.SAFE),
        ("SLH-DSA", None, "slh-dsa", RiskTier.SAFE),
        ("X25519MLKEM768", None, "x25519mlkem768", RiskTier.SAFE),
    ],
)
def test_lookup(algorithm: str, key_size: int | None, rule_id: str, tier: RiskTier) -> None:
    rule = default_classifier().lookup(algorithm, key_size)
    assert rule is not None, algorithm
    assert (rule.id, rule.tier) == (rule_id, tier)


def test_shor_rules_are_critical_and_grover_never_critical() -> None:
    for rule in load_rules():
        if rule.threat is QuantumThreat.SHOR:
            assert rule.tier is RiskTier.CRITICAL, rule.id
        if rule.threat is QuantumThreat.GROVER:
            assert rule.tier is not RiskTier.CRITICAL, rule.id


def test_every_non_safe_rule_has_replacement() -> None:
    for rule in load_rules():
        if rule.tier in (RiskTier.CRITICAL, RiskTier.MEDIUM):
            assert rule.replacement, f"{rule.id} needs a migration target"


def test_duplicate_alias_rejected() -> None:
    base = {"primitive": "hash", "threat": "none", "tier": "safe", "rationale": "x"}
    rules = [
        Rule.model_validate({"id": "a", "name": "A", "aliases": ["dup"], **base}),
        Rule.model_validate({"id": "b", "name": "B", "aliases": ["DUP"], **base}),
    ]
    with pytest.raises(ValueError, match="DUP"):
        Classifier(rules)


def test_unknown_algorithm_is_unknown_tier() -> None:
    assert default_classifier().lookup("ROT13") is None


def test_only_shor_rules_are_critical() -> None:
    for rule in load_rules():
        if rule.tier is RiskTier.CRITICAL:
            assert rule.threat is QuantumThreat.SHOR, rule.id


def test_plaintext_is_broken_but_not_a_quantum_tier() -> None:
    rule = default_classifier().lookup("HTTP")
    assert rule is not None
    assert (rule.tier, rule.threat, rule.classically_broken) == (
        RiskTier.MEDIUM,
        QuantumThreat.NONE,
        True,
    )


def test_small_dh_is_broken_like_small_rsa() -> None:
    dh = default_classifier().lookup("DH", 1024)
    rsa = default_classifier().lookup("RSA", 1024)
    assert dh is not None and rsa is not None
    assert (dh.threat, dh.classically_broken, dh.classical_security_bits) == (
        QuantumThreat.SHOR,
        True,
        rsa.classical_security_bits,
    )


def test_hmac_md5_is_deprecated_but_not_broken() -> None:
    # RFC 6151: HMAC's security doesn't rest on the hash's collision resistance, so the MD5
    # collisions that break plain MD5 don't break HMAC-MD5.
    rule = default_classifier().lookup("HmacMD5")
    assert rule is not None
    assert (rule.id, rule.tier, rule.threat, rule.classically_broken) == (
        "hmac-md5",
        RiskTier.MEDIUM,
        QuantumThreat.GROVER,
        False,
    )
    assert rule.replacement == "HMAC-SHA256"
    md5 = default_classifier().lookup("MD5")
    assert md5 is not None and md5.classically_broken  # the bare hash stays broken


def test_misuse_flags_mark_finding_broken_and_explain_why() -> None:
    from quantumtrace.core.models import CryptoAsset, Evidence, SourceType

    def asset(flags: list[str]) -> CryptoAsset:
        ev = Evidence(source_type=SourceType.CODE, location="x.py", line=1)
        return CryptoAsset(observed="AES", algorithm="AES", key_size=256, flags=flags, evidence=ev)

    clean = default_classifier().classify(asset([]))
    keyed = default_classifier().classify(asset(["hardcoded-key", "cbc-mode"]))
    assert not clean.classification.classically_broken
    assert keyed.classification.classically_broken
    assert keyed.classification.tier is RiskTier.SAFE  # quantum tier is unchanged
    assert "written in the source" in keyed.classification.rationale
