"""Harvest-Now-Decrypt-Later: which findings are exposed, and that every usage has a role."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import QuantumThreat, RiskTier, ScanResult
from quantumtrace.core.roles import Role, role_of
from quantumtrace.core.scoring import score


@pytest.fixture(scope="module")
def result(samples: Path) -> ScanResult:
    return run_scan([samples])  # all three vectors


def test_every_usage_in_the_samples_has_a_role(result: ScanResult) -> None:
    unknown = sorted(
        {f.asset.usage or "" for f in result.findings if role_of(f.asset.usage) is None}
    )
    assert unknown == [], f"add these usages to core/roles.py: {unknown}"


def test_only_shor_broken_confidentiality_is_hndl(result: ScanResult) -> None:
    hndl = [f for f in result.findings if f.classification.hndl]
    assert hndl
    for f in hndl:
        assert f.classification.threat is QuantumThreat.SHOR
        assert f.classification.tier is not RiskTier.SAFE
        assert role_of(f.asset.usage) is Role.CONFIDENTIALITY, f.asset.usage
    # signatures, certificates, host keys and digests can't be forged after the fact
    roles = {role_of(f.asset.usage) for f in result.findings if not f.classification.hndl}
    assert {Role.AUTHENTICATION, Role.DIGEST} <= roles


def test_pcap_key_exchanges(samples: Path) -> None:
    pcap = run_scan([samples / "network-capture"])
    tls = Counter(
        (f.classification.name, f.classification.hndl)
        for f in pcap.findings
        if f.asset.usage == "tls-key-exchange"
    )
    # 54 static-RSA key transport, 36 classical x25519, 7 hybrid ML-KEM (safe)
    assert tls == {("RSA", True): 54, ("ECDH", True): 36, ("X25519MLKEM768", False): 7}
    ssh = {f.classification.hndl for f in pcap.findings if f.asset.usage == "ssh-key-exchange"}
    assert ssh == {True}
    host_keys = {f.classification.hndl for f in pcap.findings if f.asset.usage == "ssh-host-key"}
    assert host_keys == {False}


def test_kms_encryption_key_is_hndl_and_signing_key_is_not(samples: Path) -> None:
    cloud = run_scan([samples / "cloud-posture"])
    rsa = {
        (f.asset.usage, f.classification.hndl)
        for f in cloud.findings
        if f.classification.rule_id == "rsa" and f.asset.evidence.location.startswith("arn:aws:kms")
    }
    assert rsa == {("ENCRYPT_DECRYPT", True), ("SIGN_VERIFY", False)}
    aes = [f for f in cloud.findings if f.asset.algorithm == "SYMMETRIC_DEFAULT"]
    assert aes and not any(f.classification.hndl for f in aes)  # Grover-only, safe


def test_hndl_does_not_change_the_score(result: ScanResult) -> None:
    unmarked = [
        f.model_copy(update={"classification": f.classification.model_copy(update={"hndl": False})})
        for f in result.findings
    ]
    assert score(unmarked) == result.score
