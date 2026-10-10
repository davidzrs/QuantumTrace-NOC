"""Golden tests for the AWS cloud-posture scanner against samples/cloud-posture."""

from __future__ import annotations

from pathlib import Path

import pytest

from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import Exposure, Finding, Observation, RiskTier, ScanResult


@pytest.fixture(scope="module")
def result(samples: Path) -> ScanResult:
    return run_scan([samples / "cloud-posture"])


def by_context(result: ScanResult, key: str, value: str) -> list[Finding]:
    return [f for f in result.findings if f.asset.evidence.context.get(key) == value]


def test_no_errors_and_no_unknowns(result: ScanResult) -> None:
    assert result.errors == []
    assert result.scanners == ["aws-cloud-posture"]
    assert result.score.counts.unknown == 0


def test_kms_rsa_signing_key_is_critical_with_mldsa_migration(result: ScanResult) -> None:
    [key] = [
        f
        for f in by_context(result, "alias", "alias/licensing-jwt-signing")
        if f.asset.usage == "SIGN_VERIFY"
    ]
    assert key.classification.tier is RiskTier.CRITICAL
    assert key.asset.key_size == 2048
    assert key.classification.replacement and "FIPS 204" in key.classification.replacement


def test_kms_symmetric_default_is_aes256_gcm_safe(result: ScanResult) -> None:
    [key] = by_context(result, "alias", "alias/s3-object-encryption")
    assert (key.classification.name, key.classification.tier) == ("AES-256", RiskTier.SAFE)
    assert key.asset.variant == "AES-256-GCM"


def test_kms_flags(result: ScanResult) -> None:
    [imported] = [
        f for f in by_context(result, "alias", "alias/partner-feed-decrypt") if f.asset.key_size
    ]
    assert "imported-key-material" in imported.asset.flags
    [pending] = by_context(result, "alias", "alias/legacy-reports-export")
    assert "key-state:PendingDeletion" in pending.asset.flags


def test_acm_sha1_certificate_is_flagged(result: ScanResult) -> None:
    findings = by_context(result, "domain", "legacy-tcp.internal.example.com")
    tiers = {(f.classification.name, f.classification.tier) for f in findings}
    assert ("SHA-1", RiskTier.MEDIUM) in tiers
    assert ("RSA", RiskTier.CRITICAL) in tiers


def test_acm_exposure_inherited_from_load_balancer(result: ScanResult) -> None:
    public = by_context(result, "domain", "www.example.com")
    internal = by_context(result, "domain", "admin.internal.example.com")
    assert {f.asset.exposure for f in public} == {Exposure.INTERNET}
    assert {f.asset.exposure for f in internal} == {Exposure.INTERNAL}


def test_legacy_elb_policy_enables_tls10_and_static_rsa(result: ScanResult) -> None:
    findings = by_context(result, "load_balancer", "public-web-alb")
    names = {(f.classification.name, f.asset.usage) for f in findings}
    assert ("TLS 1.0", "tls-protocol") in names
    [rsa_kx] = [
        f
        for f in findings
        if f.asset.usage == "tls-key-exchange" and f.classification.name == "RSA"
    ]
    assert "no-forward-secrecy" in rsa_kx.asset.flags
    assert rsa_kx.asset.exposure is Exposure.INTERNET


def test_tls13_policy_still_uses_classical_key_exchange(result: ScanResult) -> None:
    findings = by_context(result, "load_balancer", "partner-api-alb")
    [kx] = [f for f in findings if f.asset.usage == "tls-key-exchange"]  # deduped across 1.2/1.3
    assert kx.classification.name == "ECDH"  # no hybrid ML-KEM group -> HNDL exposure
    assert "no-pq-group" in kx.asset.flags
    [tls13] = [f for f in findings if f.asset.observed == "TLSv1.3"]
    assert tls13.classification.name == "TLS 1.3 (classical key exchange)"
    assert tls13.classification.tier is RiskTier.MEDIUM
    assert "TLS 1.0" not in {f.classification.name for f in findings}


def test_ciphers_split_by_mode_and_gcm_never_flagged_cbc(result: ScanResult) -> None:
    ciphers = [f for f in result.findings if f.asset.usage == "tls-cipher"]
    for f in ciphers:
        is_cbc = (f.asset.variant or "").endswith("-CBC")
        assert ("cbc-mode" in f.asset.flags) == is_cbc, (f.asset.variant, f.asset.flags)
    partner = {f.asset.variant for f in by_context(result, "load_balancer", "partner-api-alb")
               if f.asset.usage == "tls-cipher"}  # fmt: skip
    assert partner == {"AES-128-GCM", "AES-128-CBC", "AES-256-GCM", "AES-256-CBC",
                       "ChaCha20-Poly1305"}  # fmt: skip
    [cbc] = [f for f in by_context(result, "load_balancer", "public-web-alb")
             if f.asset.variant == "AES-128-CBC"]  # fmt: skip
    assert cbc.asset.evidence.context["record_macs"] == "HMAC-SHA1, HMAC-SHA256"


def test_authentication_algorithms_reported_for_every_tls_listener(result: ScanResult) -> None:
    auth = [f for f in result.findings if f.asset.usage == "tls-authentication"]
    lbs = {f.asset.evidence.context["load_balancer"] for f in auth}
    assert lbs == {"public-web-alb", "internal-admin-alb", "api-gateway-alb",
                   "partner-api-alb", "legacy-tcp-nlb"}  # fmt: skip
    assert {f.classification.name for f in auth} == {"ECDSA", "RSA"}
    assert all(f.classification.tier is RiskTier.CRITICAL for f in auth)


def test_policy_findings_are_permitted_with_json_paths(result: ScanResult) -> None:
    elb = [f for f in result.findings if "load_balancer" in f.asset.evidence.context]
    for f in elb:
        assert f.asset.evidence.context["json_path"].startswith("$.LoadBalancers[")
        expected = Observation.CONFIGURED if f.asset.usage == "transport" else Observation.PERMITTED
        assert f.asset.observation is expected


def test_unresolved_certificates_become_a_limitation(samples: Path) -> None:
    alone = run_scan([samples / "cloud-posture/load_balancer_listeners.json"])
    assert any("referenced only by ARN" in n.message for n in alone.limitations)
    with_acm = run_scan([samples / "cloud-posture"])
    assert not any("referenced only by ARN" in n.message for n in with_acm.limitations)


def test_http_redirect_is_not_plaintext_but_bare_http_is(result: ScanResult) -> None:
    assert not [
        f
        for f in by_context(result, "load_balancer", "public-web-alb")
        if f.asset.usage == "transport"
    ]
    [plain] = by_context(result, "load_balancer", "batch-internal-alb")
    assert plain.classification.name == "No encryption"


def test_score_is_in_range(result: ScanResult) -> None:
    assert 0 < result.score.value < 100
    assert result.score.counts.critical > 0
