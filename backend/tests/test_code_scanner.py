"""Golden tests for the source-code scanner against samples/sample-repos."""

from __future__ import annotations

from pathlib import Path

import pytest

from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import Confidence, Finding, Observation, ScanResult
from tests.conftest import summarise

REPOS = "sample-repos"


@pytest.fixture(scope="module")
def result(samples: Path) -> ScanResult:
    return run_scan([samples / REPOS])


def in_file(result: ScanResult, name: str) -> list[Finding]:
    return [f for f in result.findings if f.asset.evidence.location.endswith(name)]


def tiers(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.classification.tier.value, f.classification.name) for f in findings}


def test_whole_repo_has_no_unknowns_or_errors(result: ScanResult) -> None:
    assert result.errors == []
    assert result.scanners == ["source-code"]
    assert result.score.counts.unknown == 0


def test_findings_carry_line_numbers_and_snippets(result: ScanResult) -> None:
    assert result.findings
    for f in result.findings:
        assert f.asset.evidence.line, f
        assert f.asset.evidence.snippet
        assert f.asset.observation is Observation.IN_CODE


# --- Python ------------------------------------------------------------------------------
def test_python_rsa1024_and_sha1(samples: Path) -> None:
    result = run_scan([samples / REPOS / "python/license_token.py"])
    names = {name for _, name, _ in summarise(result)}
    assert {"RSA-1024", "SHA-1"} <= names
    [keygen] = [f for f in result.findings if f.asset.usage == "key-generation"]
    assert keygen.asset.evidence.line == 6


def test_python_ecb_mode_hardcoded_key_and_weak_rng(result: ScanResult) -> None:
    findings = in_file(result, "python/report_export.py")
    [aes] = [f for f in findings if f.classification.name == "AES-128"]
    assert {"ecb-mode", "hardcoded-key"} <= set(aes.asset.flags)
    assert aes.asset.variant == "AES-128-ECB"
    assert ("medium", "Non-cryptographic RNG") in tiers(findings)


def test_python_aesgcm_with_32_byte_key_is_safe(result: ScanResult) -> None:
    assert ("safe", "AES-256") in tiers(in_file(result, "python/secure_transfer.py"))


def test_python_hashlib_and_hmac(result: ScanResult) -> None:
    assert ("medium", "MD5") in tiers(in_file(result, "python/legacy_accounts.py"))
    assert tiers(in_file(result, "python/artifact_manifest.py")) == {
        ("safe", "SHA-384"),
        ("safe", "HMAC-SHA256"),
    }


def test_python_ed25519_is_shor_vulnerable(result: ScanResult) -> None:
    assert ("critical", "EdDSA") in tiers(in_file(result, "python/webhook_signature.py"))


# --- Java --------------------------------------------------------------------------------
def test_java_sha1_with_rsa(samples: Path) -> None:
    result = run_scan([samples / REPOS / "java/ReceiptSigner.java"])
    assert {("critical", "RSA-1024"), ("medium", "SHA-1")} <= {
        (t, n) for t, n, _ in summarise(result)
    }


def test_java_md5(samples: Path) -> None:
    result = run_scan([samples / REPOS / "java/CustomerDirectory.java"])
    assert ("medium", "MD5") in {(t, n) for t, n, _ in summarise(result)}


def test_java_constants_resolved(result: ScanResult) -> None:
    # TRANSFORMATION = "AES/ECB/PKCS5Padding" + 16-byte literal key
    [ecb] = [f for f in in_file(result, "java/BatchExporter.java") if f.asset.usage == "encryption"]
    assert ecb.classification.name == "AES-128"
    assert "ecb-mode" in ecb.asset.flags
    # TRANSFORMATION = "AES/GCM/NoPadding" + KEY_BITS = 256
    [gcm] = in_file(result, "java/SessionCipher.java")
    assert (gcm.classification.name, gcm.asset.flags) == ("AES-256", [])


def test_java_pbkdf2(result: ScanResult) -> None:
    assert tiers(in_file(result, "java/IdentityVault.java")) == {("safe", "PBKDF2")}


# --- Go ----------------------------------------------------------------------------------
def test_go_ed25519_is_shor_vulnerable(samples: Path) -> None:
    result = run_scan([samples / REPOS / "go/agent-enrollment/main.go"])
    assert ("critical", "EdDSA") in {(t, n) for t, n, _ in summarise(result)}


def test_go_rsa_1024_signing(result: ScanResult) -> None:
    findings = in_file(result, "go/invoice-service/main.go")
    assert {("critical", "RSA-1024"), ("medium", "SHA-1")} <= tiers(findings)


def test_go_raw_block_encrypt_is_ecb_and_math_rand_is_weak(result: ScanResult) -> None:
    findings = in_file(result, "go/batch-pipeline/main.go")
    [aes] = [f for f in findings if f.asset.usage == "encryption"]
    assert "ecb-mode" in aes.asset.flags
    assert ("medium", "Non-cryptographic RNG") in tiers(findings)


def test_go_hand_rolled_pbkdf2_detected(result: ScanResult) -> None:
    [kdf] = [f for f in in_file(result, "go/auth-gateway/main.go") if f.asset.usage == "kdf"]
    assert kdf.classification.name == "PBKDF2"
    assert "hand-rolled-crypto" in kdf.asset.flags
    assert "deriveKey" in kdf.asset.observed


def test_go_hmac_hash_not_double_counted(result: ScanResult) -> None:
    findings = in_file(result, "go/config-sync/main.go")
    assert tiers(findings) == {("safe", "SHA-384"), ("safe", "HMAC-SHA256")}


def test_precise_variants_and_confidence(result: ScanResult) -> None:
    def one(name: str, usage: str) -> Finding:
        [f] = [f for f in in_file(result, name) if f.asset.usage == usage]
        return f

    assert one("python/webhook_signature.py", "signature").asset.variant == "Ed25519"
    assert one("python/secure_transfer.py", "encryption").asset.variant == "AES-256-GCM"
    assert one("java/SessionCipher.java", "encryption").asset.variant == "AES-256-GCM"
    assert one("go/telemetry-relay/main.go", "encryption").asset.variant == "AES-256-GCM"
    assert one("java/IdentityVault.java", "kdf").asset.variant == "PBKDF2-HMAC-SHA256"
    assert one("python/member_credentials.py", "kdf").asset.variant == "PBKDF2-HMAC-SHA256"
    # the PRF inside PBKDF2HMAC(algorithm=hashes.SHA256()) is not a standalone hash
    assert not [
        f for f in in_file(result, "python/member_credentials.py") if f.asset.usage == "hash"
    ]
    # Go: key generation and signing are separate uses of Ed25519
    assert {f.asset.usage for f in in_file(result, "go/agent-enrollment/main.go")} == {
        "key-generation", "signature",
    }  # fmt: skip
    # read directly from a literal argument
    assert one("java/ReceiptSigner.java", "key-generation").asset.confidence is Confidence.HIGH
    # key size carried over from KeyPairGenerator.initialize(1024) to the signature call
    assert one("java/ReceiptSigner.java", "signature").asset.confidence is Confidence.MEDIUM
    # KeyGenerator.init(KEY_BITS) pins the AES size; a file-level literal is only a hint
    assert one("java/SessionCipher.java", "encryption").asset.confidence is Confidence.HIGH
    assert one("python/report_export.py", "encryption").asset.confidence is Confidence.MEDIUM
    assert one("go/auth-gateway/main.go", "kdf").asset.confidence is Confidence.MEDIUM
