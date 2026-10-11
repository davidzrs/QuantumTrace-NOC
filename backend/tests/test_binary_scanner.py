"""Compiled artifacts: Java bytecode and a Go executable (personal-samples/binaries)."""

from __future__ import annotations

from pathlib import Path

from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import Confidence, Finding, Observation
from tests.conftest import SAMPLE_SOURCES, summarise

JAVA = {
    ("critical", "RSA-1024", "key-generation"),
    ("critical", "RSA-1024", "signature"),
    ("medium", "SHA-1", "signature-digest"),
    ("medium", "MD5", "hash"),
    ("medium", "3DES", "encryption"),
    ("medium", "AES (key size unknown)", "encryption"),
    ("medium", "Non-cryptographic RNG", "rng"),
    ("safe", "HMAC-SHA256", "mac"),
    ("safe", "PBKDF2", "kdf"),
    ("safe", "ML-DSA", "key-generation"),
    ("safe", "ML-KEM", "key-agreement"),
}


def test_a_class_file_classifies_like_its_source(personal_samples: Path) -> None:
    compiled = run_scan([personal_samples / "binaries" / "LegacyVault.class"])
    source = run_scan([SAMPLE_SOURCES / "java"])
    assert compiled.scanners == ["binary-artifacts"] and compiled.errors == []
    assert summarise(compiled) == summarise(source) == JAVA


def _needle(f: Finding) -> str:
    """What the source line must contain: the algorithm string the call passed."""
    if f.asset.usage == "rng":
        return "new Random()"
    observed = f.asset.observed  # AES/GCM/NoPadding, or KeyPairGenerator.getInstance("RSA")
    return observed.split('"')[1] if '"' in observed else observed


def test_bytecode_findings_point_at_source_lines(personal_samples: Path) -> None:
    result = run_scan([personal_samples / "binaries" / "LegacyVault.class"])
    java = SAMPLE_SOURCES / "java" / "com" / "acme" / "vault" / "LegacyVault.java"
    lines = java.read_text().splitlines()
    for f in result.findings:
        ev = f.asset.evidence
        assert f.asset.observation is Observation.IN_CODE
        assert ev.context["class"] == "com.acme.vault.LegacyVault"
        assert ev.context["source_file"] == "LegacyVault.java"
        line = lines[(ev.line or 0) - 1]
        assert _needle(f) in line, (f.classification.name, ev.line, line)

    des = next(f for f in result.findings if f.classification.name == "3DES")
    assert "ecb-mode" in des.asset.flags and des.asset.evidence.context["method"] == "legacyCipher"
    rng = next(f for f in result.findings if f.asset.usage == "rng")
    assert "secret-context" in rng.asset.flags  # called inside sessionToken()


def test_a_jar_points_into_the_archive_and_lists_bundled_bouncycastle(
    personal_samples: Path,
) -> None:
    result = run_scan([personal_samples / "binaries" / "legacy-vault.jar"])
    assert summarise(result) == JAVA
    assert all(
        f.asset.evidence.location.endswith("legacy-vault.jar!/com/acme/vault/LegacyVault.class")
        for f in result.findings
    )
    bc_id = "maven:org.bouncycastle:bcprov-jdk18on@1.78.1"
    (bc,) = [lib for lib in result.libraries if lib.id == bc_id]
    assert bc.evidence[0].location.endswith("/bcprov-jdk18on/pom.properties")
    # Cipher.getInstance("AES/GCM/NoPadding", "BC"): the BouncyCastle provider answers
    aes = next(f for f in result.findings if f.classification.name == "AES (key size unknown)")
    assert aes.asset.library == bc_id
    assert not any("legacy-vault" in lib.id for lib in result.libraries)  # the app isn't a library


def test_go_binary_build_info_and_linked_crypto(personal_samples: Path) -> None:
    result = run_scan([personal_samples / "binaries" / "legacy-agent"])
    assert result.scanners == ["binary-artifacts"] and result.errors == []
    assert summarise(result) >= {
        ("critical", "RSA", "key-generation"),
        ("critical", "RSA", "signature"),
        ("medium", "MD5", "hash"),
        ("medium", "3DES", "encryption"),
        ("safe", "ML-KEM", "key-agreement"),
        ("safe", "PBKDF2", "kdf"),
        ("safe", "SHA-256", "hash"),
    }
    assert result.score.counts.unknown == 0
    mlkem = next(f for f in result.findings if f.classification.name == "ML-KEM")
    assert mlkem.asset.variant == "ML-KEM-768"
    for f in result.findings:  # linked, not proven called
        assert f.asset.confidence is Confidence.MEDIUM
        assert f.asset.evidence.context["main_module"] == "example.com/legacy-agent"

    libs = {lib.id: lib for lib in result.libraries}
    stdlib = next(lib for lib in libs.values() if lib.id.startswith("go:stdlib@1.24"))
    xcrypto = libs["golang:golang.org/x/crypto@v0.36.0"]
    assert xcrypto.purl == "pkg:golang/golang.org/x/crypto@v0.36.0"
    pbkdf2 = next(f for f in result.findings if f.classification.name == "PBKDF2")
    assert pbkdf2.asset.library == xcrypto.id
    assert mlkem.asset.library == stdlib.id
    assert any("linked into the executable" in n.message for n in result.limitations)


def test_a_native_binary_that_is_not_go_is_a_note(tmp_path: Path) -> None:
    (tmp_path / "agent").write_bytes(b"\x7fELF" + bytes(256))
    result = run_scan([tmp_path])
    assert result.findings == [] and result.errors == []
    assert any("agent: a native executable that isn't Go" in n.message for n in result.limitations)


def test_a_corrupt_class_file_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "Broken.class").write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x41\x00\x09\xff")
    result = run_scan([tmp_path])
    assert result.findings == [] and result.errors == []
