"""Certificate and key files (personal-samples/certificates, plus private keys made per test)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import Confidence, Finding, ScanResult
from tests.conftest import summarise

PEM = serialization.Encoding.PEM


def _by(result: ScanResult, name: str) -> list[Finding]:
    return [f for f in result.findings if Path(f.asset.evidence.location).name == name]


def test_certificates_give_their_key_signature_and_digest(personal_samples: Path) -> None:
    result = run_scan([personal_samples / "certificates"])
    assert result.scanners == ["certificates-and-keys"]
    assert result.errors == [] and result.score.counts.unknown == 0
    assert summarise(result) == {
        ("critical", "RSA-1024", "certificate-key"),
        ("critical", "RSA", "certificate-signature"),
        ("safe", "SHA-256", "certificate-signature-digest"),
        ("critical", "ECDSA", "certificate-key"),
        ("critical", "ECDSA", "certificate-signature"),
        ("safe", "SHA-384", "certificate-signature-digest"),
        ("critical", "RSA", "certificate-key"),  # the CSR's key
        ("critical", "RSA", "public-key"),
        ("critical", "RSA", "ssh-user-key"),
        ("critical", "ECDSA", "ssh-user-key"),
        ("critical", "EdDSA", "ssh-user-key"),
    }

    legacy = next(
        f for f in _by(result, "legacy-rsa1024.pem") if f.asset.usage == "certificate-key"
    )
    assert legacy.asset.variant == "RSA-1024" and legacy.classification.classically_broken
    assert "expired-certificate" in legacy.asset.flags
    assert legacy.asset.evidence.context["subject"] == "CN=legacy.internal.example"
    assert legacy.asset.evidence.context["self_signed"] == "yes"


def test_a_chain_tells_the_leaf_from_its_ca(personal_samples: Path) -> None:
    result = run_scan([personal_samples / "certificates" / "fullchain.pem"])
    keys = sorted(
        (f for f in result.findings if f.asset.usage == "certificate-key"),
        key=lambda f: f.asset.evidence.line or 0,
    )
    assert [k.asset.variant for k in keys] == ["ECDSA P-256", "ECDSA P-384"]
    assert keys[0].asset.evidence.line == 1 and (keys[1].asset.evidence.line or 0) > 1
    assert "ca" not in keys[0].asset.evidence.context
    assert keys[1].asset.evidence.context["ca"] == "yes"


def test_der_certificate_and_openssh_keys(personal_samples: Path) -> None:
    result = run_scan([personal_samples / "certificates"])
    (der,) = [f for f in _by(result, "api-ecdsa-p256.der") if f.asset.usage == "certificate-key"]
    assert der.asset.variant == "ECDSA P-256" and der.asset.evidence.line is None
    authorized = {(f.asset.evidence.line, f.asset.variant) for f in _by(result, "authorized_keys")}
    assert authorized == {(2, "RSA-2048"), (3, "ECDSA P-256")}  # the from="..." option is skipped
    (ed,) = _by(result, "id_ed25519.pub")
    assert ed.asset.variant == "Ed25519" and ed.asset.evidence.context["key_type"] == "ssh-ed25519"


def _self_signed(key: rsa.RSAPrivateKey) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bundle.example")])
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )


def test_private_keys_in_files_are_flagged(tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "server.key").write_bytes(
        key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    (tmp_path / "legacy.key").write_bytes(
        key.private_bytes(
            PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.BestAvailableEncryption(b"hunter2"),
        )
    )
    (tmp_path / "vault.key").write_bytes(
        key.private_bytes(
            PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"hunter2"),
        )
    )
    (tmp_path / "id_ed25519").write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
        )
    )
    cert = _self_signed(key)
    (tmp_path / "open.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"open", key, cert, None, serialization.NoEncryption()
        )
    )
    (tmp_path / "locked.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"locked", key, cert, None, serialization.BestAvailableEncryption(b"hunter2")
        )
    )

    result = run_scan([tmp_path])
    assert result.errors == []

    (plain,) = _by(result, "server.key")
    assert (plain.asset.usage, plain.asset.variant) == ("private-key", "RSA-2048")
    assert "private-key-in-file" in plain.asset.flags

    (encrypted,) = _by(result, "legacy.key")  # the PEM label still says RSA
    assert encrypted.asset.algorithm == "RSA" and encrypted.asset.key_size is None
    assert encrypted.asset.confidence is Confidence.MEDIUM
    assert encrypted.asset.evidence.context["encrypted"] == "yes"

    assert _by(result, "vault.key") == []  # PKCS#8 hides even the algorithm
    assert any("vault.key: an encrypted private key" in n.message for n in result.limitations)

    (openssh,) = _by(result, "id_ed25519")
    assert (openssh.asset.usage, openssh.asset.variant) == ("ssh-user-key", "Ed25519")
    assert "private-key-in-file" in openssh.asset.flags

    bundle = {f.asset.usage for f in _by(result, "open.p12")}
    assert {"certificate-key", "certificate-signature", "private-key"} <= bundle
    assert _by(result, "locked.p12") == []
    assert any("locked.p12: a password-protected PKCS#12" in n.message for n in result.limitations)


def test_an_unreadable_der_file_is_a_note(tmp_path: Path) -> None:
    (tmp_path / "broken.der").write_bytes(b"\x30\x82\x00\x10not really asn.1")
    result = run_scan([tmp_path])
    assert result.findings == [] and result.errors == []
    assert any("broken.der: not a certificate or key" in n.message for n in result.limitations)
