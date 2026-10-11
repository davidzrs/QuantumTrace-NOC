"""Regenerate personal-samples/certificates (certificates and public keys).

    cd backend && uv run python tests/sample_sources/regenerate_certs.py

Only public material is kept in the repository. The private-key cases in
tests/test_certificate_scanner.py generate their keys at test time, so no private key is ever
committed (secret scanners would rightly flag one).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parents[3] / "personal-samples" / "certificates"


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(
    subject: str,
    key: object,
    issuer: str,
    signer: object,
    digest: hashes.HashAlgorithm,
    start: datetime,
    end: datetime,
    ca: bool = False,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())  # type: ignore[attr-defined]
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return builder.sign(signer, digest)  # type: ignore[arg-type]


def main() -> None:
    # An expired self-signed RSA-1024 certificate: broken twice over. (cryptography no longer
    # signs with SHA-1, so the weak digest case comes from the pcap and code samples instead.)
    legacy = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    cert = _cert(
        "legacy.internal.example",
        legacy,
        "legacy.internal.example",
        legacy,
        hashes.SHA256(),
        datetime(2019, 1, 1, tzinfo=UTC),
        datetime(2020, 1, 1, tzinfo=UTC),
    )
    (HERE / "legacy-rsa1024.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    # A P-384 CA and the P-256 leaf it signed, as a chain and the leaf alone in DER.
    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca = _cert(
        "Acme Issuing CA",
        ca_key,
        "Acme Issuing CA",
        ca_key,
        hashes.SHA384(),
        datetime(2025, 1, 1, tzinfo=UTC),
        datetime(2040, 1, 1, tzinfo=UTC),
        ca=True,
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _cert(
        "api.example.com",
        leaf_key,
        "Acme Issuing CA",
        ca_key,
        hashes.SHA384(),
        datetime(2025, 1, 1, tzinfo=UTC),
        datetime(2035, 1, 1, tzinfo=UTC),
    )
    (HERE / "fullchain.pem").write_bytes(
        leaf.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM)
    )
    (HERE / "api-ecdsa-p256.der").write_bytes(leaf.public_bytes(serialization.Encoding.DER))

    # A certificate request for an RSA-2048 key.
    csr_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(_name("billing.example.com"))
    (HERE / "billing.csr").write_bytes(
        csr.sign(csr_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    )

    # A bare RSA-3072 public key, and OpenSSH user keys.
    signing = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    (HERE / "signing-public.pem").write_bytes(
        signing.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    openssh = serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ed = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(*openssh)
    (HERE / "id_ed25519.pub").write_bytes(ed + b" dev@laptop\n")
    rsa_user = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ecdsa_user = ec.generate_private_key(ec.SECP256R1())
    (HERE / "authorized_keys").write_bytes(
        b"# Fixture: user keys allowed to log in\n"
        + b'from="10.0.0.0/8" '
        + rsa_user.public_key().public_bytes(*openssh)
        + b" ops@bastion\n"
        + ecdsa_user.public_key().public_bytes(*openssh)
        + b" deploy@ci\n"
    )


if __name__ == "__main__":
    main()
