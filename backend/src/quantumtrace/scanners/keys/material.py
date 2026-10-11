"""Key material to assets: certificates and keys as `cryptography` objects -> `CryptoAsset`s.

Shared by the live TLS probe (the leaf certificate it receives) and the certificate and key file
scanner, so a certificate is described the same way wherever it was found.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from quantumtrace.core.models import Confidence, CryptoAsset, Evidence, Exposure, Observation

_CURVES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
# Post-quantum algorithm OIDs (NIST CSOR); `cryptography` may not load these keys yet.
PQC_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    **{f"2.16.840.1.101.3.4.3.{n}": "SLH-DSA" for n in range(20, 32)},
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
}


def key_parts(key: Any) -> tuple[str, int | None, str] | None:
    """(classifier alias, key size, variant) for a public or private key object."""
    if isinstance(key, rsa.RSAPublicKey | rsa.RSAPrivateKey):
        return "RSA", key.key_size, f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey):
        curve = _CURVES.get(key.curve.name, key.curve.name)
        return "ECDSA", key.curve.key_size, f"ECDSA {curve}"
    if isinstance(key, ed25519.Ed25519PublicKey | ed25519.Ed25519PrivateKey):
        return "Ed25519", None, "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey | ed448.Ed448PrivateKey):
        return "Ed448", None, "Ed448"
    if isinstance(key, x25519.X25519PublicKey | x25519.X25519PrivateKey):
        return "X25519", 256, "X25519"
    if isinstance(key, x448.X448PublicKey | x448.X448PrivateKey):
        return "X448", 448, "X448"
    if isinstance(key, dsa.DSAPublicKey | dsa.DSAPrivateKey):
        return "DSA", key.key_size, f"DSA-{key.key_size}"
    return None


def key_asset(
    key: Any,
    observed: str,
    usage: str,
    evidence: Evidence,
    *,
    exposure: Exposure = Exposure.UNKNOWN,
    flags: list[str] | None = None,
    confidence: Confidence = Confidence.HIGH,
) -> CryptoAsset | None:
    parts = key_parts(key)
    if parts is None:
        return None
    alias, size, variant = parts
    return CryptoAsset(
        observed=observed,
        algorithm=alias,
        key_size=size,
        variant=variant,
        usage=usage,
        observation=Observation.CONFIGURED,
        confidence=confidence,
        exposure=exposure,
        flags=sorted(set(flags or [])),
        evidence=evidence,
    )


def describe(cert: x509.Certificate) -> dict[str, str]:
    """Context for a certificate's evidence: who it is for, who signed it, until when."""
    ctx = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_after": cert.not_valid_after_utc.date().isoformat(),
    }
    try:
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if basic.ca:
            ctx["ca"] = "yes"
    except x509.ExtensionNotFound:
        pass
    if cert.issuer == cert.subject:
        ctx["self_signed"] = "yes"
    return ctx


def certificate_assets(
    cert: x509.Certificate,
    evidence: Evidence,
    *,
    exposure: Exposure = Exposure.UNKNOWN,
    key_usage: str = "certificate-key",
) -> Iterator[CryptoAsset]:
    """The certificate's key, the algorithm its issuer signed it with, and that signature's
    digest. An expired certificate is flagged; it is still inventory."""
    flags = ["expired-certificate"] if cert.not_valid_after_utc < datetime.now(UTC) else []

    def asset(observed: str, alias: str, usage: str, **kw: Any) -> CryptoAsset:
        return CryptoAsset.model_validate(
            {
                "observed": observed,
                "algorithm": alias,
                "usage": usage,
                "observation": Observation.CONFIGURED,
                "exposure": exposure,
                "evidence": evidence,
                "flags": flags,
                **kw,
            }
        )

    key_oid = cert.public_key_algorithm_oid
    key_name = getattr(key_oid, "_name", None) or key_oid.dotted_string
    key: PublicKeyTypes | None
    try:
        key = cert.public_key()
    except Exception:  # an algorithm cryptography can't load (e.g. ML-DSA): name it by OID
        key = None
    parts = key_parts(key) if key is not None else None
    if parts is not None:
        alias, size, variant = parts
        yield asset(key_name, alias, key_usage, key_size=size, variant=variant)
    elif (pqc := PQC_OIDS.get(key_oid.dotted_string)) is not None:
        yield asset(key_name, pqc, key_usage, variant=pqc)
    else:
        yield asset(key_name, key_name, key_usage)

    sig_oid = cert.signature_algorithm_oid
    sig_name = getattr(sig_oid, "_name", None) or sig_oid.dotted_string
    lowered = sig_name.lower()
    family = PQC_OIDS.get(sig_oid.dotted_string) or (
        "RSA"
        if "rsa" in lowered
        else "ECDSA"
        if "ecdsa" in lowered
        else "Ed25519"
        if "ed25519" in lowered
        else "Ed448"
        if "ed448" in lowered
        else "DSA"
        if "dsa" in lowered
        else sig_name
    )
    yield asset(sig_name, family, "certificate-signature")
    digest = cert.signature_hash_algorithm
    if digest is not None:
        alias = digest.name.upper().replace("SHA", "SHA-", 1)  # sha256 -> SHA-256
        yield asset(sig_name, alias, "certificate-signature-digest")
