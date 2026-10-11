"""What each `CryptoAsset.usage` does, in one place.

Scanners write `usage` as free text (`tls-key-exchange`, `SIGN_VERIFY`, `kdf`, ...). The role
behind it decides two things: whether a Shor-breakable finding is exposed to
Harvest-Now-Decrypt-Later (`Classification.hndl`), and how much Shor-exposed authentication
weighs in the score. A scanner that adds a usage must add it here; a test fails on any usage
the samples produce that this table doesn't know.
"""

from __future__ import annotations

from enum import StrEnum

from quantumtrace.core.models import QuantumThreat, RiskTier


class Role(StrEnum):
    # Key exchange, key transport and encryption: ciphertext or a handshake recorded today is
    # read once a quantum computer exists.
    CONFIDENTIALITY = "confidentiality"
    # Signatures, certificates, host keys: forging one needs that computer at the time of the
    # attack, so recordings don't help.
    AUTHENTICATION = "authentication"
    # Hashes, MACs and hash-based key derivation, alone or inside a signature.
    DIGEST = "digest"
    # Protocol versions, policies, whole suites, cleartext transport.
    PROTOCOL = "protocol"
    # Key generation and randomness: what the key or number is for isn't known.
    OTHER = "other"


# Lower-cased usage -> role. KMS KeyUsage values appear in upper case in the exports.
USAGE_ROLES: dict[str, Role] = {
    # network (TLS, SSH) and cloud (ELB, KMS)
    "tls-key-exchange": Role.CONFIDENTIALITY,  # includes static RSA key transport
    "ssh-key-exchange": Role.CONFIDENTIALITY,
    "key_agreement": Role.CONFIDENTIALITY,
    "encrypt_decrypt": Role.CONFIDENTIALITY,
    "tls-cipher": Role.CONFIDENTIALITY,
    "ssh-cipher": Role.CONFIDENTIALITY,
    "sign_verify": Role.AUTHENTICATION,
    "certificate-key": Role.AUTHENTICATION,
    "certificate-signature": Role.AUTHENTICATION,
    "tls-authentication": Role.AUTHENTICATION,
    "ssh-host-key": Role.AUTHENTICATION,
    "generate_verify_mac": Role.DIGEST,
    "signature-digest": Role.DIGEST,
    "certificate-signature-digest": Role.DIGEST,
    "ssh-signature-digest": Role.DIGEST,
    "ssh-kex-hash": Role.DIGEST,
    "tls-mac": Role.DIGEST,
    "ssh-mac": Role.DIGEST,
    "tls-protocol": Role.PROTOCOL,
    "tls-policy": Role.PROTOCOL,
    "tls-cipher-suite": Role.PROTOCOL,
    "transport": Role.PROTOCOL,
    # source code
    "key-agreement": Role.CONFIDENTIALITY,
    "encryption": Role.CONFIDENTIALITY,  # symmetric ciphers and RSA-OAEP / PKCS#1 encryption
    "signature": Role.AUTHENTICATION,
    "hash": Role.DIGEST,
    "mac": Role.DIGEST,
    "kdf": Role.DIGEST,
    "kdf-prf": Role.DIGEST,
    "key-generation": Role.OTHER,
    "rng": Role.OTHER,
    # certificate and key files, server configs
    "ssh-user-key": Role.AUTHENTICATION,  # authorized_keys, id_*.pub, PubkeyAcceptedAlgorithms
    "private-key": Role.OTHER,  # a key file says what it is, not what it is used for
    "public-key": Role.OTHER,
}


def role_of(usage: str | None) -> Role | None:
    """The role of a usage; None when no scanner is known to write it. An asset without a
    usage has no known purpose."""
    if not usage:
        return Role.OTHER
    return USAGE_ROLES.get(usage.lower())


def exposed_to_hndl(threat: QuantumThreat, tier: RiskTier, usage: str | None) -> bool:
    """Shor breaks it and it protects confidentiality: recorded traffic or data is exposed."""
    return (
        threat is QuantumThreat.SHOR
        and tier is not RiskTier.SAFE
        and role_of(usage) is Role.CONFIDENTIALITY
    )
