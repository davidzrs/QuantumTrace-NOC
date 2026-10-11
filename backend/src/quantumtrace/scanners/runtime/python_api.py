"""Python tracer events -> classifier aliases, mirroring what `code/python_lang.py` reports
for the same call in source, so a line found both ways becomes one finding.

The tracer names the library call and what it used (`cryptography.rsa.sign`, bits=1024). This
module only says which algorithm and usage that call is; the tier still comes from the rules.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from quantumtrace.scanners.code.python_lang import CIPHERS, HASH_NAMES, HMAC_NAMES, KDFS

AEAD_MODES = {
    "AESGCM": "GCM", "AESCCM": "CCM", "AESOCB3": "OCB", "AESSIV": "SIV", "AESGCMSIV": "GCM-SIV",
}  # fmt: skip
EDWARDS = {"ed25519": "Ed25519", "ed448": "Ed448"}
MONTGOMERY = {"x25519": "X25519", "x448": "X448"}


@dataclass(frozen=True)
class Seen:
    """One traced call, as the classifier should hear about it."""

    algorithm: str
    usage: str
    key_size: int | None = None
    certain: bool = True
    flags: tuple[str, ...] = ()
    context: Mapping[str, str] = field(default_factory=dict)
    variant: str | None = None


def describe(api: str, args: Mapping[str, object]) -> Seen | None:
    """What a traced call is, or None for a call no rule covers."""
    name = str(args.get("name") or "").lower().replace("-", "_")
    size = args.get("bits")
    bits = size if isinstance(size, int) and not isinstance(size, bool) else None
    library, _, call = api.partition(".")
    if library == "hashlib":
        if call == "pbkdf2_hmac":
            return _kdf("PBKDF2", name)
        if call == "scrypt":
            return Seen("scrypt", "kdf")
        return _hash(name)
    if library == "hmac":
        alias = HMAC_NAMES.get(name)
        return Seen(alias, "mac") if alias else None
    if library != "cryptography":
        return None
    group, _, what = call.partition(".")
    curve = str(args.get("curve") or "")
    if group == "rsa":
        if what == "generate":
            return Seen("RSA", "key-generation", bits)
        return Seen("RSA", "signature" if what in ("sign", "verify") else "encryption", bits)
    if group == "padding":
        # the padding object alone doesn't say which operation it is for
        return Seen("RSA", "encryption" if what == "OAEP" else "signature", certain=False)
    if group == "ec":
        context = {"curve": curve} if curve else {}
        if what == "generate":
            return Seen("ECDSA", "key-generation", bits, context=context)
        if what in ("sign", "verify"):
            return Seen("ECDSA", "signature", bits, context=context)
        return Seen("ECDH", "key-agreement", bits, context=context)  # exchange, ec.ECDH()
    if group in EDWARDS:
        return Seen(EDWARDS[group], "key-generation" if what == "generate" else "signature")
    if group in MONTGOMERY:
        return Seen("ECDH", "key-agreement", context={"curve": MONTGOMERY[group]})
    if group == "dsa":
        return Seen("DSA", "key-generation" if what == "generate" else "signature", bits)
    if group == "dh":
        return Seen("DH", "key-agreement", bits)
    if group == "hashes":
        return _hash(name)
    if group == "cipher":
        return _cipher(str(args.get("name") or ""), bits, str(args.get("mode") or ""))
    if group == "algorithms":
        return _cipher(what, bits, "")
    if group == "aead":
        if what == "ChaCha20Poly1305":
            return Seen("ChaCha20-Poly1305", "encryption")
        mode = AEAD_MODES.get(what)
        return Seen("AES", "encryption", bits, context={"mode": mode}) if mode else None
    if group == "fernet":  # AES-128-CBC with HMAC-SHA256, by the Fernet specification
        return Seen("AES", "encryption", 128, context={"mode": "CBC"})
    if group == "kdf":
        alias = KDFS.get(what)
        return _kdf(alias, str(args.get("hash") or "").lower()) if alias else None
    return None


def _hash(name: str) -> Seen | None:
    alias = HASH_NAMES.get(name)
    return Seen(alias, "hash") if alias else None


def _kdf(alias: str, prf: str) -> Seen:
    variant = None
    if prf and alias in ("PBKDF2", "HKDF"):
        variant = f"{alias}-HMAC-{prf.upper().replace('_', '-')}"
    return Seen(alias, "kdf", variant=variant)


def _cipher(name: str, bits: int | None, mode: str) -> Seen | None:
    alias = CIPHERS.get(name)
    if alias is None:
        return None
    if alias.startswith("AES"):
        alias = "AES"  # AES128 / AES256 classes: the size is in `bits`
    flags = ("ecb-mode",) if mode.upper() == "ECB" else ()
    context = {"mode": mode.upper()} if mode else {}
    return Seen(alias, "encryption", bits if alias == "AES" else None, flags=flags, context=context)
