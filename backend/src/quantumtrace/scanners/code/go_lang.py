"""Go: crypto/* and golang.org/x/crypto calls, plus a hand-rolled-KDF heuristic."""

from __future__ import annotations

import re

from quantumtrace.core.models import Confidence
from quantumtrace.scanners.code.common import SourceFile

HASH_CALLS = {
    ("md5", "Sum"): "MD5", ("md5", "New"): "MD5",
    ("sha1", "Sum"): "SHA-1", ("sha1", "New"): "SHA-1",
    ("sha256", "Sum256"): "SHA-256", ("sha256", "New"): "SHA-256",
    ("sha256", "Sum224"): "SHA-224", ("sha256", "New224"): "SHA-224",
    ("sha512", "Sum384"): "SHA-384", ("sha512", "New384"): "SHA-384",
    ("sha512", "Sum512"): "SHA-512", ("sha512", "New"): "SHA-512",
    ("sha3", "Sum256"): "SHA3-256", ("sha3", "New256"): "SHA3-256",
}  # fmt: skip
HMAC_HASH = {
    ("md5", "New"): "HmacMD5", ("sha1", "New"): "HMAC-SHA1", ("sha256", "New"): "HMAC-SHA256",
    ("sha512", "New384"): "HMAC-SHA384", ("sha512", "New"): "HMAC-SHA512",
}  # fmt: skip
CURVES = {"P224": 224, "P256": 256, "P384": 384, "P521": 521}


def scan(src: SourceFile) -> None:
    text = src.text
    imports = set(re.findall(r"\"((?:crypto|golang\.org/x/crypto|math)/[\w/]+)\"", text))
    aes_bits, hardcoded = src.symmetric_key_hint()

    hmac_spans: list[tuple[int, int]] = []
    for m in re.finditer(r"\bhmac\.New\(\s*(\w+)\.(\w+)", text):
        hmac_spans.append(m.span())
        if name := HMAC_HASH.get((m.group(1), m.group(2))):
            src.emit(m.start(), m.group(0) + ", ...)", name, "mac")
    for m in re.finditer(r"\b(md5|sha1|sha256|sha512|sha3)\.(\w+)\(", text):
        if any(a <= m.start() < b for a, b in hmac_spans):
            continue
        if f"crypto/{m.group(1)}" not in imports and m.group(1) != "sha3":
            continue
        if name := HASH_CALLS.get((m.group(1), m.group(2))):
            src.emit(m.start(), m.group(0).rstrip("("), name, "hash")

    rsa_bits: int | None = None
    for m in re.finditer(r"\brsa\.GenerateKey\(\s*[\w.]+\s*,\s*(\w+)", text):
        rsa_bits = src.int_value(m.group(1))
        src.emit(m.start(), m.group(0) + ")", "RSA", "key-generation", key_size=rsa_bits)
    for m in re.finditer(r"\brsa\.(SignPKCS1v15|SignPSS|EncryptOAEP|EncryptPKCS1v15)\(", text):
        usage = "encryption" if m.group(1).startswith("Encrypt") else "signature"
        conf = Confidence.MEDIUM if rsa_bits else Confidence.HIGH
        src.emit(m.start(), m.group(0).rstrip("("), "RSA", usage, key_size=rsa_bits,
                 confidence=conf)  # fmt: skip
    for m in re.finditer(r"\becdsa\.GenerateKey\(\s*elliptic\.(P\d+)\(", text):
        src.emit(m.start(), m.group(0) + ")", "ECDSA", "key-generation",
                 key_size=CURVES.get(m.group(1)), context={"curve": m.group(1)})  # fmt: skip
    for m in re.finditer(r"\bed25519\.(GenerateKey|NewKeyFromSeed|Sign)\(", text):
        usage = "signature" if m.group(1) == "Sign" else "key-generation"
        src.emit(m.start(), m.group(0).rstrip("("), "Ed25519", usage)
    for m in re.finditer(r"\becdh\.(X25519|P256|P384|P521)\(\)|\bcurve25519\.X25519\(", text):
        curve = m.group(1) or "X25519"
        src.emit(m.start(), m.group(0), "ECDH", "key-agreement", context={"curve": curve})
    for m in re.finditer(r"\bmlkem\.(GenerateKey768|GenerateKey1024)\(", text):
        src.emit(m.start(), m.group(0).rstrip("("), "ML-KEM", "key-agreement")

    has_mode = re.search(r"\bcipher\.New(GCM|CBC|CTR|OFB|CFB)\w*\(", text)
    for m in re.finditer(r"\baes\.NewCipher\(", text):
        flags = ["hardcoded-key"] if hardcoded else []
        if has_mode is None and re.search(r"\.Encrypt\(", text):
            flags.append("ecb-mode")  # raw block.Encrypt loop = ECB
        elif has_mode and has_mode.group(1) == "CBC":
            flags.append("cbc-mode")
        ctx = {"mode": has_mode.group(1)} if has_mode else None
        src.emit(m.start(), "aes.NewCipher", "AES", "encryption", key_size=aes_bits, flags=flags,
                 confidence=Confidence.MEDIUM, context=ctx)  # fmt: skip
    for m in re.finditer(r"\bdes\.(NewTripleDESCipher|NewCipher)\(", text):
        alg = "3DES" if "Triple" in m.group(1) else "DES"
        src.emit(m.start(), m.group(0).rstrip("("), alg, "encryption")
    for m in re.finditer(r"\brc4\.NewCipher\(", text):
        src.emit(m.start(), "rc4.NewCipher", "RC4", "encryption")
    for m in re.finditer(r"\bchacha20poly1305\.New(X)?\(", text):
        src.emit(m.start(), m.group(0).rstrip("("), "ChaCha20-Poly1305", "encryption")

    for m in re.finditer(
        r"\b(pbkdf2\.Key|scrypt\.Key|argon2\.IDKey|hkdf\.New|bcrypt\.GenerateFromPassword)\(", text
    ):
        name = {"pbkdf2": "PBKDF2", "scrypt": "scrypt", "argon2": "Argon2", "hkdf": "HKDF",
                "bcrypt": "bcrypt"}[m.group(1).split(".")[0]]  # fmt: skip
        src.emit(m.start(), m.group(1), name, "kdf")

    _hand_rolled_kdf(src, hmac_spans)

    if "math/rand" in imports or "math/rand/v2" in imports:
        for m in re.finditer(r"\brand\.(Read|Int\w*|Uint\w*)\(", text):
            src.emit(m.start(), f"math/rand.{m.group(1)}", "non-csprng", "rng")


def _hand_rolled_kdf(src: SourceFile, hmac_spans: list[tuple[int, int]]) -> None:
    """HMAC re-applied inside a loop with XOR accumulation is a home-made PBKDF2."""
    text = src.text
    if not hmac_spans or "^=" not in text or "pbkdf2.Key" in text:
        return
    for func in re.finditer(r"^func\s+(\w+)\s*\(", text, re.M):
        end = text.find("\n}", func.end())
        body = text[func.end() : end if end != -1 else len(text)]
        offset = func.end()
        in_body = [s for s, _ in hmac_spans if offset <= s < offset + len(body)]
        if in_body and "^=" in body and re.search(r"\bfor\b[^{]*\{[^}]*\bfor\b", body, re.S):
            src.emit(func.start(), f"func {func.group(1)} (manual HMAC iteration)", "PBKDF2",
                     "kdf", flags=["hand-rolled-crypto"], variant="PBKDF2-HMAC-SHA256 (hand-rolled)"
                     if "sha256.New" in body else None,
                     confidence=Confidence.MEDIUM)  # fmt: skip
