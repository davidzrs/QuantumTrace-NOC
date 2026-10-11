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

    hmacs = list(re.finditer(r"\bhmac\.New\(\s*(\w+)\.(\w+)", text))
    hmac_spans = [m.span() for m in hmacs]
    # HMAC calls inside a hand-rolled PBKDF2's loops are its PRF: part of that finding
    prf_calls = _hand_rolled_kdf(src, hmacs)
    for m in hmacs:
        if m.start() in prf_calls:
            continue
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

    if "math/rand" in imports or "math/rand/v2" in imports:
        for m in re.finditer(r"\brand\.(Read|Int\w*|Uint\w*)\(", text):
            src.emit_weak_rng(m.start(), f"math/rand.{m.group(1)}")


def _hand_rolled_kdf(src: SourceFile, hmacs: list[re.Match[str]]) -> set[int]:
    """HMAC re-applied inside a loop with XOR accumulation is a home-made PBKDF2. Its PRF is an
    HMAC made in the loops, or made before them into a variable the loops use (`prf.Reset()`).
    The PRF is named in the finding like a library PBKDF2's (a SHA-1 or MD5 one is also reported
    on its own, as Java's PBKDF2WithHmacSHA1 is). Any other HMAC, such as a MAC over a message
    after the key is derived, stays a finding of its own. Returns the PRF calls' offsets."""
    text = src.text
    prf_calls: set[int] = set()
    if not hmacs or "^=" not in text or "pbkdf2.Key" in text:
        return prf_calls
    for func in re.finditer(r"^func\s+(\w+)\s*\(", text, re.M):
        end = text.find("\n}", func.end())
        body = text[func.end() : end if end != -1 else len(text)]
        loops = _loop_spans(body, func.end())
        in_body = [m for m in hmacs if func.end() <= m.start() < func.end() + len(body)]
        in_loops = [m for m in in_body if _feeds_loops(text, m, loops)]
        if in_loops and "^=" in body and re.search(r"\bfor\b[^{]*\{[^}]*\bfor\b", body, re.S):
            prf = in_loops[0]
            digest = HASH_CALLS.get((prf.group(1), prf.group(2)))  # SHA-256, SHA-1, ...
            label = digest.replace("-", "") if digest else None
            src.emit(func.start(), f"func {func.group(1)} (manual HMAC iteration)", "PBKDF2",
                     "kdf", flags=["hand-rolled-crypto"],
                     variant=f"PBKDF2-HMAC-{label} (hand-rolled)" if label else None,
                     context={"prf": label} if label else None,
                     confidence=Confidence.MEDIUM)  # fmt: skip
            if digest in ("SHA-1", "MD5") and (mac := HMAC_HASH.get((prf.group(1), prf.group(2)))):
                src.emit(prf.start(), prf.group(0) + ", ...)", mac, "kdf-prf")
            prf_calls.update(m.start() for m in in_loops)
    return prf_calls


def _feeds_loops(text: str, call: re.Match[str], loops: list[tuple[int, int]]) -> bool:
    """Whether an hmac.New call is made in a loop, or assigned to a name a loop then uses."""
    if any(a <= call.start() < b for a, b in loops):
        return True
    line_start = text.rfind("\n", 0, call.start()) + 1
    assigned = re.search(r"(\w+)\s*:?=\s*$", text[line_start : call.start()])
    return assigned is not None and any(
        re.search(rf"\b{assigned.group(1)}\.", text[a:b]) for a, b in loops
    )


def _loop_spans(body: str, offset: int) -> list[tuple[int, int]]:
    """Offsets of every `for ... { ... }` block in a function body, nested ones included."""
    spans = []
    for m in re.finditer(r"\bfor\b[^{]*\{", body):
        depth, i = 1, m.end()
        while i < len(body) and depth:
            depth += {"{": 1, "}": -1}.get(body[i], 0)
            i += 1
        spans.append((offset + m.start(), offset + i))
    return spans
