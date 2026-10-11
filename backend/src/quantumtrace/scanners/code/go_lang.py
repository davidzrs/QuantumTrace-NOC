"""Go: crypto/* and golang.org/x/crypto calls, crypto/tls settings, JWT signing methods, plus a
hand-rolled-KDF heuristic. Packages are found by their imports, so a renamed import
(`m "crypto/md5"`) is read like `md5`, and `rand` is only math/rand when that is what it names."""

from __future__ import annotations

import re
from collections.abc import Iterable

from quantumtrace.core.models import Confidence
from quantumtrace.rules.tls import CIPHER_SUITES
from quantumtrace.scanners.code.common import SourceFile
from quantumtrace.scanners.code.imports import go_imports
from quantumtrace.scanners.code.protocol_rules import emit_jws, emit_tls_suites, emit_tls_version

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
HASH_PACKAGES = {
    "crypto/md5": "md5", "crypto/sha1": "sha1", "crypto/sha256": "sha256",
    "crypto/sha512": "sha512", "crypto/sha3": "sha3", "golang.org/x/crypto/sha3": "sha3",
}  # fmt: skip


def scan(src: SourceFile) -> None:
    text = src.text
    packages = go_imports(text)  # name in the code -> import path
    aes_bits, hardcoded = src.symmetric_key_hint()
    # name in the code -> hash package (`m "crypto/md5"` -> md5); sha3 was read unimported
    hashes = {name: HASH_PACKAGES[path] for name, path in packages.items() if path in HASH_PACKAGES}
    if "sha3" not in hashes.values():
        hashes["sha3"] = "sha3"

    hmacs = list(re.finditer(r"\bhmac\.New\(\s*(\w+)\.(\w+)", text))
    hmac_spans = [m.span() for m in hmacs]
    # HMAC calls inside a hand-rolled PBKDF2's loops are its PRF: part of that finding
    prf_calls = _hand_rolled_kdf(src, hmacs, hashes)
    for m in hmacs:
        if m.start() in prf_calls:
            continue
        if name := HMAC_HASH.get((hashes.get(m.group(1), m.group(1)), m.group(2))):
            src.emit(m.start(), m.group(0) + ", ...)", name, "mac")
    for m in re.finditer(rf"\b({_alternation(hashes)})\.(\w+)\(", text):
        if any(a <= m.start() < b for a, b in hmac_spans):
            continue
        if name := HASH_CALLS.get((hashes[m.group(1)], m.group(2))):
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

    # math/rand under whatever name it is imported as; `rand` may be crypto/rand instead
    weak = [n for n, path in packages.items() if path in ("math/rand", "math/rand/v2")]
    for m in re.finditer(rf"\b(?:{_alternation(weak)})\.(Read|Int\w*|Uint\w*)\(", text):
        src.emit_weak_rng(m.start(), f"math/rand.{m.group(1)}")

    tls = _alternation([n for n, path in packages.items() if path == "crypto/tls"])
    for m in re.finditer(rf"\b(?:{tls})\.Version(TLS1[0-2]|SSL30)\b", text):
        emit_tls_version(src, m.start(), m.group(0), m.group(1))
    for m in re.finditer(rf"\b(?:{tls})\.(TLS_\w+)\b", text):  # CipherSuites entries
        if "_WITH_" in m.group(1) or m.group(1) in CIPHER_SUITES.values():
            emit_tls_suites(src, m.start(), m.group(0), [m.group(1)])

    jwt = _alternation([n for n, path in packages.items() if "jwt" in path])
    for m in re.finditer(
        rf"\b(?:{jwt})\.SigningMethod((?:RS|PS|ES|HS)(?:256|384|512)|EdDSA)\b", text
    ):
        emit_jws(src, m.start(), m.group(0), m.group(1))


def _alternation(names: Iterable[str]) -> str:
    """Regex alternation of package names; one that can't match when there are none."""
    escaped = [re.escape(n) for n in names]
    return "|".join(escaped) if escaped else "(?!)"


def _hand_rolled_kdf(
    src: SourceFile, hmacs: list[re.Match[str]], hashes: dict[str, str]
) -> set[int]:
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
            package = hashes.get(prf.group(1), prf.group(1))
            digest = HASH_CALLS.get((package, prf.group(2)))  # SHA-256, SHA-1, ...
            label = digest.replace("-", "") if digest else None
            src.emit(func.start(), f"func {func.group(1)} (manual HMAC iteration)", "PBKDF2",
                     "kdf", flags=["hand-rolled-crypto"],
                     variant=f"PBKDF2-HMAC-{label} (hand-rolled)" if label else None,
                     context={"prf": label} if label else None,
                     confidence=Confidence.MEDIUM)  # fmt: skip
            if digest in ("SHA-1", "MD5") and (mac := HMAC_HASH.get((package, prf.group(2)))):
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
