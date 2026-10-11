"""Python: hashlib/hmac, pyca/cryptography (hazmat), PyCryptodome, stdlib `random` misuse,
`ssl` settings and JWT algorithms. Imported names are resolved, so `import hashlib as hl` and
`from hashlib import sha1` are read like `hashlib.sha1`."""

from __future__ import annotations

import re

from quantumtrace.core.models import Confidence
from quantumtrace.scanners.code.common import SourceFile
from quantumtrace.scanners.code.imports import python_imports
from quantumtrace.scanners.code.protocol_rules import (
    call_arguments,
    emit_jws,
    emit_tls_suites,
    emit_tls_version,
    string_literals,
    suite_names,
)

HASH_NAMES = {
    "md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256",
    "sha384": "SHA-384", "sha512": "SHA-512", "sha3_256": "SHA3-256", "sha3_384": "SHA3-384",
    "sha3_512": "SHA3-512", "sha512_256": "SHA-512",
}  # fmt: skip
HMAC_NAMES = {
    "md5": "HmacMD5", "sha1": "HMAC-SHA1", "sha256": "HMAC-SHA256",
    "sha384": "HMAC-SHA384", "sha512": "HMAC-SHA512",
}  # fmt: skip
CIPHERS = {
    "AES": "AES", "AES128": "AES-128", "AES256": "AES-256", "TripleDES": "3DES", "DES3": "3DES",
    "DES": "DES", "Blowfish": "Blowfish", "ARC4": "RC4", "ChaCha20": "ChaCha20",
}  # fmt: skip
CURVE_BITS = {"SECP256R1": 256, "SECP384R1": 384, "SECP521R1": 521, "SECP256K1": 256}
WEAK_RANDOM = ("getrandbits", "randint", "randbytes", "random", "choice", "choices")
KDFS = {
    "PBKDF2HMAC": "PBKDF2", "Scrypt": "scrypt", "HKDF": "HKDF", "HKDFExpand": "HKDF",
    "Argon2id": "Argon2",
}  # fmt: skip


def scan(src: SourceFile) -> None:
    text = src.text
    aes_bits, hardcoded = src.symmetric_key_hint()
    key_flags = ["hardcoded-key"] if hardcoded else []

    imports = python_imports(text)
    hashlib_ = _names(imports, "hashlib")  # `hashlib`, or what `import hashlib as hl` binds
    for m in re.finditer(rf"\b(?:{hashlib_})\.(\w+)\s*\(", text):
        if name := HASH_NAMES.get(m.group(1).lower()):
            src.emit(m.start(), m.group(0).rstrip("( "), name, "hash")
    for m in re.finditer(rf"\b(?:{hashlib_})\.new\(\s*[\"'](\w+)[\"']", text):
        if name := HASH_NAMES.get(m.group(1).lower()):
            src.emit(m.start(), m.group(0), name, "hash")
    for bound, leaf in _members(imports, "hashlib"):  # from hashlib import sha1 [as h]
        if name := HASH_NAMES.get(leaf.lower()):
            for m in re.finditer(rf"\b{re.escape(bound)}\s*\(", text):
                src.emit(m.start(), bound, name, "hash")
    for m in re.finditer(rf"\bhmac\.new\([^)]*?(?:(?:{hashlib_})\.(\w+)|[\"'](\w+)[\"'])", text):
        if name := HMAC_NAMES.get((m.group(1) or m.group(2)).lower()):
            src.emit(m.start(), m.group(0), name, "mac")

    # hashes.X() passed as a KDF's PRF belongs to the KDF finding, not a standalone hash
    kdf_spans = [
        m.span()
        for m in re.finditer(r"\b(?:PBKDF2HMAC|HKDF|HKDFExpand|ConcatKDFHash)\([^)]*\)", text)
    ]
    for m in re.finditer(r"\bhashes\.(SHA\w+|MD5)\s*\(", text):
        if any(a <= m.start() < b for a, b in kdf_spans):
            continue
        if name := HASH_NAMES.get(m.group(1).lower()):
            src.emit(m.start(), m.group(0).rstrip("( "), name, "hash")

    rsa_bits: int | None = None
    for m in re.finditer(r"\brsa\.generate_private_key\(([^)]*)\)", text):
        size = re.search(r"key_size\s*=\s*(\w+)", m.group(1))
        rsa_bits = src.int_value(size.group(1)) if size else None
        src.emit(m.start(), m.group(0), "RSA", "key-generation", key_size=rsa_bits)
    for m in re.finditer(r"\bRSA\.generate\(\s*(\w+)", text):  # PyCryptodome
        rsa_bits = src.int_value(m.group(1))
        src.emit(m.start(), m.group(0), "RSA", "key-generation", key_size=rsa_bits)
    for m in re.finditer(r"\bpadding\.(PKCS1v15|PSS|OAEP)\s*\(", text):
        usage = "encryption" if m.group(1) == "OAEP" else "signature"
        # key size carried over from key generation elsewhere in the file: inferred
        conf = Confidence.MEDIUM if rsa_bits else Confidence.HIGH
        src.emit(m.start(), m.group(0).rstrip("( "), "RSA", usage, key_size=rsa_bits,
                 confidence=conf)  # fmt: skip

    for m in re.finditer(r"\bec\.generate_private_key\(\s*ec\.(\w+)", text):
        curve = m.group(1)
        bits = CURVE_BITS.get(curve.upper())
        src.emit(
            m.start(),
            m.group(0),
            "ECDSA",
            "key-generation",
            key_size=bits,
            context={"curve": curve},
        )
    for m in re.finditer(r"\bec\.ECDH\s*\(", text):
        src.emit(m.start(), "ec.ECDH", "ECDH", "key-agreement")
    edwards: list[str] = []
    for m in re.finditer(r"\b(ed25519|ed448)\.(Ed25519|Ed448)Private", text):
        edwards.append(m.group(2))
        src.emit(m.start(), m.group(0), m.group(2), "key-generation")
    if edwards:
        # pyca signs with a method on the key object (`private_key.sign(data)`), so the call
        # names no algorithm. In a file holding an Ed25519/Ed448 key, a one-argument .sign() is
        # that key signing; RSA and ECDSA keys take a padding or algorithm argument too.
        for m in re.finditer(r"\b([A-Za-z_][\w.]*)\.sign\(", text):
            if _one_argument(text, m.end() - 1):
                key_alg, conf = _edwards_key(text, m.group(1), edwards)
                src.emit(m.start(), m.group(0).rstrip("("), key_alg, "signature",
                         confidence=conf)  # fmt: skip
    for m in re.finditer(r"\b(x25519|x448)\.(X25519|X448)Private", text):
        src.emit(m.start(), m.group(0), "ECDH", "key-agreement", context={"curve": m.group(2)})
    for m in re.finditer(r"\bdsa\.generate_private_key\(([^)]*)\)", text):
        size = re.search(r"key_size\s*=\s*(\w+)", m.group(1))
        src.emit(m.start(), m.group(0), "DSA", "key-generation",
                 key_size=src.int_value(size.group(1)) if size else None)  # fmt: skip
    for m in re.finditer(r"\bdh\.generate_parameters\(", text):
        src.emit(m.start(), "dh.generate_parameters", "DH", "key-agreement")

    ecb = re.search(r"\bmodes\.ECB\s*\(|\bMODE_ECB\b", text) is not None
    for m in re.finditer(r"\balgorithms\.(\w+)\s*\(", text):
        if alg := CIPHERS.get(m.group(1)):
            _cipher(src, m.start(), m.group(0).rstrip("( "), alg, aes_bits, key_flags, ecb)
    for m in re.finditer(r"\b(AES|DES3|DES|ARC4|Blowfish)\.new\(", text):  # PyCryptodome
        _cipher(
            src, m.start(), m.group(0).rstrip("("), CIPHERS[m.group(1)], aes_bits, key_flags, ecb
        )
    for m in re.finditer(r"\b(AESGCM|AESCCM|AESOCB3|AESSIV|ChaCha20Poly1305)\s*\(", text):
        alg = "ChaCha20-Poly1305" if m.group(1).startswith("ChaCha") else "AES"
        mode = {"AESGCM": "GCM", "AESCCM": "CCM", "AESOCB3": "OCB", "AESSIV": "SIV"}.get(m.group(1))
        _cipher(src, m.start(), m.group(1), alg, aes_bits, key_flags, ecb=False, mode=mode)

    for m in re.finditer(r"\b(PBKDF2HMAC|Scrypt|HKDF|HKDFExpand|Argon2id)\s*\(([^)]*)\)?", text):
        kdf = KDFS[m.group(1)]
        prf = re.search(r"hashes\.(SHA\w+)\s*\(", m.group(2) or "")
        variant = None
        if prf and kdf in ("PBKDF2", "HKDF"):
            variant = f"{kdf}-HMAC-{prf.group(1).upper().replace('_', '-')}"
        src.emit(m.start(), m.group(1), kdf, "kdf", variant=variant)
    for m in re.finditer(r"\bbcrypt\.hashpw\(", text):
        src.emit(m.start(), "bcrypt.hashpw", "bcrypt", "kdf")

    if re.search(r"^\s*(?:import random\b|from random import)", text, re.M):
        weak = "|".join(WEAK_RANDOM)
        for m in re.finditer(rf"\b(?:{_names(imports, 'random')})\.({weak})\s*\(", text):
            src.emit_weak_rng(m.start(), m.group(0).rstrip("( "))
        for bound, leaf in _members(imports, "random"):  # from random import choice [as c]
            if leaf in WEAK_RANDOM:
                for m in re.finditer(rf"\b{re.escape(bound)}\s*\(", text):
                    src.emit_weak_rng(m.start(), bound)

    _tls(src, imports)
    _jwt(src, imports)


def _cipher(
    src: SourceFile, pos: int, observed: str, alg: str, aes_bits: int | None,
    key_flags: list[str], ecb: bool, mode: str | None = None,
) -> None:  # fmt: skip
    flags = list(key_flags)
    if ecb and alg != "ChaCha20-Poly1305":
        flags.append("ecb-mode")
    size = aes_bits if alg == "AES" else None
    # AES key size comes from a file-level literal/constant, not data flow: inferred
    conf = Confidence.MEDIUM if alg == "AES" else Confidence.HIGH
    ctx = {"mode": mode} if mode else None
    src.emit(pos, observed, alg, "encryption", key_size=size, flags=flags, confidence=conf,
             context=ctx)  # fmt: skip


def _one_argument(text: str, open_paren: int) -> bool:
    """Whether the call whose `(` is at `open_paren` passes exactly one argument
    (`sign(data)` or `sign(data,)`)."""
    depth, current = 0, open_paren + 1
    args: list[str] = []
    for i in range(open_paren, len(text)):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append(text[current:i])
                args = [a for a in args if a.strip()]  # a trailing comma adds an empty one
                return len(args) == 1
        elif c == "," and depth == 1:
            args.append(text[current:i])
            current = i + 1
    return False


def _edwards_key(text: str, receiver: str, families: list[str]) -> tuple[str, Confidence]:
    """Which Edwards key a `receiver.sign()` call uses: the one assigned to that name, else the
    only kind in the file, else unknown between Ed25519 and Ed448."""
    name = re.escape(receiver.split(".")[-1])
    if m := re.search(rf"\b{name}\s*=\s*[\w.]*?(Ed25519|Ed448)PrivateKey", text):
        return m.group(1), Confidence.MEDIUM
    if len(set(families)) == 1:
        return families[0], Confidence.MEDIUM
    return "EdDSA", Confidence.LOW


def _names(imports: dict[str, str], module: str) -> str:
    """Regex alternation of the names a module is called by: its own and any `import ... as`."""
    return "|".join(re.escape(n) for n in {module, *(k for k, v in imports.items() if v == module)})


def _members(imports: dict[str, str], module: str) -> list[tuple[str, str]]:
    """(bound name, member) for each `from module import member [as bound]`."""
    prefix = module + "."
    return [(k, v.removeprefix(prefix)) for k, v in imports.items() if v.startswith(prefix)]


def _tls(src: SourceFile, imports: dict[str, str]) -> None:
    """TLS versions and cipher suites pinned with the `ssl` module."""
    text = src.text
    ssl_ = _names(imports, "ssl")
    tls_version = "|".join(
        [
            *(f"{n}\\.TLSVersion" for n in ssl_.split("|")),
            *(re.escape(k) for k, v in imports.items() if v == "ssl.TLSVersion"),
        ]
    )
    for m in re.finditer(rf"\b(?:(?:{ssl_})\.PROTOCOL_|(?:{tls_version})\.)"
                         rf"(TLSv1_1|TLSv1_2|TLSv1|SSLv3)\b", text):  # fmt: skip
        emit_tls_version(src, m.start(), m.group(0), m.group(1))
    if not any(v == "ssl" or v.startswith("ssl.") for v in imports.values()):
        return
    for m in re.finditer(r"\b[A-Za-z_][\w.]*\.set_ciphers\(", text):
        for literal in string_literals(call_arguments(text, m.end() - 1)):
            emit_tls_suites(src, m.start(), m.group(0).rstrip("("), suite_names(literal))


def _jwt(src: SourceFile, imports: dict[str, str]) -> None:
    """PyJWT, python-jose and authlib: `jwt.encode(..., algorithm="RS256")`, the `algorithms`
    accepted by `jwt.decode`, or an `"alg"` header. PyJWT and python-jose default to HS256."""
    text = src.text
    jwt_ = "|".join({"jwt", *(re.escape(k) for k, v in imports.items() if v.endswith("jwt"))})
    for m in re.finditer(rf"\b(?:{jwt_})\.(encode|decode)\(", text):
        args = call_arguments(text, m.end() - 1)
        names = re.findall(r"\balgorithm\s*=\s*[\"'](\w+)[\"']", args)
        names += re.findall(r"[\"']alg[\"']\s*:\s*[\"'](\w+)[\"']", args)
        for listed in re.findall(r"\balgorithms\s*=\s*\[([^\]]*)\]", args):
            names += string_literals(listed)
        observed = m.group(0).rstrip("(")
        for name in names:
            emit_jws(src, m.start(), observed, name)
        if not names and m.group(1) == "encode":
            emit_jws(src, m.start(), observed, "HS256", confidence=Confidence.MEDIUM)
