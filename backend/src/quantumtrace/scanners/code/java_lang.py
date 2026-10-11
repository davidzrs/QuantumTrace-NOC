"""Java: JCA/JCE `getInstance(...)` calls, constants resolved within the file, TLS versions and
suites set on SSLContext / SSL sockets, and JWT algorithms (jjwt, Nimbus)."""

from __future__ import annotations

import re

from quantumtrace.core.models import Confidence
from quantumtrace.scanners.code.common import SourceFile
from quantumtrace.scanners.code.protocol_rules import (
    call_arguments,
    emit_jws,
    emit_tls_suites,
    emit_tls_version,
    string_literals,
    suite_names,
)

_STR_ARG = r"\(\s*(?:\"([^\"]+)\"|(\w+))"  # "literal" or CONSTANT
SYMMETRIC = {"AES": "AES", "DESEDE": "3DES", "DES": "DES", "BLOWFISH": "Blowfish",
             "RC4": "RC4", "ARCFOUR": "RC4", "CHACHA20-POLY1305": "ChaCha20-Poly1305",
             "CHACHA20": "ChaCha20"}  # fmt: skip
KPG = {"RSA": "RSA", "EC": "ECDSA", "DSA": "DSA", "ED25519": "Ed25519", "ED448": "Ed448",
       "DH": "DH", "DIFFIEHELLMAN": "DH", "X25519": "ECDH", "XDH": "ECDH", "ML-DSA": "ML-DSA",
       "ML-KEM": "ML-KEM"}  # fmt: skip


def _arg(src: SourceFile, m: re.Match[str]) -> str | None:
    return m.group(1) or (src.constant(m.group(2)) if m.group(2) else None)


def scan(src: SourceFile) -> None:
    text = src.text
    aes_bits, hardcoded = src.symmetric_key_hint()
    aes_conf = Confidence.MEDIUM  # file-level hint until a KeyGenerator.init pins it down

    for m in re.finditer(r"\bKeyGenerator\.getInstance" + _STR_ARG, text):
        if (_arg(src, m) or "").upper() == "AES" and (
            init := re.search(r"\.init\(\s*(\w+)", text[m.end() :])
        ):
            aes_bits = src.int_value(init.group(1)) or aes_bits
            hardcoded = False
            aes_conf = Confidence.HIGH

    sizes: dict[str, int | None] = {}
    for m in re.finditer(r"\bKeyPairGenerator\.getInstance" + _STR_ARG, text):
        kpg_name = (_arg(src, m) or "").upper()
        if (alg := KPG.get(kpg_name)) is None:
            continue
        init = re.search(r"\.initialize\(\s*(\w+)", text[m.end() : m.end() + 400])
        size = src.int_value(init.group(1)) if init else None
        sizes[alg] = size
        src.emit(m.start(), m.group(0) + ")", alg, "key-generation", key_size=size)

    for m in re.finditer(r"\bSignature\.getInstance" + _STR_ARG, text):
        sig = _arg(src, m)
        if not sig:
            continue
        digest, _, scheme = sig.upper().partition("WITH")
        if scheme:  # SHA1withRSA -> RSA signature + SHA-1 digest
            alg = {"RSA": "RSA", "ECDSA": "ECDSA", "DSA": "DSA", "RSA/PSS": "RSA"}.get(scheme, sig)
            size = sizes.get(alg)
            src.emit(m.start(), sig, alg, "signature", key_size=size,
                     confidence=Confidence.MEDIUM if size else Confidence.HIGH)  # fmt: skip
            src.emit(m.start(), sig, digest, "signature-digest")
        else:
            alg = KPG.get(sig.upper(), sig)
            size = sizes.get(alg)
            src.emit(m.start(), sig, alg, "signature", key_size=size,
                     confidence=Confidence.MEDIUM if size else Confidence.HIGH)  # fmt: skip

    for m in re.finditer(r"\bMessageDigest\.getInstance" + _STR_ARG, text):
        if digest_name := _arg(src, m):
            src.emit(m.start(), digest_name, digest_name, "hash")
    for m in re.finditer(r"\bMac\.getInstance" + _STR_ARG, text):
        if mac_name := _arg(src, m):
            src.emit(m.start(), mac_name, mac_name, "mac")
    for m in re.finditer(r"\bKeyAgreement\.getInstance" + _STR_ARG, text):
        if ka_name := _arg(src, m):
            src.emit(m.start(), ka_name, KPG.get(ka_name.upper(), ka_name), "key-agreement")
    for m in re.finditer(r"\bKEM\.getInstance" + _STR_ARG, text):  # javax.crypto.KEM, Java 21+
        if kem := _arg(src, m):
            src.emit(m.start(), kem, {"DHKEM": "ECDH"}.get(kem.upper(), kem), "key-agreement")

    for m in re.finditer(r"\bSecretKeyFactory\.getInstance" + _STR_ARG, text):
        kdf = _arg(src, m) or ""
        if prf := re.match(r"(?i)PBKDF2WithHmac(\w+)", kdf):
            src.emit(m.start(), kdf, "PBKDF2", "kdf", context={"prf": prf.group(1)},
                     variant=f"PBKDF2-HMAC-{prf.group(1).upper()}")  # fmt: skip
            # the PRF is the HMAC, which a SHA-1 or MD5 collision doesn't break (RFC 6151)
            if weak := {"SHA1": "HMAC-SHA1", "MD5": "HmacMD5"}.get(prf.group(1).upper()):
                src.emit(m.start(), kdf, weak, "kdf-prf")
        elif kdf:
            src.emit(m.start(), kdf, kdf.split("/")[0], "kdf")

    for m in re.finditer(r"\bCipher\.getInstance" + _STR_ARG, text):
        transformation = _arg(src, m)
        if not transformation:
            continue
        alg, _, rest = transformation.partition("/")
        mode = rest.split("/")[0].upper() if rest else ""
        upper = alg.upper()
        if upper in ("RSA", "ECIES"):
            size = sizes.get("RSA")
            src.emit(m.start(), transformation, alg, "encryption", key_size=size,
                     confidence=Confidence.MEDIUM if size else Confidence.HIGH)  # fmt: skip
            continue
        sym = SYMMETRIC.get(upper, alg)
        flags = ["hardcoded-key"] if hardcoded else []
        # Java's default mode for "AES"/"DESede" without a mode is ECB.
        if sym not in ("ChaCha20-Poly1305", "ChaCha20", "RC4") and mode in ("", "ECB"):
            flags.append("ecb-mode")
        src.emit(m.start(), transformation, sym, "encryption",
                 key_size=aes_bits if sym == "AES" else None, flags=flags,
                 context={"transformation": transformation, **({"mode": mode} if mode else {})},
                 confidence=aes_conf if sym == "AES" else Confidence.HIGH)  # fmt: skip

    for m in re.finditer(r"\bSSLContext\.getInstance" + _STR_ARG, text):
        if protocol := _arg(src, m):  # "TLSv1"; "TLS" and "TLSv1.3" name no weak version
            emit_tls_version(src, m.start(), protocol, protocol)
    for m in re.finditer(r"\b[A-Za-z_][\w.]*\.setEnabledProtocols\(", text):
        for protocol in string_literals(call_arguments(text, m.end() - 1)):
            emit_tls_version(src, m.start(), protocol, protocol)
    for m in re.finditer(r"\b[A-Za-z_][\w.]*\.setEnabledCipherSuites\(", text):
        suites = [s for lit in string_literals(call_arguments(text, m.end() - 1))
                  for s in suite_names(lit)]  # fmt: skip
        emit_tls_suites(src, m.start(), m.group(0).rstrip("("), suites)
    jws = (
        r"\b(?:[a-z]\w*\.)*(?:SignatureAlgorithm|JWSAlgorithm|Jwts\.SIG)\."
        r"((?:RS|PS|ES|HS)(?:256|384|512)|EdDSA)\b"
    )
    for m in re.finditer(jws, text):
        emit_jws(src, m.start(), m.group(0), m.group(1))

    if re.search(r"^import java\.util\.Random;", text, re.M) or "java.util.Random" in text:
        for m in re.finditer(r"\bnew Random\s*\(", text):
            src.emit_weak_rng(m.start(), "java.util.Random")
