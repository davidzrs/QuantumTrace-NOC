"""TLS settings and JWT algorithms named in code, shared by the Python, Java and Go rule sets.

TLS pinned in code (`ssl.PROTOCOL_TLSv1`, `SSLContext.getInstance("TLSv1")`, `tls.VersionTLS10`,
a cipher-suite list) is reported like the same setting in a server config: the protocol, and each
named suite split into key exchange, authentication, cipher and MAC (rules/tls.py). A JWT
algorithm name (RFC 7518: RS256, ES256, HS256, ...) is the primitive that signs the token.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from quantumtrace.core.models import Confidence
from quantumtrace.rules.tls import decompose
from quantumtrace.scanners.code.common import SourceFile

# Version names as code spells them, normalised -> classifier alias. TLS 1.3 is left out:
# whether it is post-quantum depends on the key-exchange groups, which code rarely names.
_VERSIONS = {
    "SSLV3": "SSLv3", "SSL30": "SSLv3", "TLSV1": "TLSv1", "TLSV10": "TLSv1", "TLS10": "TLSv1",
    "TLSV11": "TLSv1.1", "TLS11": "TLSv1.1", "TLSV12": "TLSv1.2", "TLS12": "TLSv1.2",
}  # fmt: skip
# An OpenSSL suite name (DES-CBC3-SHA, ECDHE-RSA-AES128-GCM-SHA256) or an IANA one
_OPENSSL_SUITE = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)+")
_CIPHERS = ("AES-128", "AES-256", "3DES", "DES", "RC4", "CHACHA20")
# RFC 7518 3.1 algorithm names
_JWS = re.compile(r"(RS|PS|ES|HS)(256|384|512)(K?)")
_ES_CURVES = {"256": ("P256", 256), "384": ("P384", 384), "512": ("P521", 521)}


def tls_version(name: str) -> str | None:
    """`TLSv1_1`, `TLSv1.1`, `VersionTLS11` -> `TLSv1.1`; None for TLS 1.3 and anything else."""
    return _VERSIONS.get(re.sub(r"[^A-Z0-9]", "", name.upper()).removeprefix("VERSION"))


def emit_tls_version(src: SourceFile, pos: int, observed: str, name: str) -> None:
    if version := tls_version(name):
        src.emit(pos, observed, version, "tls-protocol")


def suite_names(cipher_string: str) -> list[str]:
    """Named suites in an OpenSSL cipher string or a list of IANA names. Keywords (HIGH, !aNULL,
    ECDHE+AESGCM) only the linked OpenSSL can expand, so they are skipped, not guessed."""
    names = []
    for token in re.split(r"[:,\s]+", cipher_string.strip("'\"")):
        if token.upper().startswith("TLS_"):
            names.append(token.upper())
        elif _OPENSSL_SUITE.fullmatch(token) and not token.startswith(("TLSV", "SSLV")):
            names.append(token)
    return names


def emit_tls_suites(src: SourceFile, pos: int, observed: str, suites: Iterable[str]) -> None:
    """Each suite's parts, as the config and cloud scanners report them."""
    for suite in suites:
        try:
            parts = decompose(suite)
        except (ValueError, IndexError):
            continue
        if not parts.cipher.startswith(_CIPHERS):  # not a suite after all
            continue
        ctx = {"suite": suite}
        if parts.key_exchange is not None:
            src.emit(
                pos,
                observed,
                parts.key_exchange,
                "tls-key-exchange",
                context=ctx,
                flags=[f for f in parts.flags if f == "no-forward-secrecy"],
                variant="RSA key transport" if parts.key_exchange == "RSA" else None,
            )
            if parts.authentication and parts.key_exchange != "RSA":
                src.emit(pos, observed, parts.authentication, "tls-authentication", context=ctx)
        src.emit(
            pos,
            observed,
            parts.cipher_label,
            "tls-cipher",
            context=ctx,
            flags=[f for f in parts.flags if f == "cbc-mode"],
            variant=parts.cipher_label,
        )
        if parts.mac:
            src.emit(pos, observed, parts.mac, "tls-mac", context=ctx)


def emit_jws(
    src: SourceFile, pos: int, observed: str, name: str,
    confidence: Confidence = Confidence.HIGH,
) -> None:  # fmt: skip
    """A JWT signing algorithm: RS/PS -> RSA, ES -> ECDSA on its curve, HS -> HMAC, EdDSA."""
    ctx = {"jwt_alg": name}
    if name.upper() == "EDDSA":
        src.emit(pos, observed, "EdDSA", "signature", context=ctx, confidence=confidence)
        return
    if (m := _JWS.fullmatch(name.upper())) is None:
        return  # "none" and unknown names
    family, bits, k = m.groups()
    if family in ("RS", "PS"):
        src.emit(pos, observed, "RSA", "signature", context=ctx, confidence=confidence)
    elif family == "ES":
        curve, size = ("SECP256K1", 256) if k else _ES_CURVES[bits]
        src.emit(pos, observed, "ECDSA", "signature", key_size=size,
                 context={**ctx, "curve": curve}, confidence=confidence)  # fmt: skip
    else:
        src.emit(pos, observed, f"HMAC-SHA{bits}", "mac", context=ctx, confidence=confidence)


def call_arguments(text: str, open_paren: int) -> str:
    """The text between a call's `(` and its matching `)`."""
    depth = 0
    for i in range(open_paren, len(text)):
        if text[i] in "([{":
            depth += 1
        elif text[i] in ")]}":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i]
    return text[open_paren + 1 :]


def string_literals(text: str) -> list[str]:
    return [m.group(2) for m in re.finditer(r"([\"'])([^\"'\n]*)\1", text)]
