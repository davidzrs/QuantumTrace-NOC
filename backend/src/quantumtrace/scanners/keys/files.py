"""Certificate and key files: PEM, DER, PKCS#12 and OpenSSH formats.

Certificates give their key, their issuer's signature algorithm and its digest (the same reading
as the live TLS probe, `material.certificate_assets`). Keys give their algorithm and size. A
private key sitting in the scanned files is flagged: whoever can read the files holds it.
Encrypted keys still show their type when the format keeps it in the clear (a traditional PEM
label, an OpenSSH key's public half); otherwise the scan says it couldn't tell.
"""

from __future__ import annotations

import base64
import re
import struct
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from quantumtrace.core.models import Confidence, CryptoAsset, Evidence, ScanNote, SourceType
from quantumtrace.scanners.keys.material import certificate_assets, describe, key_asset

SCANNER = "certificates-and-keys"
MAX_BYTES = 1024 * 1024
SUFFIXES = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".csr", ".p12", ".pfx"}
NAMES = re.compile(
    r"^(authorized_keys2?|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|ssh_host_\w+_key(\.pub)?)$"
)
_PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n(.*?)-----END \1-----", re.S)
_SSH_PUBLIC = re.compile(
    rb"(?:^|\s)((?:ssh-(?:rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp\d+|sk-[\w@.-]+)\s+[A-Za-z0-9+/=]+)"
)
_TRADITIONAL = {"RSA PRIVATE KEY": "RSA", "EC PRIVATE KEY": "ECDSA", "DSA PRIVATE KEY": "DSA"}
PRIVATE_FLAG = "private-key-in-file"


class CertificateKeyScanner:
    name = SCANNER
    source_type = SourceType.CODE

    def accepts(self, path: Path) -> bool:
        return path.suffix.lower() in SUFFIXES or bool(NAMES.match(path.name))

    def scan(self, paths: Sequence[Path]) -> Iterable[CryptoAsset | ScanNote]:
        for path in paths:
            if path.stat().st_size > MAX_BYTES:
                continue
            data = path.read_bytes()
            if path.suffix.lower() in (".p12", ".pfx"):
                yield from _pkcs12(path, data)
            elif b"-----BEGIN " in data:
                yield from _pem_file(path, data)
            elif _SSH_PUBLIC.search(data):
                yield from _ssh_public_keys(path, data)
            else:
                yield from _der(path, data)


def _evidence(path: Path, line: int | None = None, /, **context: str) -> Evidence:
    return Evidence(source_type=SourceType.CODE, location=str(path), line=line, context=context)


def _line_at(data: bytes, offset: int) -> int:
    return data.count(b"\n", 0, offset) + 1


def _pem_file(path: Path, data: bytes) -> Iterator[CryptoAsset | ScanNote]:
    for m in _PEM.finditer(data):
        label = m.group(1).decode()
        block = data[m.start() : m.end()]
        line = _line_at(data, m.start())
        try:
            yield from _pem_block(path, label, block, line)
        except ValueError:
            yield ScanNote(
                scanner=SCANNER,
                message=f"{path.name}: the {label.lower()} on line {line} couldn't be read.",
            )


def _pem_block(path: Path, label: str, block: bytes, line: int) -> Iterator[CryptoAsset | ScanNote]:
    if label in ("CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE"):
        cert = x509.load_pem_x509_certificate(block)
        yield from certificate_assets(
            cert, _evidence(path, line, kind="certificate", **describe(cert))
        )
    elif label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
        csr = x509.load_pem_x509_csr(block)
        ev = _evidence(path, line, kind="certificate request", subject=csr.subject.rfc4514_string())
        if asset := key_asset(csr.public_key(), label, "certificate-key", ev):
            yield asset
    elif label in ("PUBLIC KEY", "RSA PUBLIC KEY"):
        key = serialization.load_pem_public_key(block)
        if asset := key_asset(key, label, "public-key", _evidence(path, line, kind="public key")):
            yield asset
    elif label == "OPENSSH PRIVATE KEY":
        yield from _openssh_private(path, block, line)
    elif label.endswith("PRIVATE KEY"):
        yield from _private_pem(path, label, block, line)


def _private_pem(
    path: Path, label: str, block: bytes, line: int
) -> Iterator[CryptoAsset | ScanNote]:
    ev = _evidence(path, line, kind="private key")
    try:
        key = serialization.load_pem_private_key(block, password=None)
    except TypeError:  # encrypted: a traditional label still names the algorithm
        if (alias := _TRADITIONAL.get(label)) is not None:
            ev.context["encrypted"] = "yes"
            yield CryptoAsset(
                observed=label,
                algorithm=alias,
                usage="private-key",
                confidence=Confidence.MEDIUM,
                flags=[PRIVATE_FLAG],
                evidence=ev,
            )
            yield ScanNote(
                scanner=SCANNER,
                message=f"{path.name}: an encrypted {alias} private "
                "key; its size can't be read without the passphrase.",
            )
        else:
            yield ScanNote(
                scanner=SCANNER,
                message=f"{path.name}: an encrypted private key "
                "(PKCS#8); its algorithm can't be read without the passphrase.",
            )
        return
    if asset := key_asset(key, label, "private-key", ev, flags=[PRIVATE_FLAG]):
        yield asset


def _openssh_private(path: Path, block: bytes, line: int) -> Iterator[CryptoAsset | ScanNote]:
    """openssh-key-v1 keeps the public key in the clear, even when the private part is encrypted."""
    body = b"".join(block.splitlines()[1:-1])
    raw = base64.b64decode(body)
    magic = b"openssh-key-v1\x00"
    if not raw.startswith(magic):
        return
    i = len(magic)
    fields: list[bytes] = []
    for _ in range(3):  # ciphername, kdfname, kdfoptions
        (n,) = struct.unpack(">I", raw[i : i + 4])
        fields.append(raw[i + 4 : i + 4 + n])
        i += 4 + n
    i += 4  # number of keys
    (n,) = struct.unpack(">I", raw[i : i + 4])
    public_blob = raw[i + 4 : i + 4 + n]
    (t,) = struct.unpack(">I", public_blob[:4])
    key_type = public_blob[4 : 4 + t]
    key = serialization.load_ssh_public_key(key_type + b" " + base64.b64encode(public_blob))
    ev = _evidence(path, line, kind="OpenSSH private key", key_type=key_type.decode())
    if fields[0] != b"none":
        ev.context["encrypted"] = "yes"
    if asset := key_asset(key, key_type.decode(), "ssh-user-key", ev, flags=[PRIVATE_FLAG]):
        yield asset


def _ssh_public_keys(path: Path, data: bytes) -> Iterator[CryptoAsset]:
    for m in _SSH_PUBLIC.finditer(data):
        text = m.group(1)
        try:
            key = serialization.load_ssh_public_key(text)
        except (ValueError, UnsupportedAlgorithm):
            continue
        key_type = text.split()[0].decode()
        ev = _evidence(path, _line_at(data, m.start(1)), kind="SSH public key", key_type=key_type)
        if asset := key_asset(key, key_type, "ssh-user-key", ev):
            yield asset


def _der(path: Path, data: bytes) -> Iterator[CryptoAsset | ScanNote]:
    try:
        cert = x509.load_der_x509_certificate(data)
    except ValueError:
        pass
    else:
        yield from certificate_assets(cert, _evidence(path, kind="certificate", **describe(cert)))
        return
    for loader, usage, kind in (
        (
            lambda d: serialization.load_der_private_key(d, password=None),
            "private-key",
            "private key",
        ),
        (serialization.load_der_public_key, "public-key", "public key"),
    ):
        try:
            key = loader(data)
        except (ValueError, TypeError):
            continue
        flags = [PRIVATE_FLAG] if usage == "private-key" else []
        if asset := key_asset(key, f"DER {kind}", usage, _evidence(path, kind=kind), flags=flags):
            yield asset
        return
    if path.suffix.lower() in (".der", ".cer", ".crt", ".key"):
        yield ScanNote(
            scanner=SCANNER,
            message=f"{path.name}: not a certificate or key this "
            "scanner can read (encrypted, or an unsupported format).",
        )


def _pkcs12(path: Path, data: bytes) -> Iterator[CryptoAsset | ScanNote]:
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(data, None)
    except ValueError:
        yield ScanNote(
            scanner=SCANNER,
            message=f"{path.name}: a password-protected PKCS#12 "
            "bundle; its keys and certificates can't be read without it.",
        )
        return
    for c in [cert, *extra]:
        if c is not None:
            yield from certificate_assets(c, _evidence(path, kind="certificate", **describe(c)))
    if key is not None and (
        asset := key_asset(
            key,
            "PKCS#12 private key",
            "private-key",
            _evidence(path, kind="private key"),
            flags=[PRIVATE_FLAG],
        )
    ):
        yield asset
