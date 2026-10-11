"""Go binaries: the Go version, the modules it was built with, and the crypto it links.

Every Go executable carries build info (`\\xff Go buildinf:`: the Go version and each module with
its version) and keeps function names for stack traces even when stripped (`-s -w`). Those
names say which crypto packages are linked: `crypto/rsa.GenerateKey`, `golang.org/x/crypto/
pbkdf2.Key`. Linked is not proven called: a binary that speaks HTTPS links the TLS stack's
algorithms too, so these findings are medium confidence and the scan says why.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAGIC = b"\xff Go buildinf:"
FLAG_INLINE_STRINGS = 0x2

# package -> (classifier alias, usage when no function says otherwise)
PACKAGES: dict[str, tuple[str, str]] = {
    "crypto/md5": ("MD5", "hash"),
    "crypto/sha1": ("SHA-1", "hash"),
    "crypto/sha256": ("SHA-256", "hash"),
    "crypto/sha512": ("SHA-512", "hash"),
    "crypto/sha3": ("SHA3-256", "hash"),
    "crypto/des": ("DES", "encryption"),
    "crypto/rc4": ("RC4", "encryption"),
    "crypto/aes": ("AES", "encryption"),
    "crypto/rsa": ("RSA", "signature"),
    "crypto/ecdsa": ("ECDSA", "signature"),
    "crypto/ed25519": ("Ed25519", "signature"),
    "crypto/dsa": ("DSA", "signature"),
    "crypto/ecdh": ("ECDH", "key-agreement"),
    "crypto/mlkem": ("ML-KEM", "key-agreement"),
    "crypto/pbkdf2": ("PBKDF2", "kdf"),
    "crypto/hkdf": ("HKDF", "kdf"),
    "golang.org/x/crypto/pbkdf2": ("PBKDF2", "kdf"),
    "golang.org/x/crypto/scrypt": ("scrypt", "kdf"),
    "golang.org/x/crypto/argon2": ("Argon2", "kdf"),
    "golang.org/x/crypto/bcrypt": ("bcrypt", "kdf"),
    "golang.org/x/crypto/hkdf": ("HKDF", "kdf"),
    "golang.org/x/crypto/chacha20poly1305": ("ChaCha20-Poly1305", "encryption"),
    "golang.org/x/crypto/blowfish": ("Blowfish", "encryption"),
    "golang.org/x/crypto/curve25519": ("X25519", "key-agreement"),
    "golang.org/x/crypto/ed25519": ("Ed25519", "signature"),
    "golang.org/x/crypto/sha3": ("SHA3-256", "hash"),
}
_SYMBOL = re.compile(
    rb"(?<![\w/.-])((?:crypto|golang\.org/x/crypto)(?:/[a-z0-9_]+)*)\.(?:\(\*?\w+\)\.)?([A-Za-z]\w*)"
)


@dataclass
class GoBinary:
    go_version: str | None  # go1.24.2
    main_module: str | None
    deps: list[tuple[str, str]] = field(default_factory=list)  # (module path, version)
    functions: dict[str, set[str]] = field(default_factory=dict)  # package -> function names


def _uvarint(data: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        b = data[i]
        i += 1
        value |= (b & 0x7F) << shift
        if b < 0x80:
            return value, i
        shift += 7


def parse(data: bytes) -> GoBinary | None:
    """Build info and linked crypto functions; None when the file isn't a Go binary."""
    at = data.find(MAGIC)
    if at < 0:
        return None
    version = main = None
    deps: list[tuple[str, str]] = []
    if data[at + 15] & FLAG_INLINE_STRINGS:  # Go 1.18+: length-prefixed strings follow the header
        try:
            n, i = _uvarint(data, at + 32)
            version = data[i : i + n].decode(errors="replace")
            n, i = _uvarint(data, i + n)
            modinfo = data[i : i + n].decode(errors="replace")
        except IndexError:
            modinfo = ""
        if len(modinfo) >= 33 and modinfo[-17] == "\n":
            modinfo = modinfo[16:-16]  # sentinels around the module info
        for line in modinfo.splitlines():
            parts = line.split("\t")
            if parts[0] == "mod" and len(parts) > 1:
                main = parts[1]
            elif parts[0] == "dep" and len(parts) > 2:
                deps.append((parts[1], parts[2]))
            elif parts[0] == "=>" and len(parts) > 2 and deps:
                deps[-1] = (parts[1], parts[2])  # a replace directive swaps the module
    functions: dict[str, set[str]] = {}
    for m in _SYMBOL.finditer(data):
        package = m.group(1).decode()
        if package in PACKAGES:
            functions.setdefault(package, set()).add(m.group(2).decode())
    return GoBinary(version, main, deps, functions)


def usages(package: str, functions: set[str]) -> list[tuple[str, str, str | None]]:
    """(alias, usage, variant) for one linked package, refined by which functions are present."""
    alias, default = PACKAGES[package]
    found: list[tuple[str, str, str | None]] = []
    if package == "crypto/des":
        if "NewTripleDESCipher" in functions:
            found.append(("3DES", "encryption", "3DES"))
        if "NewCipher" in functions or not found:
            found.append(("DES", "encryption", "DES"))
        return found
    if package == "crypto/mlkem":
        sizes = sorted({s for f in functions for s in re.findall(r"(768|1024)", f)})
        return [("ML-KEM", "key-agreement", f"ML-KEM-{s}") for s in sizes] or [
            (alias, default, None)
        ]
    if package in ("crypto/rsa", "crypto/ecdsa", "crypto/dsa", "crypto/ed25519"):
        if any(f.startswith("GenerateKey") for f in functions):
            found.append((alias, "key-generation", None))
        if any(f.startswith(("Encrypt", "Decrypt")) for f in functions):
            found.append((alias, "encryption", None))
        if any(f.startswith(("Sign", "Verify")) for f in functions) or not found:
            found.append((alias, "signature", None))
        return found
    if package.endswith("/sha3"):
        return [(alias, default, "SHA-3")]
    return [(alias, default, None)]
