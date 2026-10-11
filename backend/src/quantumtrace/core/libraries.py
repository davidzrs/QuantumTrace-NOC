"""Cryptographic libraries: which packages count, how code imports them, and how findings
are tied to the library that provides them.

Two inputs name a library: the import behind a call in source code (no version), and a build
that bundles it with its version (a jar's `META-INF/maven/.../pom.properties`, a Go binary's
build info). Scanners record the library a finding came from as an id without version
(`pypi:cryptography`); `merge` then points each finding at the bundled entry nearest to its
file. Dependency manifests aren't read: declaring a package says nothing about which
algorithms run, so it could never be a finding.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass

from quantumtrace.core.models import CryptoLibrary, Evidence, Finding


@dataclass(frozen=True)
class Known:
    ecosystem: str  # pypi | golang | maven
    name: str  # package name; for a family ("org.bouncycastle:") a prefix
    modules: tuple[str, ...] = ()  # how code reaches it: Python root, Go path, Java package
    note: str | None = None

    def matches(self, package: str) -> bool:
        return package == self.name or (self.name.endswith(":") and package.startswith(self.name))


CATALOGUE: tuple[Known, ...] = (
    # Python (PyPI); `modules` are top-level import names
    Known("pypi", "cryptography", ("cryptography",)),
    Known("pypi", "pycryptodome", ("Crypto",)),
    Known("pypi", "pycryptodomex", ("Cryptodome",)),
    Known("pypi", "pyopenssl", ("OpenSSL",)),
    Known("pypi", "m2crypto", ("M2Crypto",)),
    Known("pypi", "paramiko", ("paramiko",), "SSH protocol implementation."),
    Known("pypi", "pynacl", ("nacl",), "libsodium bindings: X25519, Ed25519, XSalsa20."),
    Known("pypi", "ecdsa", ("ecdsa",)),
    Known("pypi", "rsa", ("rsa",)),
    Known("pypi", "bcrypt", ("bcrypt",)),
    Known("pypi", "argon2-cffi", ("argon2",)),
    Known("pypi", "passlib", ("passlib",)),
    Known("pypi", "pyjwt", ("jwt",)),
    Known("pypi", "python-jose", ("jose",)),
    Known("pypi", "jwcrypto", ("jwcrypto",)),
    Known("pypi", "tink", ("tink",)),
    Known("pypi", "liboqs-python", ("oqs",), "Open Quantum Safe: ML-KEM, ML-DSA, SLH-DSA."),
    Known("pypi", "pqcrypto", ("pqcrypto",), "Post-quantum KEMs and signatures."),
    # Go modules; `modules` are import-path prefixes
    Known("golang", "golang.org/x/crypto", ("golang.org/x/crypto",)),
    Known(
        "golang",
        "github.com/cloudflare/circl",
        ("github.com/cloudflare/circl",),
        "Cloudflare CIRCL: ML-KEM, ML-DSA and hybrid KEMs.",
    ),
    Known(
        "golang",
        "github.com/open-quantum-safe/liboqs-go",
        ("github.com/open-quantum-safe/liboqs-go",),
        "Open Quantum Safe: ML-KEM, ML-DSA.",
    ),
    Known("golang", "github.com/ProtonMail/go-crypto", ("github.com/ProtonMail/go-crypto",)),
    Known("golang", "filippo.io/edwards25519", ("filippo.io/edwards25519",)),
    Known("golang", "filippo.io/age", ("filippo.io/age",)),
    Known("golang", "github.com/golang-jwt/jwt", ("github.com/golang-jwt/jwt",)),
    Known("golang", "github.com/lestrrat-go/jwx", ("github.com/lestrrat-go/jwx",)),
    # Maven (groupId:artifactId); a trailing colon matches the whole group
    Known(
        "maven",
        "org.bouncycastle:",
        ("org.bouncycastle",),
        "BouncyCastle ships ML-KEM and ML-DSA from 1.79.",
    ),
    Known("maven", "com.google.crypto.tink:", ("com.google.crypto.tink",)),
    Known("maven", "io.jsonwebtoken:", ("io.jsonwebtoken",)),
    Known("maven", "com.nimbusds:nimbus-jose-jwt", ("com.nimbusds.jose",)),
    Known("maven", "org.conscrypt:", ("org.conscrypt",)),
    Known(
        "maven",
        "org.openquantumsafe:",
        ("org.openquantumsafe",),
        "Open Quantum Safe: ML-KEM, ML-DSA.",
    ),
)

STDLIBS: dict[str, tuple[str, str, str | None]] = {
    # id -> (name, ecosystem, note)
    "python:stdlib": ("Python standard library", "python", None),
    "go:stdlib": ("Go standard library", "go", "crypto/mlkem ships ML-KEM from Go 1.24."),
    "java:jdk": (
        "Java Cryptography Architecture (JDK)",
        "java",
        "The JDK ships ML-KEM and ML-DSA from Java 24.",
    ),
}
PYTHON_STDLIB = {"hashlib", "hmac", "secrets", "random", "ssl", "crypt", "uuid", "os"}


def lookup(ecosystem: str, package: str) -> Known | None:
    """The catalogue entry for a package, or None when it isn't a crypto library."""
    if ecosystem == "pypi":
        package = normalise_pypi(package)
    return next((k for k in CATALOGUE if k.ecosystem == ecosystem and k.matches(package)), None)


def normalise_pypi(name: str) -> str:
    """PEP 503: PyCryptodome, pycryptodome and py_cryptodome are one package."""
    return re.sub(r"[-_.]+", "-", name).lower()


def module_library(language: str, module: str) -> str | None:
    """The library id behind a module code imports: `cryptography.hazmat...` -> pypi:cryptography,
    `crypto/rsa` -> go:stdlib, `javax.crypto` -> java:jdk."""
    if language == "python":
        root = module.split(".")[0]
        if root in PYTHON_STDLIB:
            return "python:stdlib"
        known = next((k for k in CATALOGUE if k.ecosystem == "pypi" and root in k.modules), None)
        return f"pypi:{known.name}" if known else None
    if language == "go":
        if module.startswith("crypto/") or module in ("crypto", "math/rand", "math/rand/v2"):
            return "go:stdlib"
        for k in CATALOGUE:
            if k.ecosystem == "golang" and any(module.startswith(m) for m in k.modules):
                return f"golang:{k.name}"
        return None
    if language == "java":
        if module.startswith(("java.", "javax.")):
            return "java:jdk"
        for k in CATALOGUE:
            if k.ecosystem == "maven" and any(module.startswith(m) for m in k.modules):
                return f"maven:{k.name}"
        return None
    return None


def purl(ecosystem: str, package: str, version: str | None) -> str | None:
    """Package URL (purl spec) for a package; the version only when it is exact."""
    exact = (
        version if version and re.fullmatch(r"v?\d+(?:\.\d+)*(?:[-+.][\w.]+)?", version) else None
    )
    at = f"@{exact}" if exact else ""
    if ecosystem == "pypi":
        return f"pkg:pypi/{normalise_pypi(package)}{at}"
    if ecosystem == "golang":
        return f"pkg:golang/{package}{at}"
    if ecosystem == "maven" and ":" in package:
        group, artifact = package.split(":", 1)
        return f"pkg:maven/{group}/{artifact}{at}"
    return None


def declared(
    ecosystem: str, package: str, version: str | None, evidence: Evidence
) -> CryptoLibrary | None:
    """A CryptoLibrary for a bundled package, or None when it isn't a crypto library."""
    known = lookup(ecosystem, package)
    if known is None:
        return None
    name = normalise_pypi(package) if ecosystem == "pypi" else package
    return CryptoLibrary(
        id=_id(f"{ecosystem}:{name}", version),
        name=name,
        ecosystem=ecosystem,
        version=version,
        purl=purl(ecosystem, name, version),
        note=known.note,
        evidence=[evidence],
    )


def stdlib(
    base_id: str, version: str | None = None, evidence: Evidence | None = None
) -> CryptoLibrary:
    name, ecosystem, note = STDLIBS[base_id]
    return CryptoLibrary(
        id=_id(base_id, version),
        name=name,
        ecosystem=ecosystem,
        version=version,
        note=note,
        evidence=[evidence] if evidence else [],
    )


def _id(base: str, version: str | None) -> str:
    return f"{base}@{version}" if version else base


def base_id(library: CryptoLibrary) -> str:
    return library.id.rsplit("@", 1)[0] if library.version else library.id


def _family(base: str) -> tuple[str, ...]:
    """Import roots a library id answers to, so code calling `Crypto` reaches a declared
    pycrypto, and code calling BouncyCastle reaches whichever bcprov artifact is declared."""
    ecosystem, _, package = base.partition(":")
    known = lookup(ecosystem, package)
    return known.modules if known else ()


def merge(declared_libs: Iterable[CryptoLibrary], findings: list[Finding]) -> list[CryptoLibrary]:
    """Combine declared libraries (repeats merged) with the ones findings call, and point every
    finding's `asset.library` at a listed library id."""
    listed: dict[str, CryptoLibrary] = {}
    for lib in declared_libs:
        if (have := listed.get(lib.id)) is None:
            listed[lib.id] = lib.model_copy(deep=True)
        else:
            have.evidence.extend(e for e in lib.evidence if e not in have.evidence)

    for f in findings:
        called = f.asset.library
        if not called:
            continue
        candidates = [lib for lib in listed.values() if base_id(lib) == called]
        if not candidates and (roots := _family(called)):
            candidates = [lib for lib in listed.values() if set(_family(base_id(lib))) & set(roots)]
        if candidates:
            f.asset.library = _nearest(candidates, f.asset.evidence.location).id
        elif called in STDLIBS:
            listed[called] = stdlib(called)
        else:  # called in code, not bundled in any scanned build
            ecosystem, _, package = called.partition(":")
            known = lookup(ecosystem, package)
            listed[called] = CryptoLibrary(
                id=called,
                name=package.rstrip(":"),
                ecosystem=ecosystem,
                purl=purl(ecosystem, package, None) if not package.endswith(":") else None,
                note=known.note if known else None,
            )
    return sorted(listed.values(), key=lambda lib: (not lib.evidence, lib.name.lower(), lib.id))


def _nearest(candidates: list[CryptoLibrary], location: str) -> CryptoLibrary:
    """The bundled entry whose location is the deepest ancestor of the finding's file."""
    where = location.replace("\\", "/")

    def depth(lib: CryptoLibrary) -> int:
        best = -1
        for e in lib.evidence:
            folder = posixpath.dirname(e.location.replace("\\", "/"))
            if not folder or where.startswith(folder.rstrip("/") + "/"):
                best = max(best, len(folder))
        return best

    return max(candidates, key=depth)
