"""Which library a code finding's call comes from, read from the file's imports.

A finding's `observed` text starts with the name the code called (`hashes.SHA1`, `rsa.GenerateKey`,
`AESGCM`). The file's imports say which module bound that name, and `core.libraries` turns the
module into a library id. A hand-rolled primitive binds to no import, so it gets no library.
"""

from __future__ import annotations

import re

from quantumtrace.core.libraries import module_library
from quantumtrace.core.models import CryptoAsset

_HEAD = re.compile(r"[A-Za-z_]\w*")
_GO_PATH_CALL = re.compile(r"^([a-z0-9.\-]+(?:/[\w.\-]+)+)\.\w")  # math/rand.Read
_GO_IMPORT_BLOCK = re.compile(r"\bimport\s*\(([^)]*)\)", re.S)
_GO_IMPORT_LINE = re.compile(r"\bimport\s+(?:(\w+|\.|_)\s+)?\"([^\"]+)\"")
_GO_SPEC = re.compile(r"(?:(\w+|\.|_)\s+)?\"([^\"]+)\"")
_JAVA_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)(?:\.\*)?\s*;", re.M)
_BOUNCY = re.compile(r"\"BC\"|BouncyCastle")


def python_imports(text: str) -> dict[str, str]:
    """Bound name -> module: `import hashlib as h` binds h, `from x.y import a as b` binds b."""
    out: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if m := re.match(r"from\s+([\w.]+)\s+import\s+(.*)", line):
            module, names = m.group(1), m.group(2)
            if names.startswith("(") and ")" not in names:  # parenthesised, over several lines
                while i + 1 < len(lines) and ")" not in names:
                    i += 1
                    names += " " + lines[i].strip()
            for part in names.strip("() ").split(","):
                bits = part.split()
                if bits and bits[0] != "*":
                    out[bits[-1] if len(bits) == 3 and bits[1] == "as" else bits[0]] = (
                        f"{module}.{bits[0]}"
                    )
        elif m := re.match(r"import\s+(.*)", line):
            for part in m.group(1).split(","):
                bits = part.split()
                if bits:
                    module = bits[0]
                    out[bits[2] if len(bits) == 3 and bits[1] == "as" else module.split(".")[0]] = (
                        module
                    )
        i += 1
    return out


def go_imports(text: str) -> dict[str, str]:
    """Package name -> import path; `math/rand/v2` is used as `rand`."""
    specs = [s for block in _GO_IMPORT_BLOCK.findall(text) for s in _GO_SPEC.findall(block)]
    specs += _GO_IMPORT_LINE.findall(text)
    out: dict[str, str] = {}
    for alias, path in specs:
        parts = path.split("/")
        name = parts[-2] if re.fullmatch(r"v\d+", parts[-1]) and len(parts) > 1 else parts[-1]
        out[alias if alias and alias not in (".", "_") else name] = path
    return out


def java_imports(text: str) -> dict[str, str]:
    """Simple class name -> package for single-type imports; wildcard imports map the package."""
    out: dict[str, str] = {}
    for full in _JAVA_IMPORT.findall(text):
        package, _, simple = full.rpartition(".")
        if simple[:1].isupper():
            out[simple] = package
        else:
            out[full] = full
    return out


def attribute(language: str, text: str, raw: str, assets: list[CryptoAsset]) -> None:
    """Set `asset.library` on each code finding whose call the imports explain."""
    if language == "python":
        imports = python_imports(text)
    elif language == "go":
        imports = go_imports(text)
    else:
        imports = java_imports(text)
    lines = raw.splitlines()
    for asset in assets:
        module = _module(language, asset, imports, lines)
        if module is not None:
            asset.library = module_library(language, module)


def _module(
    language: str, asset: CryptoAsset, imports: dict[str, str], lines: list[str]
) -> str | None:
    observed = asset.observed
    if language == "go" and (m := _GO_PATH_CALL.match(observed)):
        return m.group(1)
    if language == "java":
        line = (
            lines[asset.evidence.line - 1]
            if asset.evidence.line and asset.evidence.line <= len(lines)
            else ""
        )
        if _BOUNCY.search(line):  # getInstance(..., "BC"): the BouncyCastle provider answers
            return "org.bouncycastle"
        head = _HEAD.match(observed)
        if head and head.group(0) in imports:
            return imports[head.group(0)]
        if observed.startswith("java."):
            return observed
        return "javax.crypto"  # JCA engine names ("AES/GCM/NoPadding") resolve through the JDK
    head = _HEAD.match(observed)
    if head is None:
        return None
    return imports.get(head.group(0))
