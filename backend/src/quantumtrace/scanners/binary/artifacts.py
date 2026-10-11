"""Compiled artifacts: Java bytecode (.class, .jar, .war, .ear) and Go executables.

Java classes go through the same rules as Java source (`code.java_lang`): the JCA calls read from
bytecode are written out as the source would say them, scanned, and the findings moved back to
`App.jar!/com/acme/Vault.class` at the line the class's LineNumberTable gives. Bundled libraries
(BouncyCastle inside a fat jar, Go modules in build info) become CryptoLibrary entries.
"""

from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path

from quantumtrace.core import libraries
from quantumtrace.core.models import (
    Confidence,
    CryptoAsset,
    CryptoLibrary,
    Evidence,
    Observation,
    ScanNote,
    SourceType,
)
from quantumtrace.scanners.binary import golang, java_class
from quantumtrace.scanners.code import java_lang
from quantumtrace.scanners.code.common import SourceFile

SCANNER = "binary-artifacts"
JAVA_ARCHIVES = {".jar", ".war", ".ear"}
NATIVE_MAGIC = (
    b"\x7fELF",
    b"MZ",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
)
MAX_BYTES = 128 * 1024 * 1024
MAX_CLASSES = 5000
# Classes of bundled crypto libraries: inventoried as a library, not scanned call by call.
LIBRARY_PACKAGES = tuple(
    m.replace(".", "/") + "/"
    for k in libraries.CATALOGUE
    if k.ecosystem == "maven"
    for m in k.modules
)


class BinaryArtifactScanner:
    name = SCANNER
    source_type = SourceType.CODE

    def accepts(self, path: Path) -> bool:
        suffix = path.suffix.lower()
        if suffix == ".class" or suffix in JAVA_ARCHIVES:
            return True
        if suffix in (".py", ".java", ".go", ".json", ".txt", ".md", ".pcap", ".pcapng", ".zip"):
            return False
        try:
            with path.open("rb") as fh:
                return fh.read(4).startswith(NATIVE_MAGIC)
        except OSError:
            return False

    def scan(self, paths: Sequence[Path]) -> Iterable[CryptoAsset | ScanNote | CryptoLibrary]:
        go_seen = False
        for path in paths:
            if path.stat().st_size > MAX_BYTES:
                yield ScanNote(
                    scanner=SCANNER,
                    message=f"{path.name}: over {MAX_BYTES // 2**20} MB, not inspected.",
                )
                continue
            suffix = path.suffix.lower()
            if suffix == ".class":
                yield from _class(path.read_bytes(), str(path))
            elif suffix in JAVA_ARCHIVES:
                yield from _archive(path)
            else:
                found = list(_native(path))
                go_seen = go_seen or any(isinstance(x, CryptoAsset) for x in found)
                yield from found
        if go_seen:
            yield ScanNote(
                scanner=SCANNER,
                message=(
                    "Go binaries: the crypto listed is linked into the executable, not proven "
                    "called on every path. A program that serves or calls HTTPS links the TLS "
                    "stack's algorithms too."
                ),
            )


# ---------------------------------------------------------------- Java


def _class(data: bytes, location: str) -> list[CryptoAsset]:
    try:
        cf = java_class.parse(data)
    except ValueError:
        return []
    return _java_assets(cf, location)


def _java_assets(cf: java_class.ClassFile, location: str) -> list[CryptoAsset]:
    """Write the calls out as Java, scan that with the source rules, and point the findings back
    at the class and its source lines. Method headers let the RNG rule see `sessionToken()`."""
    if not cf.calls:
        return []
    lines = ["import java.util.Random;"] if cf.uses_random else []
    origin: dict[int, java_class.Call] = {}
    method = None
    for call in cf.calls:
        if call.method != method:
            if method is not None:
                lines.append("}")
            method = call.method
            name = method if re.fullmatch(r"[A-Za-z_]\w*", method) else "init"
            lines.append(f"void {name}() {{")
        lines.append(f"{call.text};")
        origin[len(lines)] = call
    lines.append("}")
    src = SourceFile(Path(location), "java", "\n".join(lines) + "\n")
    java_lang.scan(src)
    assets = list(src.assets)
    for asset in assets:
        first = origin.get(asset.evidence.line or 0)
        for ev in asset.all_evidence:
            here = origin.get(ev.line or 0)
            ev.location = location
            ev.line = here.line if here else None
            ev.column = ev.end_column = ev.snippet = ev.snippet_start_line = None
            ctx = {k: v for k, v in ev.context.items() if k not in ("file", "language")}
            ev.context = {
                **ctx,
                "language": "java bytecode",
                "class": cf.name,
                "method": here.method if here else "",
                **({"source_file": cf.source_file} if cf.source_file else {}),
            }
        bouncy = first is not None and '"BC")' in first.text
        asset.library = "maven:org.bouncycastle:" if bouncy else "java:jdk"
    return assets


def _archive(path: Path) -> Iterator[CryptoAsset | ScanNote | CryptoLibrary]:
    try:
        with zipfile.ZipFile(path) as zf:
            yield from _archive_entries(zf, str(path))
    except zipfile.BadZipFile:
        yield ScanNote(scanner=SCANNER, message=f"{path.name}: not a readable archive.")


def _archive_entries(
    zf: zipfile.ZipFile, location: str, depth: int = 0
) -> Iterator[CryptoAsset | ScanNote | CryptoLibrary]:
    names = zf.namelist()
    classes = [n for n in names if n.endswith(".class") and not n.startswith("META-INF/")]
    app = [
        n for n in classes if not n.removeprefix("WEB-INF/classes/").startswith(LIBRARY_PACKAGES)
    ]
    if depth == 0:
        for name in app[:MAX_CLASSES]:
            yield from _class(zf.read(name), f"{location}!/{name}")
        if len(app) > MAX_CLASSES:
            yield ScanNote(
                scanner=SCANNER,
                message=f"{Path(location).name}: only the first "
                f"{MAX_CLASSES} classes were inspected.",
            )
    found_bundled = False
    for name in names:
        if name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
            props = dict(
                line.split("=", 1)
                for line in zf.read(name).decode(errors="replace").splitlines()
                if "=" in line and not line.startswith("#")
            )
            group, artifact = props.get("groupId", "").strip(), props.get("artifactId", "").strip()
            version = props.get("version", "").strip() or None
            ev = Evidence(
                source_type=SourceType.CODE,
                location=f"{location}!/{name}",
                context={"declared": f"{group}:{artifact}:{version}", "bundled": "yes"},
            )
            if lib := libraries.declared("maven", f"{group}:{artifact}", version, ev):
                found_bundled = True
                yield lib
        elif depth == 0 and name.endswith(".jar"):  # WEB-INF/lib/*.jar in a war or ear
            try:
                with zipfile.ZipFile(io.BytesIO(zf.read(name))) as inner:
                    yield from _archive_entries(inner, f"{location}!/{name}", depth + 1)
            except zipfile.BadZipFile:
                continue
    if not found_bundled and any(c.startswith("org/bouncycastle/") for c in classes):
        ev = Evidence(
            source_type=SourceType.CODE,
            location=location,
            context={"declared": "org/bouncycastle classes, no pom.properties", "bundled": "yes"},
        )
        if lib := libraries.declared("maven", "org.bouncycastle:bcprov", None, ev):
            yield lib


# ---------------------------------------------------------------- Go


def _native(path: Path) -> Iterator[CryptoAsset | ScanNote | CryptoLibrary]:
    data = path.read_bytes()
    binary = golang.parse(data)
    if binary is None:
        yield ScanNote(
            scanner=SCANNER,
            message=(
                f"{path.name}: a native executable that isn't Go. Only Go binaries and Java "
                "bytecode are inspected; scan its source or capture its traffic instead."
            ),
        )
        return
    location = str(path)
    base = {"go_version": binary.go_version or "unknown"}
    if binary.main_module:
        base["main_module"] = binary.main_module
    if binary.go_version and (m := re.match(r"go(\d+(?:\.\d+)*)", binary.go_version)):
        yield libraries.stdlib(
            "go:stdlib",
            m.group(1),
            Evidence(
                source_type=SourceType.CODE,
                location=location,
                context={"declared": f"built with {binary.go_version}"},
            ),
        )
    for module, version in binary.deps:
        known = next(
            (
                k
                for k in libraries.CATALOGUE
                if k.ecosystem == "golang" and module.startswith(k.name)
            ),
            None,
        )
        if known is not None:
            ev = Evidence(
                source_type=SourceType.CODE,
                location=location,
                context={"declared": f"dep {module} {version}", "bundled": "yes"},
            )
            if lib := libraries.declared("golang", known.name, version, ev):
                yield lib
    for package, functions in sorted(binary.functions.items()):
        library = (
            "go:stdlib"
            if package.startswith("crypto/")
            else libraries.module_library("go", package)
        )
        for alias, usage, variant in golang.usages(package, functions):
            ev = Evidence(
                source_type=SourceType.CODE,
                location=location,
                context={
                    **base,
                    "package": package,
                    "functions": ", ".join(sorted(functions)[:8])
                    + (" …" if len(functions) > 8 else ""),
                },
            )
            yield CryptoAsset(
                observed=f"{package}.{sorted(functions)[0]}",
                algorithm=alias,
                variant=variant,
                usage=usage,
                observation=Observation.IN_CODE,
                confidence=Confidence.MEDIUM,
                evidence=ev,
                library=library,
            )
