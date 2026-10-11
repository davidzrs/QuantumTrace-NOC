"""Dependency manifests: which cryptographic libraries a codebase declares, and at which version.

Reads requirements*.txt, pyproject.toml, go.mod, pom.xml and package.json. Only packages in the
`core.libraries` catalogue count; each becomes a `CryptoLibrary` with the manifest line as
evidence. They carry no risk tier of their own: the CBOM lists them as library components that
provide the algorithms the code calls through them.
"""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path

from quantumtrace.core import libraries
from quantumtrace.core.models import CryptoAsset, CryptoLibrary, Evidence, ScanNote, SourceType

SCANNER = "dependency-manifest"
MAX_BYTES = 1024 * 1024
_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*"
    r"((?:===?|>=|<=|~=|!=|>|<)\s*[^;#\s,]+(?:\s*,\s*(?:===?|>=|<=|~=|!=|>|<)\s*[^;#\s,]+)*)?"
)


class DependencyManifestScanner:
    name = SCANNER
    source_type = SourceType.CODE

    def accepts(self, path: Path) -> bool:
        n = path.name.lower()
        return (n.startswith("requirements") and n.endswith(".txt")) or n in (
            "pyproject.toml",
            "go.mod",
            "pom.xml",
            "package.json",
        )

    def scan(self, paths: Sequence[Path]) -> Iterable[CryptoAsset | ScanNote | CryptoLibrary]:
        seen = False
        for path in paths:
            if path.stat().st_size > MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            n = path.name.lower()
            parse = (
                _go_mod
                if n == "go.mod"
                else _pom
                if n == "pom.xml"
                else _package_json
                if n == "package.json"
                else _pyproject
                if n == "pyproject.toml"
                else _requirements
            )
            try:
                found = list(parse(path, text))
            except (ValueError, ET.ParseError, tomllib.TOMLDecodeError):
                yield ScanNote(
                    scanner=SCANNER,
                    message=f"{path.name}: couldn't be parsed, so its "
                    "dependencies aren't in this inventory.",
                )
                continue
            seen = True
            yield from found
        if seen:
            yield ScanNote(
                scanner=SCANNER,
                message=(
                    "Dependency manifests list direct dependencies. Cryptographic libraries "
                    "pulled in transitively (lock files, vendored or shaded code) are not in this "
                    "inventory."
                ),
            )


def _evidence(path: Path, text: str, needle: str, declared: str) -> Evidence:
    line = next((i for i, row in enumerate(text.splitlines(), 1) if needle in row), None)
    return Evidence(
        source_type=SourceType.CODE, location=str(path), line=line, context={"declared": declared}
    )


def _library(
    ecosystem: str, package: str, version: str | None, ev: Evidence
) -> Iterator[CryptoLibrary]:
    if (lib := libraries.declared(ecosystem, package, version, ev)) is not None:
        yield lib


def _pin(spec: str | None) -> str | None:
    """`==46.0.5` -> 46.0.5; a range stays as written; nothing -> None (unpinned)."""
    if not spec:
        return None
    spec = spec.replace(" ", "")
    return m.group(1) if (m := re.fullmatch(r"==([^,<>=!~*]+)", spec)) else spec


def _requirements(path: Path, text: str) -> Iterator[CryptoLibrary]:
    for i, row in enumerate(text.splitlines(), 1):
        line = row.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-")):
            continue
        if m := _REQUIREMENT.match(line):
            ev = Evidence(
                source_type=SourceType.CODE, location=str(path), line=i, context={"declared": line}
            )
            yield from _library("pypi", m.group(1), _pin(m.group(2)), ev)


def _pyproject(path: Path, text: str) -> Iterator[CryptoLibrary]:
    data = tomllib.loads(text)
    project = data.get("project", {})
    specs = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        specs.extend(extra)
    for spec in specs:
        if m := _REQUIREMENT.match(spec):
            yield from _library(
                "pypi", m.group(1), _pin(m.group(2)), _evidence(path, text, spec, spec)
            )
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, value in poetry.items():
        version = (
            value
            if isinstance(value, str)
            else value.get("version")
            if isinstance(value, dict)
            else None
        )
        yield from _library(
            "pypi", name, version, _evidence(path, text, name, f"{name} = {version}")
        )


def _go_mod(path: Path, text: str) -> Iterator[CryptoLibrary]:
    lines = text.splitlines()
    in_block = False
    for i, raw in enumerate(lines, 1):
        line = raw.split("//", 1)[0].strip()
        if m := re.fullmatch(r"go\s+(\d+(?:\.\d+)*)", line):
            # the go directive names the toolchain, so the standard library's version
            yield libraries.stdlib(
                "go:stdlib",
                m.group(1),
                Evidence(
                    source_type=SourceType.CODE,
                    location=str(path),
                    line=i,
                    context={"declared": line},
                ),
            )
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        spec = (
            line.removeprefix("require ").strip()
            if line.startswith("require ")
            else line
            if in_block
            else ""
        )
        if m := re.fullmatch(r"(\S+)\s+(v\S+)", spec):
            module = m.group(1)
            known = next(
                (
                    k
                    for k in libraries.CATALOGUE
                    if k.ecosystem == "golang" and module.startswith(k.name)
                ),
                None,
            )
            if known is not None:  # versioned paths (…/jwt/v5) belong to their family
                ev = Evidence(
                    source_type=SourceType.CODE,
                    location=str(path),
                    line=i,
                    context={"declared": raw.strip()},
                )
                yield from _library("golang", known.name, m.group(2), ev)


def _pom(path: Path, text: str) -> Iterator[CryptoLibrary]:
    # Uploads are untrusted. Without a DTD no entity can be declared, so nothing expands or
    # reaches outside; a real pom never needs one.
    if "<!DOCTYPE" in text.upper():
        raise ValueError("pom.xml with a DTD")
    root = ET.fromstring(text)  # noqa: S314 (DTD refused above)

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    props = {
        local(e.tag): (e.text or "").strip()
        for p in root
        if local(p.tag) == "properties"
        for e in p
    }
    for dep in root.iter():
        if local(dep.tag) != "dependency":
            continue
        fields = {local(c.tag): (c.text or "").strip() for c in dep}
        group, artifact = fields.get("groupId", ""), fields.get("artifactId", "")
        version = fields.get("version") or None
        if version and (m := re.fullmatch(r"\$\{([^}]+)\}", version)):
            version = props.get(m.group(1), version)
        if group and artifact:
            ev = _evidence(
                path,
                text,
                f"<artifactId>{artifact}</artifactId>",
                f"{group}:{artifact}:{version or '(managed)'}",
            )
            yield from _library("maven", f"{group}:{artifact}", version, ev)


def _package_json(path: Path, text: str) -> Iterator[CryptoLibrary]:
    data = json.loads(text)
    if not isinstance(data, dict):
        return
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            ev = _evidence(path, text, f'"{name}"', f'"{name}": "{spec}" ({section})')
            yield from _library("npm", name, str(spec), ev)
