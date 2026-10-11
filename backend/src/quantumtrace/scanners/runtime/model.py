"""What a runtime trace says once it is read: the places that ran, and what ran there."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from quantumtrace.core.models import Evidence

# Folders a tracer never counts as the project's own code (same list as the Python tracer).
NOT_PROJECT = frozenset({
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".tox", ".nox", ".idea",
    ".vscode", ".quantumtrace", "site-packages", "dist-packages",
})  # fmt: skip


def file_key(path: str | Path) -> str:
    """One spelling per file, so a trace and a scan agree on which file they mean."""
    return os.path.normcase(os.path.realpath(path))


@dataclass
class Site:
    """A place where the traced run made a cryptographic call, with what the call used."""

    file: str  # file_key of the source file
    line: int
    end_line: int
    algorithm: str  # alias the classifier resolves
    usage: str
    key_size: int | None
    certain: bool  # False when the usage is a guess (a padding object, not the operation)
    flags: list[str]
    context: dict[str, str]
    variant: str | None
    observed: str
    evidence: Evidence  # with `execution` filled in and the snippet as the file reads now


@dataclass
class RuntimeTrace:
    """One trace file, checked against the source files as they are now."""

    root: str  # file_key of the traced project folder
    language: str
    suffixes: frozenset[str]
    command: str
    sites: list[Site] = field(default_factory=list)
    # lines that ran, per file the trace still matches: line -> first test that ran it
    lines: dict[str, dict[int, str | None]] = field(default_factory=dict)
    stale: set[str] = field(default_factory=set)

    def covers(self, key: str) -> bool:
        """Whether the traced run could have run this file: the project's own code, in the
        traced language, unchanged since. Such a file with no lines recorded did not run."""
        if key in self.stale or not key.startswith(self.root + os.sep):
            return False
        relative = Path(key[len(self.root) + 1 :])
        if relative.suffix.lower() not in self.suffixes:
            return False
        return not NOT_PROJECT.intersection(part.lower() for part in relative.parts[:-1])
