"""Runtime-trace scanner: reads `.quantumtrace/*.jsonl`, written by a tracer while the project's
tests or a debug session ran (`tracers/python`), and reports what actually executed.

A trace speaks about source files by path and line, so it is only as good as those files are
unchanged: every file is checked against the hash the tracer took, and a file edited since is
left out and named in a note. The trace itself is plain data; nothing in it is executed.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from quantumtrace.core.models import (
    CryptoAsset,
    Evidence,
    Execution,
    ScanNote,
    SourceType,
)
from quantumtrace.scanners.code.common import SourceFile
from quantumtrace.scanners.runtime import python_api
from quantumtrace.scanners.runtime.model import RuntimeTrace, Site, file_key

TRACE_DIR = ".quantumtrace"
MAX_TRACE_BYTES = 16 * 1024 * 1024
MAX_TESTS = 5
LANGUAGE_SUFFIXES = {"python": frozenset({".py"})}


class RuntimeTraceScanner:
    name = "runtime-trace"
    source_type = SourceType.CODE

    def accepts(self, path: Path) -> bool:
        return path.suffix == ".jsonl" and path.parent.name == TRACE_DIR

    def scan(self, paths: Sequence[Path]) -> Iterable[CryptoAsset | ScanNote | RuntimeTrace]:
        for path in paths:
            yield from self._read(path)

    def _note(self, message: str) -> ScanNote:
        return ScanNote(scanner=self.name, message=message)

    def _read(self, path: Path) -> Iterator[ScanNote | RuntimeTrace]:
        if path.stat().st_size > MAX_TRACE_BYTES:
            yield self._note(f"{path.name} is larger than 16 MB and was not read.")
            return
        records = list(_records(path))
        runs = [r for r in records if r.get("kind") == "run"]
        if not runs:
            return  # some other .jsonl file
        usable = [r for r in runs if not r.get("unsupported")]
        if not usable:
            why = str(runs[0].get("unsupported"))
            yield self._note(
                f"The traced run recorded nothing: {why} (it ran on {runs[0].get('runtime')})."
            )
            return
        language = str(usable[0].get("language") or "python")
        command = str(usable[0].get("command") or language)
        trace = RuntimeTrace(
            root=file_key(path.parent.parent),
            language=language,
            suffixes=LANGUAGE_SUFFIXES.get(language, frozenset()),
            command=command,
        )
        files = _Files(Path(trace.root))
        for record in records:
            if record.get("kind") == "file":
                files.expect(str(record.get("file")), record.get("sha256"))
        trace.stale = files.stale

        for record in records:
            if record.get("kind") != "lines":
                continue
            key = files.fresh(str(record.get("file")))
            test = record.get("test")
            if key is not None:
                seen = trace.lines.setdefault(key, {})
                for line in record.get("lines") or []:
                    if isinstance(line, int):
                        seen.setdefault(line, str(test) if test else None)

        unknown: Counter[str] = Counter()
        calls = _calls(records, files, unknown)
        trace.sites = list(_sites(calls, command, files))
        yield trace

        total = sum(
            site.evidence.execution.calls or 0 for site in trace.sites if site.evidence.execution
        )
        yield self._note(
            f"Runtime evidence comes from one traced run (`{command}`, "
            f"{usable[0].get('runtime')}): {total} cryptographic calls at {len(trace.sites)} "
            f"places. Code that run never reached is marked as not run, which does not prove it "
            f"is unused. The Python tracer sees hashlib, hmac and the cryptography package; other "
            f"libraries only show as lines that ran."
        )
        if trace.stale:
            names = ", ".join(sorted(Path(k).name for k in trace.stale)[:5])
            yield self._note(
                f"{len(trace.stale)} file(s) changed after the traced run ({names}): their runtime "
                f"evidence was left out. Run the tests again to refresh it."
            )
        if unknown:
            names = ", ".join(name for name, _ in unknown.most_common(8))
            yield self._note(f"The traced run made calls no rule covers yet: {names}.")


def _records(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except ValueError:
                continue  # a line cut short when the traced process was killed
            if isinstance(record, dict):
                yield record


class _Files:
    """The source files a trace names, each checked once against the tracer's hash."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.hashes: dict[str, set[object]] = defaultdict(set)
        self.keys: dict[str, str | None] = {}
        self.stale: set[str] = set()
        self.sources: dict[str, SourceFile] = {}

    def expect(self, relative: str, digest: object) -> None:
        self.hashes[relative].add(digest)

    def fresh(self, relative: str) -> str | None:
        """The file's key when it is inside the traced folder and reads as it did then."""
        if relative not in self.keys:
            self.keys[relative] = self._check(relative)
        return self.keys[relative]

    def _check(self, relative: str) -> str | None:
        key = file_key(self.root / relative)
        # the trace is input: a path that climbs out of the traced folder is not followed
        if not key.startswith(str(self.root) + os.sep) or not os.path.isfile(key):
            return None
        recorded = self.hashes.get(relative, set())
        current = hashlib.sha256(Path(key).read_bytes()).hexdigest()
        if recorded != {current}:
            self.stale.add(key)
            return None
        return key

    def source(self, key: str, language: str) -> SourceFile:
        if key not in self.sources:
            self.sources[key] = SourceFile.load(Path(key), language)
        return self.sources[key]


@dataclass
class _Call:
    """One traced call site and API, summed over every process and flush of the run."""

    file: str
    line: int
    end_line: int
    api: str
    seen: python_api.Seen
    args: dict[str, object]
    via: str | None
    tests: Counter[str] = field(default_factory=Counter)
    count: int = 0


def _calls(records: list[dict[str, Any]], files: _Files, unknown: Counter[str]) -> list[_Call]:
    calls: dict[tuple[object, ...], _Call] = {}
    for record in records:
        if record.get("kind") != "call":
            continue
        key = files.fresh(str(record.get("file")))
        line, count = record.get("line"), record.get("count")
        if key is None or not isinstance(line, int) or not isinstance(count, int) or count < 1:
            continue
        end = record.get("end_line")
        end_line = end if isinstance(end, int) and end >= line else line
        api = str(record.get("api"))
        args = record.get("args")
        args = args if isinstance(args, dict) else {}
        seen = python_api.describe(api, args)
        if seen is None:
            unknown[api] += count
            continue
        via = record.get("via")
        identity = (
            key,
            line,
            end_line,
            api,
            tuple(sorted((str(k), str(v)) for k, v in args.items())),
            via,
        )
        call = calls.get(identity)
        if call is None:
            call = calls[identity] = _Call(
                key, line, end_line, api, seen, args, str(via) if via else None
            )
        call.count += count
        if test := record.get("test"):
            call.tests[str(test)] += count
    return list(calls.values())


def _sites(calls: list[_Call], command: str, files: _Files) -> Iterator[Site]:
    """Calls that are one place in the code become one site: `key.sign(data, PKCS1v15(), SHA1())`
    is seen as the padding object and as the signing call, on lines that overlap."""
    kdf_spans = defaultdict(list)
    for call in calls:
        if call.seen.usage == "kdf":
            kdf_spans[call.file].append(call)
    by_algorithm: dict[tuple[str, str], list[_Call]] = defaultdict(list)
    for call in calls:
        # a hash handed to a KDF is that KDF's PRF, as in the source scan
        prf_of = next(
            (
                k for k in kdf_spans[call.file]
                if call.seen.usage == "hash" and k.line <= call.line <= k.end_line
            ),
            None,
        )  # fmt: skip
        if prf_of is None:
            by_algorithm[(call.file, call.seen.algorithm)].append(call)

    for (file, _), group in by_algorithm.items():
        group.sort(key=lambda c: (c.line, c.end_line))
        cluster: list[_Call] = []
        last = 0
        for call in group:
            if cluster and call.line > last:
                yield from _cluster_sites(file, cluster, command, files)
                cluster = []
            cluster.append(call)
            last = max(last, call.end_line) if len(cluster) > 1 else call.end_line
        if cluster:
            yield from _cluster_sites(file, cluster, command, files)


def _cluster_sites(file: str, cluster: list[_Call], command: str, files: _Files) -> Iterator[Site]:
    certain = [c for c in cluster if c.seen.certain]
    guesses = [c for c in cluster if not c.seen.certain]
    kinds = {(c.seen.usage, c.seen.key_size) for c in certain} or {
        (c.seen.usage, None) for c in guesses
    }
    for usage, key_size in sorted(kinds, key=lambda k: (k[0], k[1] or 0)):
        own = [c for c in certain if (c.seen.usage, c.seen.key_size) == (usage, key_size)]
        members = [*own, *guesses] if certain else [c for c in guesses if c.seen.usage == usage]
        lead = max(own or members, key=lambda c: c.count)
        # one statement can be seen through several calls: count it once, by its busiest call
        per_api: Counter[str] = Counter()
        for c in members:
            per_api[c.api] += c.count
        tests: Counter[str] = Counter()
        for c in members:
            if c.api == lead.api:
                tests.update(c.tests)
        flags = sorted({f for c in members for f in c.seen.flags})
        context = {k: v for c in members for k, v in c.seen.context.items()}
        parameters = {"api": lead.api.removeprefix("cryptography.")}
        if key_size is not None:
            parameters["key_size"] = str(key_size)
        parameters.update(context)
        for c in members:
            if c.via:
                parameters["via"] = c.via
            if isinstance(prf := c.args.get("hash"), str):
                parameters["hash"] = prf
        line = min(c.line for c in own or members)
        end_line = max(c.end_line for c in members)
        language = "python"
        snippet, snippet_start = files.source(file, language).snippet(line)
        evidence = Evidence(
            source_type=SourceType.CODE,
            location=file,
            line=line,
            snippet=snippet,
            snippet_start_line=snippet_start,
            context={"language": language, "file": file},
            execution=Execution(
                ran=True,
                calls=max(per_api.values()),
                tests=[name for name, _ in tests.most_common(MAX_TESTS)],
                test_count=len(tests),
                parameters=parameters,
                run=command,
            ),
        )
        yield Site(
            file=file,
            line=min(c.line for c in members),
            end_line=end_line,
            algorithm=lead.seen.algorithm,
            usage=usage,
            key_size=key_size,
            certain=bool(certain),
            flags=flags,
            context=context,
            variant=next((c.seen.variant for c in members if c.seen.variant), None),
            observed=lead.api.removeprefix("cryptography."),
            evidence=evidence,
        )
