"""Lay runtime evidence over the source scan: what was found in code, and what of it ran.

A traced call at a place the source scan also found becomes one finding: the code's own text
and snippet, with the parameters the run really used (a key size the source scan could only
infer is now read off the key). A traced call the source scan did not find is a finding of its
own. What is left of the source findings is split by whether its line ran.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

from quantumtrace.core.classifier import normalise
from quantumtrace.core.models import (
    Confidence,
    CryptoAsset,
    Evidence,
    Execution,
    Observation,
    SourceType,
)
from quantumtrace.scanners.code.common import variant_name
from quantumtrace.scanners.runtime.model import RuntimeTrace, Site, file_key

# A padding object doesn't say whether RSA signs or encrypts with it, so the source scan and
# the trace may each have picked one. At the same place they mean the same call.
_INTERCHANGEABLE = {"signature", "encryption"}


def apply(
    assets: list[CryptoAsset], traces: Sequence[RuntimeTrace], scanned: Iterable[Path]
) -> list[CryptoAsset]:
    """The scan's assets with every trace applied. Without a trace nothing changes."""
    if not traces:
        return assets
    spelled = {file_key(path): str(path) for path in scanned}
    static = [a for a in assets if _in_code(a)]
    executed: dict[tuple[object, ...], CryptoAsset] = {}
    for trace in traces:
        for site in trace.sites:
            # a trace only speaks about files this scan read
            if site.file in spelled:
                _add(executed, _asset(site, _take(static, site), spelled[site.file]))

    out: list[CryptoAsset] = []
    remaining = {id(a) for a in static}
    for asset in assets:
        if not _in_code(asset):
            out.append(asset)
        elif id(asset) in remaining:
            out.extend(_by_what_ran(asset, traces))
    return [*out, *executed.values()]


def _in_code(asset: CryptoAsset) -> bool:
    return (
        asset.observation is Observation.IN_CODE and asset.evidence.source_type is SourceType.CODE
    )


def _take(static: list[CryptoAsset], site: Site) -> tuple[CryptoAsset, Evidence] | None:
    """The source finding at the traced place, taken out of its asset: it is the same call."""
    for asset in static:
        if normalise(asset.algorithm) != normalise(site.algorithm):
            continue
        same_usage = asset.usage == site.usage or {asset.usage, site.usage} <= _INTERCHANGEABLE
        # an inferred size gives way to the one the run used; a size read off the line does not
        same_size = (
            asset.key_size is None
            or site.key_size is None
            or asset.key_size == site.key_size
            or asset.confidence is not Confidence.HIGH
        )
        if not (same_usage and same_size):
            continue
        for place in asset.all_evidence:
            if (
                place.line is not None
                and site.line <= place.line <= site.end_line
                and file_key(place.location) == site.file
            ):
                rest = [p for p in asset.all_evidence if p is not place]
                if rest:
                    asset.evidence, asset.more_evidence = rest[0], rest[1:]
                else:
                    static[:] = [a for a in static if a is not asset]
                return asset, place
    return None


def _asset(site: Site, found: tuple[CryptoAsset, Evidence] | None, location: str) -> CryptoAsset:
    source, place = found or (None, None)
    flags = set(site.flags)
    if source is not None:
        kept = set(source.flags)
        if "mode" in site.context:
            kept.discard("ecb-mode")  # the source scan guessed the mode file-wide; the run knows
        flags |= kept
    execution = site.evidence.execution
    evidence = place.model_copy(deep=True) if place is not None else site.evidence.model_copy()
    evidence.location = location
    evidence.context = {**evidence.context, **site.context, "file": location}
    evidence.execution = execution
    algorithm = source.algorithm if source is not None else site.algorithm
    key_size = site.key_size
    if key_size is None and source is not None:
        key_size = source.key_size
    usage = site.usage if site.certain or source is None else source.usage
    variant = variant_name(algorithm, key_size, sorted(flags), evidence.context) or site.variant
    if variant is None and source is not None and source.key_size == key_size:
        variant = source.variant
    seen = {
        "variant": variant,
        "key_size": key_size,
        "usage": usage,
        "observation": Observation.EXECUTED,
        "confidence": Confidence.HIGH,
        "flags": sorted(flags),
        "evidence": evidence,
        "more_evidence": [],
    }
    if source is not None:  # everything else the code scan knew stays: its text, its library
        return source.model_copy(update=seen)
    return CryptoAsset(observed=site.observed, algorithm=algorithm, library=site.library, **seen)


def _add(executed: dict[tuple[object, ...], CryptoAsset], asset: CryptoAsset) -> None:
    """Repeats of the same asset in a file are one finding with several places, as in the
    source scan."""
    key = (
        file_key(asset.evidence.location), normalise(asset.algorithm), asset.key_size,
        asset.usage, asset.variant,
    )  # fmt: skip
    existing = executed.get(key)
    if existing is None:
        executed[key] = asset
        return
    if all(e.line != asset.evidence.line for e in existing.all_evidence):
        existing.more_evidence.append(asset.evidence)
    existing.flags = sorted({*existing.flags, *asset.flags})


def _by_what_ran(asset: CryptoAsset, traces: Sequence[RuntimeTrace]) -> list[CryptoAsset]:
    """A source finding split by what the trace says of each of its places: the line ran, the
    line did not run, or no trace covers it."""
    groups: dict[str, list[Evidence]] = {}
    for place in asset.all_evidence:
        execution = _line_ran(place, traces)
        state = "unseen" if execution is None else "ran" if execution.ran else "idle"
        groups.setdefault(state, []).append(place.model_copy(update={"execution": execution}))
    return [
        asset.model_copy(
            update={
                "evidence": places[0],
                "more_evidence": places[1:],
                "observation": Observation.EXECUTED if state == "ran" else asset.observation,
            }
        )
        for state, places in groups.items()
    ]


def _line_ran(place: Evidence, traces: Sequence[RuntimeTrace]) -> Execution | None:
    key = file_key(place.location)
    for trace in traces:
        if not trace.covers(key):
            continue
        seen = trace.lines.get(key, {})
        if place.line in seen:
            test = seen[place.line] if place.line is not None else None
            return Execution(
                ran=True,
                tests=[test] if test else [],
                test_count=1 if test else 0,
                run=trace.command,
            )
        return Execution(ran=False, run=trace.command)
    return None
