"""Export a ScanResult as a CycloneDX 1.6 CBOM (cryptographic-asset components).

One component per distinct algorithm (rule + key size); every place it was seen becomes an
evidence occurrence, so the CBOM stays compact but fully traceable.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from uuid import UUID

from quantumtrace import __version__
from quantumtrace.core.classifier import load_misuse
from quantumtrace.core.models import Finding, Primitive, QuantumThreat, ScanResult

SPEC_VERSION = "1.6"
_PROTOCOL_TYPES = {"tls": "tls", "ssh": "ssh", "ipsec": "ipsec", "ike": "ike"}


def to_cyclonedx(result: ScanResult) -> dict[str, Any]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        groups[_bom_ref(f)].append(f)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{UUID(result.id)}",
        "version": 1,
        "metadata": {
            "timestamp": result.created_at.isoformat(),
            "tools": {
                "components": [
                    {"type": "application", "name": "quantumtrace", "version": __version__}
                ]
            },
            "properties": [
                {"name": "quantumtrace:risk-score", "value": str(result.score.value)},
                {"name": "quantumtrace:grade", "value": result.score.grade},
                *({"name": "quantumtrace:target", "value": t} for t in result.targets),
                *(
                    {"name": "quantumtrace:limitation", "value": n.message}
                    for n in result.limitations
                ),
            ],
        },
        "components": [_component(ref, fs) for ref, fs in sorted(groups.items())],
    }


def _bom_ref(f: Finding) -> str:
    """One component per precise algorithm form: AES-128-GCM and AES-128-CBC stay distinct."""
    c = f.classification
    rule = c.rule_id if c.rule_id != "unknown" else f"unknown-{f.asset.algorithm}"
    size = f"-{f.asset.key_size}" if f.asset.key_size else ""
    variant = (
        f"/{f.asset.variant}" if f.asset.variant and c.primitive is not Primitive.PROTOCOL else ""
    )
    # a hard-coded key or hand-rolled code is broken where the same algorithm elsewhere isn't
    misused = "/misused" if set(f.asset.flags) & load_misuse().keys() else ""
    return re.sub(r"[^a-z0-9/.\-]+", "-", f"crypto/{rule}{size}{variant}{misused}".lower())


def _component(ref: str, findings: list[Finding]) -> dict[str, Any]:
    first = findings[0]
    c = first.classification
    name = first.asset.variant or (
        f"{c.name}-{first.asset.key_size}" if first.asset.key_size else c.name
    )

    crypto: dict[str, Any]
    if c.primitive is Primitive.PROTOCOL:
        name = c.name
        proto = c.name.split(" ")[0].lower()
        version = re.search(r"\d+(?:\.\d+)?", c.name)
        props: dict[str, Any] = {"type": _PROTOCOL_TYPES.get(proto, "other")}
        if version and proto in _PROTOCOL_TYPES:
            props["version"] = version.group(0)
        suites = sorted({
            s.strip()
            for f in findings
            for s in (f.asset.evidence.context.get("cipher_suite"),
                      *f.asset.evidence.context.get("suites", "").split(","))
            if s and s.strip() and not s.strip().startswith("group:")
        })  # fmt: skip
        if suites and props["type"] == "tls":
            props["cipherSuites"] = [{"name": s} for s in suites]
        crypto = {"assetType": "protocol", "protocolProperties": props}
    else:
        algo: dict[str, Any] = {"primitive": c.primitive.value}
        if first.asset.key_size:
            algo["parameterSetIdentifier"] = str(first.asset.key_size)
        if curve := first.asset.evidence.context.get("curve"):
            algo["curve"] = curve
        if mode := _mode(first.asset.variant):
            algo["mode"] = mode
        if c.classical_security_bits is not None:
            algo["classicalSecurityLevel"] = c.classical_security_bits
        if c.nist_quantum_level is not None:
            algo["nistQuantumSecurityLevel"] = c.nist_quantum_level
        elif c.threat is QuantumThreat.SHOR:
            algo["nistQuantumSecurityLevel"] = 0
        crypto = {"assetType": "algorithm", "algorithmProperties": algo}
    if c.oid:
        crypto["oid"] = c.oid

    occurrences = []
    for f, ev in ((fi, ev) for fi in findings for ev in fi.asset.all_evidence):
        ctx = ev.context
        where = ev.location
        if path := ctx.get("json_path"):
            where = f"{where}#{path}"
        elif pkt := ctx.get("packet"):
            where = f"{where}/packet-{pkt}"
        occ: dict[str, Any] = {"location": where}
        if ev.line:
            occ["line"] = ev.line
        if ev.column:
            occ["offset"] = ev.column
        occ["additionalContext"] = (
            f"[{f.asset.observation.value}, {f.asset.confidence.value} confidence] "
            f"{f.asset.usage or ''} observed={f.asset.observed}"
        )
        occurrences.append(occ)

    properties = [
        {"name": "quantumtrace:tier", "value": c.tier.value},
        *(
            {"name": "quantumtrace:observation", "value": o}
            for o in sorted({f.asset.observation.value for f in findings})
        ),
        *(
            {"name": "quantumtrace:confidence", "value": c}
            for c in sorted({f.asset.confidence.value for f in findings})
        ),
        {"name": "quantumtrace:threat", "value": c.threat.value},
        {"name": "quantumtrace:classically-broken", "value": str(c.classically_broken).lower()},
        {"name": "quantumtrace:rationale", "value": c.rationale},
    ]
    if c.nist_reference:
        properties.append({"name": "quantumtrace:nist-reference", "value": c.nist_reference})
    if c.replacement:
        properties.append({"name": "quantumtrace:replacement", "value": c.replacement})
    for flag in sorted({fl for f in findings for fl in f.asset.flags}):
        properties.append({"name": "quantumtrace:flag", "value": flag})

    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": name,
        "cryptoProperties": crypto,
        "evidence": {"occurrences": occurrences},
        "properties": properties,
    }


_MODES = {"GCM": "gcm", "CBC": "cbc", "CCM": "ccm", "ECB": "ecb", "CTR": "ctr"}


def _mode(variant: str | None) -> str | None:
    if not variant:
        return None
    return next((v for k, v in _MODES.items() if variant.upper().endswith(k)), None)
