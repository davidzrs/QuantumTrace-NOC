from __future__ import annotations

import json
from pathlib import Path

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from quantumtrace.cbom.cyclonedx import to_cyclonedx
from quantumtrace.core.engine import run_scan


def test_cbom_validates_against_cyclonedx_1_6(samples: Path) -> None:
    bom = to_cyclonedx(run_scan([samples]))  # all three vectors
    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    assert errors is None, errors


def test_cbom_groups_occurrences_per_algorithm(samples: Path) -> None:
    result = run_scan([samples / "cloud-posture"])
    bom = to_cyclonedx(result)
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs))
    occurrences = sum(len(c["evidence"]["occurrences"]) for c in bom["components"])
    assert occurrences == sum(len(f.asset.all_evidence) for f in result.findings)
    rsa = next(c for c in bom["components"] if c["name"] == "RSA-2048")
    algo = rsa["cryptoProperties"]["algorithmProperties"]
    assert algo["nistQuantumSecurityLevel"] == 0
    assert algo["classicalSecurityLevel"] == 112


def test_cbom_keeps_cipher_modes_and_protocol_suites(samples: Path) -> None:
    bom = to_cyclonedx(run_scan([samples]))
    names = {c["name"]: c for c in bom["components"]}
    assert {"AES-128-GCM", "AES-128-CBC", "AES-256-GCM"} <= set(names)
    assert names["AES-128-GCM"]["cryptoProperties"]["algorithmProperties"]["mode"] == "gcm"
    hybrid = names["TLS 1.3 (hybrid post-quantum)"]["cryptoProperties"]["protocolProperties"]
    assert hybrid["version"] == "1.3"
    assert {"name": "TLS_AES_256_GCM_SHA384"} in hybrid["cipherSuites"]
    pq = names["X25519MLKEM768"]["cryptoProperties"]["algorithmProperties"]
    assert pq["nistQuantumSecurityLevel"] == 3


def test_cbom_occurrences_are_precise(samples: Path) -> None:
    bom = to_cyclonedx(run_scan([samples]))
    locations = [o["location"] for c in bom["components"] for o in c["evidence"]["occurrences"]]
    assert any("#$.LoadBalancers[" in loc for loc in locations)  # cloud: JSON path
    assert any("/packet-" in loc for loc in locations)  # network: packet number
    limits = [p for p in bom["metadata"]["properties"] if p["name"] == "quantumtrace:limitation"]
    assert limits
