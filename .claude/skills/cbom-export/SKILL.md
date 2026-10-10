---
name: cbom-export
description: Work on the CycloneDX 1.6 Cryptography Bill of Materials (CBOM) export — component structure, cryptoProperties, evidence occurrences, validation. Use when changing cbom/cyclonedx.py or when judges/users need standard-compliant output.
---

# CBOM export (CycloneDX 1.6)

Code: `backend/src/quantumtrace/cbom/cyclonedx.py`. Test: `backend/tests/test_cbom.py`.
Standardisation and traceability are 20% of judging.

## Shape we produce
- One `components[]` entry per distinct algorithm form, keyed by
  `bom-ref = crypto/<rule-id>[/<variant>]`, so AES-128-GCM and AES-128-CBC stay separate.
- `classicalSecurityLevel` / `nistQuantumSecurityLevel` come from the rule
  (`classical_security_bits`, `nist_quantum_level`), or from key size for RSA/DH/EC.
- TLS protocol components list the `cipherSuites` they were seen with.
- Occurrence locations carry `#<json_path>` (cloud) or `/packet-<n>` (pcap).
  `additionalContext` starts with the observation, e.g. `[permitted]`.
- `metadata.properties` includes every `quantumtrace:limitation`.
- `type: "cryptographic-asset"` and `cryptoProperties`:
  - algorithms: `assetType: "algorithm"`, `algorithmProperties.primitive` (from the rule),
    `parameterSetIdentifier` (key size), `curve`, `nistQuantumSecurityLevel: 0` for Shor-broken
  - protocols: `assetType: "protocol"`, `protocolProperties.type` (`tls`, `ssh`, ...) and `version`
  - `oid` when the rule has one
- `evidence.occurrences[]`: one per finding, with `location` (path, ARN or flow), optional
  `line`, and `additionalContext` (usage and observed string). This is how traceability works.
- `properties[]` in the `quantumtrace:` namespace: tier, threat, classically-broken, rationale,
  nist-reference, replacement, and one entry per flag.
- `metadata.properties`: risk score, grade, targets.

## Rules
- The output **must** validate. The test uses
  `cyclonedx.validation.json.JsonStrictValidator(SchemaVersion.V1_6)`. Run
  `uv run pytest tests/test_cbom.py`.
- Only use enum values the 1.6 schema allows (e.g. primitive `key-agree`, not `kex`).
- Don't drop findings: `sum(len(occurrences)) == len(findings)` is asserted.
- Ideas for richer CBOMs: `assetType: "certificate"` with `certificateProperties` for ACM and
  pcap certs, `related-crypto-material` for KMS keys (`size`, `state`), and `dependencies` linking
  protocols to the algorithms they negotiate. Add a validating test with each one.

## Manual check
```sh
cd backend && uv run quantumtrace scan ../samples -f cbom -o /tmp/qt.cdx.json
```
Optionally inspect it with the CycloneDX CLI or the Sunshine/CBOMkit viewers.
