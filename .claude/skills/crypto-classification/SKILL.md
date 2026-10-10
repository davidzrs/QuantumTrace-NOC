---
name: crypto-classification
description: Add or change how QuantumTrace classifies algorithms — risk tiers (critical/medium/safe), Shor vs Grover threat, key-size thresholds, NIST FIPS 203/204/205 mapping, replacements, ELB TLS policy tables. Use for any edit to rules/*.yaml or when a finding is unknown/misclassified.
---

# Crypto classification rules

The single source of truth is `backend/src/quantumtrace/rules/algorithms.yaml`. Detection
accuracy is 40% of the judging score, so be precise and cite standards.

## Tier model
| tier | threat | examples | why |
| --- | --- | --- | --- |
| critical | shor | RSA, DSA, ECDSA, EdDSA, ECDH(E), DH(E), SM2 | polynomial-time break |
| medium | grover | AES-128, 3DES, DES, RC4, SHA-1, MD5, SHA-224 | effective security halved |
| safe | grover/none | AES-192/256, ChaCha20, SHA-256+, HMAC-SHA256+, ML-KEM, ML-DSA, SLH-DSA, X25519MLKEM768 | margin survives Grover / PQC standard |
| unknown | unknown | anything unmatched | add a rule |

Rules that are enforced by `tests/test_classifier.py`:
- every `shor` rule is `critical`
- no `grover` rule is `critical`
- every critical or medium rule has a `replacement`
- aliases are unique across rules (normalised: upper-case, non-alphanumerics stripped)

`classically_broken: true` (MD5, SHA-1, DES, 3DES, RC4, RSA-1024, TLS 1.0/1.1, plaintext) keeps
the quantum tier honest while scoring treats the primitive as critical.

## Lookup
`Classifier.lookup(algorithm, key_size)` first tries `"<algorithm><key_size>"`, then
`"<algorithm>"`. So a key-size-specific rule (`rsa-1024` with alias `RSA-1024`, or `aes-128`)
overrides the generic one. Add a sized alias rather than special-casing in a scanner.

## Adding or changing a rule
1. Add the entry with `id`, `name`, `primitive` (CycloneDX primitive names: `pke`,
   `signature`, `kem`, `key-agree`, `block-cipher`, `stream-cipher`, `ae`, `hash`, `mac`, `kdf`,
   `protocol`, `other`), `threat`, `tier`, `oid` when known, `nist_reference`, `replacement`,
   a one-sentence `rationale`, and `aliases` covering every spelling the scanners see:
   - AWS: `RSA_2048`, `ECC_NIST_P256`, `EC_prime256v1`, `SYMMETRIC_DEFAULT`, `HMAC_256`, `ML_DSA_65`
   - Java: `SHA1withRSA`, `DESede`, `PBKDF2WithHmacSHA256`, `HmacSHA256`
   - OpenSSL/TLS: `ECDHE`, `AES128`, `DES-CBC3`; IANA: `TLS_AES_128_GCM_SHA256`
   - Go/Python module names map in the scanner to one of the above.
2. Add parametrised cases to `tests/test_classifier.py`.
3. Run `uv run pytest -q`, then `uv run quantumtrace scan ../samples` and confirm there are no unknowns.

## NIST references to use
- FIPS 203 ML-KEM (KEM; replaces RSA/ECDH key establishment)
- FIPS 204 ML-DSA (signatures; replaces RSA/ECDSA/EdDSA signing)
- FIPS 205 SLH-DSA (stateless hash-based signatures; conservative alternative)
- SP 800-208 LMS/XMSS (stateful hash-based, firmware signing)
- NIST IR 8547: quantum-vulnerable algorithms deprecated after 2030, disallowed after 2035
- CNSA 2.0: AES-256, SHA-384+, ML-KEM-1024, ML-DSA-87 for national-security systems

## TLS specifics
- `rules/tls.py` `decompose()` splits OpenSSL and IANA suite names into key exchange, cipher and MAC.
  Bare `AES128-SHA` means static RSA key transport, flagged `no-forward-secrecy`, which is the
  worst case for Harvest-Now-Decrypt-Later.
- TLS 1.3 suites carry no key exchange. Groups come from the handshake (`supported_groups`) or,
  for ELB, from the policy's `groups`. The default is classical `X25519`/`secp256r1`, i.e. ECDH.
- `rules/aws_elb_policies.yaml` maps `SslPolicy` to protocols, ciphers and groups. Verify
  against AWS docs when you add a policy, since PQ policy names are marked TODO.

## Pitfalls
- Curve names are ambiguous: `secp256r1` is both an ECDSA curve and an ECDH group. Scanners
  should emit `ECDHE` for key-exchange contexts.
- A SHA-256 digest inside an RSA signature is safe. The **RSA** is the critical part, so emit
  both assets.
- Don't call AES-256 "critical" because it appears with RSA in the same suite. Classify each
  primitive on its own.
