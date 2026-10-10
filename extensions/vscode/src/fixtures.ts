/** Test data shaped like `quantumtrace scan --format json` output. */
import type { Finding } from "@quantumtrace/sdk";

type Asset = Finding["asset"];

interface Overrides {
  asset?: Partial<Omit<Asset, "evidence">>;
  evidence?: Partial<Asset["evidence"]>;
  classification?: Partial<Finding["classification"]>;
}

/** RSA-1024 key generation in a Python file, unless overridden. */
export function finding(overrides: Overrides = {}): Finding {
  return {
    id: "f1",
    asset: {
      observed: "rsa.generate_private_key(public_exponent=65537, key_size=1024)",
      algorithm: "RSA",
      variant: null,
      key_size: 1024,
      usage: "key-generation",
      observation: "in-code",
      confidence: "high",
      exposure: "unknown",
      flags: [],
      more_evidence: [],
      ...overrides.asset,
      evidence: {
        source_type: "code",
        location: "license_token.py",
        line: 6,
        snippet: null,
        snippet_start_line: null,
        context: { language: "python" },
        ...overrides.evidence,
      },
    },
    classification: {
      rule_id: "rsa-1024",
      name: "RSA-1024",
      primitive: "pke",
      threat: "shor",
      tier: "critical",
      classically_broken: true,
      nist_reference: "NIST SP 800-131A (disallowed), NIST IR 8547",
      replacement: "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)",
      oid: "1.2.840.113549.1.1.1",
      classical_security_bits: 80,
      nist_quantum_level: 0,
      rationale: "Shor-vulnerable and below the 112-bit classical security floor.",
      ...overrides.classification,
    },
  };
}

/** MD5 called on lines 4 and 6 (one-based), merged by the engine into one finding. */
export const md5 = finding({
  asset: { observed: "hashlib.md5", algorithm: "MD5", key_size: null, usage: "hash" },
  evidence: { line: 4, context: { language: "python", also_lines: "6" } },
  classification: {
    rule_id: "md5",
    name: "MD5",
    primitive: "hash",
    threat: "grover",
    tier: "medium",
    nist_reference: null,
    replacement: "SHA-384 / SHA3-384",
    rationale: "Trivially collidable; must not be used for any security purpose.",
  },
});
