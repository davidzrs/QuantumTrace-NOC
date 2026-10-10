import type { Finding, RiskTier } from "@quantumtrace/sdk";
import { describe, expect, it } from "vitest";
import { migrationPriorities } from "./priorities";

let seq = 0;
const f = (rule: string, tier: RiskTier, exposure: Finding["asset"]["exposure"], broken = false): Finding => ({
  id: String(seq++),
  asset: {
    observed: rule,
    algorithm: rule,
    variant: null,
    key_size: null,
    usage: null,
    observation: "negotiated",
    confidence: "high",
    exposure,
    flags: [],
    evidence: { source_type: "cloud", location: "x", line: null, snippet: null, context: {} },
    more_evidence: [],
  },
  classification: {
    rule_id: rule,
    name: rule.toUpperCase(),
    primitive: "pke",
    threat: "shor",
    tier,
    classically_broken: broken,
    nist_reference: null,
    replacement: null,
    oid: null,
    classical_security_bits: null,
    nist_quantum_level: null,
    rationale: "",
  },
});

describe("migrationPriorities", () => {
  it("ranks broken, then internet-facing, then count; ignores non-critical", () => {
    const ranked = migrationPriorities([
      f("ecdh", "critical", "internal"),
      f("ecdh", "critical", "internal"),
      f("ecdh", "critical", "internal"),
      f("rsa", "critical", "internet"),
      f("plaintext", "critical", "internal", true),
      f("aes-128", "medium", "internet"),
    ]);
    expect(ranked.map((r) => r.ruleId)).toEqual(["plaintext", "rsa", "ecdh"]);
    expect(ranked[2]?.count).toBe(3);
  });
});
