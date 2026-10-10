import type { Finding, RiskTier } from "@quantumtrace/sdk";
import { describe, expect, it } from "vitest";
import { fixBy, fixRows } from "./fix";

let seq = 0;
const f = (
  rule: string,
  tier: RiskTier,
  exposure: Finding["asset"]["exposure"],
  { broken = false, location = "x" } = {},
): Finding => ({
  id: String(seq++),
  asset: {
    observed: rule,
    algorithm: rule,
    variant: null,
    key_size: null,
    usage: null,
    observation: "configured",
    confidence: "high",
    exposure,
    flags: [],
    evidence: { source_type: "cloud", location, line: null, snippet: null, snippet_start_line: null, context: {} },
    more_evidence: [],
  },
  classification: {
    rule_id: rule,
    name: rule.toUpperCase(),
    primitive: "signature",
    threat: tier === "critical" ? "shor" : tier === "medium" ? "grover" : "none",
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

describe("fixBy", () => {
  it("puts classically broken Shor exposure first and keeps Grover as hardening", () => {
    expect(fixBy(f("rsa-1024", "critical", "unknown", { broken: true }).classification)).toBe("now");
    expect(fixBy(f("rsa", "critical", "internet").classification)).toBe("before-2030");
    expect(fixBy(f("md5", "medium", "unknown", { broken: true }).classification)).toBe("harden");
    expect(fixBy(f("aes-256", "safe", "unknown").classification)).toBe("none");
  });
});

describe("fixRows", () => {
  it("groups identical findings and orders by urgency, breakage, exposure, then count", () => {
    const rows = fixRows([
      f("aes-256", "safe", "internet"),
      f("sha1", "medium", "internet"),
      f("md5", "medium", "unknown", { broken: true }),
      f("ecdsa", "critical", "internal", { location: "a" }),
      f("ecdsa", "critical", "internal", { location: "b" }),
      f("rsa", "critical", "internet"),
      f("rsa-1024", "critical", "unknown", { broken: true }),
    ]);
    expect(rows.map((r) => r.lead.classification.rule_id)).toEqual([
      "rsa-1024", "rsa", "ecdsa", "md5", "sha1", "aes-256",
    ]);
    expect(rows[2]?.members).toHaveLength(2);
  });

  it("keeps one row per finding when ungrouped", () => {
    const same = [f("ecdsa", "critical", "internal"), f("ecdsa", "critical", "internal")];
    expect(fixRows(same, false)).toHaveLength(2);
  });
});
