import type { Finding, RiskTier } from "@quantumtrace/sdk";
import { describe, expect, it } from "vitest";
import { fixBy, fixRows } from "./fix";

let seq = 0;
const f = (
  rule: string,
  tier: RiskTier,
  exposure: Finding["asset"]["exposure"],
  { broken = false, hndl = false, location = "x", bits = null as number | null, flags = [] as string[] } = {},
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
    flags,
    evidence: { source_type: "cloud", location, line: null, column: null, end_column: null, snippet: null, snippet_start_line: null, context: {}, execution: null },
    more_evidence: [],
    library: null,
  },
  classification: {
    rule_id: rule,
    name: rule.toUpperCase(),
    primitive: "signature",
    threat: tier === "critical" ? "shor" : tier === "medium" ? "grover" : "none",
    tier,
    classically_broken: broken,
    hndl,
    nist_reference: null,
    replacement: null,
    oid: null,
    classical_security_bits: bits,
    nist_quantum_level: null,
    rationale: "",
  },
});

describe("fixBy", () => {
  it("puts classically broken Shor exposure first and keeps Grover as hardening", () => {
    expect(fixBy(f("rsa-1024", "critical", "unknown", { broken: true }))).toBe("now");
    expect(fixBy(f("rsa", "critical", "internet"))).toBe("before-2030");
    expect(fixBy(f("md5", "medium", "unknown", { broken: true }))).toBe("harden");
    expect(fixBy(f("aes-256", "safe", "unknown"))).toBe("none");
  });

  it("follows NIST IR 8547: 112-bit keys by 2030, stronger ones by 2035", () => {
    expect(fixBy(f("rsa", "critical", "internet", { bits: 112 }))).toBe("before-2030");
    expect(fixBy(f("ecdsa", "critical", "internet", { bits: 128 }))).toBe("before-2035");
    expect(fixBy(f("rsa", "critical", "internet", { bits: 192 }))).toBe("before-2035");
  });

  it("asks for a review of hand-rolled code instead of calling it fine", () => {
    expect(fixBy(f("pbkdf2", "safe", "unknown", { flags: ["hand-rolled-crypto"] }))).toBe("review");
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

  it("puts harvest-now, decrypt-later exposure first within the same urgency", () => {
    const rows = fixRows([
      f("ecdsa", "critical", "internet"),
      f("ecdh", "critical", "internal", { hndl: true }),
      f("rsa-1024", "critical", "unknown", { broken: true }),
    ]);
    expect(rows.map((r) => r.lead.classification.rule_id)).toEqual(["rsa-1024", "ecdh", "ecdsa"]);
  });

  it("keeps one row per finding when ungrouped", () => {
    const same = [f("ecdsa", "critical", "internal"), f("ecdsa", "critical", "internal")];
    expect(fixRows(same, false)).toHaveLength(2);
  });
});
