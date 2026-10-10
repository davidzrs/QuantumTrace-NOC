import type { Finding, RiskTier, ScanResult } from "@quantumtrace/sdk";
import { describe, expect, it } from "vitest";
import { badge, headline, keyExchange, sections } from "./report";

let n = 0;
function finding(tier: RiskTier, usage: string, observation = "negotiated", name = "X"): Finding {
  return {
    id: `f${n++}`,
    asset: {
      observed: name,
      algorithm: name,
      variant: null,
      key_size: null,
      usage,
      observation,
      confidence: "high",
      exposure: "internet",
      flags: [],
      evidence: { source_type: "network", location: "h:443", line: null, snippet: null, snippet_start_line: null, context: {} },
      more_evidence: [],
    },
    classification: {
      rule_id: name,
      name,
      primitive: "other",
      threat: "none",
      tier,
      classically_broken: false,
      nist_reference: null,
      replacement: null,
      oid: null,
      classical_security_bits: null,
      nist_quantum_level: null,
      rationale: "",
    },
  } as Finding;
}

function result(findings: Finding[]): ScanResult {
  const count = (t: RiskTier) => findings.filter((f) => f.classification.tier === t).length;
  return {
    id: "scan",
    created_at: "2026-10-10T00:00:00Z",
    targets: ["h:443"],
    scanners: ["tls-probe"],
    findings,
    score: {
      value: 0,
      grade: "A",
      counts: { critical: count("critical"), medium: count("medium"), safe: count("safe"), unknown: count("unknown") },
    },
    limitations: [],
    errors: [],
  };
}

const github = result([
  finding("medium", "tls-protocol"),
  finding("critical", "tls-key-exchange", "negotiated", "ECDH"),
  finding("medium", "tls-cipher"),
  finding("medium", "tls-protocol", "permitted"),
  finding("critical", "certificate-key"),
  finding("safe", "certificate-signature-digest"),
]);

describe("sections", () => {
  it("splits negotiated, permitted and certificate findings, worst first", () => {
    const s = sections(github);
    expect(s.map((x) => [x.id, x.findings.length])).toEqual([
      ["negotiated", 3],
      ["permitted", 1],
      ["certificate", 2],
    ]);
    expect(s[0]!.findings[0]!.classification.tier).toBe("critical");
  });

  it("drops empty sections", () => {
    expect(sections(result([finding("safe", "tls-protocol")])).map((x) => x.id)).toEqual(["negotiated"]);
  });
});

describe("summary", () => {
  it("finds the negotiated key exchange, not a permitted one", () => {
    const r = result([finding("critical", "tls-key-exchange", "permitted"), finding("safe", "tls-key-exchange")]);
    expect(keyExchange(r)?.classification.tier).toBe("safe");
  });

  it("leads with the Shor count", () => {
    expect(headline(github, "github.com")).toBe("2 of 6 findings on github.com break under Shor's algorithm.");
  });

  it("falls back to Grover, then all clear", () => {
    expect(headline(result([finding("medium", "tls-cipher")]), "a.com")).toMatch(/1 finding is weakened/);
    expect(headline(result([finding("safe", "tls-cipher")]), "a.com")).toMatch(/holds up/);
  });

  it("badges the worst tier's count", () => {
    expect(badge(github)).toEqual({ text: "2", tier: "critical" });
    expect(badge(result([finding("safe", "tls-protocol")]))).toEqual({ text: "PQ", tier: "safe" });
  });
});
