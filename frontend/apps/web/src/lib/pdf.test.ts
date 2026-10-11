import type { Finding, RiskTier, ScanResult } from "@quantumtrace/sdk";
import { describe, expect, it } from "vitest";
import { pdfText, renderPdf } from "./pdf";

type Source = Finding["asset"]["evidence"]["source_type"];

function finding(n: number, tier: RiskTier, source: Source = "code", broken = false): Finding {
  return {
    id: `f${n}`,
    asset: {
      observed: `ALG${n}`,
      algorithm: `ALG${n}`,
      variant: null,
      key_size: null,
      usage: "encryption",
      observation: "in-code",
      confidence: "high",
      exposure: "internal",
      flags: [],
      evidence: { source_type: source, location: `src/file${n}.py`, line: n, column: null, end_column: null, snippet: null, snippet_start_line: null, context: {}, execution: null },
      more_evidence: [],
      library: null,
    },
    classification: {
      rule_id: `rule-${n}`,
      name: `Algorithm ${n}`,
      primitive: "block-cipher",
      threat: tier === "critical" ? "shor" : "grover",
      tier,
      classically_broken: broken,
      hndl: false,
      nist_reference: null,
      replacement: tier === "safe" ? null : "ML-KEM (FIPS 203)",
      oid: null,
      classical_security_bits: null,
      nist_quantum_level: null,
      rationale: "",
    },
  };
}

function scan(findings: Finding[], limitations: string[] = []): ScanResult {
  const count = (t: RiskTier) => findings.filter((f) => f.classification.tier === t).length;
  return {
    id: "0123456789abcdef",
    created_at: "2026-10-11T09:14:00Z",
    targets: ["samples/"],
    scanners: ["code"],
    findings,
    score: { value: 4.0, grade: "C", counts: { critical: count("critical"), medium: count("medium"), safe: count("safe"), unknown: count("unknown") } },
    score_by_source: {},
    limitations: limitations.map((message) => ({ scanner: "code", message })),
    errors: [],
    libraries: [],
  };
}

const REPORT = "https://quantumtrace.test/scans/0123456789abcdef";

describe("pdf summary", () => {
  it("keeps the text the built-in font can print", () => {
    expect(pdfText("Shor’s – “quoted” · café")).toBe("Shor’s – “quoted” · café");
    expect(pdfText("10.0.0.5:51000 → 10.0.0.9:443 ≥ 1")).toBe("10.0.0.5:51000 -> 10.0.0.9:443 >= 1");
    expect(pdfText("Dvořák 鍵")).toBe("Dvorák ?");
  });

  it("sums a scan up on one page, most urgent fix first", async () => {
    const doc = await renderPdf(scan([finding(1, "medium"), finding(2, "critical"), finding(3, "critical", "code", true), finding(4, "safe")]), REPORT);
    const pdf = doc.output();
    expect(doc.getNumberOfPages()).toBe(1);
    expect(pdf).toContain(" of 4 cryptographic assets are critical.");
    expect(pdf).toContain("Quantum risk score");
    expect(pdf).toContain("What to fix first");
    const order = ["Fix now", "Before 2030", "Harden"].map((tag) => pdf.indexOf(`(${tag})`));
    expect(order.every((at) => at > 0)).toBe(true);
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(pdf).toContain("Recommended: ML-KEM");
    expect(pdf).toContain("The full details are in the online report");
    expect(pdf).toContain(REPORT);
    expect(pdf).toContain("Page 1 of 1");
  });

  it("caps the fixes and blind spots so a big scan stays short", async () => {
    const many = Array.from({ length: 60 }, (_, i) => finding(i, i % 3 ? "critical" : "medium", i % 2 ? "code" : "cloud"));
    const doc = await renderPdf(scan(many, Array.from({ length: 10 }, (_, i) => `Blind spot ${i}.`)), REPORT);
    const pdf = doc.output();
    expect(doc.getNumberOfPages()).toBeLessThanOrEqual(2);
    expect(pdf).toContain("By source");
    expect(pdf).toContain("And 52 more issues in the full report.");
    expect(pdf).toContain("Blind spot 5.");
    expect(pdf).not.toContain("Blind spot 6.");
  });

  it("says so when nothing was found", async () => {
    const pdf = (await renderPdf(scan([]), REPORT)).output();
    expect(pdf).toContain("No cryptography found.");
    expect(pdf).not.toContain("What to fix first");
  });
});
