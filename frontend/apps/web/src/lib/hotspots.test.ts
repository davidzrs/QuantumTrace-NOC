import type { Finding, RiskTier } from "@quantumtrace/sdk";
import { describe, expect, it } from "vitest";
import { codeHotspots, commonDir } from "./hotspots";

type Evidence = Finding["asset"]["evidence"];
const ev = (location: string, source_type: Evidence["source_type"] = "code"): Evidence => ({
  source_type,
  location,
  line: 1,
  column: null,
  end_column: null,
  snippet: null,
  snippet_start_line: null,
  execution: null,
  context: {},
});

let seq = 0;
const f = (tier: RiskTier, where: Evidence, ...more: Evidence[]): Finding => ({
  id: String(seq++),
  asset: {
    observed: "x",
    algorithm: "x",
    variant: null,
    key_size: null,
    usage: null,
    observation: "in-code",
    confidence: "high",
    exposure: "unknown",
    flags: [],
    evidence: where,
    more_evidence: more,
    library: null,
  },
  classification: {
    rule_id: "x",
    name: "X",
    primitive: "pke",
    threat: "shor",
    tier,
    classically_broken: false,
    hndl: false,
    nist_reference: null,
    replacement: null,
    oid: null,
    classical_security_bits: null,
    nist_quantum_level: null,
    rationale: "",
  },
});

describe("codeHotspots", () => {
  it("ranks files by Shor, then Grover, counting every occurrence", () => {
    const spots = codeHotspots([
      f("medium", ev("repo/hash.py"), ev("repo/hash.py"), ev("repo/hash.py")),
      f("critical", ev("repo/auth.py")),
      f("safe", ev("repo/auth.py")),
      f("critical", ev("repo/keys.go"), ev("repo/keys.go")),
      f("critical", ev("arn:aws:kms:key/1", "cloud")),
    ]);
    expect(spots.map((s) => s.path)).toEqual(["repo/keys.go", "repo/auth.py", "repo/hash.py"]);
    expect(spots[1]).toMatchObject({ total: 2, ticks: ["critical", "safe"] });
    expect(spots[2]?.counts.medium).toBe(3);
  });
});

describe("commonDir", () => {
  it("finds the shared folder, never a partial name", () => {
    expect(commonDir(["repo/go/a.go", "repo/java/B.java"])).toBe("repo/");
    expect(commonDir(["repo/app/a.py", "repo/apple/b.py"])).toBe("repo/");
    expect(commonDir(["a.py", "repo/b.py"])).toBe("");
    expect(commonDir(["repo/src/a.py"])).toBe("repo/src/");
  });
});
