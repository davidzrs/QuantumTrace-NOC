import type { Finding } from "@quantumtrace/sdk";
import { describe, expect, it } from "vitest";
import { findComponent } from "./cbom";

const SUITE = "TLS_RSA_WITH_AES_128_CBC_SHA";
const FLOW = "10.0.0.5:51000 -> 10.0.0.9:443";

function tlsFinding(usage: string, algorithm: string): Finding {
  return {
    id: usage,
    asset: {
      observed: SUITE,
      algorithm,
      variant: null,
      key_size: null,
      usage,
      observation: "negotiated",
      confidence: "high",
      exposure: "internal",
      flags: [],
      evidence: {
        source_type: "network",
        location: FLOW,
        line: null,
        column: null,
        end_column: null,
        snippet: null,
        snippet_start_line: null,
        execution: null,
        context: { packet: "12" },
      },
      more_evidence: [],
      library: null,
    },
    classification: {
      rule_id: algorithm.toLowerCase(),
      name: algorithm,
      primitive: "block-cipher",
      threat: "grover",
      tier: "medium",
      classically_broken: false,
      hndl: false,
      nist_reference: null,
      replacement: null,
      oid: null,
      classical_security_bits: null,
      nist_quantum_level: null,
      rationale: "",
    },
  };
}

const component = (ref: string, usage: string) => ({
  "bom-ref": ref,
  evidence: {
    occurrences: [
      { location: `${FLOW}/packet-12`, additionalContext: `[negotiated, high confidence] ${usage} observed=${SUITE}` },
    ],
  },
});

describe("findComponent", () => {
  it("tells apart components recorded at the same place by usage", () => {
    // Sorted by bom-ref as the API emits them: the cipher comes before the key exchange.
    const cbom = {
      components: [
        component("crypto/aes-128/aes-128-cbc", "tls-cipher"),
        component("crypto/rsa/rsa-key-transport", "tls-key-exchange"),
        component("crypto/sha1", "tls-mac"),
      ],
    };
    const ref = (f: Finding) => (findComponent(cbom, f) as { "bom-ref": string } | undefined)?.["bom-ref"];
    expect(ref(tlsFinding("tls-key-exchange", "RSA"))).toBe("crypto/rsa/rsa-key-transport");
    expect(ref(tlsFinding("tls-cipher", "AES-128"))).toBe("crypto/aes-128/aes-128-cbc");
    expect(ref(tlsFinding("tls-mac", "SHA-1"))).toBe("crypto/sha1");
    expect(ref(tlsFinding("tls-authentication", "RSA"))).toBeUndefined();
  });

  it("tells apart two findings on one line by column", () => {
    const at = (column: number, extra: object = {}) => ({
      ...tlsFinding("tls-cipher", "AES-128"),
      asset: { ...tlsFinding("tls-cipher", "AES-128").asset, evidence: { ...tlsFinding("tls-cipher", "AES-128").asset.evidence, line: 7, column, ...extra } },
    });
    const occ = (offset: number) => ({ location: `${FLOW}/packet-12`, line: 7, offset, additionalContext: `[configured, high confidence] tls-cipher observed=${SUITE}` });
    const cbom = {
      components: [
        { "bom-ref": "crypto/aes-128", evidence: { occurrences: [occ(5)] } },
        { "bom-ref": "crypto/aes-128/misused", evidence: { occurrences: [occ(31)] } },
      ],
    };
    const ref = (f: Finding) => (findComponent(cbom, f) as { "bom-ref": string } | undefined)?.["bom-ref"];
    expect(ref(at(5))).toBe("crypto/aes-128");
    expect(ref(at(31))).toBe("crypto/aes-128/misused");
  });
});
