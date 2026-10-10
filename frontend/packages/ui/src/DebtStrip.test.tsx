import type { Finding, RiskTier } from "@quantumtrace/sdk";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DebtStrip } from "./DebtStrip";

function finding(id: string, tier: RiskTier): Finding {
  return {
    id,
    asset: {
      observed: "RSA_2048",
      algorithm: "RSA",
      variant: null,
      key_size: 2048,
      usage: null,
      observation: "configured",
      confidence: "high",
      exposure: "internet",
      flags: [],
      evidence: { source_type: "cloud", location: "arn:x", line: null, snippet: null, context: {} },
      more_evidence: [],
    },
    classification: {
      rule_id: "rsa",
      name: "RSA",
      primitive: "pke",
      threat: "shor",
      tier,
      classically_broken: false,
      nist_reference: null,
      replacement: null,
      oid: null,
      classical_security_bits: null,
      nist_quantum_level: null,
      rationale: "",
    },
  };
}

afterEach(cleanup);

describe("DebtStrip", () => {
  it("renders one group per tier present, with counts in the accessible name", () => {
    render(
      <DebtStrip
        findings={[finding("a", "critical"), finding("b", "critical"), finding("c", "safe")]}
        onSelectTier={() => {}}
      />,
    );
    expect(screen.getByRole("button", { name: /^2 critical/ })).toBeTruthy();
    expect(screen.getByRole("button", { name: /^1 resilient/ })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /weakened/ })).toBeNull();
  });

  it("reports the selected tier", () => {
    const onSelect = vi.fn();
    render(<DebtStrip findings={[finding("a", "medium")]} onSelectTier={onSelect} />);
    fireEvent.click(screen.getByRole("button"));
    expect(onSelect).toHaveBeenCalledWith("medium");
  });
});
