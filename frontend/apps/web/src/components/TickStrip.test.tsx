import type { Finding, RiskTier } from "@quantumtrace/sdk";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Source } from "../lib/format";
import { TickStrip } from "./TickStrip";

let seq = 0;
function finding(tier: RiskTier, source: Source): Finding {
  return {
    id: String(seq++),
    asset: {
      observed: "RSA",
      algorithm: "RSA",
      variant: null,
      key_size: null,
      usage: null,
      observation: "configured",
      confidence: "high",
      exposure: "internet",
      flags: [],
      evidence: { source_type: source, location: "x", line: null, column: null, end_column: null, snippet: null, snippet_start_line: null, context: {}, execution: null },
      more_evidence: [],
      library: null,
    },
    classification: {
      rule_id: "rsa",
      name: "RSA",
      primitive: "signature",
      threat: tier === "critical" ? "shor" : "grover",
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
  };
}

afterEach(cleanup);

describe("TickStrip", () => {
  it("splits only the hovered tier by source, in one word each", () => {
    const findings = [
      ...Array.from({ length: 30 }, () => finding("critical", "network")),
      finding("critical", "code"),
      finding("critical", "cloud"),
      finding("medium", "cloud"),
    ];
    const { container } = render(<TickStrip findings={findings} focus={undefined} focusSource={undefined} onSelect={() => {}} />);
    const labels = () => [...container.querySelectorAll("[aria-hidden] > span")].map((el) => el.textContent);
    expect(labels()).toEqual([]);

    fireEvent.mouseEnter(screen.getByRole("button", { name: /32 Critical/ }));
    expect(labels()).toEqual(["Cloud · 1", "Code · 1", "Network · 30"]);
  });

  it("filters by the source clicked, or by the whole tier between sources and from the keyboard", () => {
    const findings = [finding("critical", "network"), finding("critical", "code")];
    const onSelect = vi.fn();
    const { container } = render(<TickStrip findings={findings} focus={undefined} focusSource={undefined} onSelect={onSelect} />);
    const tier = screen.getByRole("button", { name: /2 Critical/ });

    fireEvent.click(container.querySelector('[data-source="code"] .qt-tick')!);
    expect(onSelect).toHaveBeenLastCalledWith("critical", "code");
    fireEvent.click(tier);
    expect(onSelect).toHaveBeenLastCalledWith("critical", undefined);
  });
});
