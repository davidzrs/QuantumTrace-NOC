import type { Finding, RiskTier } from "@quantumtrace/sdk";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Source } from "../lib/format";
import { FindingsTable } from "./FindingsTable";

function finding(n: number, tier: RiskTier = "critical"): Finding {
  return {
    id: `f${n}`,
    asset: {
      observed: `ALG${n}`,
      algorithm: `ALG${n}`,
      variant: null,
      key_size: null,
      usage: null,
      observation: "configured",
      confidence: "high",
      exposure: "internet",
      flags: [],
      evidence: { source_type: "cloud", location: `arn:${n}`, line: null, column: null, end_column: null, snippet: null, snippet_start_line: null, context: {} },
      more_evidence: [],
    },
    classification: {
      rule_id: `rule-${String(n).padStart(2, "0")}`,
      name: `Algorithm ${n}`,
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

const findings = Array.from({ length: 25 }, (_, n) => finding(n, n < 20 ? "critical" : "medium"));
const bodyRows = () => within(screen.getAllByRole("rowgroup")[1]!).getAllByRole("row");
// The panel asks /health whether AI fixes are on: answer from the cache, never the network.
const client = (aiFix = false) => {
  const c = new QueryClient();
  c.setQueryData(["health"], { ai_fix: aiFix });
  return c;
};
const table = (tier?: RiskTier, list = findings, queries = client(), source?: Source, onSourceChange = () => {}) => (
  <QueryClientProvider client={queries}>
    <FindingsTable
      scanId="s"
      findings={list}
      tier={tier}
      onTierChange={() => {}}
      source={source}
      onSourceChange={onSourceChange}
      query=""
      onQueryChange={() => {}}
    />
  </QueryClientProvider>
);

beforeAll(() => {
  // jsdom has no modal dialogs or scrolling.
  if (typeof HTMLDialogElement.prototype.showModal !== "function") {
    HTMLDialogElement.prototype.showModal = function (this: HTMLDialogElement) {
      this.setAttribute("open", "");
    };
  }
  Element.prototype.scrollIntoView = vi.fn();
});
afterEach(cleanup);

describe("FindingsTable", () => {
  it("pages the list instead of scrolling it, from below the table or above it", () => {
    render(table());
    expect(bodyRows()).toHaveLength(8);
    expect(screen.getByText("Page 1 of 4")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Previous" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("button", { name: "Previous page" })).toHaveProperty("disabled", true);

    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("Page 2 of 4")).toBeTruthy();
    expect(screen.getByText("9–16 of 25 rows")).toBeTruthy();

    for (let i = 0; i < 2; i++) fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(screen.getByText("Page 4 of 4")).toBeTruthy();
    expect(bodyRows()).toHaveLength(1);
    expect(screen.getByRole("button", { name: "Next" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("button", { name: "Next page" })).toHaveProperty("disabled", true);

    fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
    expect(screen.getByText("Page 3 of 4")).toBeTruthy();
  });

  it("lists only the source picked on the strip, with a chip that clears it", () => {
    const code = finding(99);
    code.asset.evidence = { ...code.asset.evidence, source_type: "code", location: "app/auth.py", line: 3 };
    const onSourceChange = vi.fn();
    render(table(undefined, [...findings, code], client(), "code", onSourceChange));
    expect(bodyRows()).toHaveLength(1);
    expect(screen.getByRole("button", { name: /^All/ }).textContent).toBe("All1");

    fireEvent.click(screen.getByRole("button", { name: /Showing source code only/ }));
    expect(onSourceChange).toHaveBeenCalledWith(undefined);
  });

  it("starts a new filter from the first page", () => {
    const { rerender } = render(table());
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("Page 2 of 4")).toBeTruthy();

    rerender(table("critical"));
    expect(screen.getByText("Page 1 of 3")).toBeTruthy();
  });

  it("opens a row in a panel that steps through rows and pages with them", () => {
    render(table());
    const last = bodyRows()[7]!;
    fireEvent.click(within(last).getByRole("button"));
    const panel = screen.getByRole("dialog");
    expect(within(panel).getByText("8 of 25")).toBeTruthy();

    fireEvent.click(within(panel).getByRole("button", { name: "Next finding" }));
    expect(within(panel).getByText("9 of 25")).toBeTruthy();
    expect(screen.getByText("Page 2 of 4")).toBeTruthy();

    fireEvent.keyDown(panel, { key: "ArrowLeft" });
    expect(within(panel).getByText("8 of 25")).toBeTruthy();
    expect(screen.getByText("Page 1 of 4")).toBeTruthy();

    fireEvent.click(within(panel).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("offers Fix with AI on code findings, and says how to turn it on when the API has it off", () => {
    const code = finding(99);
    code.asset.evidence = { ...code.asset.evidence, source_type: "code", location: "app/auth.py", line: 3, snippet: "key = RSA.generate(1024)", snippet_start_line: 3 };
    const list = [code, finding(1)];
    const tabs = () => within(screen.getByRole("group", { name: "Show" })).getAllByRole("button").map((b) => b.textContent);

    render(table(undefined, list, client(true)));
    fireEvent.click(screen.getByRole("button", { name: /Open details for .* at app\/auth\.py/ }));
    expect(tabs()).toEqual(["Details", "CBOM component", "Fix with AI"]);
    fireEvent.click(within(screen.getByRole("group", { name: "Show" })).getByRole("button", { name: "Fix with AI" }));
    const panel = screen.getByRole("dialog");
    expect(within(panel).getByText("key = RSA.generate(1024)")).toBeTruthy();
    expect(within(panel).getAllByRole("button", { name: "Fix with AI" })).toHaveLength(2); // the tab and the action

    // Stepping to the cloud finding drops the tab and falls back to the details.
    fireEvent.click(within(panel).getByRole("button", { name: "Previous finding" }));
    expect(tabs()).toEqual(["Details", "CBOM component"]);
    cleanup();

    render(table(undefined, list, client(false)));
    fireEvent.click(screen.getByRole("button", { name: /Open details for .* at app\/auth\.py/ }));
    expect(tabs()).toEqual(["Details", "CBOM component", "Fix with AI"]);
    fireEvent.click(within(screen.getByRole("group", { name: "Show" })).getByRole("button", { name: "Fix with AI" }));
    const off = screen.getByRole("dialog");
    expect(within(off).getByText(/AI fixes are off on this API/)).toBeTruthy();
    const action = within(off).getAllByRole("button", { name: "Fix with AI" }).find((b) => b.classList.contains("btn"));
    expect(action).toHaveProperty("disabled", true);
  });
});
