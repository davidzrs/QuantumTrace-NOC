import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../lib/api";
import { ApiStatus } from "./ApiStatus";

const health = {
  status: "ok",
  version: "0.1.0",
  max_upload_mb: 4,
  max_unpacked_mb: 50,
  persistent: true,
  max_repo_mb: 150,
  ai_fix: true,
};

const shown = () =>
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ApiStatus />
    </QueryClientProvider>,
  );

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("ApiStatus", () => {
  it("says Online without the version, and shows the details when clicked", async () => {
    vi.spyOn(api, "health").mockResolvedValue(health);
    shown();
    const button = await screen.findByRole("button", { name: "Scanner Online" });
    expect(screen.queryByText(/0\.1\.0/)).toBeNull();

    fireEvent.click(button);
    expect(button.getAttribute("aria-expanded")).toBe("true");
    const panel = screen.getByRole("region", { name: "Scanner status" });
    expect(panel.textContent).toContain("v0.1.0");
    expect(panel.textContent).toContain("Kept for 30 days");
    expect(panel.textContent).toContain("Up to 4 MB sent, 50 MB unpacked");

    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("region", { name: "Scanner status" })).toBeNull();
  });

  it("says why it is offline", async () => {
    vi.spyOn(api, "health").mockRejectedValue(new Error("Failed to fetch"));
    shown();
    fireEvent.click(await screen.findByRole("button", { name: "Scanner Offline" }));
    expect(screen.getByRole("alert").textContent).toContain("Failed to fetch");
  });
});
