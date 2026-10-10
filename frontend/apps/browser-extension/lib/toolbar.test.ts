import { afterEach, describe, expect, it, vi } from "vitest";
import { setToolbarBadge } from "./toolbar";

function recorder(calls: string[]) {
  return {
    setBadgeText: async ({ text }: { text: string }) => void calls.push(`text:${text}`),
    setBadgeBackgroundColor: async ({ color }: { color: string }) => void calls.push(`color:${color}`),
  };
}

describe("setToolbarBadge", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("uses action on Manifest V3 (Chrome)", async () => {
    const calls: string[] = [];
    vi.stubGlobal("browser", { action: recorder(calls) });
    await setToolbarBadge(1, "4", "#b3123f");
    expect(calls).toEqual(["text:4", "color:#b3123f"]);
  });

  it("falls back to browserAction on Manifest V2 (Firefox)", async () => {
    const calls: string[] = [];
    vi.stubGlobal("browser", { browserAction: recorder(calls) });
    await setToolbarBadge(1, "PQ", "#0f7b6c");
    expect(calls).toEqual(["text:PQ", "color:#0f7b6c"]);
  });

  it("never throws, so a badge failure can't replace a finished check with an error", async () => {
    vi.stubGlobal("browser", {});
    await expect(setToolbarBadge(1, "4", "#b3123f")).resolves.toBeUndefined();
    vi.stubGlobal("browser", { action: { setBadgeText: () => Promise.reject(new Error("no tab")) } });
    await expect(setToolbarBadge(1, "4", "#b3123f")).resolves.toBeUndefined();
  });
});
