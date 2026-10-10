import { beforeEach, describe, expect, it, vi } from "vitest";
import { forget, MAX_HISTORY, readHistory, remember, writeHistory } from "./history";

describe("scan history", () => {
  // Recent Node versions ship their own (disabled) localStorage that shadows jsdom's.
  beforeEach(() => {
    const items = new Map<string, string>();
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => items.get(k) ?? null,
      setItem: (k: string, v: string) => void items.set(k, v),
    });
  });

  it("keeps the newest scan first without duplicates", () => {
    remember("a");
    remember("b");
    remember("a");
    expect(readHistory()).toEqual(["a", "b"]);
  });

  it("forgets deleted scans", () => {
    writeHistory(["a", "b", "c"]);
    forget(["a", "c"]);
    expect(readHistory()).toEqual(["b"]);
  });

  it("caps the list and ignores junk", () => {
    writeHistory(Array.from({ length: MAX_HISTORY + 5 }, (_, i) => `s${i}`));
    expect(readHistory()).toHaveLength(MAX_HISTORY);
    localStorage.setItem("quantumtrace:scan-ids", "{not json");
    expect(readHistory()).toEqual([]);
  });
});
