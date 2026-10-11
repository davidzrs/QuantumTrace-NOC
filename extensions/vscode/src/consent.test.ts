import { describe, expect, it } from "vitest";
import { ApiConsent, originOf } from "./consent";
import type { Store } from "./dismissals";

function memory(): Store {
  const values = new Map<string, unknown>();
  return {
    get: <T>(key: string, fallback: T) => (values.has(key) ? (values.get(key) as T) : fallback),
    update: (key, value) => {
      values.set(key, value);
      return Promise.resolve();
    },
  };
}

describe("originOf", () => {
  it("ignores the path, so the same API is recognised however its address is written", () => {
    expect(originOf("https://api.example.com/")).toBe("https://api.example.com");
    expect(originOf("https://api.example.com/api/v1")).toBe("https://api.example.com");
    expect(originOf("http://localhost:8000")).toBe("http://localhost:8000");
  });

  it("falls back to the text for something that is not a URL", () => {
    expect(originOf("not a url")).toBe("not a url");
  });
});

describe("ApiConsent", () => {
  it("has no answer until the user gives one", () => {
    expect(new ApiConsent(memory()).answerFor("https://api.example.com")).toBeUndefined();
  });

  it("remembers yes and no across restarts", async () => {
    const store = memory();
    await new ApiConsent(store).record("https://yes.example.com", true);
    await new ApiConsent(store).record("https://no.example.com", false);
    const consent = new ApiConsent(store);
    expect(consent.answerFor("https://yes.example.com/")).toBe(true);
    expect(consent.answerFor("https://no.example.com")).toBe(false);
  });

  it("does not carry a yes for one API over to another", async () => {
    const consent = new ApiConsent(memory());
    await consent.record("https://api.example.com", true);
    expect(consent.answerFor("https://other.example.com")).toBeUndefined();
    expect(consent.answerFor("http://api.example.com")).toBeUndefined();
  });

  it("keeps one question's answer apart from another's", async () => {
    const store = memory();
    await new ApiConsent(store).record("https://api.example.com", true);
    const aiFix = new ApiConsent(store, "quantumtrace.aiFixConsent");
    expect(aiFix.answerFor("https://api.example.com")).toBeUndefined();
    await aiFix.record("https://api.example.com", false);
    expect(new ApiConsent(store).answerFor("https://api.example.com")).toBe(true);
  });

  it("lets a later answer replace an earlier one", async () => {
    const consent = new ApiConsent(memory());
    await consent.record("https://api.example.com", false);
    await consent.record("https://api.example.com", true);
    expect(consent.answerFor("https://api.example.com")).toBe(true);
  });
});
