import { describe, expect, it } from "vitest";
import { observationLabel, runtimeNote } from "./format";

const ran = {
  ran: true,
  calls: 14,
  tests: ["tests/test_auth.py::test_login"],
  test_count: 2,
  parameters: { api: "rsa.sign", key_size: "1024" },
  run: "python -m pytest",
};

describe("runtimeNote", () => {
  it("says how often a place ran, in how many tests, and with what", () => {
    expect(runtimeNote(ran)).toBe("Ran 14 times in 2 tests (key size 1024)");
    expect(runtimeNote({ ...ran, calls: 1, test_count: 1, parameters: {} })).toBe("Ran 1 time in 1 test");
    expect(runtimeNote({ ...ran, parameters: { mode: "ECB", via: "jwt" } })).toBe(
      "Ran 14 times in 2 tests (ECB mode, through jwt)",
    );
  });

  it("names the traced command when no test ran it, or when the place did not run", () => {
    expect(runtimeNote({ ...ran, tests: [], test_count: 0, parameters: {} })).toBe(
      "Ran 14 times during python -m pytest",
    );
    expect(runtimeNote({ ...ran, calls: null, tests: [], test_count: 0, parameters: {} })).toBe(
      "Ran during python -m pytest",
    );
    expect(runtimeNote({ ...ran, ran: false, calls: null, tests: [], test_count: 0, parameters: {} })).toBe(
      "Did not run during python -m pytest",
    );
  });

  it("says nothing when no trace covers the place", () => {
    expect(runtimeNote(null)).toBeUndefined();
  });
});

describe("observationLabel", () => {
  it("has words for evidence from a traced run", () => {
    expect(observationLabel("executed")).toBe("Seen running");
  });
});
