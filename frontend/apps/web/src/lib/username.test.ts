import { describe, expect, it } from "vitest";
import { authMessage, emailFor, normaliseUsername, usernameOf, usernameProblem } from "./username";

describe("usernames", () => {
  it("are case-insensitive and trimmed", () => {
    expect(normaliseUsername("  David_S ")).toBe("david_s");
    expect(emailFor("David_S")).toBe("david_s@users.quantumtrace.app");
  });

  it("round-trip through the sign-in email", () => {
    expect(usernameOf(emailFor("pq-team"))).toBe("pq-team");
    expect(usernameOf(null)).toBe("");
  });

  it.each([
    ["", "Enter a username."],
    ["ab", "Usernames are 3 to 20 characters long."],
    ["a".repeat(21), "Usernames are 3 to 20 characters long."],
    ["david santos", "Usernames use only letters, digits, - and _."],
    ["david@x", "Usernames use only letters, digits, - and _."],
  ])("rejects %j", (name, problem) => {
    expect(usernameProblem(name)).toBe(problem);
  });

  it("accepts letters, digits, - and _", () => {
    expect(usernameProblem("Quantum_Trace-26")).toBeNull();
  });
});

describe("auth messages", () => {
  it("say what went wrong without naming Firebase", () => {
    expect(authMessage("auth/email-already-in-use")).toMatch(/username is taken/);
    expect(authMessage("auth/invalid-credential")).toBe("Wrong username or password.");
    expect(authMessage("auth/weak-password")).toMatch(/at least 6 characters/);
    expect(authMessage(undefined)).toMatch(/Try again/);
  });
});
