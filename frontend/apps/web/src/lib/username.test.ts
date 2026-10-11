import { describe, expect, it } from "vitest";
import { authMessage, emailFor, normaliseUsername, passwordProblem, usernameOf, usernameProblem } from "./username";

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

describe("passwords", () => {
  it("only need to be present to sign in", () => {
    expect(passwordProblem("", null)).toBe("Enter your password.");
    expect(passwordProblem("x", null)).toBeNull();
  });

  it.each([
    ["", "", "Choose a password."],
    ["short", "short", "Use at least 6 characters for the password."],
    ["longenough", "", "Type the password again to confirm it."],
    ["longenough", "longenougH", "The two passwords don’t match. Type them again."],
  ])("rejects %j confirmed as %j for a new account", (password, confirm, problem) => {
    expect(passwordProblem(password, confirm)).toBe(problem);
  });

  it("accept a new password typed the same twice", () => {
    expect(passwordProblem("longenough", "longenough")).toBeNull();
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
