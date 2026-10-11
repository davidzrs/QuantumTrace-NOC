import { describe, expect, it } from "vitest";
import {
  commandLink,
  explanation,
  headline,
  inlineHint,
  label,
  lensTitle,
  ranSummary,
  testName,
} from "./explain";
import { finding, md5 } from "./fixtures";

const LINK = "command:quantumtrace.dismiss?x";

describe("label", () => {
  it("prefers the engine's precise variant", () => {
    expect(label(finding({ asset: { variant: "AES-128-ECB" } }))).toBe("AES-128-ECB");
  });

  it("adds the key size when the rule name does not carry it", () => {
    const rsa = finding({ asset: { key_size: 2048 }, classification: { name: "RSA" } });
    expect(label(rsa)).toBe("RSA-2048");
    expect(label(finding())).toBe("RSA-1024");
  });
});

describe("headline", () => {
  it("says what was found and why it matters, in the engine's words", () => {
    expect(headline(md5)).toBe(
      "MD5: Trivially collidable; must not be used for any security purpose.",
    );
  });
});

describe("inlineHint", () => {
  it("says in a few words what the finding is and which attack applies", () => {
    expect(inlineHint([finding()])).toBe("RSA-1024: broken by Shor's algorithm");
    expect(inlineHint([md5])).toBe("MD5: weakened by Grover's algorithm");
  });

  it("falls back to what is wrong today, then to the tier, when no quantum attack applies", () => {
    const rng = finding({
      asset: { key_size: null },
      classification: { name: "Non-cryptographic RNG", tier: "medium", threat: "none" },
    });
    expect(inlineHint([rng])).toBe("Non-cryptographic RNG: already broken today");
    const unknown = finding({
      asset: { key_size: null },
      classification: { name: "ROT13", tier: "unknown", threat: "unknown", classically_broken: false },
    });
    expect(inlineHint([unknown])).toBe("ROT13: unclassified");
  });

  it("describes the first finding and counts the others on the line", () => {
    expect(inlineHint([finding(), md5])).toBe("RSA-1024: broken by Shor's algorithm (+1 more)");
    expect(inlineHint([finding(), md5, md5])).toMatch(/\(\+2 more\)$/);
    expect(inlineHint([])).toBe("");
  });

  it("stays short even when the name is long, and keeps the reason", () => {
    const long = finding({ asset: { variant: "X".repeat(200) } });
    const hint = inlineHint([long, md5]);
    expect(hint.length).toBeLessThanOrEqual(72);
    expect(hint).toMatch(/^X+…: broken by Shor's algorithm \(\+1 more\)$/);
  });
});

type Execution = NonNullable<ReturnType<typeof finding>["asset"]["evidence"]["execution"]>;

const ran = (over: Partial<Execution> = {}): Execution => ({
  ran: true,
  calls: 14,
  tests: ["tests/test_auth.py::TestAuth::test_login", "tests/test_auth.py::test_logout"],
  test_count: 2,
  parameters: { api: "rsa.sign", key_size: "1024" },
  run: "python -m pytest",
  ...over,
});

describe("what a traced run saw", () => {
  it("names a test by its last part, pytest or unittest style", () => {
    expect(testName("tests/test_auth.py::TestAuth::test_login")).toBe("test_login");
    expect(testName("tests.test_auth.TestAuth.test_login")).toBe("test_login");
    expect(testName("test_login")).toBe("test_login");
  });

  it("says how often a line ran and in which test", () => {
    expect(ranSummary(ran())).toBe("ran 14× in test_login and 1 more test");
    expect(ranSummary(ran({ tests: ["t::test_a"], test_count: 1 }))).toBe("ran 14× in test_a");
    expect(ranSummary(ran({ test_count: 4 }))).toBe("ran 14× in test_login and 3 more tests");
  });

  it("names the command when no test ran it, and leaves out a count the tracer does not have", () => {
    expect(ranSummary(ran({ tests: [], test_count: 0, run: "python app.py" }))).toBe(
      "ran 14× during python app.py",
    );
    expect(ranSummary(ran({ calls: null, tests: ["t::test_a"], test_count: 1 }))).toBe("ran in test_a");
    expect(ranSummary(ran({ calls: null, tests: [], test_count: 0, run: null }))).toBe("ran");
    expect(ranSummary(ran({ ran: false }))).toBe("did not run");
  });

  it("heads the line with the finding: the words above a line that ran", () => {
    expect(lensTitle(finding(), ran())).toBe("RSA-1024 · ran 14× in test_login and 1 more test");
  });

  it("adds to a line's few words that the run never reached it", () => {
    expect(inlineHint([md5], true)).toBe("MD5: weakened by Grover's algorithm · did not run");
    const long = finding({ asset: { variant: "X".repeat(200) } });
    const hint = inlineHint([long, md5], true);
    expect(hint.length).toBeLessThanOrEqual(72);
    expect(hint).toMatch(/: broken by Shor's algorithm \(\+1 more\) · did not run$/);
  });

  it("says in the pop-up how it ran: times, tests, and what the call really used", () => {
    const text = explanation(finding(), LINK, { execution: ran() });
    expect(text).toContain(
      "$(play)&nbsp; **Seen running** 14× in `test_login`, `test_logout` · key size 1024",
    );
    const through = explanation(finding(), LINK, {
      execution: ran({
        tests: ["a::t1"],
        test_count: 7,
        parameters: { via: "jwt", mode: "ECB", curve: "secp256r1" },
      }),
    });
    expect(through).toContain("in `t1` and 6 more · secp256r1 · ECB mode · through jwt");
  });

  it("says in the pop-up that it did not run, and during which command", () => {
    const idle = ran({ ran: false, calls: null, tests: [], test_count: 0 });
    expect(explanation(md5, LINK, { execution: idle })).toContain(
      "$(circle-slash)&nbsp; **Did not run** during `python -m pytest`",
    );
    expect(explanation(md5, LINK)).not.toContain("Did not run");
    expect(explanation(md5, LINK, { execution: null })).not.toContain("Seen running");
  });

  it("keeps test names and commands from the trace from becoming links or tags", () => {
    const hostile = ran({
      tests: ["t::test_[x](command:evil)`<img>"],
      test_count: 1,
      run: "py `x` [y](z)",
    });
    expect(explanation(finding(), LINK, { execution: hostile })).toContain(
      "in `test_x(command:evil)img`",
    );
    expect(explanation(finding(), LINK, { execution: { ...hostile, ran: false } })).toContain(
      "during `py x y(z)`",
    );
  });
});

describe("explanation", () => {
  it("opens with a coloured title: icon, name and the tier in the line's colour", () => {
    const [title] = explanation(finding(), LINK).split("  \n");
    expect(title).toBe(
      '<span style="color:var(--vscode-quantumtrace-criticalForeground);">$(error)</span>&nbsp; ' +
        "**RSA-1024** &nbsp;" +
        '<span style="color:var(--vscode-quantumtrace-criticalForeground);' +
        "background-color:var(--vscode-quantumtrace-criticalLineBackground);" +
        'border-radius:4px;">&nbsp;Critical&nbsp;</span>',
    );
    expect(explanation(md5, LINK)).toContain("$(warning)</span>&nbsp; **MD5** &nbsp;");
    expect(explanation(md5, LINK)).toContain("&nbsp;Weakened&nbsp;</span>");
  });

  it("keeps the real tier name when the line is drawn in another colour", () => {
    const text = explanation(finding(), LINK, { tone: "medium" });
    expect(text).toContain("quantumtrace-mediumForeground");
    expect(text).not.toContain("quantumtrace-criticalForeground");
    expect(text).toContain("&nbsp;Critical&nbsp;</span>");
  });

  it("uses only the inline styles VS Code keeps in a hover", () => {
    const allowed =
      /^(color:var\(--vscode(-[a-zA-Z]+)+\);)?(background-color:var\(--vscode(-[a-zA-Z]+)+\);)?(border-radius:[0-9]+px;)?$/;
    const aes = finding({ asset: { flags: ["ecb-mode"], confidence: "medium" } });
    const text = explanation(aes, LINK, { withRationale: true });
    const styles = [...text.matchAll(/style="([^"]*)"/g)].map((match) => match[1]);
    expect(styles.length).toBeGreaterThan(3);
    for (const style of styles) expect(style).toMatch(allowed);
  });

  it("tells Shor from Grover under the title and says how to fix", () => {
    const shor = explanation(finding(), LINK);
    expect(shor).toContain(
      ">Broken by Shor's algorithm · already broken without a quantum computer</span>",
    );
    expect(shor).toContain(
      "$(lightbulb)&nbsp; **How to fix:** switch to ML-KEM \\(FIPS 203\\) / ML-DSA \\(FIPS 204\\)",
    );
    expect(shor).toContain("$(book)&nbsp; NIST SP 800-131A");
    expect(explanation(md5, LINK)).toContain(">Security halved by Grover's algorithm · already");
  });

  it("lists misuse flags and how sure the scanner is", () => {
    const aes = finding({
      asset: { flags: ["ecb-mode", "hardcoded-key"], confidence: "medium" },
    });
    const text = explanation(aes, LINK);
    expect(text).toContain("$(tag)&nbsp; `ecb-mode` `hardcoded-key`");
    expect(text).toContain("$(info)&nbsp; Medium confidence");
  });

  it("leaves out what the engine did not provide", () => {
    const unknown = finding({
      classification: {
        tier: "unknown",
        threat: "unknown",
        classically_broken: false,
        replacement: null,
        nist_reference: null,
      },
    });
    const parts = explanation(unknown, LINK).split("\n\n");
    expect(parts).toHaveLength(2); // the title and the dismiss button, nothing in between
    expect(parts[0]).toContain("$(info)</span>&nbsp; **RSA-1024** &nbsp;");
    expect(parts[0]).toContain("&nbsp;Unclassified&nbsp;</span>");
    expect(parts[0]).not.toContain("  \n");
  });

  it("starts the verdict with a capital when the quantum threat is not what breaks it", () => {
    const rng = finding({ classification: { tier: "medium", threat: "none" } });
    expect(explanation(rng, LINK)).toContain(">Already broken without a quantum computer</span>");
  });

  it("states the engine's reason only when asked, right after the title", () => {
    const reason = "Trivially collidable; must not be used for any security purpose.";
    expect(explanation(md5, LINK)).not.toContain(reason);
    expect(explanation(md5, LINK, { withRationale: true }).split("\n\n")[1]).toBe(reason);
  });

  it("ends with the dismiss button", () => {
    expect(explanation(md5, LINK).split("\n\n").at(-1)).toBe(
      '<span style="background-color:var(--vscode-badge-background);border-radius:4px;">&nbsp; ' +
        '[<span style="color:var(--vscode-badge-foreground);">$(close) Dismiss warning</span>]' +
        `(${LINK}) &nbsp;</span>`,
    );
  });

  it("puts Fix with AI before the dismiss button, only when given its link", () => {
    const fixLink = "command:quantumtrace.fix?y";
    const [fix, dismiss, ...rest] = (explanation(md5, LINK, { fixLink }).split("\n\n").at(-1) ?? "")
      .split(" &nbsp; ");
    expect(fix).toBe(
      '<span style="background-color:var(--vscode-badge-background);border-radius:4px;">&nbsp; ' +
        '[<span style="color:var(--vscode-badge-foreground);">$(sparkle) Fix with AI</span>]' +
        `(${fixLink}) &nbsp;</span>`,
    );
    expect(dismiss).toContain(`$(close) Dismiss warning</span>](${LINK})`);
    expect(rest).toEqual([]);
    expect(explanation(md5, LINK)).not.toContain("Fix with AI");
  });

  it("keeps text taken from source code from becoming a link, a tag or an icon", () => {
    const hostile = finding({
      classification: { name: "[run](command:x) <img src=x> $(flame) &amp;" },
      asset: { key_size: null },
    });
    expect(explanation(hostile, LINK)).toContain(
      "**\\[run\\]\\(command:x\\) \\<img src=x\\> \\$\\(flame\\) \\&amp;**",
    );
  });
});

describe("commandLink", () => {
  it("survives arguments with parentheses and quotes inside a Markdown link", () => {
    const args = ["file:///a (1).py", 3, "md5", 'hash "x"'];
    const link = commandLink("quantumtrace.dismiss", args);
    expect(link).not.toMatch(/[()\s"]/);
    const query = link.slice(link.indexOf("?") + 1);
    expect(JSON.parse(decodeURIComponent(query))).toEqual(args);
  });
});
