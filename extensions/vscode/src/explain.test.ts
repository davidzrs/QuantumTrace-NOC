import { describe, expect, it } from "vitest";
import { commandLink, explanation, headline, inlineHint, label } from "./explain";
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
