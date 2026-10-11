import type { FixSuggestion } from "@quantumtrace/sdk";
import { describe, expect, it } from "vitest";
import { EngineError } from "./engine";
import { EarlierPlaceError, linesLabel, replacement, report, requestFix } from "./fix";
import { finding, md5 } from "./fixtures";

function suggestion(overrides: Partial<FixSuggestion> = {}): FixSuggestion {
  return {
    finding_id: "f1",
    summary: "Generate an ML-DSA-65 key instead of RSA-1024.",
    original_snippet: "def make_key():\n    return rsa.generate_private_key(65537, 1024)",
    fixed_snippet: "def make_key():\n    return oqs.Signature(\"ML-DSA-65\")",
    changed: true,
    snippet_start_line: 3,
    explanation: "RSA falls to Shor's algorithm.",
    caveats: [],
    model: "gemini-test",
    ...overrides,
  };
}

/** A file as the editor holds it: `lineAt` for zero-based lines. */
const editor = (text: string) => {
  const lines = text.split("\n");
  return (line: number) => lines[line];
};

describe("replacement", () => {
  it("puts back the indentation the engine removed from the snippet", () => {
    const file = [
      "class Keys:",
      "",
      "    def make_key():",
      "        return rsa.generate_private_key(65537, 1024)",
      "",
    ].join("\n");
    expect(replacement(suggestion(), editor(file))).toEqual({
      startLine: 2,
      endLine: 3,
      lines: ["    def make_key():", '        return oqs.Signature("ML-DSA-65")'],
    });
  });

  it("keeps tabs when the file is indented with tabs", () => {
    const file = "x\n\n\tdef make_key():\n\t    return rsa.generate_private_key(65537, 1024)";
    expect(replacement(suggestion(), editor(file))?.lines).toEqual([
      "\tdef make_key():",
      '\t    return oqs.Signature("ML-DSA-65")',
    ]);
  });

  it("takes a rewrite with more or fewer lines, and leaves blank lines empty", () => {
    const file = "a\nb\ndef make_key():\n    return rsa.generate_private_key(65537, 1024)";
    const longer = suggestion({ fixed_snippet: "import oqs\r\n\r\ndef make_key():\r\n    pass" });
    expect(replacement(longer, editor(file))).toEqual({
      startLine: 2,
      endLine: 3,
      lines: ["import oqs", "", "def make_key():", "    pass"],
    });
    expect(replacement(suggestion({ fixed_snippet: "pass" }), editor(file))?.lines).toEqual(["pass"]);
  });

  it("matches blank lines inside the snippet whatever whitespace the file has on them", () => {
    const fix = suggestion({ original_snippet: "a = 1\n\nb = md5()", fixed_snippet: "a = 1\n\nb = sha384()" });
    const file = "x\ny\n  a = 1\n      \n  b = md5()";
    expect(replacement(fix, editor(file))?.lines).toEqual(["  a = 1", "", "  b = sha384()"]);
  });

  it("refuses when the file no longer reads as the snippet does", () => {
    const edited = "a\nb\ndef make_key():\n    return rsa.generate_private_key(65537, 2048)";
    expect(replacement(suggestion(), editor(edited))).toBeUndefined();
    const shifted = "a\nb\nc\ndef make_key():\n    return rsa.generate_private_key(65537, 1024)";
    expect(replacement(suggestion(), editor(shifted))).toBeUndefined();
    expect(replacement(suggestion(), editor("a\nb\ndef make_key():"))).toBeUndefined();
  });

  it("refuses a line the engine cut short, so the rest of it is not lost", () => {
    const long = `    token = sign("${"x".repeat(300)}")`;
    const fix = suggestion({
      original_snippet: `key = rsa.generate()\n${long.trimStart().slice(0, 196)}`,
      fixed_snippet: "key = mldsa.generate()\ntoken = sign(",
    });
    expect(replacement(fix, editor(`a\nb\n    key = rsa.generate()\n${long}`))).toBeUndefined();
  });
});

describe("linesLabel", () => {
  it("counts from one, as the editor does", () => {
    expect(linesLabel(9, 13)).toBe("lines 10–14");
    expect(linesLabel(4, 4)).toBe("line 5");
  });
});

describe("report", () => {
  it("gives the whole suggestion: what, why, the rewrite and who wrote it", () => {
    expect(report(suggestion(), "src/keys.py")).toBe(
      [
        "Fix with AI: src/keys.py, lines 3–4",
        "Generate an ML-DSA-65 key instead of RSA-1024.",
        "Why: RSA falls to Shor's algorithm.",
        "Rewrite:",
        "  def make_key():",
        '      return oqs.Signature("ML-DSA-65")',
        "Written by gemini-test from those lines. Review it before you keep it.",
      ].join("\n"),
    );
  });

  it("lists what else must change, or what to change instead when the lines stay", () => {
    const caveats = ["Add `import oqs`.", "Install liboqs-python."];
    expect(report(suggestion({ caveats }), "keys.py")).toContain(
      "Also change:\n  - Add `import oqs`.\n  - Install liboqs-python.\nRewrite:",
    );
    const elsewhere = report(suggestion({ caveats, changed: false }), "keys.py");
    expect(elsewhere).toContain("Change instead:\n  - Add `import oqs`.");
    expect(elsewhere).not.toContain("Rewrite:");
  });
});

describe("requestFix", () => {
  const json = (body: unknown, status = 200) =>
    new Response(status === 204 ? null : JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });

  /** RSA on line 6 (one-based), MD5 on lines 4 and 6: what the API finds in the uploaded file. */
  const SCAN = { id: "scan-1", findings: [finding(), md5], limitations: [], errors: [] };
  const TARGET = {
    text: "import rsa\n",
    name: "src/keys.py",
    line: 5,
    ruleId: "rsa-1024",
    usage: "key-generation",
    observed: finding().asset.observed,
  };

  /** A stand-in API that records what it was asked. */
  function api(fix: (url: string) => Response = () => json(suggestion())) {
    const calls: string[] = [];
    const uploads: { name: string; text: string }[] = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url).pathname;
      calls.push(`${request.method} ${url}`);
      if (request.method === "DELETE") return json(null, 204);
      if (url === "/api/v1/scans") {
        for (const file of (init?.body as FormData).getAll("files") as File[]) {
          uploads.push({ name: file.name, text: await file.text() });
        }
        return json(SCAN);
      }
      return fix(url);
    };
    return { calls, uploads, options: { baseUrl: "http://qt.test", apiKey: "k", fetch: fetchImpl } };
  }

  it("uploads the editor's text, asks for that finding's fix, then deletes the scan", async () => {
    const { calls, uploads, options } = api();
    const fix = await requestFix(options, TARGET);
    expect(fix.fixed_snippet).toContain("ML-DSA-65");
    expect(uploads).toEqual([{ name: "src/keys.py", text: "import rsa\n" }]);
    expect(calls).toEqual([
      "POST /api/v1/scans",
      "POST /api/v1/scans/scan-1/findings/f1/fix",
      "DELETE /api/v1/scans/scan-1",
    ]);
  });

  it("points at the first place when the line is a repeat, without asking the model", async () => {
    const { calls, options } = api();
    const repeat = requestFix(options, { ...TARGET, ruleId: "md5", usage: "hash", observed: "hashlib.md5" });
    await expect(repeat).rejects.toThrow(EarlierPlaceError);
    await expect(repeat).rejects.toMatchObject({ line: 3 });
    expect(calls.filter((call) => call.endsWith("/fix"))).toEqual([]);
    expect(calls).toContain("DELETE /api/v1/scans/scan-1");
  });

  describe("when unsaved edits changed what the engine makes of the line", () => {
    // the key size came from another line, which a first fix rewrote: RSA-1024 is now plain RSA
    const reclassified = (tier: "critical" | "safe") => {
      const now = finding({ asset: { key_size: null }, classification: { rule_id: "rsa", name: "RSA", tier } });
      const stand = api();
      const fetchImpl: typeof fetch = async (input, init) => {
        const response = await stand.options.fetch(input, init);
        const isUpload = stand.calls.at(-1) === "POST /api/v1/scans";
        return isUpload ? json({ ...SCAN, findings: [now, md5] }) : response;
      };
      return { calls: stand.calls, options: { ...stand.options, fetch: fetchImpl } };
    };

    it("fixes the same code under the rule the engine gives it now", async () => {
      const { calls, options } = reclassified("critical");
      await expect(requestFix(options, TARGET)).resolves.toMatchObject({ changed: true });
      expect(calls).toContain("POST /api/v1/scans/scan-1/findings/f1/fix");
    });

    it("does not ask for a fix once the engine calls the line safe", async () => {
      const { calls, options } = reclassified("safe");
      await expect(requestFix(options, TARGET)).rejects.toThrow(/did not find this warning on line 6/);
      expect(calls.filter((call) => call.endsWith("/fix"))).toEqual([]);
    });

    it("does not take other code on the line for it", async () => {
      const { calls, options } = reclassified("critical");
      const other = requestFix(options, { ...TARGET, observed: "padding.PKCS1v15" });
      await expect(other).rejects.toThrow(/did not find this warning on line 6/);
      expect(calls.filter((call) => call.endsWith("/fix"))).toEqual([]);
    });
  });

  it("says so when the API's scan has no such finding on that line", async () => {
    const { calls, options } = api();
    const gone = requestFix(options, { ...TARGET, line: 40 });
    await expect(gone).rejects.toThrow(/did not find this warning on line 41.*scan it again/);
    await expect(requestFix(options, { ...TARGET, usage: "signature" })).rejects.toThrow(EngineError);
    expect(calls.filter((call) => call.endsWith("/fix"))).toEqual([]);
  });

  it("passes on the API's own words when AI fixes are off or the limit is reached", async () => {
    const off = "AI fixes are off. Set GEMINI_API_KEY on the API to turn them on.";
    await expect(requestFix(api(() => json({ detail: off }, 503)).options, TARGET)).rejects.toThrow(off);
    const limit = "Gemini's free-tier limit was reached. Wait a minute and try again.";
    const { calls, options } = api(() => json({ detail: limit }, 429));
    await expect(requestFix(options, TARGET)).rejects.toThrow(limit);
    expect(calls.at(-1)).toBe("DELETE /api/v1/scans/scan-1"); // deleted even when the fix fails
  });

  it("points at the API key command on 401 and names the URL when the API is unreachable", async () => {
    const denied = api(() => json({ detail: "Invalid or missing X-API-Key" }, 401));
    await expect(requestFix(denied.options, TARGET)).rejects.toThrow(/Set API key/);
    const down = { baseUrl: "http://qt.test", fetch: () => Promise.reject(new TypeError("fetch failed")) };
    await expect(requestFix(down, TARGET)).rejects.toThrow(/Can't reach.*http:\/\/qt\.test/);
  });

  it("still returns the fix when the scan cannot be deleted", async () => {
    const { options } = api();
    const flaky: typeof fetch = (input, init) =>
      (input instanceof Request ? input.method : init?.method) === "DELETE"
        ? Promise.reject(new TypeError("fetch failed"))
        : options.fetch(input, init);
    await expect(requestFix({ ...options, fetch: flaky }, TARGET)).resolves.toMatchObject({ changed: true });
  });
});
