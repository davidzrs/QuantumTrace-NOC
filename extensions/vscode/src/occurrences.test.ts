import { describe, expect, it } from "vitest";
import { finding, md5, repeat } from "./fixtures";
import { applyEdits, type Edit, mostSevereFirst, occurrences } from "./occurrences";

const SOURCE = [
  "import hashlib",
  "",
  "def digest(data):",
  "    return hashlib.md5(data).hexdigest()",
  "",
  "legacy = hashlib.md5(b'x')",
];
const lineAt = (line: number) => SOURCE[line];
const spans = (items: { line: number; start: number; end: number }[]) =>
  items.map((o) => [o.line, o.start, o.end]);

const insert = (line: number, char: number, text: string): Edit => ({
  startLine: line,
  startChar: char,
  endLine: line,
  endChar: char,
  text,
});

describe("what a traced run saw of each place", () => {
  it("stays with its own line: one place of a finding can have run and another not", () => {
    const seen = { ran: true, calls: 3, tests: ["t::test_a"], test_count: 1, parameters: {}, run: "pytest" };
    const traced = structuredClone(md5);
    traced.asset.evidence.execution = seen;
    for (const place of traced.asset.more_evidence) {
      place.execution = { ...seen, ran: false, calls: null, tests: [], test_count: 0 };
    }
    const places = occurrences([traced], lineAt).map((o) => [o.line, o.execution?.ran, o.execution?.calls]);
    expect(places).toEqual([
      [3, true, 3],
      [5, false, null],
    ]);
  });

  it("is null when no trace covers the place", () => {
    expect(occurrences([md5], lineAt).map((o) => o.execution)).toEqual([null, null]);
  });
});

describe("occurrences", () => {
  it("underlines the observed call on every line the engine reported", () => {
    expect(spans(occurrences([md5], lineAt))).toEqual([
      [3, 11, 22],
      [5, 9, 20],
    ]);
  });

  it("falls back to the line without indentation when the observed text is not on it", () => {
    const random = finding({ asset: { observed: "java.util.Random" }, evidence: { line: 1 } });
    const [hit] = occurrences([random], () => "    Random r = new Random();  ");
    expect([hit?.start, hit?.end]).toEqual([4, 28]);
  });

  it("skips safe findings, evidence that is not code, and lines the file no longer has", () => {
    const safe = finding({ classification: { tier: "safe" } });
    const cloud = finding({ evidence: { source_type: "cloud" } });
    const beyond = finding({ evidence: { line: 99 } });
    expect(occurrences([safe, cloud, beyond], lineAt)).toEqual([]);
  });

  it("lists a line once even when the engine repeats it", () => {
    const repeated = finding({
      asset: { observed: "hashlib.md5", more_evidence: [repeat(6), repeat(6), repeat(4)] },
      evidence: { line: 4 },
    });
    expect(occurrences([repeated], lineAt).map((o) => o.line)).toEqual([3, 5]);
  });

  it("uses the engine's column when the call is still there", () => {
    const twice = finding({ asset: { observed: "md5" }, evidence: { line: 1, column: 15 } });
    const [hit] = occurrences([twice], () => "md5_name = h.(md5(x))");
    expect([hit?.start, hit?.end]).toEqual([14, 17]);
    const [moved] = occurrences([twice], () => "  md5(x)");
    expect([moved?.start, moved?.end]).toEqual([2, 5]);
  });

  it("gives the same key to a line that only moved", () => {
    const [before] = occurrences([md5], lineAt);
    const [after] = occurrences([md5], (line) => (line === 3 ? `\t${SOURCE[3]}` : SOURCE[line]));
    expect(after?.key).toBe(before?.key);
  });
});

describe("mostSevereFirst", () => {
  it("puts the critical finding of a line above the weakened one, whatever the engine's order", () => {
    // public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA1())
    const line = "public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA1())";
    const sha1 = finding({
      asset: { observed: "hashes.SHA1", usage: "hash" },
      evidence: { line: 1 },
      classification: { rule_id: "sha1", name: "SHA-1", tier: "medium", threat: "grover" },
    });
    const rsa = finding({ asset: { observed: "padding.PKCS1v15", usage: "signature" }, evidence: { line: 1 } });
    const unknown = finding({ evidence: { line: 1 }, classification: { rule_id: "x", tier: "unknown" } });
    const items = occurrences([sha1, unknown, rsa], () => line);

    const rules = (list: typeof items) => list.map((o) => o.finding.classification.rule_id);
    expect(rules(mostSevereFirst(items))).toEqual(["rsa-1024", "sha1", "x"]);
    expect(rules(items)).toEqual(["sha1", "x", "rsa-1024"]); // the input is left as it was
  });

  it("keeps the engine's order between findings of the same tier", () => {
    const first = finding({ evidence: { line: 1 }, classification: { rule_id: "a" } });
    const second = finding({ evidence: { line: 1 }, classification: { rule_id: "b" } });
    const items = mostSevereFirst(occurrences([first, second], () => "x"));
    expect(items.map((o) => o.finding.classification.rule_id)).toEqual(["a", "b"]);
  });
});

describe("applyEdits", () => {
  const items = occurrences([md5], lineAt);

  it("moves underlines down when a line is added above them", () => {
    expect(spans(applyEdits(items, [insert(0, 0, "import os\n")]))).toEqual([
      [4, 11, 22],
      [6, 9, 20],
    ]);
  });

  it("keeps an underline intact when Enter is pressed at the start of its line", () => {
    expect(spans(applyEdits(items, [insert(5, 0, "\n")]))).toEqual([
      [3, 11, 22],
      [6, 9, 20],
    ]);
  });

  it("shifts columns when text before the underline on the same line changes", () => {
    const rename: Edit = { startLine: 5, startChar: 0, endLine: 5, endChar: 6, text: "old" };
    expect(spans(applyEdits(items, [rename]))).toEqual([
      [3, 11, 22],
      [5, 6, 17],
    ]);
  });

  it("leaves an underline alone when the edit comes after it", () => {
    expect(spans(applyEdits(items, [insert(5, 26, "  # legacy")]))).toEqual(spans(items));
  });

  it("drops an underline when the code under it is edited", () => {
    expect(spans(applyEdits(items, [insert(3, 15, "x")]))).toEqual([[5, 9, 20]]);
  });

  it("pulls an underline up when the empty line before it is deleted", () => {
    const join: Edit = { startLine: 4, startChar: 0, endLine: 5, endChar: 0, text: "" };
    expect(spans(applyEdits(items, [join]))).toEqual([
      [3, 11, 22],
      [4, 9, 20],
    ]);
  });

  it("applies several edits from one change, each positioned against the old document", () => {
    const edits = [insert(0, 0, "# a\n"), insert(4, 0, "# b\n")];
    expect(spans(applyEdits(items, edits))).toEqual([
      [4, 11, 22],
      [7, 9, 20],
    ]);
  });
});
