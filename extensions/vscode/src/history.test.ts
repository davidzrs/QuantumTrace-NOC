import { describe, expect, it } from "vitest";
import { finding, md5 } from "./fixtures";
import { MarkHistory } from "./history";
import { applyEdits, occurrences } from "./occurrences";

const FILE = "file:///repo/license_token.py";
const BEFORE = ["import rsa", "", "", "", "", "key = rsa.generate_private_key(public_exponent=65537, key_size=1024)"];
const text = (lines: readonly string[]) => lines.join("\n");
const marksOf = (lines: readonly string[]) => occurrences([finding()], (line) => lines[line]);

describe("MarkHistory", () => {
  it("brings a file's marks back when an undo returns it to a text it had", () => {
    const history = new MarkHistory();
    const scanned = marksOf(BEFORE);
    history.remember(FILE, text(BEFORE), scanned);

    // a fix rewrites the marked line: the mark goes
    const after = [...BEFORE.slice(0, 5), 'key = oqs.Signature("ML-DSA-65")'];
    const edit = { startLine: 5, startChar: 0, endLine: 5, endChar: BEFORE[5]?.length ?? 0, text: after[5] ?? "" };
    const moved = applyEdits(scanned, [edit]);
    expect(moved).toEqual([]);
    history.remember(FILE, text(after), moved);

    // undo, then redo
    expect(history.recall(FILE, text(BEFORE))).toEqual(scanned);
    expect(history.recall(FILE, text(after))).toEqual([]);
  });

  it("knows nothing about a text the file never read as, or about another file", () => {
    const history = new MarkHistory();
    history.remember(FILE, text(BEFORE), marksOf(BEFORE));
    expect(history.recall(FILE, `${text(BEFORE)}\n`)).toBeUndefined();
    expect(history.recall("file:///repo/other.py", text(BEFORE))).toBeUndefined();
    expect(history.has(FILE)).toBe(true);
    expect(history.has("file:///repo/other.py")).toBe(false);
  });

  it("takes the latest marks for a text, as a new scan of it knows best", () => {
    const history = new MarkHistory();
    history.remember(FILE, "a", marksOf(BEFORE));
    const rescanned = occurrences([md5], () => "hashlib.md5(x)");
    history.remember(FILE, "a", rescanned);
    expect(history.recall(FILE, "a")).toEqual(rescanned);
  });

  it("hands out copies, so dismissing a mark now does not rewrite the past", () => {
    const history = new MarkHistory();
    const scanned = marksOf(BEFORE);
    history.remember(FILE, "a", scanned);
    const [recalled] = history.recall(FILE, "a") ?? [];
    expect(recalled).toBeDefined();
    if (recalled) recalled.key = "changed";
    if (scanned[0]) scanned[0].key = "changed too";
    expect(history.recall(FILE, "a")?.[0]?.key).toBe("rsa-1024|key-generation|" + BEFORE[5]);
  });

  it("keeps the texts seen last and forgets everything on clear", () => {
    const history = new MarkHistory(2);
    history.remember(FILE, "one", []);
    history.remember(FILE, "two", []);
    history.remember(FILE, "one", []); // seen again: now the newest
    history.remember(FILE, "three", []);
    expect(history.recall(FILE, "two")).toBeUndefined();
    expect(history.recall(FILE, "one")).toEqual([]);
    expect(history.recall(FILE, "three")).toEqual([]);
    history.clear();
    expect(history.has(FILE)).toBe(false);
  });
});
