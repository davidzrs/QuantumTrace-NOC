import { describe, expect, it } from "vitest";
import { dismissed, Dismissals, type Store } from "./dismissals";

function memory(initial?: unknown): Store {
  const values = new Map<string, unknown>();
  if (initial !== undefined) values.set("quantumtrace.dismissed", initial);
  return {
    get: <T>(key: string, fallback: T) => (values.has(key) ? (values.get(key) as T) : fallback),
    update: (key, value) => {
      if (value === undefined) values.delete(key);
      else values.set(key, value);
      return Promise.resolve();
    },
  };
}

const MD5_KEY = "md5|hash|h = hashlib.md5(x)";
const md5 = dismissed(MD5_KEY, "MD5", "medium", 4);
const item = (key: string, line = 0) => dismissed(key, "X", "medium", line);

describe("dismissed", () => {
  it("keeps the line of code out of the key, even when the code contains the separator", () => {
    expect(md5).toEqual({ key: MD5_KEY, label: "MD5", tier: "medium", line: 4, text: "h = hashlib.md5(x)" });
    expect(dismissed("rsa|signature|a = b | c", "RSA", "critical", 0).text).toBe("a = b | c");
  });
});

describe("Dismissals", () => {
  it("remembers a dismissal for one file only", async () => {
    const dismissals = new Dismissals(memory());
    await dismissals.add("src/a.py", md5);
    expect(dismissals.has("src/a.py", MD5_KEY)).toBe(true);
    expect(dismissals.has("src/b.py", MD5_KEY)).toBe(false);
    expect(dismissals.has("src/a.py", "sha1|hash|h = hashlib.sha1(x)")).toBe(false);
  });

  it("survives a restart, because it lives in the store", async () => {
    const store = memory();
    await new Dismissals(store).add("src/a.py", md5);
    expect(new Dismissals(store).has("src/a.py", MD5_KEY)).toBe(true);
    expect(new Dismissals(store).list()).toEqual([{ file: "src/a.py", item: md5 }]);
  });

  it("lists every dismissal by file, then by line", async () => {
    const dismissals = new Dismissals(memory());
    await dismissals.add("b.go", item("two", 9));
    await dismissals.add("a.py", item("late", 30));
    await dismissals.add("a.py", item("early", 2));
    expect(dismissals.list().map((row) => `${row.file}:${row.item.key}`)).toEqual([
      "a.py:early",
      "a.py:late",
      "b.go:two",
    ]);
  });

  it("undoes one dismissal and leaves the others", async () => {
    const dismissals = new Dismissals(memory());
    await dismissals.add("a.py", item("one"));
    await dismissals.add("a.py", item("two"));
    await dismissals.add("a.py", item("two"));
    expect(dismissals.count()).toBe(2);
    await dismissals.remove("a.py", "one");
    expect(dismissals.has("a.py", "one")).toBe(false);
    expect(dismissals.has("a.py", "two")).toBe(true);
    expect(dismissals.count()).toBe(1);
  });

  it("restores everything on clear", async () => {
    const dismissals = new Dismissals(memory());
    await dismissals.add("a.py", item("one"));
    await dismissals.add("b.go", item("two"));
    await dismissals.clear();
    expect(dismissals.count()).toBe(0);
    expect(dismissals.list()).toEqual([]);
  });

  it("still honours and lists dismissals saved by versions that stored only the key", async () => {
    const dismissals = new Dismissals(memory({ "a.py": [MD5_KEY] }));
    expect(dismissals.has("a.py", MD5_KEY)).toBe(true);
    expect(dismissals.list()).toEqual([
      {
        file: "a.py",
        item: { key: MD5_KEY, label: "md5", tier: "unknown", line: null, text: "h = hashlib.md5(x)" },
      },
    ]);
    await dismissals.add("a.py", item("new"));
    expect(dismissals.count()).toBe(2);
    await dismissals.remove("a.py", MD5_KEY);
    expect(dismissals.has("a.py", MD5_KEY)).toBe(false);
  });
});
