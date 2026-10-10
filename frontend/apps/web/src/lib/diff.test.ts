import { describe, expect, it } from "vitest";
import { diffLines } from "./diff";

describe("diffLines", () => {
  it("keeps unchanged lines and numbers them from the snippet start", () => {
    expect(diffLines("a\nb", "a\nb", 10)).toEqual([
      { op: "same", text: "a", before: 10 },
      { op: "same", text: "b", before: 11 },
    ]);
  });

  it("shows a replaced line as a removal then an addition", () => {
    const d = diffLines('k = 1\nc = AES.new(k, AES.MODE_ECB)\nreturn c', 'k = 1\nc = AES.new(k, AES.MODE_GCM)\nreturn c', 5);
    expect(d.map((l) => l.op)).toEqual(["same", "del", "add", "same"]);
    expect(d[1]).toEqual({ op: "del", text: "c = AES.new(k, AES.MODE_ECB)", before: 6 });
    expect(d[3]?.before).toBe(7);
  });

  it("handles added and removed lines at the edges", () => {
    expect(diffLines("x", "import os\nx\ny").map((l) => l.op)).toEqual(["add", "same", "add"]);
    expect(diffLines("a\nx", "x").map((l) => l.op)).toEqual(["del", "same"]);
  });
});
