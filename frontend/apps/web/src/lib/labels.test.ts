import { describe, expect, it } from "vitest";
import { placeLabels, type LabelBox } from "./labels";

const box = (segLeft: number, segWidth: number): LabelBox => ({ segLeft, segWidth, name: 30, sep: 8, num: 12 });

describe("placeLabels", () => {
  it("centres a label that fits its segment, on one line", () => {
    expect(placeLabels([box(100, 100)], 400)).toEqual([{ left: 125, width: 50, twoLine: false }]);
  });

  it("puts the count on a second line when the segment is too narrow, still centred", () => {
    expect(placeLabels([box(100, 40)], 400)).toEqual([{ left: 105, width: 30, twoLine: true }]);
  });

  it("keeps crowded labels apart and inside the lane, in order", () => {
    const placed = placeLabels([box(370, 6), box(380, 4), box(390, 10)], 400, 8);
    placed.forEach((p, i) => {
      expect(p.twoLine).toBe(true);
      expect(p.left).toBeGreaterThanOrEqual(0);
      expect(p.left + p.width).toBeLessThanOrEqual(400);
      const prev = placed[i - 1];
      if (prev) expect(p.left).toBeGreaterThanOrEqual(prev.left + prev.width + 8);
    });
  });
});
