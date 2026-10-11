/** A label's segment on the debt strip and its measured text, in px from the left of the lane. */
export interface LabelBox {
  segLeft: number;
  segWidth: number;
  /** Widths of the label's parts on one line: "Cloud", " · ", "35". */
  name: number;
  sep: number;
  num: number;
}

export interface Placement {
  left: number;
  width: number;
  /** Count on a second line, without the separator. */
  twoLine: boolean;
}

/**
 * Where the strip's hover labels go: each centred over its segment, on one line ("Cloud · 35")
 * when that fits the segment, else with the count on a line of its own. A label still wider than
 * its segment is nudged just enough to keep `gap` px from its neighbours and stay inside the lane,
 * so none is ever cut or drawn over another.
 */
export function placeLabels(boxes: LabelBox[], laneWidth: number, gap = 8): Placement[] {
  const out = boxes.map((b) => {
    const oneLine = b.name + b.sep + b.num;
    const twoLine = oneLine > b.segWidth;
    const width = twoLine ? Math.max(b.name, b.num) : oneLine;
    return { left: b.segLeft + (b.segWidth - width) / 2, width, twoLine };
  });
  let floor = 0;
  for (const p of out) {
    p.left = Math.max(p.left, floor);
    floor = p.left + p.width + gap;
  }
  let ceiling = laneWidth;
  for (const p of [...out].reverse()) {
    p.left = Math.max(0, Math.min(p.left, ceiling - p.width));
    ceiling = p.left - gap;
  }
  return out;
}
